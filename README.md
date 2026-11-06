# wgmux — WireGuard multiplexer with an eBPF steering datapath

[![CI](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml/badge.svg)](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml)

WireGuard's AllowedIPs is a one-to-one map: within one device, a prefix
belongs to exactly one peer (it is both the routing table and the
source-address ACL — "cryptokey routing"). **wgmux makes the same
inner IP prefix valid via several peers, and selects one of them per
flow** (or spreads flows over several, ECMP-style), without patching
the kernel and without adding a routing pass.

```
                 main netns              backend netns "wgmux-wg-mux"
                                                (hidden, per instance)
 app ──FIB×1──▶ wg-mux ──veth/netkit──▶ TCX ingress (eBPF)
 (only visible      pair ×1                 │ map lookup: flow → steering (LPM)
  interface)                               │ bpf_redirect, no FIB, no TTL--
                                       ┌─────┼─────┐
                                   wg-site-a wg-site-b    one device per peer,
                                     AllowedIPs identical on all of them
```

Each peer gets its **own** WireGuard device in a hidden backend
network namespace, so the duplicate AllowedIPs live in separate
per-device tables and are perfectly legal. A pair of TC/eBPF programs
steers packets between the single interconnect and the peer devices
with `bpf_redirect`. The only routing lookup for inner traffic is
the one in the main namespace that picked the front interface,
exactly as with a plain `wg0` (plus, in veth mode, one forwarding
hop in the backend on the return path — see the last section).

Returns are symmetric: each peer device's ingress program records
the flow (reversed key) in a shared map, so replies — and replies to
remote-initiated flows — keep using the peer they arrived on.

The full design contract — engine interface, configuration
lifecycle, persistence — lives in [`docs/design.md`](docs/design.md).

## Use it: hand over the wg configs you already have

Before wgmux, one of your tunnels works and the other cannot exist:

```console
$ wg-quick up site-a.conf     # fine
$ wg-quick up site-b.conf     # impossible: 10.20.0.10/32 already
                              # claimed by site-a's peer
```

With wgmux you pass both files to `wgmuxctl` instead, unmodified:

```console
$ wgmuxd -engine kernel &                       # data plane (root)
$ wgmuxctl apply site-a.conf site-b.conf        # files used as-is
$ ip link show wg-mux                           # the aggregated NIC
$ curl http://10.20.0.10:8080/                  # reaches the site via A
$ wgmuxctl activate 10.20.0.10/32 site-b        # flip to B (new flows)
$ wgmuxctl activate -flush 10.20.0.10/32 site-a # ...and move established flows too
$ wgmuxctl status
$ wgmuxctl destroy
```

Each file contributes one peer (peer name = file base name):
`[Interface]` PrivateKey/ListenPort belong to that peer's device,
`[Peer]` PublicKey / PresharedKey / AllowedIPs / Endpoint /
PersistentKeepalive map directly. `[Interface]` Address, when the
files agree on it, becomes the front address. The steered prefixes
are *derived* by grouping the peers' AllowedIPs — each distinct
CIDR's candidates are the peers claiming it, the default is `mode:
single` / `policy: static`, and the default active peer is the
first file's.
wg-quick-only keys (DNS, Table, hooks, SaveConfig) are ignored with
a printed warning; **hook commands are never executed**. A file
with more than one `[Peer]` section is rejected (for now).

A YAML config (`-c wgmux.yaml`, see `wgmux.example.yaml`) is the
optional overlay: ECMP prefixes and weights, policies (`failover`,
`bgp`), per-prefix active, several muxes in one file, inline peers. In YAML form a
peer can reference a wg file with `wg_config:` instead of inline
fields, and `prefixes:` entries then act as per-CIDR overrides over
the derived set.

## ECMP: spread flows over several sites

By default a prefix is `mode: single`: all new flows go to one
selected peer. With `mode: ecmp` a prefix is carried by several peers
at once, new flows spread by flow hash in proportion to weights:

```yaml
prefixes:
  - cidr: 10.20.0.10/32
    mode: ecmp
    weights: {site-a: 3, site-b: 1}   # 3:1; omit for equal weights
    policy: failover                  # drop a dead site, re-add on recovery
```

Internally every prefix is a table of 64 hash slots holding peer IDs
(single = all 64 slots one peer); a selection is compiled into it
proportionally and *resiliently* — changing membership moves only the
slots it has to. `wgmuxctl status` shows each peer's slot count. An
established flow stays on its peer (it is pinned) until the pin is
flushed; replies follow the peer they arrived on.

Runtime control, per prefix:

```console
$ wgmuxctl select 10.20.0.10/32 site-a=3 site-b=1   # ECMP 3:1
$ wgmuxctl activate 10.20.0.10/32 site-b            # exactly one peer
$ wgmuxctl select -flush 10.20.0.10/32 site-a       # site-b leaves: its flows move now
```

`-flush` calls `FlushPeer` for every peer that was in the previous
selection and is not in the new one. Without it a selection change is
graceful: established flows keep their peer, only new flows follow
the new selection.

Runtime selections (`activate`, `select`, failover, BGP) are persisted
by the daemon and survive a re-apply and a daemon restart, as long as
the prefix's candidates, mode and configured selection are unchanged.
`wgmuxctl apply -reset-selections` drops them and returns to the
configured ones.

## Policies: failover and BGP

`policy` says who changes a prefix's selection at runtime: `static`
(only you), `failover` (handshake-age monitor) or `bgp`.
**`wgmuxctl run -c wgmux.yaml`** is the policy runner: for every mux
in the config (or `-name`) it runs the failover monitor and the BGP
source, until SIGINT/SIGTERM. Run it as a service next to the daemon:

```sh
install -m 644 contrib/wgmuxd.service contrib/wgmux-policy.service /etc/systemd/system/
systemctl enable --now wgmuxd wgmux-policy      # the latter needs /etc/wgmux/wgmux.yaml
```

([`contrib/wgmux-policy.service`](contrib/wgmux-policy.service)
`Requires=wgmuxd.service`.) `wgmuxctl monitor` and `wgmuxctl bgp` are
the single-purpose, single-mux foreground variants.

The runners read peer names, candidates and the current selection
from the daemon's `State`, never from config peer IDs, so a re-apply
that reorders peers cannot make them act on the wrong peer.

- **Failover** — a peer is healthy if its last handshake is younger
  than `failover.handshake_max_age_seconds`. `single`: when the
  selected peer is unhealthy and a healthy candidate exists, select
  the first healthy one (no preemption back). `ecmp`: the selection
  is the configured weights restricted to healthy peers (a recovered
  peer comes back with its weight); with none healthy, nothing
  changes. When a peer turns unhealthy the monitor also flushes its
  flow pins (`FlushPeer`), so established flows move off it rather
  than black-holing.
- **BGP** — see below.

## Data plane / control plane split

Two processes, one narrow API (`internal/api`, JSON over a unix
socket):

- **wgmuxd** — the data plane. Hosts mux instances behind one
  engine interface and serves the API. It executes desired state
  (`Apply`), teardown (`Destroy`), snapshots (`State`) and selection
  changes (`SetSelection`, `FlushPeer`). It decides *nothing*.
- **wgmuxctl** — the control plane. Translates wg files / YAML into
  API calls and owns every policy: manual activation,
  handshake-based failover, BGP. It never touches netlink or BPF;
  policies are interchangeable because they all funnel into
  `SetSelection(prefix, peers[, weights])`. Peers are addressed by
  name everywhere. wgmuxctl refuses a daemon with a different API
  version.

```sh
wgmuxd -engine kernel -socket /run/wgmux/wgmuxd.sock -state-dir /var/lib/wgmux &   # data plane (root)
wgmuxctl apply site-a.conf site-b.conf             # desired state, from files
wgmuxctl apply -c wgmux.yaml                       # ...or from the YAML overlay
wgmuxctl apply -c wgmux.yaml -reset-selections     # ...discarding runtime selections
wgmuxctl status                                    # instances, peers, selections, slots
wgmuxctl activate [-flush] 10.20.0.10/32 site-b    # one peer
wgmuxctl select [-flush] 10.20.0.10/32 site-a=3 site-b=1   # ECMP
wgmuxctl run -c wgmux.yaml                         # policy runner (failover + BGP, all muxes)
wgmuxctl destroy                                   # explicit teardown
```

## Engines

One daemon runs **one engine kind**, chosen at startup; every
instance it hosts uses it. Both sit behind the same interface
(`Apply` / `SetSelection` / `FlushPeer` / `State` / `Close` — desired
state and decisions in, snapshots out) and are each built in their natural
shape:

- **`kernel`** (default) — per instance: one in-tree WireGuard
  device per peer in a per-instance backend netns
  (`wgmux-<name>`), one interconnect (veth or netkit) to the front,
  eBPF steering as drawn above.
- **`userspace`** — wireguard-go, no netns, no BPF: per instance one
  front TUN in the main namespace and one wireguard-go device per
  peer over an in-memory channel TUN, with a packet pump in the
  daemon steering between them. Steering reuses the kernel
  datapath's selection code (`internal/steer`), so a flow picks the
  same candidate under either engine.

Difference that matters: with `kernel` the datapath survives the
daemon (see Persistence); with `userspace` the daemon *is* the
crypto datapath and must keep running.

## Configuration lifecycle

What is configured *when* is part of the design
(`docs/design.md` has the contract):

| When | What |
|---|---|
| **Daemon startup** | socket; **engine kind** (`-engine`); state dir; pin root; for kernel: `-interconnect`, `-attach`; restore on/off |
| **Instance creation** | mux name (= front NIC name, default `wg-mux`); kernel backend-address override. Backend ns (`wgmux-<name>`) and pin dir (`<pin root>/wgmux/<name>`) are derived, never configured |
| **Every Apply** | the peer set (from wg files: keys, ports, endpoints, AllowedIPs, PSKs, keepalive); front address/MTU; `manage_routes`; per-prefix mode/policy/active/weights overrides |
| **Runtime** | `SetSelection` / `FlushPeer` decisions (manual, failover, BGP) — never configuration; persisted and kept across re-apply |
| **Derived** | peer names (file base names); steered prefixes + candidates (AllowedIPs grouping); default mode `single`, policy `static`, active (first candidate) |

Creation parameters are immutable for an instance's lifetime:
`wgmuxctl apply` checks the daemon's startup configuration and the
existing instance, and rejects an apply that assumes a different
engine/interconnect/attach or a different backend address (destroy
+ recreate is the way to change them).

## Switchable axes

| Axis | Values | Set where |
|---|---|---|
| engine | `kernel` \| `userspace` | wgmuxd startup (`-engine`) |
| interconnect | `veth` \| `netkit` | wgmuxd startup, kernel only (netkit needs kernel ≥ 6.7) |
| attach | `tcx` \| `tc` | wgmuxd startup, kernel only (tcx needs ≥ 6.6; `tc` = legacy clsact) |
| per-prefix `mode` | `single` \| `ecmp` | YAML overlay / derived default `single` |
| per-prefix `policy` | `static` \| `failover` \| `bgp` (legacy: `active` = static+single, `hash` = static+ecmp) | YAML overlay / derived default `static` |

Selection changes are map writes: no reload, no device churn.

## Persistence and recovery

Every create/apply is recorded in a **spec store**
(`<state dir>/instances/<name>.json`, atomic writes) together with the
runtime selections; `destroy` deletes the record. An apply that
fails is rolled back to the previous spec. Leftover kernel objects of
an instance the daemon no longer has an engine for are purged rather
than leaked or collided with. On startup the daemon restores from the store:

- **kernel**: an instance whose kernel objects are still there
  (backend ns, pins, steering map) is **adopted** — nothing in the
  datapath is touched; traffic never stopped. Missing objects →
  the instance is **rebuilt** from its stored spec.
- **userspace**: instances are always **rebuilt** from the store
  (tunnels re-handshake; a brief outage is inherent).
- `-restore=false` loads instances as `stored`, awaiting an
  explicit apply. A store entry written by the other engine kind is
  reported `orphaned` and left untouched; a failed restore marks
  the instance `failed` (with the error) and never blocks startup.
  Instance states: `active` / `adopted` / `restored` / `stored` /
  `failed` / `orphaned`, via `wgmuxctl list` / `status`.

Stopping wgmuxd (SIGTERM) is detach-only: listener closed, kernel
datapath, pins and store left as they are. Host-reboot recovery is
the same rebuild path driven by systemd —
[`contrib/wgmuxd.service`](contrib/wgmuxd.service) starts the
daemon at boot and every stored instance comes back, like
`wg-quick@` units replaying configs.

## BGP integration (`policy: bgp`)

For a prefix with `policy: bgp`, the selection follows BGP paths: the
neighbor a path arrived from is mapped by IP to the wgmux peer whose
tunnel carries it (`bgp.neighbors[].wg_peer`). A `single` prefix
follows the best path; an `ecmp` prefix follows the whole multipath
set at equal weight. Two sources feed the same decision stream:

- **FRR** (`bgp.mode: frr`) — an external FRRouting daemon polled via
  `vtysh -c 'show ip bgp json'`; every path marked `bestpath` or
  `multipath` counts, so FRR's `maximum-paths` drives the ECMP set.
  With FRR in play, zebra can own the main-namespace routes to the
  front interface; set `manage_routes: false` so wgmuxd leaves the FIB
  to FRR. (An FPM-based event feed is the planned upgrade from
  polling; the Decision contract is identical.)
- **GoBGP** (`bgp.mode: gobgp`) — an embedded GoBGP server in
  wgmuxctl; best-path changes stream in via its watch API. **Limit:**
  the watch API reports only the single best path, so an `ecmp`
  prefix follows the best path's peer only — use FRR for real
  multipath. Origination helpers (`Announce`/`Withdraw`) support
  anycast-style failover.

A BGP decision can never steer a prefix to a peer that is not one of
its candidates as the daemon reports them; withdrawn paths leave the
last selection in place until a new path or an operator decision.
Run it with `wgmuxctl run` (or `wgmuxctl bgp`).

## Layout

```
bpf/mux.c                 the two steering programs (see bpf/NOTES.md)
cmd/wgmuxd                data-plane daemon
cmd/wgmuxctl              control-plane CLI (+ `run`: failover / BGP policy runner)
internal/api              the c-plane ⇄ d-plane contract (unix-socket JSON)
internal/daemon           wgmuxd's api.Handler: instance registry + spec store/restore
internal/engine           the Engine interface: kernel WireGuard / wireguard-go pump
internal/topology         backend netns + interconnect pair + routes
internal/datapath         BPF loading, tcx/tc attach, pinned maps
internal/steer            steering entries & the datapath hash, mirrored in Go
internal/monitor          failover policy (pure evaluation + loop)
internal/bgp              GoBGP + FRR selection sources
internal/config           YAML overlay + wg-quick parsing, prefix derivation
docs/design.md            the design contract (engine interface, lifecycle, persistence)
contrib/wgmuxd.service    systemd unit (host-reboot recovery)
contrib/wgmux-policy.service  systemd unit for `wgmuxctl run` (failover / BGP)
```

## Requirements & status

- Linux ≥ 6.6 for `attach: tcx` (older: `tc`), ≥ 6.7 for
  `interconnect: netkit`. Root/CAP_NET_ADMIN + CAP_BPF.
- Build: Go ≥ 1.24. The compiled BPF object is committed
  (`internal/datapath/mux.o`); regenerating it needs clang + libbpf
  headers (`make generate`).
- IPv4 only for now; see `bpf/NOTES.md` for the datapath's known
  limitations (flow pinning is LRU best-effort, slots are 64 per prefix, ICMP pins per
  host-pair, MTU is the minimum across peers).

Verified: configuration validation and steering/hash logic (unit
tests), the FRR/GoBGP decision extraction (unit tests), and — in CI,
on every push — the full end-to-end matrix below: real WireGuard
tunnels carrying real traffic to two sites that share one inner IP,
including activation flips and automatic failover. The verifier half
can additionally be run on any suitable host with
`WGMUX_TEST_LOAD=1 go test ./internal/datapath/`.

## End-to-end tests

`test/e2e/` runs the real thing on a containerlab topology: a mux
node plus **two sites that both own the same inner IP
(10.20.0.10)**. The Go test (build tag `e2e`) deploys the lab and
drives the whole lifecycle with the user-visible commands, logging
each one: one daemon → two instances applied **from wg-quick files**
→ traffic lands on the active site on both fronts → an activate on
one instance leaves the other untouched → a re-apply changes the
desired state without recreating the instance (creation time
unchanged) → applies assuming another engine or creation parameter
are rejected → **the daemon is killed and restarted**: with the
kernel engine traffic keeps flowing while no daemon runs, and the
new daemon reports the instances `adopted` and serves decisions
with no re-apply (userspace: `restored` from the store) → the
failover monitor flips the first instance when site-a's tunnel dies
→ destroying one instance leaves the other passing traffic. Further
scenarios cover **ECMP** (many parallel short connections land on
both sites, distinguishable by their HTTP response), **failover of an
established long-lived flow** (it moves after site-a dies, via
`FlushPeer`), and a **re-apply preserving a runtime selection**.

```sh
make e2e   # needs docker + containerlab on the host
# knobs: WGMUX_E2E_ENGINE=kernel|userspace
#        WGMUX_E2E_INTERCONNECT=veth|netkit  WGMUX_E2E_ATTACH=tcx|tc
```

CI runs the unit suite plus this e2e matrix on every push:
{engine=kernel, interconnect=veth}, {engine=kernel,
interconnect=netkit} and {engine=userspace} — interconnect/attach
are kernel-daemon settings, so there is no userspace interconnect
axis.

One datapath asymmetry worth knowing: in veth mode the return path
(site → client) takes one forwarding pass through the backend
namespace's stack (a TC program cannot fabricate the MAC-header
state a redirect to an Ethernet device requires on a WireGuard
receive skb — see `bpf/NOTES.md`). The forward path is pure eBPF in
both modes, and netkit mode is pure eBPF in both directions
(`bpf_redirect_peer`).
