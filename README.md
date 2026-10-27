# wgmux — WireGuard multiplexer with an eBPF steering datapath

[![CI](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml/badge.svg)](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml)

WireGuard's AllowedIPs is a one-to-one map: within one device, a prefix
belongs to exactly one peer (it is both the routing table and the
source-address ACL — "cryptokey routing"). **wgmux makes the same
inner IP prefix valid via several peers, and selects exactly one of
them per packet**, without patching the kernel and without adding a
routing pass.

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
$ wgmuxctl activate 10.20.0.10/32 site-b        # flip to B
$ wgmuxctl status
$ wgmuxctl destroy
```

Each file contributes one peer (peer name = file base name):
`[Interface]` PrivateKey/ListenPort belong to that peer's device,
`[Peer]` PublicKey / PresharedKey / AllowedIPs / Endpoint /
PersistentKeepalive map directly. `[Interface]` Address, when the
files agree on it, becomes the front address. The steered prefixes
are *derived* by grouping the peers' AllowedIPs — each distinct
CIDR's candidates are the peers claiming it, the default policy is
`active`, and the default active peer is the first file's.
wg-quick-only keys (DNS, Table, hooks, SaveConfig) are ignored with
a printed warning; **hook commands are never executed**. A file
with more than one `[Peer]` section is rejected (for now).

A YAML config (`-c wgmux.yaml`, see `wgmux.example.yaml`) is the
optional overlay: policies (`failover`, `bgp`, `hash`, per-prefix
active), several muxes in one file, inline peers. In YAML form a
peer can reference a wg file with `wg_config:` instead of inline
fields, and `prefixes:` entries then act as per-CIDR overrides over
the derived set.

## Data plane / control plane split

Two processes, one narrow API (`internal/api`, JSON over a unix
socket):

- **wgmuxd** — the data plane. Hosts mux instances behind one
  engine interface and serves the API. It executes desired state
  (`Apply`), teardown (`Destroy`), snapshots (`State`) and single
  selection changes (`SetActive`). It decides *nothing*.
- **wgmuxctl** — the control plane. Translates wg files / YAML into
  API calls and owns every policy: manual activation,
  handshake-based failover, BGP. It never touches netlink or BPF;
  policies are interchangeable because they all funnel into
  `SetActive(prefix, peer)`.

```sh
wgmuxd -engine kernel -socket /run/wgmux/wgmuxd.sock        -state-dir /var/lib/wgmux &                 # data plane (root)
wgmuxctl apply site-a.conf site-b.conf             # desired state, from files
wgmuxctl status                                    # all instances, via the API
wgmuxctl activate 10.20.0.10/32 site-b             # one decision
wgmuxctl apply -c wgmux.yaml --monitor --bgp       # YAML overlay + policies
wgmuxctl destroy                                   # explicit teardown
```

## Engines

One daemon runs **one engine kind**, chosen at startup; every
instance it hosts uses it. Both sit behind the same interface
(`Apply` / `SetActive` / `State` / `Close` — desired state and
decisions in, snapshots out) and are each built in their natural
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
| **Every Apply** | the peer set (from wg files: keys, ports, endpoints, AllowedIPs, PSKs, keepalive); front address/MTU; `manage_routes`; per-prefix policy/active overrides |
| **Runtime** | `SetActive` decisions (manual, failover, BGP) — never configuration |
| **Derived** | peer names (file base names); steered prefixes + candidates (AllowedIPs grouping); default active (first candidate); default policy (`active`) |

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
| per-prefix `policy` | `active` \| `hash` \| `failover` \| `bgp` | YAML overlay / derived defaults |

Selection changes are map writes: no reload, no device churn.

## Persistence and recovery

Every create/apply is recorded in a **spec store**
(`<state dir>/instances/<name>.json`, atomic writes); `destroy`
deletes the record. On startup the daemon restores from the store:

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

For a prefix with `policy: bgp`, the active peer follows BGP best
paths: the neighbor a best path arrived from is mapped by IP to the
wgmux peer whose tunnel carries it (`bgp.neighbors[].wg_peer`). Two
sources feed the same decision stream:

- **GoBGP** (`bgp.mode: gobgp`) — an embedded GoBGP server in
  wgmuxctl; best-path changes stream in via its watch API. Origination
  helpers (`Announce`/`Withdraw`) support anycast-style failover:
  announce a prefix only while its peer is active.
- **FRR** (`bgp.mode: frr`) — an external FRRouting daemon polled via
  `vtysh -c 'show ip bgp json'`. With FRR in play, zebra can own the
  main-namespace routes to the front interface; set
  `manage_routes: false` so wgmuxd leaves the FIB to FRR. (An
  FPM-based event feed is the planned upgrade from polling; the
  Decision contract is identical.)

A BGP decision can never steer a prefix to a peer that is not one of
its configured candidates — the control plane enforces that before
calling `SetActive`.

## Layout

```
bpf/mux.c                 the two steering programs (see bpf/NOTES.md)
cmd/wgmuxd                data-plane daemon
cmd/wgmuxctl              control-plane CLI (+ failover / BGP runners)
internal/api              the c-plane ⇄ d-plane contract (unix-socket JSON)
internal/daemon           wgmuxd's api.Handler: instance registry + spec store/restore
internal/engine           the Engine interface: kernel WireGuard / wireguard-go pump
internal/topology         backend netns + interconnect pair + routes
internal/datapath         BPF loading, tcx/tc attach, pinned maps
internal/steer            steering entries & the datapath hash, mirrored in Go
internal/monitor          failover policy
internal/bgp              GoBGP + FRR selection sources
internal/config           YAML overlay + wg-quick parsing, prefix derivation
docs/design.md            the design contract (engine interface, lifecycle, persistence)
contrib/wgmuxd.service    systemd unit (host-reboot recovery)
```

## Requirements & status

- Linux ≥ 6.6 for `attach: tcx` (older: `tc`), ≥ 6.7 for
  `interconnect: netkit`. Root/CAP_NET_ADMIN + CAP_BPF.
- Build: Go ≥ 1.24. The compiled BPF object is committed
  (`internal/datapath/mux.o`); regenerating it needs clang + libbpf
  headers (`make generate`).
- IPv4 only for now; see `bpf/NOTES.md` for the datapath's known
  limitations (flow pinning is LRU best-effort, ICMP pins per
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
→ destroying one instance leaves the other passing traffic.

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
