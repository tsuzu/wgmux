# wgmux design

wgmux aggregates several WireGuard tunnels that all claim the same inner
addresses (duplicate AllowedIPs) behind a single visible interface, and
steers each flow to exactly one of the candidate peers. This document is
the design contract: the engine interface, the configuration lifecycle
(what is set when), and the persistence/recovery model.

## Concepts

- **Daemon (wgmuxd)** — one process hosting mux instances and serving
  the control API on a unix socket. It is started with **one engine
  kind**; every instance it hosts uses that kind.
- **Engine** — the datapath implementation behind a common interface.
  Two realizations exist, each in its natural shape:
  - `kernel`: in-tree WireGuard devices hidden in a per-instance
    backend network namespace, steered by eBPF/TC programs.
  - `userspace`: wireguard-go devices inside the daemon process,
    steered by an in-process packet pump. No netns, no BPF.
- **Mux instance** — one aggregated NIC: one front interface, a set of
  peer tunnels (one WireGuard device each), and steered prefixes whose
  candidate sets are the peers claiming them via AllowedIPs.
- **Front** — the only interface visible in the main namespace. Its
  name is the mux instance's name.
- **Steering** — per-prefix peer selection: one peer (`single`) or
  several, optionally weighted (`ecmp`), realized as a hash-slot
  table, plus a flow table pinning established flows to their peer.
  Decisions (manual, failover, BGP) reach the datapath exclusively as
  `SetSelection` / `FlushPeer` calls. See "Selection model".

## The Engine interface

The daemon knows exactly one interface; everything below it — netns,
interconnects, BPF maps and pins, TUN devices, pump goroutines — is
the engine's private business.

```go
type Engine interface {
    Apply(spec api.ApplySpec) error
    SetSelection(prefix *net.IPNet, sel []api.PeerWeight) error
    FlushPeer(peer string) error
    State() (api.State, error)
    Close() error
}
```

Peers are addressed by **name** everywhere in the API. `PeerSpec.ID`
(1..255; 0 means "no peer") is the datapath's internal handle,
assigned by the control plane and never used to address a peer in a
request.

One `Engine` value exists per mux instance. The daemon is a registry:
it creates instances through a factory for its configured engine kind,
addresses them by name, and delegates. The interface deliberately has
no peer-lifecycle granularity (no AddPeer/RemovePeer): `Apply` carries
the full desired state, and an engine that wants incremental updates
implements them internally.

`ApplySpec` carries **only engine-neutral desired state**:

```go
type ApplySpec struct {
    Front        FrontSpec // Name (= instance name), Address, MTU
    ManageRoutes bool
    Peers        []PeerSpec
    Prefixes     []PrefixSpec
}
```

No engine field, no netns/interconnect/attach/pin fields: those are
implementation, and an interface that names them is not an interface.

## Configuration lifecycle

What is configured *when* is part of the design, not an accident of
the current code.

| When | What | Notes |
|---|---|---|
| **Daemon startup** | socket path; **engine kind** (`-engine kernel\|userspace`); state dir; pin root (bpffs base, kernel); for kernel: interconnect (`veth\|netkit`), attach (`tcx\|tc`); restore on/off | Fixed for the process lifetime. Supplied as flags so a systemd unit fully describes the daemon. |
| **Instance creation** | mux name (= front NIC name); for kernel: backend address override | Once per mux, immutable afterwards; changing one means destroy + recreate. Backend ns name (`wgmux-<name>`) and pin dir (`<pin root>/wgmux/<name>`) are derived from the name, never configured. Backend address defaults to a host address in the front subnet, derived at first Apply. |
| **Every Apply** | the peer set (usually from wg config files: keys, listen ports, endpoints, AllowedIPs, preshared keys, keepalive); front address and MTU; `manage_routes`; per-prefix `mode` / `policy` / `active` / `weights` overrides | The desired state. Re-applying to an existing instance replaces it wholesale; no daemon or instance restart is involved. |
| **Runtime** | `SetSelection` / `FlushPeer` decisions (manual activate/select, failover monitor, BGP sources) | Decisions, not configuration. They never mutate the applied spec, only the current selection, which `State` reports and the daemon persists (see "Selection persistence"). |
| **Derived** | peer names (wg file base names); steered prefixes and candidate sets (AllowedIPs grouping); default mode (`single`), default policy (`static`), default active (first candidate) | The user never writes these. |

Default instance name for a bare file-based apply is `wg-mux`; a
second instance always needs an explicit `--name` (names are unique
per daemon, and the name is the NIC name).

## User experience

The primary experience is: **hand wgmux the WireGuard config files
you already have.**

```console
$ wgmuxctl apply site-a.conf site-b.conf   # files used as-is
$ ip link show wg-mux                      # the aggregated NIC
$ curl http://10.20.0.10:8080/             # reaches the site via A
$ wgmuxctl activate 10.20.0.10/32 site-b   # flip to B
$ wgmuxctl destroy                         # tear down
```

- Each file contributes one peer: `[Interface]` PrivateKey/ListenPort
  belong to that peer's device, `[Peer]` PublicKey / PresharedKey /
  AllowedIPs / Endpoint / PersistentKeepalive map directly. A file
  with more than one `[Peer]` section is rejected (v1).
- `[Interface]` Address, if identical across files, becomes the front
  address; the mux-level config may override it.
- wg-quick hook keys (PreUp/PostUp/…), DNS, Table, SaveConfig are
  ignored with a warning. Hooks are **never executed**.
- A YAML mux config exists only as an optional overlay: policies
  (`failover`, `bgp`), ECMP prefixes with weights, per-prefix active,
  several muxes in one file, inline peers. The basic case needs no YAML at all.
- The inner WireGuard details a user already knows (keys, endpoints,
  AllowedIPs) are the configuration. Netns names, pin dirs, and attach
  modes never appear in user-facing configuration.

## Selection model

Per prefix (all configurable in the YAML overlay; derived prefixes
default to `single` / `static`):

| Field | Values | Meaning |
|---|---|---|
| `mode` | `single` (default), `ecmp` | one selected peer carries all new flows / several, spread by flow hash in proportion to weights |
| `policy` | `static` (default), `failover`, `bgp` | WHO changes the selection at runtime: nobody but the operator / the handshake-age monitor / BGP paths. Informational for the data plane; the policy runner finds its prefixes by it. Legacy `active` = static+single, `hash` = static+ecmp |
| `active` | a candidate | initial selection of a `single` prefix (default: first candidate) |
| `weights` | `{peer: n}` | initial selection of an `ecmp` prefix; keys must be candidates, weights positive; default every candidate at weight 1 |

Validation: at most 64 candidates (the slot-table size), peer IDs in
1..255, `weights` only in `ecmp`, `active` only in `single`.

### Slot tables

Every steered prefix is a table of **64 slots** (`steer.Slots`), each
holding a peer ID. A new flow takes `slots[Hash(flowkey) & 63]`;
`single` is a table whose 64 slots all hold one peer; a `NoPeer` (0)
slot drops. A selection is compiled into the table by
`steer.BuildSlots(prev, sel)`:

- **proportional** — largest-remainder apportionment of the 64 slots
  by weight (ties by selection order), every selected peer gets at
  least one slot;
- **resilient** — a peer that stays keeps its lowest-indexed existing
  slots up to its new target; freed slots are filled in ascending
  order to under-target peers, so a membership change moves only the
  slots it must;
- **deterministic** — the same `(prev, sel)` always gives the same
  table, and the kernel and userspace engines build identical tables.

`State` reports each peer's slot count per prefix (`wgmuxctl status`
prints `slots a=48 b=16`), read back from the datapath, not from the
control plane's intent.

### Flow pins and generations

Established flows are pinned in an LRU flow table so they keep their
peer while the slot table changes (and so replies, which record the
reversed key, follow the peer a flow arrived on). A pin is
`{peer_id, gen}`; each peer has a current generation (`peer_dev[id]`
holds `{ifindex, gen}`). A pin is honored only if the peer still
exists and the pin's generation equals the peer's; otherwise the flow
re-selects through the slot table and is re-pinned with the current
generation.

- `SetSelection` alone does **not** flush: established flows keep
  their peer (graceful). This is what manual `activate` does by
  default.
- `FlushPeer(peer)` bumps that peer's generation: every pin to it is
  invalid in O(1) and its flows re-steer by the current selection on
  their next packet. This is how failover actually moves established
  flows off a dead peer. `wgmuxctl activate|select -flush` flushes
  every peer that left the selection.

### Selection persistence

The daemon records runtime selections in the spec store (by
canonical CIDR), atomically, after every successful `SetSelection`
and `Apply`. On `Apply` (and on restore/adopt) the effective
selection of a prefix is the stored override **iff** all of:

- the override exists and the request has not set `reset_selections`
  (`wgmuxctl apply -reset-selections`);
- the prefix's candidates, mode and *configured* selection equal the
  previously applied spec's (i.e. the operator did not change what
  that prefix means);
- the override still validates against the prefix.

Otherwise the configured selection applies and the override is
dropped. So a plain re-apply of an unchanged config keeps a failover
or an operator's `activate`, while editing a prefix's candidates,
mode, active or weights resets just that prefix.

### Apply failure and rollback

If an Apply fails and the instance had a previous spec, the daemon
re-applies the previous spec (rollback); the instance stays `active`
with `Error: "apply failed (rolled back): ..."`. If the rollback
fails too the instance is `failed`. The store keeps the last
*successful* spec.

### Purge

An instance with no live engine (stored or failed) can still have
leftovers in the kernel from an earlier life. When an engine offers
`Purge()`, the daemon builds an engine through the factory and calls
it before Apply (so a fresh build never collides with leftovers) or
instead of Close on Destroy (so nothing leaks). The kernel engine's
Purge unpins the pin dir (maps and links), deletes the backend
namespace `wgmux-<name>` and deletes the main-namespace link `<name>`
only when it is a veth or netkit (never anything else); routes go
with the link.

### In-place re-apply (kernel)

When Front, ManageRoutes and the peer set are unchanged, a re-apply
only recompiles the steering entries (against the live tables, so
resilient slot placement holds), swaps them in, and fixes routes for
added/removed prefixes: no device, namespace or program churn, and
flow pins survive. The datapath carries a spec hash (computed with
the selections cleared) that is written last, so an interrupted
rebuild is never mistaken for a complete one when a daemon adopts.

### Policy runner

Policies are control-plane processes that talk to the daemon through
the API only. `wgmuxctl run -c wgmux.yaml` runs, for every mux in the
config (or `-name`), the failover monitor (if a prefix has
`policy: failover`) and the BGP source (if a prefix has
`policy: bgp` and `bgp.mode` is set), until SIGINT/SIGTERM; a crashed
BGP source is restarted with backoff.
[`contrib/wgmux-policy.service`](../contrib/wgmux-policy.service)
runs it under systemd after `wgmuxd.service`. The runners read peer
names, candidates and the current selection from the daemon's `State`
on every pass and never from config peer IDs, so a re-apply that
reorders peers cannot make them act on the wrong peer.

- **Failover** (per interval): a peer is healthy if its last
  handshake is within `handshake_max_age_seconds`. `single`: if the
  selected peer is unhealthy and a healthy candidate exists, select
  the first healthy candidate (no preemption back when the old one
  recovers). `ecmp`: the desired selection is the configured weights
  restricted to healthy candidates (a recovered peer is re-added with
  its configured weight); if none is healthy the current selection is
  kept. On a peer's healthy-to-unhealthy transition the monitor calls
  `FlushPeer` once, after the selection change.
- **BGP**: `single` follows the best path's peer; `ecmp` follows the
  whole multipath set at equal weight (FRR: every path marked
  bestpath or multipath). The embedded GoBGP source sees only the
  best path, so there an `ecmp` prefix collapses to the best path's
  peer. Decisions are validated against the daemon's candidates; the
  latest decision per prefix is re-asserted periodically.

A prefix has one owner: manual selections on a `failover` or `bgp`
prefix are overridden by the runner as soon as it disagrees (failover
ECMP) or the peer fails / the path changes (single).

## Engine realizations

### kernel

Per instance: a backend netns `wgmux-<name>` holding one wg device
per peer and one interconnect (veth or netkit pair) to the front. The
eBPF steering programs and their final datapath shape are documented
in `bpf/NOTES.md`; this refactor does not change them. Maps and links
are pinned under the instance's pin dir, which is what makes
daemon-less survival and later re-adoption possible. The datapath
keeps forwarding if the daemon exits.

### userspace

Per instance: one front TUN in the main namespace (the mux name), one
wireguard-go `device.Device` per peer bound to an in-memory
`tun.Device`, and a pump: front TUN → steering → the selected peer's
virtual TUN, and back, recording reverse flows on return. Steering
reuses the same selection code as the BPF datapath
(`internal/steer`: Entry / FlowKey / Hash / slot tables), so a flow
picks the same candidate under either engine, with the same
pin-generation semantics; the flow table is a Go LRU with
best-effort parity to the BPF one. wireguard-go is used strictly
through its public API (`device.NewDevice(tun.Device, conn.Bind,
logger)`, UAPI) — no fork, no internal patches. Forwarding lasts as
long as the daemon process.

## Persistence and recovery

The daemon keeps a **spec store**: for every instance, a file under
the state dir (`<state dir>/instances/<name>.json`, written atomically
— tmp file + fsync + rename — on every successful create/apply)
holding the creation parameters and the last applied spec. `Destroy`
deletes the file. The store is the record of *what should exist*;
kernel objects are the record of *what does exist*.

### Daemon restart

- **kernel**: on startup the daemon loads the store and **adopts**
  each instance whose kernel objects are actually still there —
  backend ns present, pin dir present, steering map openable. Adoption
  changes nothing in the datapath: traffic never stopped, `State`
  reads from pins + wgctrl, `SetSelection` writes the pinned map. The
  stored spec's spec hash must match the pinned one, and the stored
  runtime selections are merged in as for an Apply. An
  instance whose objects are missing (ns deleted by hand, or a host
  reboot — see below) is **rebuilt** from its stored spec instead.
- **userspace**: nothing survives the process, so instances are
  always **rebuilt** from the store on startup. Tunnels re-handshake;
  brief outage is inherent to this engine.

Restore-on-startup is the default; `-restore=false` loads instances
as stored-but-inactive, awaiting an explicit apply.

### Host reboot

Kernel state does not survive a reboot (netns, devices, and bpffs
contents are runtime state), so host-reboot recovery for *both*
engines is the same mechanism: a systemd unit starts wgmuxd, and the
daemon's restore path rebuilds every stored instance, exactly like
`wg-quick@` units replay configs at boot.

```ini
[Unit]
Description=wgmux (kernel engine)
After=network-pre.target
Wants=network-pre.target

[Service]
ExecStart=/usr/local/bin/wgmuxd -engine kernel -socket /run/wgmux/wgmuxd.sock \
    -state-dir /var/lib/wgmux -pin-root /sys/fs/bpf -interconnect veth -attach tcx
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Stopping the daemon is **not** destroying state: SIGTERM closes the
listener and exits. For the kernel engine the datapath, pins, and
store are left untouched (a later daemon re-adopts). For userspace
the datapath necessarily ends with the process. Destruction happens
only through the explicit `destroy` operation.

### Mismatches

- Stored instance kind ≠ the daemon's engine kind: the instance is
  reported as `orphaned` in listings and left untouched — this daemon
  is not its owner. (Run two daemons with different sockets if both
  kinds are needed on one host.)
- Stored spec that no longer applies cleanly (e.g. a port now taken
  by another instance): restore marks the instance `failed` with the
  error, and continues with the others; it never blocks daemon
  startup.
- Instance states exposed by `State`/listings: `active`, `adopted`,
  `restored` (rebuilt at startup), `stored` (restore off), `failed`,
  `orphaned`.

## API sketch

All methods are addressed by mux name; `info` reports
`api_version` (control-plane tools refuse a daemon whose version
differs from theirs).

- `create(name, params)` — params: backend address override (kernel).
  The engine kind is the daemon's, so it is not a parameter.
- `apply(name, spec, reset_selections)` — spec as above; applying to a
  nonexistent instance is an error (create first — `wgmuxctl apply`
  does create-if-absent for the user). Each prefix is
  `{cidr, candidates[names], mode, policy, selection[{peer, weight}]}`.
- `set_selection(name, cidr, selection)` — graceful; replaces the
  prefix's selection.
- `flush_peer(name, peer)` — invalidate every flow pin to the peer.
- `state(name)` / `list()` — includes the engine kind reported by the
  engine itself, peer states, per-prefix mode/policy/selection/slots,
  and named datapath counters (kernel: from the BPF debug map via the
  daemon; userspace: pump counters under the same names). The control
  plane never reads pins or maps directly.
- `destroy(name)`

## Constraints and non-goals

- UDP listen ports are global to the main namespace in both engines;
  two instances (or peers) cannot share one. This is a configuration
  constraint, validated at apply time, not a structural limit.
- IPv4 only, as in the current datapath.
- Performance of the userspace pump, and of the kernel veth return
  hop, is unmeasured; the design does not claim parity.
- Incremental (diffing) Apply is an engine-internal optimization,
  explicitly not part of the interface.
