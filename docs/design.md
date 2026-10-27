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
- **Steering** — per-prefix candidate selection (`active` peer, or
  per-flow `hash`), plus a flow table pinning established flows to
  their peer. Decisions (manual, failover, BGP) reach the datapath
  exclusively as `SetActive` calls.

## The Engine interface

The daemon knows exactly one interface; everything below it — netns,
interconnects, BPF maps and pins, TUN devices, pump goroutines — is
the engine's private business.

```go
type Engine interface {
    Apply(spec api.ApplySpec) error
    SetActive(prefix *net.IPNet, peerID uint32) error
    State() (api.State, error)
    Close() error
}
```

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
| **Every Apply** | the peer set (usually from wg config files: keys, listen ports, endpoints, AllowedIPs, preshared keys, keepalive); front address and MTU; `manage_routes`; per-prefix policy/active overrides | The desired state. Re-applying to an existing instance replaces it wholesale; no daemon or instance restart is involved. |
| **Runtime** | `SetActive` decisions (manual activate, failover monitor, BGP sources) | Decisions, not configuration. They never mutate the stored spec's identity, only the current selection, which `State` reports. |
| **Derived** | peer names (wg file base names); steered prefixes and candidate sets (AllowedIPs grouping); default active (first candidate); default policy (`active`) | The user never writes these. |

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
  (`failover`, `bgp`, `hash`, per-prefix active), several muxes in one
  file, inline peers. The basic case needs no YAML at all.
- The inner WireGuard details a user already knows (keys, endpoints,
  AllowedIPs) are the configuration. Netns names, pin dirs, and attach
  modes never appear in user-facing configuration.

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
(`internal/steer`: Entry / FlowKey / Hash / Pick), so a flow picks the
same candidate under either engine; the flow table is a Go LRU with
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
  reads from pins + wgctrl, `SetActive` writes the pinned map. An
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

All methods are addressed by mux name:

- `create(name, params)` — params: backend address override (kernel).
  The engine kind is the daemon's, so it is not a parameter.
- `apply(name, spec)` — spec as above; applying to a nonexistent
  instance is an error (create first — `wgmuxctl apply` does
  create-if-absent for the user).
- `set_active(name, cidr, peer_id)`
- `state(name)` / `list()` — includes the engine kind reported by the
  engine itself, peer states, current selections, and named datapath
  counters (kernel: from the BPF debug map via the daemon; userspace:
  pump counters under the same names). The control plane never reads
  pins or maps directly.
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
