# wgmux — WireGuard multiplexer with an eBPF steering datapath

[![CI](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml/badge.svg)](https://github.com/tsuzu/wgmux/actions/workflows/ci.yml)

WireGuard's AllowedIPs is a one-to-one map: within one device, a prefix
belongs to exactly one peer (it is both the routing table and the
source-address ACL — "cryptokey routing"). **wgmux makes the same
inner IP prefix valid via several peers, and selects exactly one of
them per packet**, without patching the kernel and without adding a
routing pass.

```
                 main netns                     backend netns "wgmux"
                                                (hidden)
 app ──FIB×1──▶ wg-mux ──veth/netkit──▶ TCX ingress (eBPF)
 (only visible      pair ×1                 │ map lookup: flow → steering (LPM)
  interface)                               │ bpf_redirect, no FIB, no TTL--
                                       ┌─────┼─────┐
                                     wg-a   wg-b   wg-c     one device per peer,
                                     AllowedIPs identical on all of them
```

Each peer gets its **own** WireGuard device in a hidden backend
network namespace, so the duplicate AllowedIPs live in separate
per-device tables and are perfectly legal. A pair of TC/eBPF programs
steers packets between the single interconnect and the peer devices
with `bpf_redirect` — inside the backend there is **no FIB lookup, no
`ip_forward`, no neighbour resolution, no TTL decrement**. The only
routing lookup for inner traffic is the one in the main namespace
that picked the front interface, exactly as with a plain `wg0`.

Returns are symmetric: each peer device's ingress program records the
flow (reversed key) in a shared map and redirects the packet out of
the interconnect, so replies — and replies to remote-initiated flows —
keep using the peer they arrived on.

## Data plane / control plane split

Two processes, one narrow API (`internal/api`, JSON over a unix
socket):

- **wgmuxd** — the data plane. Owns all kernel state: namespaces, peer
  engines, BPF programs and maps. It executes desired state
  (`Apply`), teardown (`Destroy`), snapshots (`State`) and single
  selection changes (`SetActive`). It decides *nothing*.
- **wgmuxctl** — the control plane. Owns the YAML config and every
  policy: manual activation, handshake-based failover, BGP. It never
  touches netlink or BPF; policies are interchangeable because they
  all funnel into `SetActive(prefix, peer)`.

```sh
wgmuxd -socket /run/wgmux/wgmuxd.sock &        # data plane (root)
wgmuxctl -c wgmux.yaml apply                   # push desired state
wgmuxctl -c wgmux.yaml status
wgmuxctl -c wgmux.yaml activate 10.20.0.10/32 site-b
wgmuxctl -c wgmux.yaml apply --monitor --bgp   # + policy daemons
wgmuxctl -c wgmux.yaml destroy
```

## Switchable axes

Everything the design discussions left open is a configuration knob:

| Axis | Values | Notes |
|---|---|---|
| `engine` | `kernel` \| `userspace` | in-tree WireGuard devices, or **wireguard-go** hosted by wgmuxd (see below) |
| `interconnect` | `veth` \| `netkit` | L2 pair (BPF adds/strips Ethernet) or L3 pair (kernel ≥ 6.7), exactly one pair total |
| `attach` | `tcx` \| `tc` | TCX links (≥ 6.6) or legacy clsact filters |
| per-prefix `policy` | `active` \| `hash` \| `failover` \| `bgp` | one chosen peer / per-flow hash over candidates / handshake-driven flips / BGP best path |

Selection changes are map writes: no reload, no device churn.

## wireguard-go engine (`engine: userspace`)

The same multiplexing works without kernel WireGuard. Each peer
becomes a wireguard-go device hosted by wgmuxd, bound to a TUN device
created inside the backend namespace while its UDP sockets are opened
in the main namespace — the userspace mirror of the kernel device's
birth-namespace behaviour, so ciphertext routing is unchanged. The
steering programs attach to the TUN devices exactly as they attach to
kernel wg devices; the datapath cannot tell the engines apart.

Difference that matters: with `engine: kernel` the datapath survives
wgmuxd exiting (a restarted daemon re-adopts on the next `apply`);
with `engine: userspace` the daemon *is* the crypto datapath and must
keep running.

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
internal/daemon           wgmuxd's api.Handler: reconciliation & state
internal/engine           PeerEngine: kernel WireGuard / wireguard-go
internal/topology         backend netns + interconnect pair + routes
internal/datapath         BPF loading, tcx/tc attach, pinned maps
internal/steer            steering entries & the datapath hash, mirrored in Go
internal/monitor          failover policy
internal/bgp              GoBGP + FRR selection sources
internal/config           YAML config & validation
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

Verified so far: configuration validation and steering/hash logic
(unit tests), the FRR/GoBGP decision extraction (unit tests), and the
BPF object compiles. The verifier half can be run on any suitable
host with `WGMUX_TEST_LOAD=1 go test ./internal/datapath/`.

## End-to-end tests

`test/e2e/` runs the real thing on a containerlab topology: a mux
node plus **two sites that both own the same inner IP
(10.20.0.10)**. The Go test (build tag `e2e`) deploys the lab,
applies a failover configuration, and asserts actual HTTP traffic —
it lands on the active site, follows `wgmuxctl activate` to the
other site, and fails over when the active site's tunnel dies:

```sh
make e2e   # needs docker + containerlab on the host
# knobs: WGMUX_E2E_ENGINE=kernel|userspace
#        WGMUX_E2E_INTERCONNECT=veth|netkit  WGMUX_E2E_ATTACH=tcx|tc
```

CI runs the unit suite plus this e2e matrix on every push.
