# wgmux v2 contract (ECMP + selection lifecycle) — work brief

This file is the shared contract for the v2 change set. The types
and signatures referenced here already exist on branch `v2-ecmp`
(stubs return `errTODO` or panic "implemented by the ... workstream").
Do NOT change a signature in a file you do not own; if the contract
is genuinely wrong, implement the closest correct thing inside your
own files and explain it in your final report.

## Goals

1. Besides single-active steering, a prefix can be ECMP: several
   selected peers, optionally weighted, new flows spread by hash.
2. Failover actually moves traffic (flow pins to a dead peer are
   invalidated), works for single and ECMP, and BGP can drive ECMP
   (multipath).
3. Runtime selections survive re-apply and restarts; recovery paths
   are consistent; no leaks; nothing unrelated is touched.

## Model

- `api.PrefixSpec{CIDR, Candidates []name, Mode single|ecmp, Policy
  static|failover|bgp (informational), Selection []PeerWeight}`.
  Peers are addressed by NAME everywhere in the API. `PeerSpec.ID`
  (1..255) is the datapath ID, assigned by the control plane.
- Helpers in `internal/api`: `EffectiveMode`, `DefaultSelection`
  (single → first candidate; ecmp → all, weight 1),
  `EffectiveSelection`, `ValidateSelection`.
- Datapath form: every steered prefix is a **slot table** of
  `steer.Slots = 64` peer IDs. A new flow takes
  `slots[Hash(flowkey) & 63]`. single = all 64 slots one peer.
  `steer.NoPeer = 0` in a slot → drop.
- `steer.BuildSlots(prev, sel)` — proportional (largest remainder,
  ties by sel order, every selected peer ≥1 slot), resilient (keeps a
  staying peer's lowest-indexed existing slots up to its new target;
  freed slots filled in ascending slot order to under-target peers in
  sel order), deterministic. Empty sel → all NoPeer.
- **Flow pins with generations.** `peer_dev[id] = {ifindex, gen}`,
  `flow_peer[key] = {peer_id, gen}`. A pin is honored only if
  `peer_dev[pin.peer_id]` exists, ifindex != 0 and `gen == pin.gen`;
  otherwise the flow re-selects through the slot table and is
  re-pinned with the current gen. `FlushPeer(peer)` = `gen++` for that
  peer: O(1) invalidation of all its pins. `mux_from_wg` pins the
  reversed key with `{own_peer_id, peer_dev[own].gen}`. SetSelection
  alone does NOT flush (graceful: established flows keep their peer).
- Userspace engine mirrors this exactly in Go (same Hash, same slot
  tables via steer.Table, same gen semantics).

## BPF map contract (bpf/mux.c ↔ internal/steer/maps.go)

| map | type | key | value |
|---|---|---|---|
| `steering` | LPM_TRIE, 1024, NO_PREALLOC | `{u32 prefixlen; u32 addr}` | `{u32 slot[64]}` |
| `flow_peer` | LRU_HASH, 65536 | `struct flow_key` (unchanged) | `{u32 peer_id; u32 gen}` |
| `peer_dev` | ARRAY, 256 | `u32 peer_id` | `{u32 ifindex; u32 gen}` |
| `runtime_cfg` | ARRAY, 1 | `u32 0` | `{u32 back_ifindex; u8 front_mac[6]; u8 back_mac[6]; u64 spec_hash}` (24 bytes) |
| `debug` | ARRAY, 16 | `u32` | `u64` |

Debug counter indices (renamed, legacy slots dropped):
0 front_entries, 1 front_redirects, 2 front_unsteered (no LPM match /
unparseable → TC_ACT_OK), 3 front_no_peer (slot NoPeer or no
peer_dev → SHOT), 4 front_pin_hits, 5 front_pin_stale (pin found but
gen/peer invalid), 6 wg_entries, 7 wg_redirects, 8 wg_cfg_fail.
`datapath.DebugCounterNames` lists these names in order. The
userspace pump reports the same names where they correspond.

## Daemon semantics

- Per-instance locking: a registry mutex guards the map only; each
  instance has its own mutex. A long Apply on one instance never
  blocks SetSelection/State on another.
- Store `Record` gains `Version int` (=2) and
  `Selections map[string][]api.PeerWeight` (runtime overrides, by
  canonical CIDR). Written atomically after every successful
  SetSelection and Apply.
- Effective spec given to engines: for each prefix, Selection =
  override if (override exists AND !ResetSelections AND the prefix's
  Candidates, EffectiveMode and configured Selection are equal to the
  previously applied spec's AND ValidateSelection(override) passes);
  else the configured EffectiveSelection (and the override is
  dropped). The daemon validates every selection before calling the
  engine. Restore/adopt also use the merged effective spec.
- Apply failure: if the instance had a previous spec, the daemon
  re-applies it (rollback); status stays `active` with
  `Error: "apply failed (rolled back): ..."`; if rollback fails too,
  status `failed`. The store keeps the last *successful* spec.
- Destroy / Apply on an instance without a live engine (stored,
  failed): build an engine via the factory; if it is a `Purger`, call
  `Purge()` first (Apply) or instead of Close (Destroy), so leftovers
  are removed instead of leaked or collided with.
- `DaemonInfo.APIVersion = api.Version`.

## Kernel engine semantics

- Apply: if a previous spec exists and Front, ManageRoutes and Peers
  are deep-equal → **in-place**: `SetSpecHash(0)`, compile entries with
  `prev` = current `SteeringSnapshot`, `ReplaceSteering`, fix main-ns
  routes for added/removed prefixes (when ManageRoutes),
  `SetSpecHash(h)`. No device, ns or program churn; pins survive.
  Otherwise full rebuild as today, ending with `SetSpecHash(h)` as the
  very last step. With no previous spec in memory: `Purge()` first.
- Spec hash: FNV-1a 64 over `json.Marshal` of the spec with every
  `Prefixes[i].Selection` cleared; 0 maps to 1.
- Adopt: existing probes + `SpecHash(pinDir) == hash(spec)`; also
  load in-memory selections from the given (merged) spec.
- Purge: unpin pin dir (all maps incl. `debug`, links), delete backend
  ns `wgmux-<name>`, delete main-ns link `<name>` ONLY if it is a veth
  or netkit (never anything else), main-ns routes go with the link.
- AddPeer: create the wg device under a unique temporary name
  (`wgmt<random hex>`, < 16 chars), configure, move into the backend,
  rename there to `wg-<peer>`. Never adopt/steal an existing main-ns
  link. BuildInterconnect must refuse to reuse a pre-existing main-ns
  link named like the front unless it is a veth/netkit (error
  otherwise).
- SetSelection: compile with prev = current table, `SetSlots`.
  FlushPeer: `BumpPeerGen(id)`.
- State: Selection from memory; `Slots` (per peer NAME) from
  `SteeringSnapshot` ground truth.

## Control plane semantics

- YAML per prefix: `mode: single|ecmp` (default single),
  `policy: static|failover|bgp` (default static), `active: <peer>`
  (single initial), `weights: {peer: n}` (ecmp initial; default equal
  over all candidates; weight keys must be candidates). Legacy
  `policy: active` = static/single, `policy: hash` = static/ecmp.
- Failover monitor, every interval, from the DAEMON's `State` (peer
  names, candidates, current selection — never config IDs); config
  supplies only thresholds and configured weights:
  - healthy(peer) = last handshake within `handshake_max_age`.
  - single: active unhealthy and a healthy candidate exists → select
    the first healthy candidate (config order); no preemption back.
  - ecmp: desired = configured-weight selection restricted to healthy
    candidates; if none healthy keep current; SetSelection when it
    differs from current.
  - On a peer's healthy→unhealthy transition (tracked in monitor
    memory, once per transition) → `FlushPeer(peer)` after the
    selection change.
- BGP: `Decision{Prefix, WgPeers []string}`. single → first; ecmp →
  all (multipath, equal weight). FRR: collect paths with
  `bestpath` or `multipath` true. GoBGP: best path; multipath if
  feasible with the API, otherwise documented single-best limitation.
- `wgmuxctl run -c cfg.yaml` runs monitor + BGP for ALL muxes in the
  config until signalled (supervised); `contrib/wgmux-policy.service`.
- CLI: `activate [-flush] <cidr> <peer>`, `select [-flush] <cidr>
  <peer>[=weight]...`, status shows mode/policy/selection/slots;
  `apply -reset-selections`. Refuse daemons with `APIVersion !=
  api.Version`.

## Workstreams and file ownership

| WS | owns |
|---|---|
| A datapath | `bpf/mux.c`, `bpf/NOTES.md`, `internal/datapath/**` (incl. `mux.o`), `Makefile` |
| B steer + userspace | `internal/steer/**`, `internal/engine/userspace*.go`, `internal/engine/pump.go`, `internal/engine/chantun.go` |
| C control plane | `internal/config/**`, `cmd/wgmuxctl/**`, `internal/monitor/**`, `internal/bgp/**`, `contrib/**`, `README.md`, `docs/design.md`, `wgmux.example.yaml`, `test/e2e/**` |
| D daemon + kernel engine | `internal/daemon/**`, `internal/engine/kernel*.go`, `internal/engine/engine.go`, `internal/topology/**`, `internal/netnsutil/**`, `cmd/wgmuxd/**` |

`internal/api/**` and this file are frozen (owned by the lead).

## Tooling

- macOS host: `GOOS=linux go build ./...` and `GOOS=linux go vet
  ./...` work; portable unit tests run natively.
- Linux container (image `wgmux-dev`: Go 1.25, clang, libbpf-dev):
  ```sh
  docker run --rm --privileged -v "$PWD":/src -v wgmux-gocache:/root/go -w /src wgmux-dev \
    bash -c 'mount -t bpf bpf /sys/fs/bpf; go test ./...'
  ```
  BPF rebuild inside it:
  `clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c bpf/mux.c -o internal/datapath/mux.o`;
  verifier check: `WGMUX_TEST_LOAD=1 go test ./internal/datapath/`.
- Do not push, do not touch `main`. Commit your work on your
  worktree branch when done.
