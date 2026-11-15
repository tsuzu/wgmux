# wgmux datapath notes (`bpf/mux.c`)

Two TC programs, both `SEC("tcx/ingress")`, both attached **inside the
backend netns**. There is no FIB lookup, no `ip_forward` and no TTL
decrement inside the backend: packets are moved between devices with
`bpf_redirect()` only, so the only routing decision for inner packets
remains the single FIB lookup in the main netns that selected the front
interface (exactly as with a plain single `wg0`).

## Attach points

| Program | Attach point | Direction handled |
|---|---|---|
| `mux_from_front` | TCX ingress on the backend end of the interconnect (veth peer / netkit peer in the backend netns) | local → remote: select a Peer, redirect to its wg device (egress) |
| `mux_from_wg` | TCX ingress on each per-Peer wg device in the backend netns; one program instance per device | remote → local: record flow, then hand the packet toward the main netns — veth: pass to the backend stack (`TC_ACT_OK`), which forwards it out of the interconnect; netkit: `bpf_redirect_peer` to the front device |

`mux_from_wg` is loaded once per wg device because `own_peer_id` is a
per-instance constant (see below).

## Map contract (fixed; the Go loader depends on these names/layouts)

- `steering` — `BPF_MAP_TYPE_LPM_TRIE`, `max_entries` 1024,
  `BPF_F_NO_PREALLOC`.
  Key `struct steering_key { __u32 prefixlen; __u32 addr; }`
  (addr in network byte order; the program always looks up with
  `prefixlen = 32`, LPM finds the longest matching entry).
  Value `struct steering_val { __u32 slot[64]; }` — the prefix's ECMP
  slot table. A new flow takes `slot[flow_hash(flow_key) & 63]`
  (single-peer prefix: all 64 slots the same peer id; weighted ECMP:
  slots apportioned by weight). Slot value `0` (`steer.NoPeer`) means
  drop. There is no policy field: policy is control-plane
  information only.
- `flow_peer` — `BPF_MAP_TYPE_LRU_HASH`, `max_entries` 65536.
  Key `struct flow_key { __u32 saddr; __u32 daddr; __u16 sport;
  __u16 dport; __u8 proto; __u8 pad[3]; }`, all fields as they appear
  in the packet (addresses and ports in network byte order).
  Value `struct flow_pin { __u32 peer_id; __u32 gen; }`. Keys are
  always stored in the local→remote direction: `mux_from_wg` inserts
  the *reversed* key with `{own_peer_id, peer_dev[own].gen}` (gen 0 if
  the peer_dev entry is missing) so the reply of a remote-initiated
  flow, and later packets of a flow whichever side started it, hit
  the same entry. Consulted before `steering` in `mux_from_front`.
  **A pin is honored only if** `peer_dev[pin.peer_id]` exists, its
  ifindex is non-zero and its `gen` equals `pin.gen`; otherwise
  (counted as `front_pin_stale`) the flow re-selects through the slot
  table and is re-pinned with the peer's current gen.
- `peer_dev` — `BPF_MAP_TYPE_ARRAY`, `max_entries` 256.
  Key `__u32` peer_id, value `struct peer_info { __u32 ifindex;
  __u32 gen; }`: ifindex of that Peer's wg device *in the backend
  netns* and the peer's pin generation. A steered packet whose slot
  is `0`, or whose peer has no entry / ifindex 0, is dropped with
  `TC_ACT_SHOT` (`front_no_peer`), not passed. Bumping `gen`
  (`datapath.BumpPeerGen`, i.e. FlushPeer) invalidates every pin to
  that peer in O(1).
- `runtime_cfg` — `BPF_MAP_TYPE_ARRAY`, `max_entries` 1, only key 0.
  Value `struct runtime_cfg { __u32 back_ifindex; __u8 front_mac[6];
  __u8 back_mac[6]; __u64 spec_hash; }` (24 bytes): ifindex of the
  interconnect backend end, the fixed MAC addresses of the two
  interconnect ends (used only in veth / `l2_mode`), and the kernel
  engine's completed-apply marker (`spec_hash`, 0 while an apply is in
  progress; never read by the programs).
- `debug` — `BPF_MAP_TYPE_ARRAY`, 16 `__u64` counters, indices:
  0 front_entries, 1 front_redirects, 2 front_unsteered (no LPM match
  or unparseable: `TC_ACT_OK`), 3 front_no_peer (`TC_ACT_SHOT`),
  4 front_pin_hits, 5 front_pin_stale, 6 wg_entries, 7 wg_redirects,
  8 wg_cfg_fail (`datapath.DebugCounterNames`).

## Per-instance constants (`const volatile`, rewritten by the loader)

- `l2_mode` (`bool`) — `true` when the interconnect is veth: packets
  at the interconnect carry an Ethernet header, and it is still
  there at TC ingress (nothing pulls it earlier on this path).
  `mux_from_front` parses after `ETH_HLEN` and does NOT remove
  the header: `bpf_redirect` to a WireGuard device (not a
  MAC-header-xmit device) makes the redirect core pull
  `skb_network_offset(skb)` bytes itself
  (`__bpf_redirect_no_mac`, net/core/filter.c) — the packet must
  arrive in the standard received state, data at the MAC header.
  Any in-program strip removes the header twice. In the return
  direction, `mux_from_wg` (veth mode) records the flow and
  returns `TC_ACT_OK`: the backend stack forwards the packet out
  of the interconnect and builds the Ethernet header itself
  (topology enables `ip_forward` and disables `rp_filter` in the
  backend namespace for this). A TC-side grow+redirect cannot
  work here: a wg receive skb has no usable MAC header state,
  `bpf_skb_net_hdr_push` shifts `mac_header` and
  `network_header` together so their relation never changes, and
  `__bpf_redirect_common` drops packets with
  `mac_header >= network_header` — there is no TC helper that
  sets `mac_header` below `network_header` from scratch.
  `false` for netkit L3: packets are raw IP at the interconnect
  in both directions, `mux_from_wg` redirects, and no header
  conversion or stack hop happens.
  (`bpf_skb_adjust_room` cannot do the forward strip either: per
  net/core/filter.c's `bpf_skb_net_hdr_pop`, a shrink deletes
  `len_diff` bytes at offset `mac_header_len` [+ L3 base length
  for `BPF_ADJ_ROOM_NET`] from `skb->data` and then pulls
  `len_diff` bytes — a tunnel-decap primitive that preserves the
  outer headers. With a MAC header present, no mode's deletion
  window starts at offset 0.)
- `own_peer_id` (`__u32`) — only used by `mux_from_wg`: the peer_id of
  the wg device that instance is attached to; recorded into
  `flow_peer` for the flows arriving from that Peer.

## Verifier notes

- All packet parsing goes through `bpf_skb_load_bytes()` (20-byte IPv4
  header first, then 4 bytes of L4 ports at `hdr_off + IHL*4`), so no
  direct-access pointer arithmetic has to be tracked across the
  variable IHL. IHL is validated (`5 <= ihl <= 15`).
- `slot[]` indexing is verifier-friendly by construction: the index is
  `flow_hash(fk) & 63`, with `barrier_var` between the hash and the
  mask so clang cannot delete the mask as redundant (the verifier
  could not re-derive the bound without it).
- No loops at all; hashing is a fixed Jenkins-style mix over the
  flow-key fields.
- Non-IPv4, truncated or otherwise unparseable packets return
  `TC_ACT_OK` (pass) in both programs, never a drop.

## Known limitations

- **IPv4 only.** IPv6 packets pass unsteered (`TC_ACT_OK`). Extending
  means a `*_key6` variant (or 16-byte addresses) in `steering` and
  `flow_peer`, plus `ETH_P_IPV6` in the Ethernet header written by
  `mux_from_wg`.
- **Non-TCP/UDP flows have ports = 0.** ICMP (and any other protocol)
  therefore pins per host-pair + protocol only: two peers talking to
  the same remote host with ICMP cannot be distinguished, and all ICMP
  between a host pair follows one peer.
- **Flow pinning is best-effort.** Entries live in an LRU hash; under
  pressure (more than 65536 flows) old entries can be evicted, after
  which a mid-flight flow may be re-steered by `steering` and break if
  the new peer is a different host.
- **Slot-table changes and established flows.** Replacing a slot
  table (`SetSlots`) does not move established flows: they keep their
  pin (graceful). New flows use the new table. To move existing flows
  off a peer, flush it: `BumpPeerGen` increments `peer_dev[id].gen`,
  every pin to that peer becomes stale and re-selects through the
  slot table on its next packet. Flush is per peer, O(1), and also
  invalidates the reverse pins `mux_from_wg` recorded for that peer.
- **ECMP granularity.** 64 slots per prefix: weights are quantized to
  1/64 and every selected peer gets at least one slot. Unpinned flows
  of a prefix whose table changed re-hash to whatever the new table
  says (resilient `BuildSlots` keeps most slots stable).
- **Spec hash / in-place re-apply.** `ReplaceSteering` updates the
  LPM trie key by key (put new, then delete stale) without reloading
  programs, so lookups during the update see either the old or new
  table of a prefix, never an empty trie. `runtime_cfg.spec_hash` is
  set to 0 before such an update and to the new hash afterwards.
- **GSO/GRO.** The programs never segment or coalesce packets; they
  only adjust the L2 room and redirect the `skb`. Oversized (GSO)
  `skb`s coming from the front are handed to the wg device as-is and
  rely on WireGuard's own segmentation on transmit, as with a plain
  `wg0`; the redirect path does not re-check the packet against the
  target wg device's MTU, so the front / interconnect MTU should be
  set to the smallest MTU of the peer wg devices to avoid silent
  drops for non-GSO traffic. The Ethernet header grow/shrink via
  `bpf_skb_adjust_room` may, on packets with little headroom, expand
  the `skb` head — cheaper than a routing pass, but not zero-cost.
- **Build and verification.** The committed object is
  `internal/datapath/mux.o`, built in the `wgmux-dev` image:

  ```sh
  clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -c bpf/mux.c -o internal/datapath/mux.o
  ```

  The kernel verifier accepts both programs (verified with
  `WGMUX_TEST_LOAD=1 go test ./internal/datapath/` in a privileged
  container with bpffs mounted; the same test also exercises the
  runtime map API and, through `BPF_PROG_TEST_RUN`, slot selection,
  pin-generation invalidation, NoPeer drops and unsteered pass).

## Place in the engine model

These programs are the **kernel engine's** realization of the
steering contract (see `docs/design.md`). They are per-instance:
each mux instance has its own backend namespace (`wgmux-<name>`),
its own interconnect and peer devices, and its own copy of the
maps/programs pinned under `<pin root>/wgmux/<name>/`. Two
instances steering overlapping prefixes therefore have fully
separate forwarding domains — which matters because in veth mode
the return path uses the backend namespace's FIB, and that FIB is
per-instance state like everything else here.

The pins are also the persistence mechanism: because the steering
state lives in pinned maps (not in the daemon), the kernel
datapath keeps forwarding while wgmuxd is stopped, and a restarted
daemon *adopts* the instance — it probes the namespace, the pin
dir and the pinned steering map, and resumes `State`/`SetSelection`
against them without reprogramming anything. The userspace
(wireguard-go) engine implements the same selection semantics in a
Go pump (`internal/steer`); it uses none of this file's machinery.
