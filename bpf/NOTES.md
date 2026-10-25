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
| `mux_from_wg` | TCX ingress on each per-Peer wg device in the backend netns; one program instance per device | remote → local: record flow, redirect out of the backend interconnect end (egress) toward the main netns |

`mux_from_wg` is loaded once per wg device because `own_peer_id` is a
per-instance constant (see below).

## Map contract (fixed; the Go loader depends on these names/layouts)

- `steering` — `BPF_MAP_TYPE_LPM_TRIE`, `max_entries` 1024,
  `BPF_F_NO_PREALLOC`.
  Key `struct steering_key { __u32 prefixlen; __u32 addr; }`
  (addr in network byte order; the program always looks up with
  `prefixlen = 32`, LPM finds the longest matching entry).
  Value `struct steering_val { __u32 peer_id[4]; __u8 count;
  __u8 active; __u8 policy; __u8 pad; }`.
  `peer_id[0..count)` are the candidate peers for the prefix.
  - `policy == 0`: use `peer_id[active]` (bounds-checked,
    `active < count`, otherwise the packet passes unsteered).
  - `policy == 1`: use `peer_id[flow_hash(flow_key) % count]` —
    deterministic per flow, so a given flow stays on one peer as long
    as the candidate set does not change.
- `flow_peer` — `BPF_MAP_TYPE_LRU_HASH`, `max_entries` 65536.
  Key `struct flow_key { __u32 saddr; __u32 daddr; __u16 sport;
  __u16 dport; __u8 proto; __u8 pad[3]; }`, all fields as they appear
  in the packet (addresses and ports in network byte order).
  Value `__u32` peer_id. Keys are always stored in the
  local→remote direction: `mux_from_wg` inserts the *reversed* key so
  the reply of a remote-initiated flow, and later packets of a flow
  whichever side started it, hit the same entry. Consulted before
  `steering` in `mux_from_front`, so an established flow is pinned
  even if `steering.active` / the candidate set changes afterwards.
- `peer_dev` — `BPF_MAP_TYPE_ARRAY`, `max_entries` 256.
  Key `__u32` peer_id, value `__u32` ifindex of that Peer's wg device
  *in the backend netns*. A steered packet whose peer has no entry (or
  ifindex 0) is dropped with `TC_ACT_SHOT`, not passed.
- `runtime_cfg` — `BPF_MAP_TYPE_ARRAY`, `max_entries` 1, only key 0.
  Value `struct runtime_cfg { __u32 back_ifindex; __u8 front_mac[6];
  __u8 back_mac[6]; }`: ifindex of the interconnect backend end, and
  the fixed MAC addresses of the two interconnect ends (used only in
  veth / `l2_mode`; the link is point-to-point, no ARP is involved).

## Per-instance constants (`const volatile`, rewritten by the loader)

- `l2_mode` (`bool`) — `true` when the interconnect is veth: packets
  at the interconnect carry an Ethernet header. `mux_strip_l2`
  (XDP on the backend end) performs peer selection for steered
  IPv4 frames and records the flow; it does not strip anything —
  on veth, an XDP_PASS frame goes through the driver's
  `eth_type_trans()`, which pulls the Ethernet header as part of
  normal delivery (stripping in XDP as well pulled it twice).
  `mux_from_front` therefore always parses at offset 0, in both
  modes. In the return direction `mux_from_wg` grows the room back
  with `bpf_skb_adjust_room(skb, +ETH_HLEN, BPF_ADJ_ROOM_MAC, 0)`
  and writes an Ethernet header (`dst = front_mac`,
  `src = back_mac`, `ethertype = ETH_P_IP`). `false` for netkit L3:
  packets are raw IP at the interconnect in both directions and no
  header conversion happens.
  (`bpf_skb_adjust_room` cannot do the strip: per
  net/core/filter.c's `bpf_skb_net_hdr_pop`, a shrink deletes
  `len_diff` bytes at offset `mac_header_len` [+ L3 base length for
  `BPF_ADJ_ROOM_NET`] from `skb->data` and then pulls `len_diff`
  bytes — a tunnel-decap primitive that preserves the outer
  headers. With a MAC header present, no mode's deletion window
  starts at offset 0. The grow direction is the designed encap
  case and works because a wg receive skb has `mac_header_len`
  == 0, putting the insertion at offset 0.)
- `own_peer_id` (`__u32`) — only used by `mux_from_wg`: the peer_id of
  the wg device that instance is attached to; recorded into
  `flow_peer` for the flows arriving from that Peer.

## Verifier notes

- All packet parsing goes through `bpf_skb_load_bytes()` (20-byte IPv4
  header first, then 4 bytes of L4 ports at `hdr_off + IHL*4`), so no
  direct-access pointer arithmetic has to be tracked across the
  variable IHL. IHL is validated (`5 <= ihl <= 15`).
- `peer_id[]` indexing is verifier-friendly by construction: after the
  policy branch, `idx` satisfies `idx < count <= 4`, and is then
  additionally masked with `& (4 - 1)` before the array access so the
  verifier can prove the access is in bounds.
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
- **Policy 1 rehashing.** Changing `count` or the candidate order for
  a prefix changes `hash % count` for existing flows that are not (or
  no longer) pinned in `flow_peer`, with the same caveat.
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
- **Compile check passed (2026-10-26)**, once clang 18 + libbpf
  headers were installed; the committed object is
  `internal/datapath/mux.o`:

  ```sh
  clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/mux.c -o internal/datapath/mux.o
  ```

  (The multiarch include dir is needed for `asm/types.h` on
  Debian/Ubuntu.) **Verifier check is still outstanding**: the
  authoring environment is a restricted container where BPF program
  loads are not permitted, so run
  `WGMUX_TEST_LOAD=1 go test ./internal/datapath/` on a normal host
  to have the kernel verifier check both programs and all maps.
