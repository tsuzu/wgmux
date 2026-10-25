// SPDX-License-Identifier: GPL-2.0
/*
 * wgmux datapath — TC programs for the backend network namespace.
 *
 * Per-Peer WireGuard devices live in a hidden backend netns.  A single
 * interconnect pair (veth, or netkit in L3 mode) links the main netns
 * (front end) to the backend.  All steering is done here, in TC ingress:
 * no kernel FIB lookup, no ip_forward and no TTL decrement happen inside
 * the backend.
 *
 *   mux_from_front: TC ingress on the backend end of the interconnect.
 *                   Parses the inner IPv4 packet, selects a Peer and
 *                   bpf_redirect()s the packet to that Peer's wg device
 *                   (egress).  On a veth interconnect the packet still
 *                   carries its Ethernet header at TC ingress, and the
 *                   program deliberately does NOT remove it:
 *                   bpf_redirect to a non-MAC-xmit device (WireGuard)
 *                   pulls skb_network_offset bytes in the redirect
 *                   core itself (__bpf_redirect_no_mac).  See the
 *                   comment at the redirect in mux_from_front.
 *
 *   mux_from_wg:    TC ingress on each wg device.  Records the flow so
 *                   that replies return via the same Peer, then
 *                   bpf_redirect()s the packet out of the interconnect
 *                   backend end (egress) toward the main netns.
 *
 * Why not strip with bpf_skb_adjust_room() in TC?  Reading
 * __bpf_skb_adjust_room/bpf_skb_net_hdr_pop in net/core/filter.c:
 * the helper deletes len_diff bytes at offset (mac_header_len [+ L3
 * base len for NET]) from skb->data and then pulls len_diff bytes —
 * it is a tunnel-decap primitive that PRESERVES the outer headers.
 * With a 14-byte MAC header present there is no mode whose deletion
 * window starts at offset 0, so it cannot remove the outermost
 * Ethernet header; the e2e captures showed it eating IP/TCP header
 * bytes instead (see git history).  Its GROW direction cannot
 * fabricate a MAC header on a wg receive skb either — see the
 * comment in mux_from_wg.
 *
 * Wire format / map contract (fixed — the Go loader depends on it):
 * see NOTES.md in this directory.
 *
 * IPv4 only, for now.  Non-IPv4 / unparseable packets are passed with
 * TC_ACT_OK, never dropped, so that other traffic on these devices is
 * not broken by the multiplexer.
 */

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/* Shared types (must match the Go loader exactly)                     */
/* ------------------------------------------------------------------ */

#define MAX_CANDIDATE_PEERS 4
#define STEERING_MAX_ENTRIES 1024
#define FLOW_PEER_MAX_ENTRIES 65536
#define PEER_DEV_MAX_ENTRIES 256

struct steering_key {
	__u32 prefixlen;
	__u32 addr; /* network byte order */
};

struct steering_val {
	__u32 peer_id[MAX_CANDIDATE_PEERS];
	__u8 count;
	__u8 active;
	__u8 policy; /* 0 = peer_id[active], 1 = per-flow hash over peer_id[0..count) */
	__u8 pad;
};

struct flow_key {
	__u32 saddr; /* network byte order */
	__u32 daddr; /* network byte order */
	__u16 sport; /* network byte order, as on the wire; 0 if not TCP/UDP */
	__u16 dport; /* network byte order, as on the wire; 0 if not TCP/UDP */
	__u8 proto;
	__u8 pad[3];
};

struct runtime_cfg {
	__u32 back_ifindex;
	__u8 front_mac[6];
	__u8 back_mac[6];
};

/* ------------------------------------------------------------------ */
/* Load-time constants (rewritten per instance by the Go loader)       */
/* ------------------------------------------------------------------ */

/* true: interconnect is veth (packets there carry an Ethernet header).
 * false: interconnect is netkit L3 (packets there are raw IP).
 */
const volatile bool l2_mode;

/* Only used by mux_from_wg: the peer_id of the wg device this program
 * instance is attached to.
 */
const volatile __u32 own_peer_id;

/* ------------------------------------------------------------------ */
/* Maps                                                                */
/* ------------------------------------------------------------------ */

/* All maps are pinned by name: the daemon's runtime operations
 * (activation, status, monitoring) address them through the pin
 * directory long after the loading process has moved on. Without
 * the pinning declaration cilium/ebpf silently skips pinning even
 * when a PinPath is given.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, STEERING_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct steering_key);
	__type(value, struct steering_val);
} steering SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_PEER_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct flow_key);
	__type(value, __u32);
} flow_peer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PEER_DEV_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, __u32);
} peer_dev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct runtime_cfg);
} runtime_cfg SEC(".maps");

/*
 * Datapath observability counters (indices fixed; see NOTES.md).
 * Written by mux_from_front; read by wgmuxctl status.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, __u64);
} debug SEC(".maps");

#define DBG_FRONT_ENTRIES 0  /* mux_from_front invocations */
#define DBG_FRAMED 1	     /* of those, on an L2 (veth) interconnect */
#define DBG_STRIP_CALLS 2    /* unused (kept for index stability) */
#define DBG_LAST_LEN 3	     /* skb->len at entry */
#define DBG_LAST_WORD0 4     /* first 4 bytes at entry */
#define DBG_AFTER_LEN 5	     /* unused (kept for index stability) */
#define DBG_AFTER_WORD0 6    /* unused (kept for index stability) */
#define DBG_REDIRECTS 7	     /* bpf_redirect calls from mux_from_front */
#define DBG_WG_ENTRIES 8     /* mux_from_wg invocations */
#define DBG_WG_CFG_FAIL 9    /* runtime_cfg missing/back_ifindex 0 */
#define DBG_WG_GROW_FAIL 10  /* bpf_skb_adjust_room grow failed */
#define DBG_WG_STORE_FAIL 11 /* bpf_skb_store_bytes of the eth header failed */
#define DBG_WG_REDIRECTS 12  /* bpf_redirect calls from mux_from_wg */

static __always_inline void dbg_set(__u32 idx, __u64 val)
{
	__u64 *slot = bpf_map_lookup_elem(&debug, &idx);

	if (slot)
		*slot = val;
}

static __always_inline void dbg_inc(__u32 idx)
{
	__u64 *slot = bpf_map_lookup_elem(&debug, &idx);

	if (slot)
		__sync_fetch_and_add(slot, 1);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Parse an IPv4 packet starting at @hdr_off and fill @fk in the
 * forward direction (local -> remote, exactly as seen on the wire).
 *
 * Returns 0 on success, -1 if the packet is not IPv4 or cannot be
 * parsed safely; callers treat -1 as "pass" (TC_ACT_OK).
 *
 * Parsing goes through bpf_skb_load_bytes() everywhere, so there is no
 * direct-packet-access pointer arithmetic for the verifier to track
 * across the variable-length (IHL) IPv4 header.
 */
static __always_inline int parse_flow_key(struct __sk_buff *skb,
					  __u32 hdr_off,
					  struct flow_key *fk)
{
	struct iphdr iph = {};
	__u32 ihl;

	if (bpf_skb_load_bytes(skb, hdr_off, &iph, sizeof(iph)) < 0)
		return -1;

	if (iph.version != 4)
		return -1;

	/* ihl is in 32-bit words; valid range is 5..15 (20..60 bytes). */
	if (iph.ihl < sizeof(iph) / 4 || iph.ihl > 15)
		return -1;
	ihl = (__u32)iph.ihl * 4;

	__builtin_memset(fk, 0, sizeof(*fk));
	fk->saddr = iph.saddr;
	fk->daddr = iph.daddr;
	fk->proto = iph.protocol;
	/* sport/dport stay 0 for non-TCP/UDP (e.g. ICMP): see NOTES.md. */

	if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
		__u16 ports[2] = {};

		if (bpf_skb_load_bytes(skb, hdr_off + ihl, ports,
				       sizeof(ports)) < 0)
			return -1;
		fk->sport = ports[0];
		fk->dport = ports[1];
	}

	return 0;
}

/*
 * Note on barrier_var (from bpf_helpers.h): it hides a value's
 * provenance from clang. It is needed before masking an index into a
 * map value array (see mux_from_front): clang can prove from the
 * source-level range checks that the mask is redundant and delete
 * it, but the kernel verifier cannot reproduce that proof (it does
 * not narrow a map-loaded u8 through the wrapped subtract-and-
 * compare sequence clang emits for the checks), so the unmasked
 * index looks unbounded to the verifier and the load fails.
 */

/*
 * Simple Jenkins-style mix over the flow key fields.  Used for
 * steering policy 1 to spread flows deterministically over the
 * candidate peers for a prefix (same flow -> same hash -> same peer,
 * at least until the candidate set changes).
 */
static __always_inline __u32 flow_hash(const struct flow_key *fk)
{
	__u32 h = 0x9e3779b9;

	h ^= fk->saddr;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h ^= fk->daddr;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	h ^= ((__u32)fk->sport << 16) | fk->dport;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h ^= fk->proto;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/*
 * Shared peer selection: an established flow (flow_peer) wins;
 * otherwise the steering LPM decides by destination and the choice
 * is recorded so the flow sticks to its peer.  Returns 0 and sets
 * *peer_id_out, or -1 when the destination is not steered.
 */
static __always_inline int select_peer(const struct flow_key *fk,
				       __u32 *peer_id_out)
{
	__u32 *pinned = bpf_map_lookup_elem(&flow_peer, fk);

	if (pinned) {
		*peer_id_out = *pinned;
		return 0;
	}

	struct steering_key skey = {
		.prefixlen = 32,
		.addr = fk->daddr,
	};
	struct steering_val *val = bpf_map_lookup_elem(&steering, &skey);
	__u32 idx;

	if (!val)
		return -1;

	if (val->count == 0 || val->count > MAX_CANDIDATE_PEERS)
		return -1;

	if (val->policy == 0) {
		if (val->active >= val->count)
			return -1;
		idx = val->active;
	} else if (val->policy == 1) {
		idx = flow_hash(fk) % val->count;
	} else {
		return -1; /* unknown policy */
	}

	/*
	 * Mask the index to the array bounds so the verifier can
	 * prove the peer_id[] access is in range.  The mask is a
	 * no-op semantically (idx < count <= 4 in both policies
	 * above), but it must survive compilation: barrier_var hides
	 * idx's provenance so clang cannot delete the mask as
	 * redundant (see barrier_var).
	 */
	barrier_var(idx);
	idx &= MAX_CANDIDATE_PEERS - 1;
	*peer_id_out = val->peer_id[idx];

	bpf_map_update_elem(&flow_peer, fk, peer_id_out, BPF_ANY);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Program A: interconnect (backend end) -> selected wg device         */
/* ------------------------------------------------------------------ */

SEC("tcx/ingress")
int mux_from_front(struct __sk_buff *skb)
{
	const __u32 hdr_off = l2_mode ? ETH_HLEN : 0;
	struct flow_key fk;
	__u32 peer_id;
	__u32 *ifindex;
	__u32 word0 = 0;

	dbg_inc(DBG_FRONT_ENTRIES);
	dbg_set(DBG_LAST_LEN, skb->len);
	if (bpf_skb_load_bytes(skb, 0, &word0, sizeof(word0)) == 0)
		dbg_set(DBG_LAST_WORD0, word0);
	if (l2_mode)
		dbg_inc(DBG_FRAMED);

	if (parse_flow_key(skb, hdr_off, &fk) < 0)
		return TC_ACT_OK; /* non-IPv4 / unparseable: pass */

	if (select_peer(&fk, &peer_id) < 0)
		return TC_ACT_OK; /* not a steered destination */

	/* Resolve the peer to its wg device in the backend netns. */
	ifindex = bpf_map_lookup_elem(&peer_dev, &peer_id);
	if (!ifindex || *ifindex == 0)
		return TC_ACT_SHOT; /* steered peer has no device: drop */

	/*
	 * NO header stripping here — bpf_redirect does it.  The wg
	 * device is not a MAC-header-xmit device, so the redirect
	 * core (__bpf_redirect_no_mac, net/core/filter.c) pulls
	 * skb_network_offset(skb) bytes itself: it expects the
	 * packet in the standard received state, data at the MAC
	 * header with the network header pointing at the L3 header.
	 * Stripping in the program as well removes the header
	 * twice (the e2e saga in git history: adjust_room variants,
	 * an XDP variant and an in-place copy all delivered packets
	 * missing exactly their first 14 IP bytes for this reason).
	 */
	dbg_inc(DBG_REDIRECTS);
	return bpf_redirect(*ifindex, 0);
}

/* ------------------------------------------------------------------ */
/* Program B: wg device -> interconnect (backend end) -> main netns    */
/* ------------------------------------------------------------------ */

SEC("tcx/ingress")
int mux_from_wg(struct __sk_buff *skb)
{
	struct flow_key fk;
	struct flow_key rev;
	struct runtime_cfg *cfg;
	__u32 zero = 0;
	__u32 back_ifindex;
	__u32 own = own_peer_id;

	dbg_inc(DBG_WG_ENTRIES);

	/* wg devices are L3, so the packet is raw IP in both modes. */
	if (parse_flow_key(skb, 0, &fk) < 0)
		return TC_ACT_OK; /* non-IPv4 / unparseable: pass */

	/*
	 * Record the reverse key, i.e. in the same shape a packet of
	 * the reply flow will have in mux_from_front (local -> remote):
	 * swap addresses and ports.  A later locally-originated packet
	 * belonging to this flow then hits in flow_peer and returns
	 * via this peer even if the steering policy has moved on.
	 */
	__builtin_memset(&rev, 0, sizeof(rev));
	rev.saddr = fk.daddr;
	rev.daddr = fk.saddr;
	rev.sport = fk.dport;
	rev.dport = fk.sport;
	rev.proto = fk.proto;
	bpf_map_update_elem(&flow_peer, &rev, &own, BPF_ANY);

	if (l2_mode) {
		/*
		 * Veth mode: hand the packet to the backend stack
		 * (TC_ACT_OK) and let it forward the packet out of
		 * the interconnect; the kernel builds the Ethernet
		 * header (the backend ARPs for the front address like
		 * for any connected route).
		 *
		 * Why not grow a header and bpf_redirect like the
		 * forward direction does in reverse?  A wg receive skb
		 * has no usable MAC header state (mac_header unset or
		 * equal to network_header), bpf_skb_adjust_room's push
		 * shifts mac_header and network_header together, and
		 * no TC helper can set mac_header below network_header
		 * from scratch — while __bpf_redirect_common drops any
		 * packet with mac_header >= network_header.  Verified
		 * empirically: grows and stores all succeeded, the
		 * redirect was called, and the packet died in the core
		 * every time.  The cost of this design is one stack
		 * forwarding pass (and a TTL decrement) on the return
		 * path in veth mode only; netkit mode redirects in
		 * both directions and never touches the stack.
		 */
		return TC_ACT_OK;
	}

	cfg = bpf_map_lookup_elem(&runtime_cfg, &zero);
	if (!cfg || cfg->back_ifindex == 0) {
		dbg_inc(DBG_WG_CFG_FAIL);
		return TC_ACT_SHOT; /* not (yet) configured: drop */
	}

	/* Copy everything out of the map before touching the packet. */
	back_ifindex = cfg->back_ifindex;

	/* netkit L3 mode: no header to add, the packet stays raw IP. */
	dbg_inc(DBG_WG_REDIRECTS);
	return bpf_redirect(back_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
