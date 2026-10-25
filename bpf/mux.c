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
 *                   carries its Ethernet header at TC ingress (neither
 *                   XDP_PASS delivery nor anything else pulls it before
 *                   TC — verified empirically), so the header is
 *                   removed in place first (see strip_l2_header).
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
 * bytes instead (see git history).  Its GROW direction is, however,
 * exactly the encap operation mux_from_wg needs.
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
#define DBG_FRAMED 1	     /* of those, detected as Ethernet-framed */
#define DBG_STRIP_CALLS 2    /* strip_l2_header invocations */
#define DBG_LAST_LEN 3	     /* skb->len at entry */
#define DBG_LAST_WORD0 4     /* first 4 bytes at entry */
#define DBG_AFTER_LEN 5	     /* skb->len after strip */
#define DBG_AFTER_WORD0 6    /* first 4 bytes after strip */
#define DBG_REDIRECTS 7	     /* bpf_redirect calls from mux_from_front */

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

/*
 * Remove the Ethernet header in place (veth mode): shift the L3
 * packet down over it with load/store_bytes, then trim the tail.
 * Every helper used here has elementary semantics (copy bytes at
 * offsets from skb->data; set the length), unlike the header-anchor
 * arithmetic of bpf_skb_adjust_room — see the file header for why
 * that helper cannot do this job.  The copy is the veth mode's
 * cost; netkit mode never pays it.
 */
static __always_inline int strip_l2_header(struct __sk_buff *skb)
{
	__u32 total = skb->len;
	__u32 remain;
	int i;

	if (total <= ETH_HLEN || total > ETH_HLEN + 8 * 256)
		return -1;
	remain = total - ETH_HLEN;

	for (i = 0; i < 8; i++) {
		__u8 buf[256];
		__u32 n;

		if (remain == 0)
			break;
		n = remain < 256 ? remain : 256;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + i * 256, buf, n) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, i * 256, buf, n, 0) < 0)
			return -1;
		remain -= n;
	}

	if (bpf_skb_change_tail(skb, total - ETH_HLEN, 0) < 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Program A: interconnect (backend end) -> selected wg device         */
/* ------------------------------------------------------------------ */

SEC("tcx/ingress")
int mux_from_front(struct __sk_buff *skb)
{
	struct flow_key fk;
	__u32 peer_id;
	__u32 *ifindex;
	__u32 target_ifindex;
	__u32 hdr_off = 0;
	bool framed = false;
	__u32 word0 = 0;

	dbg_inc(DBG_FRONT_ENTRIES);
	dbg_set(DBG_LAST_LEN, skb->len);
	if (bpf_skb_load_bytes(skb, 0, &word0, sizeof(word0)) == 0)
		dbg_set(DBG_LAST_WORD0, word0);

	/*
	 * Detect the framing from the packet itself instead of
	 * assuming it from l2_mode: the e2e captures showed the
	 * strip being applied to a packet whose header was already
	 * gone (the delivered packet was missing its first 14 IP
	 * bytes).  A veth frame carrying IPv4 has ethertype 0x0800
	 * at [12..13]; an already-L3 packet does not (those bytes
	 * are inside its IP header).  Only a positively framed
	 * packet is parsed after ETH_HLEN and stripped.
	 */
	if (l2_mode) {
		__u16 ethertype = 0;

		if (bpf_skb_load_bytes(skb, 12, &ethertype,
				       sizeof(ethertype)) == 0 &&
		    ethertype == bpf_htons(ETH_P_IP)) {
			hdr_off = ETH_HLEN;
			framed = true;
		}
	}

	if (parse_flow_key(skb, hdr_off, &fk) < 0)
		return TC_ACT_OK; /* non-IPv4 / unparseable: pass */

	if (select_peer(&fk, &peer_id) < 0)
		return TC_ACT_OK; /* not a steered destination */

	/* Resolve the peer to its wg device in the backend netns. */
	ifindex = bpf_map_lookup_elem(&peer_dev, &peer_id);
	if (!ifindex || *ifindex == 0)
		return TC_ACT_SHOT; /* steered peer has no device: drop */
	target_ifindex = *ifindex;

	if (framed)
		dbg_inc(DBG_FRAMED);

	/* wg devices are L3: remove the interconnect Ethernet header. */
	if (framed) {
		dbg_inc(DBG_STRIP_CALLS);
		if (strip_l2_header(skb) < 0)
			return TC_ACT_SHOT;
		dbg_set(DBG_AFTER_LEN, skb->len);
		word0 = 0;
		if (bpf_skb_load_bytes(skb, 0, &word0, sizeof(word0)) == 0)
			dbg_set(DBG_AFTER_WORD0, word0);
	}

	dbg_inc(DBG_REDIRECTS);
	return bpf_redirect(target_ifindex, 0);
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

	cfg = bpf_map_lookup_elem(&runtime_cfg, &zero);
	if (!cfg || cfg->back_ifindex == 0)
		return TC_ACT_SHOT; /* not (yet) configured: drop */

	/* Copy everything out of the map before touching the packet. */
	back_ifindex = cfg->back_ifindex;

	if (l2_mode) {
		struct ethhdr eth = {};

		__builtin_memcpy(eth.h_dest, cfg->front_mac,
				 sizeof(eth.h_dest));
		__builtin_memcpy(eth.h_source, cfg->back_mac,
				 sizeof(eth.h_source));
		eth.h_proto = bpf_htons(ETH_P_IP);

		/*
		 * The packet must cross a veth to reach the main
		 * netns, so it needs an Ethernet header again.
		 * point-to-point link: fixed MACs, no ARP involved.
		 *
		 * GROW with BPF_ADJ_ROOM_MAC is the helper's designed
		 * encap case (see the file header): a wg receive skb
		 * has no MAC header (mac_header_len == 0), so the room
		 * is inserted at offset 0, in front of the IP header,
		 * and the data pointer ends up at the inserted room,
		 * ready for the store_bytes below.
		 */
		if (bpf_skb_adjust_room(skb, (__s32)ETH_HLEN,
					 BPF_ADJ_ROOM_MAC, 0) < 0)
			return TC_ACT_SHOT;

		if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
			return TC_ACT_SHOT;
	}
	/* netkit L3 mode: no header to add, the packet stays raw IP. */

	return bpf_redirect(back_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
