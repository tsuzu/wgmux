// Package steer holds the steering model shared by every datapath
// realization. A prefix's selection (one peer, or several weighted
// peers for ECMP) is compiled into a fixed-size hash-slot table:
// slot[Hash(flow) & (Slots-1)] is the peer a NEW flow takes. The
// kernel engine programs these tables into the BPF steering map; the
// userspace engine evaluates the same tables in Go (Table). Because
// both use Entry/Pick/Hash, a flow selects the same peer either way.
//
// BuildSlots is resilient: changing a selection moves only the slots
// that must move (a removed peer's slots, or the minimum needed to
// rebalance weights), so flows of unaffected peers keep their slot
// even when they are not pinned.
package steer

import (
	"encoding/binary"
	"net"
	"sync"

	"github.com/tsuzu/wgmux/internal/api"
)

// Slots is the number of hash slots per prefix (power of two; the
// datapath masks with Slots-1). It bounds weight resolution: a
// weighted selection is realized to the nearest 1/Slots.
const Slots = 64

// NoPeer is the reserved peer ID meaning "no peer" (a slot holding it
// drops the packet in both datapaths). Real peer IDs start at 1.
const NoPeer uint32 = 0

// SlotTable maps hash slots to peer IDs.
type SlotTable [Slots]uint32

// WeightedPeer is one selected peer in datapath-ID form.
type WeightedPeer struct {
	ID     uint32
	Weight uint32 // 0 = 1
}

// BuildSlots compiles sel into a slot table. Target slot counts are
// proportional to weights (largest-remainder rounding; ties broken by
// position in sel, earlier first; every selected peer gets >= 1 slot
// as long as len(sel) <= Slots). When prev is non-nil, slots already
// owned by a peer that stays selected are kept, up to its new target
// count (keeping the lowest-indexed ones); only freed slots are
// reassigned, filled in ascending slot order to peers below target
// in sel order. Deterministic. An empty sel yields an all-NoPeer table.
func BuildSlots(prev *SlotTable, sel []WeightedPeer) SlotTable {
	panic("steer.BuildSlots: implemented by the steer workstream")
}

// Share counts the slots each peer ID owns in t (NoPeer excluded).
func (t SlotTable) Share() map[uint32]int {
	out := map[uint32]int{}
	for _, id := range t {
		if id != NoPeer {
			out[id]++
		}
	}
	return out
}

// Entry is one steered prefix in datapath form.
type Entry struct {
	PrefixLen uint32
	Addr      uint32 // wire representation, see WireAddr
	Slots     SlotTable
}

// Key returns the entry's steering-map key.
func (e Entry) Key() SteeringKey { return SteeringKey{PrefixLen: e.PrefixLen, Addr: e.Addr} }

// Prefix returns the entry's prefix as a net.IPNet.
func (e Entry) Prefix() *net.IPNet {
	return &net.IPNet{
		IP:   WireIP(e.Addr),
		Mask: net.CIDRMask(int(e.PrefixLen), 32),
	}
}

// KeyOf returns the steering key of a CIDR prefix.
func KeyOf(prefix *net.IPNet) SteeringKey {
	ones, _ := prefix.Mask.Size()
	return SteeringKey{PrefixLen: uint32(ones), Addr: WireAddr(prefix.IP)}
}

// ToWeighted resolves an API selection (peer names) to datapath IDs.
func ToWeighted(sel []api.PeerWeight, ids map[string]uint32) ([]WeightedPeer, error) {
	panic("steer.ToWeighted: implemented by the steer workstream")
}

// EntriesFromSpec compiles every prefix's EffectiveSelection into an
// Entry. ids maps peer name -> datapath ID. prev (may be nil) holds
// the currently programmed tables by key; it is passed to BuildSlots
// so an in-place re-apply moves as few slots as possible.
func EntriesFromSpec(prefixes []api.PrefixSpec, ids map[string]uint32, prev map[SteeringKey]SlotTable) ([]Entry, error) {
	panic("steer.EntriesFromSpec: implemented by the steer workstream")
}

// WireAddr returns an IPv4 address in the u32 representation the
// BPF programs use. The programs copy iphdr fields verbatim with
// bpf_skb_load_bytes, so the in-memory bytes of the u32 are the
// packet bytes in order; map keys are compared as byte strings, so
// Go must produce a value whose in-memory bytes are also the packet
// bytes in order. On the little-endian hosts wgmux targets that is
// binary.LittleEndian — binary.BigEndian here byte-swaps every key
// and no steering lookup ever hits (found by the containerlab e2e).
func WireAddr(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

// WireIP is the inverse of WireAddr.
func WireIP(w uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], w)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// FlowKey mirrors struct flow_key in bpf/mux.c. Addresses and ports are in
// the wire representation (see WireAddr): their in-memory bytes are
// exactly the packet bytes, as bpf_skb_load_bytes leaves them.
type FlowKey struct {
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
}

// Reverse returns the key of the flow travelling in the opposite
// direction (what the return path pins the original flow under).
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{
		SAddr: k.DAddr,
		DAddr: k.SAddr,
		SPort: k.DPort,
		DPort: k.SPort,
		Proto: k.Proto,
	}
}

// Hash is an exact transcription of flow_hash() in bpf/mux.c, so the
// control plane predicts the same candidate the datapath picks.
// Field values must be in the same representation the BPF program
// loads from the packet (addresses/ports as they appear in memory
// after bpf_skb_load_bytes on a little-endian host).
func Hash(k FlowKey) uint32 {
	h := uint32(0x9e3779b9)
	h ^= k.SAddr
	h *= 0x85ebca6b
	h ^= h >> 13
	h ^= k.DAddr
	h *= 0xc2b2ae35
	h ^= h >> 16
	h ^= uint32(k.SPort)<<16 | uint32(k.DPort)
	h *= 0x85ebca6b
	h ^= h >> 13
	h ^= uint32(k.Proto)
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// Pick returns the peer ID the datapath would choose for a flow that
// has no (valid) pinned flow entry: Slots[Hash(k) & (Slots-1)].
func (e Entry) Pick(k FlowKey) uint32 {
	return e.Slots[Hash(k)&(Slots-1)]
}

// Table is the Go evaluation of a set of steering entries: a
// longest-prefix-match lookup plus runtime slot changes. The kernel
// engine programs the same entries into the BPF LPM trie instead.
type Table struct {
	mu      sync.RWMutex
	entries []Entry // sorted by PrefixLen, longest first
	nets    []*net.IPNet
}

// NewTable builds a Table from entries (any order).
func NewTable(entries []Entry) *Table {
	panic("steer.NewTable: implemented by the steer workstream")
}

// Lookup returns the entry governing dst (longest prefix match).
func (t *Table) Lookup(dst net.IP) (Entry, bool) {
	panic("steer.Table.Lookup: implemented by the steer workstream")
}

// SetSlots replaces one existing prefix's slot table; error if the
// prefix is not in the table.
func (t *Table) SetSlots(key SteeringKey, slots SlotTable) error {
	panic("steer.Table.SetSlots: implemented by the steer workstream")
}

// Replace swaps the whole entry set atomically (in-place re-apply).
func (t *Table) Replace(entries []Entry) {
	panic("steer.Table.Replace: implemented by the steer workstream")
}

// Entries returns a snapshot of the current entries.
func (t *Table) Entries() []Entry {
	panic("steer.Table.Entries: implemented by the steer workstream")
}
