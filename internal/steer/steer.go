// Package steer holds the steering model shared by every datapath
// realization: the entries that say which peers may carry a prefix
// and how one is picked, plus the flow hash the kernel programs use.
// The kernel engine programs these entries into BPF maps; the
// userspace engine evaluates the same entries in Go (Table). Because
// both use Entry/Pick/Hash, a prefix selects the same peer either
// way.
package steer

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/tsuzu/wgmux/internal/api"
)

// Policy codes as stored in the steering map (see bpf/mux.c) and in
// Entry.Policy. The datapaths have no "failover": the control plane
// implements it by rewriting the active index of a PolicyActive entry.
const (
	PolicyActive uint8 = 0
	PolicyHash   uint8 = 1
)

const MaxCandidates = 4

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

// Entry is one steering decision: the candidates for a prefix, which
// one is active, and the selection policy.
type Entry struct {
	PrefixLen uint32
	Addr      uint32 // wire representation, see WireAddr
	PeerIDs   [MaxCandidates]uint32
	Count     uint8
	Active    uint8
	Policy    uint8
}

// Prefix returns the entry's prefix as a net.IPNet.
func (e Entry) Prefix() *net.IPNet {
	return &net.IPNet{
		IP:   WireIP(e.Addr),
		Mask: net.CIDRMask(int(e.PrefixLen), 32),
	}
}

// ActivePeer returns the currently selected peer ID for
// policy=active entries.
func (e Entry) ActivePeer() uint32 {
	if int(e.Active) < int(e.Count) {
		return e.PeerIDs[e.Active]
	}
	return e.PeerIDs[0]
}

// EntriesFromSpec resolves control-plane prefix specs into steering
// entries. Decision policies arrive already normalised: "hash" runs
// the hash policy, everything else ("active", and the control-plane
// policies failover/bgp that drive SetActive) runs as active.
func EntriesFromSpec(prefixes []api.PrefixSpec) ([]Entry, error) {
	out := make([]Entry, 0, len(prefixes))
	for _, p := range prefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return nil, fmt.Errorf("prefix %s: %w", p.CIDR, err)
		}
		ones, _ := ipnet.Mask.Size()
		e := Entry{PrefixLen: uint32(ones), Addr: WireAddr(ipnet.IP)}
		for i, id := range p.CandidateIDs {
			if i >= MaxCandidates {
				return nil, fmt.Errorf("prefix %s: too many candidates", p.CIDR)
			}
			e.PeerIDs[i] = id
			if id == p.ActiveID {
				e.Active = uint8(i)
			}
		}
		e.Count = uint8(len(p.CandidateIDs))
		if p.Policy == "hash" {
			e.Policy = PolicyHash
		}
		out = append(out, e)
	}
	return out, nil
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

// Pick returns the candidate index the datapath would choose for a flow
// that has no pinned flow entry yet.
func (e Entry) Pick(k FlowKey) int {
	if e.Count == 0 {
		return -1
	}
	if e.Policy == PolicyHash {
		return int(Hash(k) % uint32(e.Count))
	}
	if int(e.Active) < int(e.Count) {
		return int(e.Active)
	}
	return 0
}

// Table is the Go evaluation of a set of steering entries: a
// longest-prefix-match lookup plus runtime activation changes. The
// kernel engine programs the same entries into the BPF LPM trie
// instead; both share Entry/Pick so selection semantics agree.
type Table struct {
	mu      sync.RWMutex
	entries []Entry // sorted by PrefixLen, longest first
	nets    []*net.IPNet
}

// NewTable builds a Table from entries (any order).
func NewTable(entries []Entry) *Table {
	es := make([]Entry, len(entries))
	copy(es, entries)
	sort.SliceStable(es, func(i, j int) bool { return es[i].PrefixLen > es[j].PrefixLen })
	t := &Table{entries: es}
	for _, e := range es {
		t.nets = append(t.nets, e.Prefix())
	}
	return t
}

// Lookup returns the entry governing dst (longest prefix match).
func (t *Table) Lookup(dst net.IP) (Entry, bool) {
	dst4 := dst.To4()
	if dst4 == nil {
		return Entry{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for i, n := range t.nets {
		if n.Contains(dst4) {
			return t.entries[i], true
		}
	}
	return Entry{}, false
}

// SetActive flips the active candidate of one prefix to peerID,
// mirroring datapath.SetActive's semantics and errors.
func (t *Table) SetActive(prefix *net.IPNet, peerID uint32) error {
	ones, _ := prefix.Mask.Size()
	addr := WireAddr(prefix.IP)
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.entries {
		e := &t.entries[i]
		if e.PrefixLen != uint32(ones) || e.Addr != addr {
			continue
		}
		for j := 0; j < int(e.Count); j++ {
			if e.PeerIDs[j] == peerID {
				e.Active = uint8(j)
				return nil
			}
		}
		return fmt.Errorf("peer %d is not a candidate for prefix %s", peerID, prefix)
	}
	return fmt.Errorf("prefix %s not in steering table", prefix)
}

// Entries returns a snapshot of the current entries.
func (t *Table) Entries() []Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Entry, len(t.entries))
	copy(out, t.entries)
	return out
}
