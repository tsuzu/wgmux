// Package steer translates the declarative config into the exact values
// written to the datapath's BPF maps, and mirrors the datapath's hash
// selection so control-plane behaviour (status display, tests) matches
// what the kernel program will do.
package steer

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/tsuzu/wgmux/internal/config"
)

// Policy codes as stored in the steering map (see bpf/mux.c). The
// datapath has no "failover": the control plane implements it by
// rewriting the active index of a PolicyActive entry.
const (
	PolicyActive uint8 = 0
	PolicyHash   uint8 = 1
)

const MaxCandidates = 4

// Entry is one steering map value plus its LPM key.
type Entry struct {
	PrefixLen uint32
	Addr      uint32 // network byte order, as the LPM trie expects
	PeerIDs   [MaxCandidates]uint32
	Count     uint8
	Active    uint8
	Policy    uint8
}

// BuildEntries resolves a config into steering entries, one per prefix,
// with peer IDs in candidate order.
func BuildEntries(cfg *config.Config) ([]Entry, error) {
	entries := make([]Entry, 0, len(cfg.Prefixes))
	for _, p := range cfg.Prefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return nil, fmt.Errorf("prefix %q: %w", p.CIDR, err)
		}
		ones, _ := ipnet.Mask.Size()
		e := Entry{PrefixLen: uint32(ones)}
		e.Addr = binary.BigEndian.Uint32(ipnet.IP.To4())
		for i, name := range p.Candidates {
			peer := cfg.PeerByName(name)
			if peer == nil {
				return nil, fmt.Errorf("prefix %q: unknown candidate %q", p.CIDR, name)
			}
			e.PeerIDs[i] = uint32(peer.ID)
			if name == p.Active {
				e.Active = uint8(i)
			}
		}
		e.Count = uint8(len(p.Candidates))
		switch p.Policy {
		case config.PolicyHash:
			e.Policy = PolicyHash
		default: // active and failover both run as active in the datapath
			e.Policy = PolicyActive
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// FlowKey mirrors struct flow_key in bpf/mux.c. Addresses and ports are in
// network byte order, exactly as they appear in the packet.
type FlowKey struct {
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
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
