package engine

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tsuzu/wgmux/internal/steer"
)

// parseFlow extracts the steering flow key from a raw IPv4 packet,
// in the same wire representation the BPF programs build theirs
// (addresses/ports as packet bytes; ports only for TCP/UDP — ICMP
// pins per host pair, exactly as in bpf/mux.c).
func parseFlow(pkt []byte) (steer.FlowKey, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return steer.FlowKey{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return steer.FlowKey{}, false
	}
	fk := steer.FlowKey{
		SAddr: steer.WireAddr(net.IP(pkt[12:16])),
		DAddr: steer.WireAddr(net.IP(pkt[16:20])),
		Proto: pkt[9],
	}
	if (fk.Proto == 6 || fk.Proto == 17) && len(pkt) >= ihl+4 {
		fk.SPort = binary.LittleEndian.Uint16(pkt[ihl : ihl+2])
		fk.DPort = binary.LittleEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return fk, true
}

// flowTable pins flows to the peer that carried them, mirroring the
// BPF flow_peer map. The kernel map is an LRU hash of 65536
// entries; this is a FIFO-evicted map of the same size — parity is
// best-effort (eviction order differs), selection of new flows is
// identical because both consult the same steering entries.
type flowTable struct {
	mu    sync.Mutex
	m     map[steer.FlowKey]uint32
	order []steer.FlowKey // insertion order, oldest first
	head  int             // index of oldest live entry in order
	cap   int
}

func newFlowTable(capacity int) *flowTable {
	return &flowTable{m: make(map[steer.FlowKey]uint32), cap: capacity}
}

func (f *flowTable) get(k steer.FlowKey) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.m[k]
	return id, ok
}

func (f *flowTable) put(k steer.FlowKey, peerID uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.m[k]; !exists {
		f.order = append(f.order, k)
	}
	f.m[k] = peerID
	// FIFO eviction: a key is queued once, at its first insertion;
	// re-insertions only update the map value.
	for len(f.m) > f.cap && f.head < len(f.order) {
		old := f.order[f.head]
		f.head++
		delete(f.m, old)
	}
	// Compact the order slice occasionally to bound memory.
	if f.head > 4096 && f.head*2 > len(f.order) {
		f.order = append([]steer.FlowKey(nil), f.order[f.head:]...)
		f.head = 0
	}
}

// pumpCounters are the userspace datapath's observability counters,
// reported under the same names as the kernel engine's BPF debug
// counters where they correspond (see api.State).
type pumpCounters struct {
	frontEntries   atomic.Uint64
	frontRedirects atomic.Uint64
	frontDrops     atomic.Uint64
	wgEntries      atomic.Uint64
	wgRedirects    atomic.Uint64
	wgDrops        atomic.Uint64
}

func (c *pumpCounters) snapshot() map[string]uint64 {
	return map[string]uint64{
		"front_entries":   c.frontEntries.Load(),
		"front_redirects": c.frontRedirects.Load(),
		"front_drops":     c.frontDrops.Load(),
		"wg_entries":      c.wgEntries.Load(),
		"wg_redirects":    c.wgRedirects.Load(),
		"wg_drops":        c.wgDrops.Load(),
	}
}
