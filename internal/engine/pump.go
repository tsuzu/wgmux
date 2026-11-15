package engine

import (
	"container/list"
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

// flowVal is a flow pin: the peer that carries the flow and the
// peer's generation when the pin was made (flow_peer in the BPF
// datapath). The pin is honored only while the peer exists and its
// current generation still equals Gen.
type flowVal struct {
	peer uint32
	gen  uint32
}

// flowTable pins flows to the peer that carried them, mirroring the
// BPF flow_peer LRU hash (65536 entries): least-recently-used
// eviction, bounded. It is sharded by flow hash so the pump's
// readers (front loop, one writer goroutine per peer) rarely
// contend; each shard is an independent LRU of cap/shards entries.
type flowTable struct {
	shards []*flowShard
}

type flowShard struct {
	mu  sync.Mutex
	m   map[steer.FlowKey]*list.Element
	lru *list.List // front = most recently used
	cap int
}

type flowEnt struct {
	k steer.FlowKey
	v flowVal
}

func newFlowTable(capacity int) *flowTable {
	n := 1
	if capacity >= 1024 {
		n = 16
	}
	per := capacity / n
	if per < 1 {
		per = 1
	}
	f := &flowTable{shards: make([]*flowShard, n)}
	for i := range f.shards {
		f.shards[i] = &flowShard{m: make(map[steer.FlowKey]*list.Element), lru: list.New(), cap: per}
	}
	return f
}

func (f *flowTable) shard(k steer.FlowKey) *flowShard {
	return f.shards[int(steer.Hash(k)>>8)%len(f.shards)]
}

// get returns the pin for k and marks it recently used.
func (f *flowTable) get(k steer.FlowKey) (flowVal, bool) {
	s := f.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.m[k]
	if !ok {
		return flowVal{}, false
	}
	s.lru.MoveToFront(el)
	return el.Value.(*flowEnt).v, true
}

// put pins k to v, evicting the least recently used entry when full.
func (f *flowTable) put(k steer.FlowKey, v flowVal) {
	s := f.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[k]; ok {
		el.Value.(*flowEnt).v = v
		s.lru.MoveToFront(el)
		return
	}
	s.m[k] = s.lru.PushFront(&flowEnt{k: k, v: v})
	for s.lru.Len() > s.cap {
		old := s.lru.Back()
		s.lru.Remove(old)
		delete(s.m, old.Value.(*flowEnt).k)
	}
}

func (f *flowTable) len() int {
	n := 0
	for _, s := range f.shards {
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// pumpCounters are the userspace datapath's observability counters,
// reported under the same names as the kernel engine's BPF debug
// counters where they correspond (see api.State).
type pumpCounters struct {
	frontEntries   atomic.Uint64
	frontRedirects atomic.Uint64
	frontUnsteered atomic.Uint64
	frontNoPeer    atomic.Uint64
	frontPinHits   atomic.Uint64
	frontPinStale  atomic.Uint64
	frontDrops     atomic.Uint64 // queue full / closed (userspace only)
	wgEntries      atomic.Uint64
	wgRedirects    atomic.Uint64
	wgDrops        atomic.Uint64 // front TUN write failed (userspace only)
}

func (c *pumpCounters) snapshot() map[string]uint64 {
	return map[string]uint64{
		"front_entries":   c.frontEntries.Load(),
		"front_redirects": c.frontRedirects.Load(),
		"front_unsteered": c.frontUnsteered.Load(),
		"front_no_peer":   c.frontNoPeer.Load(),
		"front_pin_hits":  c.frontPinHits.Load(),
		"front_pin_stale": c.frontPinStale.Load(),
		"front_drops":     c.frontDrops.Load(),
		"wg_entries":      c.wgEntries.Load(),
		"wg_redirects":    c.wgRedirects.Load(),
		"wg_drops":        c.wgDrops.Load(),
	}
}
