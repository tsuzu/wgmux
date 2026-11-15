package engine

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/steer"
)

func makePkt(src, dst string, proto byte, sport, dport uint16, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	if proto == 6 || proto == 17 {
		pkt = append(pkt[:20], make([]byte, 4)...)
		pkt = append(pkt, make([]byte, len(payload))...)
		binary.BigEndian.PutUint16(pkt[20:22], sport)
		binary.BigEndian.PutUint16(pkt[22:24], dport)
		copy(pkt[24:], payload)
	} else {
		copy(pkt[20:], payload)
	}
	return pkt
}

func TestChanTUNContract(t *testing.T) {
	vt := newChanTUN("test", 1420)
	if vt.File() != nil {
		t.Error("File() must be nil for an in-memory TUN")
	}
	if mtu, _ := vt.MTU(); mtu != 1420 {
		t.Errorf("MTU = %d", mtu)
	}
	select {
	case ev := <-vt.Events():
		if ev != 1 { // tun.EventUp
			t.Errorf("first event = %v, want EventUp", ev)
		}
	default:
		t.Error("no EventUp queued at construction")
	}

	if !vt.enqueue([]byte("hello")) {
		t.Fatal("enqueue failed")
	}
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := vt.Read(bufs, sizes, 0)
	if err != nil || n != 1 || sizes[0] != 5 || string(bufs[0][:5]) != "hello" {
		t.Fatalf("Read = %d, %v, sizes %v", n, err, sizes)
	}

	var got []byte
	vt.onWrite = func(pkt []byte) { got = pkt }
	if _, err := vt.Write([][]byte{[]byte("world")}, 0); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Errorf("Write delivered %q", got)
	}

	done := make(chan error, 1)
	go func() {
		_, err := vt.Read(bufs, sizes, 0)
		done <- err
	}()
	vt.Close()
	select {
	case err := <-done:
		if err != os.ErrClosed {
			t.Errorf("blocked Read after Close: err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	if vt.enqueue([]byte("x")) {
		t.Error("enqueue after Close succeeded")
	}
}


// testRig wires a userspaceMux's pump pieces by hand (Apply itself
// needs a real TUN device and netlink, which unit tests cannot
// create). The mux's lock-protected fields are populated the way
// Apply does, so SetSelection / FlushPeer / State / the in-place
// apply run for real; only the wireguard devices (dev == nil) are
// absent.
type testRig struct {
	m      *userspaceMux
	peers  map[uint32]*userspacePeer
	front  *chanTUN
	frontW [][]byte // packets written to the front TUN
}

var rigPeers = []api.PeerSpec{{Name: "a", ID: 1}, {Name: "b", ID: 2}, {Name: "c", ID: 3}}

func rigSpec() api.ApplySpec {
	return api.ApplySpec{
		Front: api.FrontSpec{Name: "test", Address: "10.200.0.1/24", MTU: 1420},
		Peers: rigPeers,
		Prefixes: []api.PrefixSpec{
			{CIDR: "10.20.0.0/24", Candidates: []string{"a", "b", "c"}, Mode: api.ModeECMP, Policy: api.PolicyFailover},
			{CIDR: "10.30.0.0/24", Candidates: []string{"a", "b"}},
		},
	}
}

func newTestRig(t *testing.T) *testRig {
	t.Helper()
	spec := rigSpec()
	entries, err := steer.EntriesFromSpec(spec.Prefixes, PeerIDs(spec), nil)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := selectionsOf(spec)
	if err != nil {
		t.Fatal(err)
	}
	r := &testRig{
		m:     &userspaceMux{name: "test"},
		peers: map[uint32]*userspacePeer{},
		front: newChanTUN("front", 1420),
	}
	r.front.onWrite = func(pkt []byte) { r.frontW = append(r.frontW, pkt) }
	r.m.spec = &spec
	r.m.table = steer.NewTable(entries)
	r.m.flows = newFlowTable(65536)
	r.m.sel = sel
	r.m.byName = map[string]*userspacePeer{}
	r.m.peers = r.peers
	for _, ps := range spec.Peers {
		p := &userspacePeer{id: ps.ID, spec: ps, vt: newChanTUN("peer-"+ps.Name, 1420)}
		peer := p
		p.vt.onWrite = func(pkt []byte) { r.m.fromPeer(r.front, r.m.flows, peer, pkt) }
		r.peers[ps.ID] = p
		r.m.byName[ps.Name] = p
	}
	return r
}

func (r *testRig) queued(peerID uint32) int { return len(r.peers[peerID].vt.in) }

// send forwards one TCP packet from the front toward dst and
// returns the peer ID that queued it (0 = dropped), draining the
// queue.
func (r *testRig) send(dst string, sport uint16) uint32 {
	pkt := makePkt("10.200.0.2", dst, 6, sport, 8080, "x")
	r.m.forwardFromFront(pkt, r.peers, r.m.table, r.m.flows)
	for id, p := range r.peers {
		select {
		case <-p.vt.in:
			return id
		default:
		}
	}
	return 0
}

func (r *testRig) counter(name string) uint64 { return r.m.counters.snapshot()[name] }

func prefixNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPumpECMPDistribution(t *testing.T) {
	r := newTestRig(t)
	const flows = 3000
	got := map[uint32]int{}
	first := map[uint16]uint32{}
	for port := uint16(1); port <= flows; port++ {
		id := r.send("10.20.0.10", port)
		if id == 0 {
			t.Fatalf("flow %d dropped", port)
		}
		got[id]++
		first[port] = id
	}
	for id := uint32(1); id <= 3; id++ {
		if got[id] < 800 || got[id] > 1200 {
			t.Errorf("peer %d carried %d/%d flows: %v", id, got[id], flows, got)
		}
	}
	if r.counter("front_redirects") != flows || r.counter("front_entries") != flows {
		t.Errorf("counters = %v", r.m.counters.snapshot())
	}
	if r.counter("front_pin_hits") != 0 {
		t.Errorf("pin hits on fresh flows: %d", r.counter("front_pin_hits"))
	}
	// Second packets of each flow hit their pins and go to the same peer.
	for port := uint16(1); port <= flows; port++ {
		if id := r.send("10.20.0.10", port); id != first[port] {
			t.Fatalf("flow %d moved %d -> %d", port, first[port], id)
		}
	}
	if r.counter("front_pin_hits") != flows {
		t.Errorf("pin hits = %d, want %d", r.counter("front_pin_hits"), flows)
	}
	// The single-mode prefix sends everything to its first candidate.
	for port := uint16(1); port <= 50; port++ {
		if id := r.send("10.30.0.1", port); id != 1 {
			t.Fatalf("single prefix flow went to %d, want 1", id)
		}
	}
}

func TestPumpWeightedDistribution(t *testing.T) {
	r := newTestRig(t)
	if err := r.m.SetSelection(prefixNet(t, "10.20.0.0/24"), []api.PeerWeight{{Peer: "a", Weight: 3}, {Peer: "b", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	got := map[uint32]int{}
	for port := uint16(1); port <= 4000; port++ {
		got[r.send("10.20.0.10", port)]++
	}
	if got[3] != 0 || got[0] != 0 {
		t.Errorf("unselected peer / drops: %v", got)
	}
	if got[1] < 2700 || got[1] > 3300 {
		t.Errorf("3:1 weighting gave a=%d b=%d", got[1], got[2])
	}
}

func TestPumpDropsAndCounters(t *testing.T) {
	r := newTestRig(t)
	if id := r.send("10.99.0.1", 1); id != 0 || r.counter("front_unsteered") != 1 {
		t.Errorf("no-LPM: id=%d unsteered=%d", id, r.counter("front_unsteered"))
	}
	r.m.forwardFromFront([]byte{1, 2, 3}, r.peers, r.m.table, r.m.flows)
	if r.counter("front_unsteered") != 2 {
		t.Errorf("unparseable not counted unsteered: %d", r.counter("front_unsteered"))
	}
	// A slot naming a peer that does not exist -> front_no_peer.
	r.m.table.Replace([]steer.Entry{{PrefixLen: 24, Addr: steer.WireAddr(net.ParseIP("10.20.0.0")), Slots: steer.BuildSlots(nil, []steer.WeightedPeer{{ID: 99}})}})
	if id := r.send("10.20.0.10", 1); id != 0 || r.counter("front_no_peer") != 1 {
		t.Errorf("unknown peer: id=%d no_peer=%d", id, r.counter("front_no_peer"))
	}
	// A full peer queue counts as a drop.
	r.m.table.Replace([]steer.Entry{{PrefixLen: 24, Addr: steer.WireAddr(net.ParseIP("10.20.0.0")), Slots: steer.BuildSlots(nil, []steer.WeightedPeer{{ID: 1}})}})
	for i := 0; i < 200; i++ {
		pkt := makePkt("10.200.0.2", "10.20.0.10", 6, uint16(5000+i), 80, "x")
		r.m.forwardFromFront(pkt, r.peers, r.m.table, r.m.flows)
	}
	if r.counter("front_drops") != 200-128 {
		t.Errorf("front_drops = %d, want %d", r.counter("front_drops"), 200-128)
	}
}

func TestPinsSurviveSetSelection(t *testing.T) {
	r := newTestRig(t)
	cidr := prefixNet(t, "10.20.0.0/24")
	first := map[uint16]uint32{}
	for port := uint16(1); port <= 300; port++ {
		first[port] = r.send("10.20.0.10", port)
	}
	if err := r.m.SetSelection(cidr, []api.PeerWeight{{Peer: "a"}}); err != nil {
		t.Fatal(err)
	}
	for port := uint16(1); port <= 300; port++ {
		if id := r.send("10.20.0.10", port); id != first[port] {
			t.Fatalf("pinned flow %d moved %d -> %d by SetSelection", port, first[port], id)
		}
	}
	for port := uint16(1000); port < 1200; port++ {
		if id := r.send("10.20.0.10", port); id != 1 {
			t.Fatalf("new flow %d went to %d, want 1", port, id)
		}
	}
	if err := r.m.SetSelection(prefixNet(t, "10.77.0.0/24"), []api.PeerWeight{{Peer: "a"}}); err == nil {
		t.Error("SetSelection on unsteered prefix accepted")
	}
	if err := r.m.SetSelection(cidr, []api.PeerWeight{{Peer: "nobody"}}); err == nil {
		t.Error("SetSelection with unknown peer accepted")
	}
}

func TestFlushPeerResteersPinnedFlows(t *testing.T) {
	r := newTestRig(t)
	cidr := prefixNet(t, "10.20.0.0/24")
	first := map[uint16]uint32{}
	onB := 0
	for port := uint16(1); port <= 600; port++ {
		first[port] = r.send("10.20.0.10", port)
		if first[port] == 2 {
			onB++
		}
	}
	if onB == 0 {
		t.Fatal("no flow on peer b")
	}
	// Failover shape: drop b from the selection, then flush it.
	if err := r.m.SetSelection(cidr, []api.PeerWeight{{Peer: "a"}, {Peer: "c"}}); err != nil {
		t.Fatal(err)
	}
	// Before the flush b's flows stay (graceful).
	for port := uint16(1); port <= 600; port++ {
		if id := r.send("10.20.0.10", port); id != first[port] {
			t.Fatalf("flow %d moved before flush", port)
		}
	}
	if err := r.m.FlushPeer("b"); err != nil {
		t.Fatal(err)
	}
	staleBefore := r.counter("front_pin_stale")
	for port := uint16(1); port <= 600; port++ {
		id := r.send("10.20.0.10", port)
		if first[port] == 2 {
			if id != 1 && id != 3 {
				t.Fatalf("flow %d still on %d after flush", port, id)
			}
		} else if id != first[port] {
			t.Fatalf("flow %d of peer %d moved to %d by flushing b", port, first[port], id)
		}
	}
	if got := r.counter("front_pin_stale") - staleBefore; got != uint64(onB) {
		t.Errorf("front_pin_stale = %d, want %d", got, onB)
	}
	// Re-pinned with the new generation: the next packets hit.
	hits := r.counter("front_pin_hits")
	for port := uint16(1); port <= 600; port++ {
		r.send("10.20.0.10", port)
	}
	if r.counter("front_pin_hits")-hits != 600 {
		t.Errorf("re-pinned flows did not hit")
	}
	if err := r.m.FlushPeer("zzz"); err == nil {
		t.Error("FlushPeer(unknown) accepted")
	}
}

func TestFlushPeerStillSelectedKeepsSteeringByTable(t *testing.T) {
	// Flushing a peer that is still selected invalidates its pins,
	// but a re-steered flow hashes to the same slot, i.e. the same
	// peer: the pin is merely refreshed.
	r := newTestRig(t)
	id := r.send("10.20.0.10", 7)
	if err := r.m.FlushPeer(r.m.spec.Peers[id-1].Name); err != nil {
		t.Fatal(err)
	}
	if got := r.send("10.20.0.10", 7); got != id {
		t.Errorf("flow moved %d -> %d", id, got)
	}
	if r.counter("front_pin_stale") != 1 {
		t.Errorf("pin_stale = %d", r.counter("front_pin_stale"))
	}
}

func TestReversePinsUseCurrentGeneration(t *testing.T) {
	r := newTestRig(t)
	// A reply arrives from peer b (e.g. the remote initiated the
	// flow): it reaches the front and pins the reverse flow to b
	// regardless of what the steering table would choose.
	reverseFrom := func(port uint16) {
		reply := makePkt("10.20.0.10", "10.200.0.2", 6, 8080, port, "synack")
		if _, err := r.peers[2].vt.Write([][]byte{reply}, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Find a port whose table pick is NOT b.
	var port uint16
	for p := uint16(1); ; p++ {
		fk, _ := parseFlow(makePkt("10.200.0.2", "10.20.0.10", 6, p, 8080, "x"))
		e, _ := r.m.table.Lookup(net.ParseIP("10.20.0.10"))
		if e.Pick(fk) != 2 {
			port = p
			break
		}
	}
	reverseFrom(port)
	if len(r.frontW) != 1 {
		t.Fatalf("front received %d packets", len(r.frontW))
	}
	if r.counter("wg_entries") != 1 || r.counter("wg_redirects") != 1 {
		t.Errorf("counters = %v", r.m.counters.snapshot())
	}
	if id := r.send("10.20.0.10", port); id != 2 {
		t.Fatalf("reverse-pinned flow went to %d, want 2", id)
	}
	// Flush b: the old reverse pin is stale and the flow re-steers
	// by the table (not b).
	if err := r.m.FlushPeer("b"); err != nil {
		t.Fatal(err)
	}
	if id := r.send("10.20.0.10", port); id == 2 || id == 0 {
		t.Fatalf("flow stayed on flushed b / dropped: %d", id)
	}
	// A reply arriving after the flush pins with the CURRENT gen.
	reverseFrom(port)
	hitsBefore := r.counter("front_pin_hits")
	if id := r.send("10.20.0.10", port); id != 2 {
		t.Fatalf("post-flush reverse pin went to %d, want 2", id)
	}
	if r.counter("front_pin_hits") != hitsBefore+1 {
		t.Error("post-flush reverse pin was not a valid hit")
	}
}

func TestStateReportsSelectionAndSlots(t *testing.T) {
	r := newTestRig(t)
	st, err := r.m.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.Engine != api.EngineUserspace || st.Mux != "test" || len(st.Peers) != 3 {
		t.Errorf("state header = %+v", st)
	}
	if len(st.Prefixes) != 2 {
		t.Fatalf("prefixes = %+v", st.Prefixes)
	}
	e := st.Prefixes[0]
	if e.CIDR != "10.20.0.0/24" || e.Mode != api.ModeECMP || e.Policy != api.PolicyFailover || len(e.Candidates) != 3 {
		t.Errorf("ecmp prefix state = %+v", e)
	}
	if e.Slots["a"]+e.Slots["b"]+e.Slots["c"] != steer.Slots || e.Slots["a"] != 22 {
		t.Errorf("slots = %v", e.Slots)
	}
	s := st.Prefixes[1]
	if s.Mode != api.ModeSingle || s.Policy != api.PolicyStatic || s.Slots["a"] != steer.Slots || len(s.Selection) != 1 || s.Selection[0].Peer != "a" {
		t.Errorf("single prefix state = %+v", s)
	}
	if err := r.m.SetSelection(prefixNet(t, "10.20.0.0/24"), []api.PeerWeight{{Peer: "b", Weight: 2}, {Peer: "c", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	st, _ = r.m.State()
	e = st.Prefixes[0]
	if e.Slots["b"] != 43 || e.Slots["c"] != 21 || e.Slots["a"] != 0 {
		t.Errorf("slots after SetSelection = %v", e.Slots)
	}
	if len(e.Selection) != 2 || e.Selection[0] != (api.PeerWeight{Peer: "b", Weight: 2}) {
		t.Errorf("selection = %v", e.Selection)
	}
	if st.Counters["front_entries"] != 0 {
		t.Errorf("counters = %v", st.Counters)
	}
}

func TestApplyInPlaceKeepsPinsAndMinimizesMoves(t *testing.T) {
	r := newTestRig(t)
	before := map[uint16]uint32{}
	for port := uint16(1); port <= 300; port++ {
		before[port] = r.send("10.20.0.10", port)
	}
	var slotsBefore steer.SlotTable
	e, _ := r.m.table.Lookup(net.ParseIP("10.20.0.10"))
	slotsBefore = e.Slots

	// Same peers/front; the ecmp prefix drops candidate c and a new
	// prefix appears.
	next := rigSpec()
	next.Prefixes[0].Candidates = []string{"a", "b"}
	next.Prefixes = append(next.Prefixes, api.PrefixSpec{CIDR: "10.40.0.0/24", Candidates: []string{"c"}})
	if err := r.m.Apply(next); err != nil {
		t.Fatal(err)
	}
	e, _ = r.m.table.Lookup(net.ParseIP("10.20.0.10"))
	for i, id := range slotsBefore {
		if id != 3 && e.Slots[i] != id {
			t.Errorf("slot %d of staying peer moved %d -> %d", i, id, e.Slots[i])
		}
		if e.Slots[i] == 3 {
			t.Errorf("slot %d still on dropped c", i)
		}
	}
	if _, ok := r.m.table.Lookup(net.ParseIP("10.40.0.1")); !ok {
		t.Error("added prefix not steered")
	}
	// Established flows (even those on c, not flushed) keep their pin.
	for port := uint16(1); port <= 300; port++ {
		if id := r.send("10.20.0.10", port); id != before[port] {
			t.Fatalf("pinned flow %d moved %d -> %d by in-place apply", port, before[port], id)
		}
	}
	st, _ := r.m.State()
	if len(st.Prefixes) != 3 || st.Prefixes[0].Slots["c"] != 0 || len(st.Prefixes[0].Selection) != 2 {
		t.Errorf("state after in-place apply = %+v", st.Prefixes)
	}

	// An apply that moves a selection explicitly takes effect.
	next.Prefixes[0].Selection = []api.PeerWeight{{Peer: "b"}}
	if err := r.m.Apply(next); err != nil {
		t.Fatal(err)
	}
	if id := r.send("10.20.0.10", 9999); id != 2 {
		t.Errorf("new flow after selection apply went to %d, want 2", id)
	}

	// A bad prefix is rejected and leaves the table untouched.
	bad := next
	bad.Prefixes = append([]api.PrefixSpec(nil), next.Prefixes...)
	bad.Prefixes[1].CIDR = "fd00::/64"
	if err := r.m.Apply(bad); err == nil {
		t.Error("in-place apply with IPv6 prefix accepted")
	}
	if id := r.send("10.20.0.10", 10000); id != 2 {
		t.Errorf("table changed by failed apply: %d", id)
	}
}

func TestFlowTableLRU(t *testing.T) {
	f := newFlowTable(2)
	k := func(p uint16) steer.FlowKey { return steer.FlowKey{SPort: p} }
	f.put(k(1), flowVal{1, 0})
	f.put(k(2), flowVal{2, 0})
	if v, ok := f.get(k(1)); !ok || v.peer != 1 { // refresh 1
		t.Fatal("get 1")
	}
	f.put(k(3), flowVal{3, 0}) // evicts 2, the least recently used
	if _, ok := f.get(k(2)); ok {
		t.Error("LRU kept the least recently used entry")
	}
	if _, ok := f.get(k(1)); !ok {
		t.Error("recently used entry evicted")
	}
	f.put(k(1), flowVal{9, 4}) // update in place
	if v, _ := f.get(k(1)); v != (flowVal{9, 4}) {
		t.Errorf("update lost: %v", v)
	}
	if f.len() != 2 {
		t.Errorf("len = %d", f.len())
	}

	big := newFlowTable(65536)
	for i := 0; i < 200000; i++ {
		big.put(steer.FlowKey{SAddr: uint32(i), DPort: uint16(i >> 16)}, flowVal{1, 0})
	}
	if n := big.len(); n > 65536 || n < 60000 {
		t.Errorf("bounded table holds %d entries", n)
	}
}
