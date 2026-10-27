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
// needs a real TUN device, which unit tests cannot create).
type testRig struct {
	m     *userspaceMux
	peers map[uint32]*userspacePeer
	front *chanTUN
	table *steer.Table
	flows *flowTable
}

func newTestRig(t *testing.T, policy string) *testRig {
	t.Helper()
	entries, err := steer.EntriesFromSpec([]api.PrefixSpec{
		{CIDR: "10.20.0.10/32", CandidateIDs: []uint32{1, 2}, ActiveID: 1, Policy: policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &testRig{
		m:     &userspaceMux{name: "test"},
		peers: map[uint32]*userspacePeer{},
		front: newChanTUN("front", 1420),
		table: steer.NewTable(entries),
		flows: newFlowTable(16),
	}
	for _, id := range []uint32{1, 2} {
		vt := newChanTUN("peer", 1420)
		peerID := id
		vt.onWrite = func(pkt []byte) { r.m.fromPeer(r.front, r.flows, peerID, pkt) }
		r.peers[id] = &userspacePeer{dev: nil, vt: vt}
	}
	// The front's own "written" packets are what the stack would
	// receive; capture them via a sink chanTUN behavior: replace
	// onWrite to record into the rig.
	return r
}

func (r *testRig) queued(peerID uint32) int { return len(r.peers[peerID].vt.in) }

func TestPumpSteeringAndPinning(t *testing.T) {
	r := newTestRig(t, "active")
	pkt := makePkt("10.200.0.2", "10.20.0.10", 6, 40000, 8080, "syn")
	r.m.forwardFromFront(pkt, r.peers, r.table, r.flows)
	if r.queued(1) != 1 || r.queued(2) != 0 {
		t.Fatalf("active policy: queued p1=%d p2=%d, want 1/0", r.queued(1), r.queued(2))
	}

	// Flip the active peer: the established flow stays pinned to
	// peer 1 (as the BPF flow map guarantees), a new flow moves.
	_, pfx, _ := net.ParseCIDR("10.20.0.10/32")
	if err := r.table.SetActive(pfx, 2); err != nil {
		t.Fatal(err)
	}
	r.m.forwardFromFront(pkt, r.peers, r.table, r.flows)
	if r.queued(1) != 2 || r.queued(2) != 0 {
		t.Fatalf("pinned flow moved: p1=%d p2=%d, want 2/0", r.queued(1), r.queued(2))
	}
	newFlow := makePkt("10.200.0.2", "10.20.0.10", 6, 40001, 8080, "syn")
	r.m.forwardFromFront(newFlow, r.peers, r.table, r.flows)
	if r.queued(2) != 1 {
		t.Fatalf("new flow after flip: p2=%d, want 1", r.queued(2))
	}

	// Unsteered destination drops.
	other := makePkt("10.200.0.2", "10.99.0.1", 6, 40000, 80, "x")
	before := r.m.counters.frontDrops.Load()
	r.m.forwardFromFront(other, r.peers, r.table, r.flows)
	if r.m.counters.frontDrops.Load() != before+1 {
		t.Error("unsteered packet not counted as drop")
	}
}

func TestPumpReturnPinsReverseFlow(t *testing.T) {
	r := newTestRig(t, "active")
	// A packet arrives FROM peer 2 (e.g. peer 2 was used before a
	// flip, or the remote initiated): it must reach the front, and
	// the reverse flow must pin replies to peer 2 even though the
	// steering entry's active peer is 1.
	reply := makePkt("10.20.0.10", "10.200.0.2", 6, 8080, 40000, "syn-ack")
	var frontGot [][]byte
	r.front.onWrite = func(pkt []byte) { frontGot = append(frontGot, pkt) }
	// chanTUN.Write is what the wireguard-go device calls; emulate.
	if _, err := r.peers[2].vt.Write([][]byte{reply}, 0); err != nil {
		t.Fatal(err)
	}
	if len(frontGot) != 1 {
		t.Fatalf("front received %d packets, want 1", len(frontGot))
	}
	fwd := makePkt("10.200.0.2", "10.20.0.10", 6, 40000, 8080, "ack")
	r.m.forwardFromFront(fwd, r.peers, r.table, r.flows)
	if r.queued(2) != 1 || r.queued(1) != 0 {
		t.Fatalf("reverse-pinned flow: p1=%d p2=%d, want 0/1", r.queued(1), r.queued(2))
	}
	if got := r.m.counters.snapshot(); got["wg_entries"] != 1 || got["wg_redirects"] != 1 {
		t.Errorf("counters = %v", got)
	}
}
