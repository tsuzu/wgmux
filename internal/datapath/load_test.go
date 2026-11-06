package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/tsuzu/wgmux/internal/steer"
)

const (
	tcActOK       = 0
	tcActShot     = 2
	tcActRedirect = 7
)

// TestMapLayoutSizes pins the Go map structs to the C layout in
// bpf/mux.c (pure Go, no kernel needed).
func TestMapLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SteeringKey", unsafe.Sizeof(steer.SteeringKey{}), 8},
		{"SteeringVal", unsafe.Sizeof(steer.SteeringVal{}), 4 * steer.Slots},
		{"PeerVal", unsafe.Sizeof(steer.PeerVal{}), 8},
		{"FlowKeyT", unsafe.Sizeof(steer.FlowKeyT{}), 16},
		{"FlowVal", unsafe.Sizeof(steer.FlowVal{}), 8},
		{"RuntimeCfg", unsafe.Sizeof(steer.RuntimeCfg{}), 24},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: Go size %d, C size %d", c.name, c.got, c.want)
		}
	}
	if steer.Slots != 64 {
		t.Errorf("steer.Slots = %d, want 64", steer.Slots)
	}
	if len(DebugCounterNames) != 9 {
		t.Errorf("DebugCounterNames has %d entries, want 9", len(DebugCounterNames))
	}
}

// bpfTempDir returns a fresh directory on bpffs for pinning.
func bpfTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/sys/fs/bpf", "wgmuxtest")
	if err != nil {
		t.Skipf("no writable bpffs at /sys/fs/bpf (mount -t bpf bpf /sys/fs/bpf): %v", err)
	}
	t.Cleanup(func() {
		Unpin(dir)
		os.RemoveAll(dir)
	})
	return dir
}

func needKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("WGMUX_TEST_LOAD") != "1" {
		t.Skip("set WGMUX_TEST_LOAD=1 to run against the kernel")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
}

// TestLoadCollection asks the real kernel verifier to check both
// programs and all maps. It needs privileges, so it only runs when
// WGMUX_TEST_LOAD=1 is set in the environment.
func TestLoadCollection(t *testing.T) {
	needKernel(t)
	for _, l2 := range []bool{false, true} {
		pin := bpfTempDir(t)
		spec, err := loadSpec(l2, nil)
		if err != nil {
			t.Fatal(err)
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pin},
		})
		if err != nil {
			t.Fatalf("l2=%v: verifier rejected collection: %v", l2, err)
		}
		for _, name := range []string{ProgFromFront, ProgFromWG} {
			if coll.Programs[name] == nil {
				t.Errorf("l2=%v: program %s missing", l2, name)
			}
		}
		for _, name := range []string{MapSteering, MapFlowPeer, MapPeerDev, MapRuntimeCfg, MapDebug} {
			if coll.Maps[name] == nil {
				t.Errorf("l2=%v: map %s missing", l2, name)
			}
		}
		coll.Close()
		if err := Unpin(pin); err != nil {
			t.Errorf("Unpin: %v", err)
		}
		if _, err := os.Stat(pin); !os.IsNotExist(err) {
			t.Errorf("l2=%v: pin dir not removed after Unpin (err=%v)", l2, err)
		}
	}
	// Per-peer instance: own_peer_id constant rewrite must also load.
	id := uint32(7)
	spec, err := loadSpec(true, &id)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: bpfTempDir(t)}})
	if err != nil {
		t.Fatalf("from_wg instance: %v", err)
	}
	coll.Close()
}

func wire16(p uint16) uint16 {
	return binary.LittleEndian.Uint16([]byte{byte(p >> 8), byte(p)})
}

// udpPacket builds Ethernet+IPv4+UDP (eth=true) or IPv4+UDP.
func udpPacket(eth bool, src, dst string, sport, dport uint16) []byte {
	var b []byte
	if eth {
		b = append(b, make([]byte, 12)...)
		b = append(b, 0x08, 0x00)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], net.ParseIP(src).To4())
	copy(ip[16:], net.ParseIP(dst).To4())
	b = append(b, ip...)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], 8)
	b = append(b, udp...)
	// pad: BPF_PROG_TEST_RUN needs at least ETH_HLEN of data
	for len(b) < 60 {
		b = append(b, 0)
	}
	return b
}

func allSlots(id uint32) (t steer.SlotTable) {
	for i := range t {
		t[i] = id
	}
	return
}

func TestKernelRoundTrips(t *testing.T) {
	needKernel(t)
	pin := bpfTempDir(t)

	spec, err := loadSpec(true, nil) // stack_return: veth-style
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pin},
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer coll.Close()

	prefix := &net.IPNet{IP: net.IPv4(10, 1, 0, 0), Mask: net.CIDRMask(16, 32)}
	key := steer.KeyOf(prefix)
	entry := steer.Entry{PrefixLen: key.PrefixLen, Addr: key.Addr, Slots: allSlots(1)}

	// peer 1, 2 -> ifindex 1 (lo; test-run only checks the verdict).
	info := Info{BackIfindex: 1, PeerIfindex: map[uint32]int{1: 1, 2: 1}}
	maps := map[string]*ebpf.Map{
		MapSteering: coll.Maps[MapSteering], MapFlowPeer: coll.Maps[MapFlowPeer],
		MapPeerDev: coll.Maps[MapPeerDev], MapRuntimeCfg: coll.Maps[MapRuntimeCfg],
		MapDebug: coll.Maps[MapDebug],
	}
	if err := populate(info, []steer.Entry{entry}, maps); err != nil {
		t.Fatal(err)
	}

	// --- spec hash.
	if h, err := SpecHash(pin); err != nil || h != 0 {
		t.Fatalf("initial SpecHash = %d, %v; want 0", h, err)
	}
	if err := SetSpecHash(pin, 0xdeadbeefcafe1234); err != nil {
		t.Fatal(err)
	}
	if h, err := SpecHash(pin); err != nil || h != 0xdeadbeefcafe1234 {
		t.Fatalf("SpecHash = %x, %v", h, err)
	}
	// runtime_cfg other fields must survive SetSpecHash.
	var rc steer.RuntimeCfg
	if err := coll.Maps[MapRuntimeCfg].Lookup(uint32(0), &rc); err != nil || rc.BackIfindex != 1 {
		t.Fatalf("runtime_cfg after SetSpecHash: %+v, %v", rc, err)
	}

	// --- snapshot / SetSlots / ReplaceSteering.
	snap, err := SteeringSnapshot(pin)
	if err != nil || len(snap) != 1 || snap[key] != entry.Slots {
		t.Fatalf("snapshot = %v, %v", snap, err)
	}
	var mixed steer.SlotTable
	for i := range mixed {
		mixed[i] = uint32(1 + i%2)
	}
	if err := SetSlots(pin, key, mixed); err != nil {
		t.Fatal(err)
	}
	snap, _ = SteeringSnapshot(pin)
	if snap[key] != mixed {
		t.Fatal("SetSlots not visible in snapshot")
	}
	other := steer.KeyOf(&net.IPNet{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)})
	if err := SetSlots(pin, other, mixed); err == nil {
		t.Fatal("SetSlots on a missing key must fail")
	}
	e2 := steer.Entry{PrefixLen: other.PrefixLen, Addr: other.Addr, Slots: allSlots(2)}
	if err := ReplaceSteering(pin, []steer.Entry{e2}); err != nil {
		t.Fatal(err)
	}
	snap, _ = SteeringSnapshot(pin)
	if len(snap) != 1 || snap[other] != e2.Slots {
		t.Fatalf("after ReplaceSteering: %v", snap)
	}
	if err := ReplaceSteering(pin, []steer.Entry{{PrefixLen: key.PrefixLen, Addr: key.Addr, Slots: allSlots(1)}, e2}); err != nil {
		t.Fatal(err)
	}
	snap, _ = SteeringSnapshot(pin)
	if len(snap) != 2 {
		t.Fatalf("want 2 entries, got %v", snap)
	}

	// --- BumpPeerGen.
	if err := BumpPeerGen(pin, 2); err != nil {
		t.Fatal(err)
	}
	var pv steer.PeerVal
	if err := coll.Maps[MapPeerDev].Lookup(uint32(2), &pv); err != nil || pv.Gen != 1 || pv.Ifindex != 1 {
		t.Fatalf("peer_dev[2] = %+v, %v", pv, err)
	}
	if err := BumpPeerGen(pin, 2); err != nil { // keep gens distinct from peer 1's
		t.Fatal(err)
	}

	// --- datapath behaviour via BPF_PROG_TEST_RUN.
	front := coll.Programs[ProgFromFront]
	run := func(pkt []byte) uint32 {
		t.Helper()
		ret, _, err := front.Test(pkt)
		if err != nil {
			t.Fatalf("test run: %v", err)
		}
		return ret
	}
	flowA := udpPacket(true, "192.168.9.9", "10.1.2.3", 1111, 53)
	fkA := steer.FlowKeyT{
		SAddr: steer.WireAddr(net.ParseIP("192.168.9.9")), DAddr: steer.WireAddr(net.ParseIP("10.1.2.3")),
		SPort: wire16(1111), DPort: wire16(53), Proto: 17,
	}
	pinOf := func() steer.FlowVal {
		t.Helper()
		var v steer.FlowVal
		if err := coll.Maps[MapFlowPeer].Lookup(fkA, &v); err != nil {
			t.Fatalf("flow_peer lookup: %v", err)
		}
		return v
	}

	// unsteered -> OK
	if r := run(udpPacket(true, "192.168.9.9", "8.8.8.8", 1, 2)); r != tcActOK {
		t.Fatalf("unsteered: ret %d, want %d", r, tcActOK)
	}
	// Reset to a single peer-1 table for flowA, 10.1/16 => peer 1.
	if err := SetSlots(pin, key, allSlots(1)); err != nil {
		t.Fatal(err)
	}
	if r := run(flowA); r != tcActRedirect {
		t.Fatalf("steered: ret %d, want %d", r, tcActRedirect)
	}
	if v := pinOf(); v.PeerID != 1 || v.Gen != 0 {
		t.Fatalf("pin = %+v, want {1,0}", v)
	}
	// Selection change alone does not move an established flow.
	if err := SetSlots(pin, key, allSlots(2)); err != nil {
		t.Fatal(err)
	}
	if r := run(flowA); r != tcActRedirect {
		t.Fatalf("pinned: ret %d", r)
	}
	if v := pinOf(); v.PeerID != 1 {
		t.Fatalf("pin moved without flush: %+v", v)
	}
	// FlushPeer(1): pin invalid, flow re-selects through slots -> peer 2.
	if err := BumpPeerGen(pin, 1); err != nil {
		t.Fatal(err)
	}
	if r := run(flowA); r != tcActRedirect {
		t.Fatalf("after flush: ret %d", r)
	}
	if v := pinOf(); v.PeerID != 2 || v.Gen != 2 {
		t.Fatalf("pin after flush = %+v, want {2,2}", v)
	}
	// NoPeer slots: new flow dropped, established flow still redirects.
	if err := SetSlots(pin, key, steer.SlotTable{}); err != nil {
		t.Fatal(err)
	}
	if r := run(udpPacket(true, "192.168.9.9", "10.1.2.3", 2222, 53)); r != tcActShot {
		t.Fatalf("NoPeer: ret %d, want %d", r, tcActShot)
	}
	if r := run(flowA); r != tcActRedirect {
		t.Fatalf("established flow with NoPeer slots: ret %d", r)
	}
	// Flushing the pinned peer with NoPeer slots drops the flow too.
	if err := BumpPeerGen(pin, 2); err != nil {
		t.Fatal(err)
	}
	if r := run(flowA); r != tcActShot {
		t.Fatalf("stale pin + NoPeer: ret %d, want %d", r, tcActShot)
	}
	// Peer without a device -> SHOT.
	if err := SetSlots(pin, key, allSlots(9)); err != nil {
		t.Fatal(err)
	}
	if r := run(udpPacket(true, "192.168.9.9", "10.1.2.3", 3333, 53)); r != tcActShot {
		t.Fatalf("peer without device: ret %d, want %d", r, tcActShot)
	}

	c, err := Counters(pin)
	if err != nil {
		t.Fatal(err)
	}
	if c["front_unsteered"] != 1 || c["front_no_peer"] != 3 || c["front_pin_stale"] != 2 ||
		c["front_pin_hits"] != 2 || c["front_redirects"] != 4 || c["front_entries"] != 8 {
		t.Errorf("counters = %v", c)
	}

	// --- mux_from_wg pins the reversed key with {own, gen}.
	own := uint32(2)
	wspec, err := loadSpec(true, &own)
	if err != nil {
		t.Fatal(err)
	}
	wcoll, err := ebpf.NewCollectionWithOptions(wspec, ebpf.CollectionOptions{MapReplacements: maps})
	if err != nil {
		t.Fatalf("load from_wg: %v", err)
	}
	defer wcoll.Close()
	if ret, _, err := wcoll.Programs[ProgFromWG].Test(udpPacket(false, "10.1.7.7", "192.168.5.5", 5000, 6000)); err != nil || ret != tcActOK {
		t.Fatalf("from_wg: ret %d, %v", ret, err)
	}
	rev := steer.FlowKeyT{
		SAddr: steer.WireAddr(net.ParseIP("192.168.5.5")), DAddr: steer.WireAddr(net.ParseIP("10.1.7.7")),
		SPort: wire16(6000), DPort: wire16(5000), Proto: 17,
	}
	var fv steer.FlowVal
	if err := coll.Maps[MapFlowPeer].Lookup(rev, &fv); err != nil || fv.PeerID != 2 || fv.Gen != 3 {
		t.Fatalf("reverse pin = %+v, %v; want {2,3}", fv, err)
	}

	// --- Unpin removes everything including debug.
	coll.Close()
	wcoll.Close()
	if err := Unpin(pin); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		ents, _ := os.ReadDir(pin)
		t.Fatalf("pin dir still present after Unpin: %v %v", err, ents)
	}
	if _, err := os.Stat(filepath.Join(pin, MapDebug)); !os.IsNotExist(err) {
		t.Fatal("debug map left pinned")
	}
}
