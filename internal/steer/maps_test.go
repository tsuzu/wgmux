package steer

import (
	"testing"
	"unsafe"
)

// The BPF side (bpf/mux.c) depends on these exact sizes.
func TestMapLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SteeringKey", unsafe.Sizeof(SteeringKey{}), 8},
		{"SteeringVal", unsafe.Sizeof(SteeringVal{}), 20},
		{"FlowKeyT", unsafe.Sizeof(FlowKeyT{}), 16},
		{"RuntimeCfg", unsafe.Sizeof(RuntimeCfg{}), 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s size = %d, want %d (must match bpf/mux.c)", c.name, c.got, c.want)
		}
	}
}

func TestHashPickIsStable(t *testing.T) {
	e := Entry{Count: 3, Policy: PolicyHash}
	e.PeerIDs = [MaxCandidates]uint32{10, 20, 30}
	k := FlowKey{SAddr: 0x0200a8c0, DAddr: 0x0a14000a, SPort: 0x3039, DPort: 0x5000, Proto: 6}
	first := e.Pick(k)
	for i := 0; i < 100; i++ {
		if got := e.Pick(k); got != first {
			t.Fatalf("hash pick unstable: %d then %d", first, got)
		}
	}
	if first < 0 || first >= 3 {
		t.Fatalf("hash pick out of range: %d", first)
	}
	// Different flows should not all land on the same candidate.
	seen := map[int]bool{}
	for port := uint16(0); port < 64; port++ {
		k2 := k
		k2.SPort = port
		seen[e.Pick(k2)] = true
	}
	if len(seen) < 2 {
		t.Errorf("hash does not spread flows across candidates: %v", seen)
	}
}
