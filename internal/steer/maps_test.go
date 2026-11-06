package steer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/tsuzu/wgmux/internal/api"
)

// The BPF side (bpf/mux.c) depends on these exact sizes.
func TestMapLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SteeringKey", unsafe.Sizeof(SteeringKey{}), 8},
		{"SteeringVal", unsafe.Sizeof(SteeringVal{}), 4 * Slots},
		{"FlowKeyT", unsafe.Sizeof(FlowKeyT{}), 16},
		{"FlowVal", unsafe.Sizeof(FlowVal{}), 8},
		{"PeerVal", unsafe.Sizeof(PeerVal{}), 8},
		{"RuntimeCfg", unsafe.Sizeof(RuntimeCfg{}), 24},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s size = %d, want %d (must match bpf/mux.c)", c.name, c.got, c.want)
		}
	}
}

// The steering lookup key the BPF program builds holds the packet's
// address bytes in order. The Go-written key must be byte-identical
// when marshalled little-endian: a byte-swapped key silently never
// matches (the containerlab e2e caught exactly that).
func TestSteeringKeyWireBytes(t *testing.T) {
	entries, err := EntriesFromSpec([]api.PrefixSpec{
		{CIDR: "10.20.0.10/32", Candidates: []string{"a", "b"}},
	}, map[string]uint32{"a": 1, "b": 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	key := entries[0].Key()
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[0:4], key.PrefixLen)
	binary.LittleEndian.PutUint32(buf[4:8], key.Addr)
	want := []byte{32, 0, 0, 0, 10, 20, 0, 10}
	if !bytes.Equal(buf[:], want) {
		t.Fatalf("steering key bytes = %v, want %v", buf, want)
	}
	if entries[0].MapVal().Slots != entries[0].Slots {
		t.Error("MapVal slots differ from entry slots")
	}
}
