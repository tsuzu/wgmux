package steer

import (
	"net"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
)

func mustEntries(t *testing.T, specs []api.PrefixSpec) []Entry {
	t.Helper()
	es, err := EntriesFromSpec(specs)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestTableLongestPrefixMatch(t *testing.T) {
	tab := NewTable(mustEntries(t, []api.PrefixSpec{
		{CIDR: "10.0.0.0/8", CandidateIDs: []uint32{1}, ActiveID: 1, Policy: "active"},
		{CIDR: "10.20.0.0/16", CandidateIDs: []uint32{2}, ActiveID: 2, Policy: "active"},
		{CIDR: "10.20.0.10/32", CandidateIDs: []uint32{3, 4}, ActiveID: 3, Policy: "active"},
	}))
	cases := []struct {
		dst  string
		want uint32 // governing entry's active peer; 0 = no match
	}{
		{"10.20.0.10", 3},  // /32 wins over /16 and /8
		{"10.20.0.11", 2},  // /16 wins over /8
		{"10.30.0.1", 1},   // only /8
		{"192.168.0.1", 0}, // nothing
	}
	for _, c := range cases {
		e, ok := tab.Lookup(net.ParseIP(c.dst))
		if c.want == 0 {
			if ok {
				t.Errorf("Lookup(%s) matched %v, want no match", c.dst, e.Prefix())
			}
			continue
		}
		if !ok {
			t.Errorf("Lookup(%s) no match, want active peer %d", c.dst, c.want)
			continue
		}
		if got := e.ActivePeer(); got != c.want {
			t.Errorf("Lookup(%s) active peer = %d, want %d", c.dst, got, c.want)
		}
	}
}

// The userspace pump must select exactly what the BPF datapath
// would: for a fresh flow, Lookup(dst) + Entry.Pick(flowkey).
func TestTablePickParity(t *testing.T) {
	es := mustEntries(t, []api.PrefixSpec{
		{CIDR: "10.20.0.10/32", CandidateIDs: []uint32{11, 22, 33}, ActiveID: 22, Policy: "hash"},
		{CIDR: "10.20.0.0/24", CandidateIDs: []uint32{44, 55}, ActiveID: 55, Policy: "active"},
	})
	tab := NewTable(es)
	byPrefix := map[string]Entry{}
	for _, e := range es {
		byPrefix[e.Prefix().String()] = e
	}
	flows := []FlowKey{
		{SAddr: 0x0200c60a, DAddr: 0x0a00140a, SPort: 0x3930, DPort: 0x5000, Proto: 6},
		{SAddr: 0x0200c60a, DAddr: 0x0a00140a, SPort: 0x3a30, DPort: 0x5000, Proto: 6},
		{SAddr: 0x0200c60a, DAddr: 0x0a00140a, SPort: 0x1111, DPort: 0x0035, Proto: 17},
		{SAddr: 0x0200c60a, DAddr: 0x0a00140a, SPort: 0, DPort: 0, Proto: 1},
		{SAddr: 0x0200c60a, DAddr: 0x6300140a, SPort: 0x3930, DPort: 0x5000, Proto: 6}, // 10.20.0.99: /24 active
	}
	for _, fk := range flows {
		dst := WireIP(fk.DAddr)
		got, ok := tab.Lookup(dst)
		if !ok {
			t.Fatalf("no entry for %s", dst)
		}
		want := byPrefix[got.Prefix().String()]
		if gi, wi := got.Pick(fk), want.Pick(fk); gi != wi {
			t.Errorf("flow %+v: table pick %d != entry pick %d", fk, gi, wi)
		}
		if got.PeerIDs[got.Pick(fk)] == 0 {
			t.Errorf("flow %+v: picked empty candidate", fk)
		}
	}
	// Hash entries ignore Active; active entries always pick Active.
	hashE := byPrefix["10.20.0.10/32"]
	if hashE.ActivePeer() != 22 {
		t.Errorf("hash entry ActivePeer = %d, want 22 (spec sanity)", hashE.ActivePeer())
	}
	actE := byPrefix["10.20.0.0/24"]
	for _, fk := range flows {
		if idx := actE.Pick(fk); actE.PeerIDs[idx] != 55 {
			t.Errorf("active entry picked peer %d, want 55", actE.PeerIDs[idx])
		}
	}
}

func TestTableSetActive(t *testing.T) {
	tab := NewTable(mustEntries(t, []api.PrefixSpec{
		{CIDR: "10.20.0.10/32", CandidateIDs: []uint32{1, 2}, ActiveID: 1, Policy: "active"},
	}))
	_, pfx, _ := net.ParseCIDR("10.20.0.10/32")
	if err := tab.SetActive(pfx, 2); err != nil {
		t.Fatal(err)
	}
	e, _ := tab.Lookup(net.ParseIP("10.20.0.10"))
	if e.ActivePeer() != 2 {
		t.Errorf("after SetActive, active = %d, want 2", e.ActivePeer())
	}
	if err := tab.SetActive(pfx, 99); err == nil {
		t.Error("SetActive to non-candidate peer accepted")
	}
	_, other, _ := net.ParseCIDR("10.99.0.0/24")
	if err := tab.SetActive(other, 1); err == nil {
		t.Error("SetActive on unknown prefix accepted")
	}
}

func TestFlowKeyReverse(t *testing.T) {
	k := FlowKey{SAddr: 1, DAddr: 2, SPort: 3, DPort: 4, Proto: 6}
	r := k.Reverse()
	if r != (FlowKey{SAddr: 2, DAddr: 1, SPort: 4, DPort: 3, Proto: 6}) {
		t.Errorf("Reverse = %+v", r)
	}
	if k.Reverse().Reverse() != k {
		t.Error("Reverse is not an involution")
	}
}
