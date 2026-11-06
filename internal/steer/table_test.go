package steer

import (
	"net"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
)

var testIDs = map[string]uint32{"a": 1, "b": 2, "c": 3, "d": 4}

func mustEntries(t *testing.T, specs []api.PrefixSpec) []Entry {
	t.Helper()
	es, err := EntriesFromSpec(specs, testIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func single(cidr, peer string) api.PrefixSpec {
	return api.PrefixSpec{CIDR: cidr, Candidates: []string{peer}, Mode: api.ModeSingle}
}

func TestTableLongestPrefixMatch(t *testing.T) {
	tab := NewTable(mustEntries(t, []api.PrefixSpec{
		single("10.0.0.0/8", "a"),
		single("10.20.0.0/16", "b"),
		single("10.20.0.10/32", "c"),
	}))
	cases := []struct {
		dst  string
		want uint32 // governing entry's peer; 0 = no match
	}{
		{"10.20.0.10", 3},
		{"10.20.0.11", 2},
		{"10.30.0.1", 1},
		{"192.168.0.1", 0},
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
			t.Errorf("Lookup(%s) no match, want peer %d", c.dst, c.want)
			continue
		}
		if e.Slots[0] != c.want || e.Slots[Slots-1] != c.want {
			t.Errorf("Lookup(%s) slots = %v, want all %d", c.dst, e.Slots, c.want)
		}
	}
	if _, ok := tab.Lookup(net.ParseIP("::1")); ok {
		t.Error("IPv6 destination matched")
	}
}

func TestTableSetSlotsReplaceEntries(t *testing.T) {
	tab := NewTable(mustEntries(t, []api.PrefixSpec{single("10.20.0.10/32", "a")}))
	_, pfx, _ := net.ParseCIDR("10.20.0.10/32")
	ns := BuildSlots(nil, []WeightedPeer{{ID: 2}, {ID: 3}})
	if err := tab.SetSlots(KeyOf(pfx), ns); err != nil {
		t.Fatal(err)
	}
	e, _ := tab.Lookup(net.ParseIP("10.20.0.10"))
	if e.Slots != ns {
		t.Error("SetSlots not visible through Lookup")
	}
	_, other, _ := net.ParseCIDR("10.99.0.0/24")
	if err := tab.SetSlots(KeyOf(other), ns); err == nil {
		t.Error("SetSlots on unknown prefix accepted")
	}

	snap := tab.Entries()
	snap[0].Slots = SlotTable{}
	if e2, _ := tab.Lookup(net.ParseIP("10.20.0.10")); e2.Slots != ns {
		t.Error("Entries returned an aliased slice")
	}

	tab.Replace(mustEntries(t, []api.PrefixSpec{single("10.99.0.0/24", "d")}))
	if _, ok := tab.Lookup(net.ParseIP("10.20.0.10")); ok {
		t.Error("old prefix survived Replace")
	}
	if e3, ok := tab.Lookup(net.ParseIP("10.99.0.7")); !ok || e3.Slots[5] != 4 {
		t.Errorf("new prefix missing after Replace: %v %v", ok, e3)
	}
	if len(tab.Entries()) != 1 {
		t.Errorf("Entries len = %d", len(tab.Entries()))
	}
}

func TestEntriesFromSpec(t *testing.T) {
	// ecmp weighted 2:1 using explicit Selection.
	es, err := EntriesFromSpec([]api.PrefixSpec{{
		CIDR: "10.1.0.0/16", Candidates: []string{"a", "b"}, Mode: api.ModeECMP,
		Selection: []api.PeerWeight{{Peer: "a", Weight: 2}, {Peer: "b", Weight: 1}},
	}}, testIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sh := es[0].Slots.Share(); sh[1] != 43 || sh[2] != 21 {
		t.Errorf("2:1 share = %v", sh)
	}
	// Default ecmp selection: all candidates equal.
	es, _ = EntriesFromSpec([]api.PrefixSpec{{CIDR: "10.1.0.0/16", Candidates: []string{"a", "b"}, Mode: api.ModeECMP}}, testIDs, nil)
	if sh := es[0].Slots.Share(); sh[1] != 32 || sh[2] != 32 {
		t.Errorf("default ecmp share = %v", sh)
	}
	// Default single: first candidate.
	es, _ = EntriesFromSpec([]api.PrefixSpec{{CIDR: "10.1.0.0/16", Candidates: []string{"b", "a"}}}, testIDs, nil)
	if sh := es[0].Slots.Share(); sh[2] != 64 {
		t.Errorf("default single share = %v", sh)
	}

	// prev is honored: an unchanged selection keeps the table intact.
	key := es[0].Key()
	prevT := BuildSlots(nil, []WeightedPeer{{ID: 2, Weight: 1}, {ID: 1, Weight: 1}})
	es, _ = EntriesFromSpec([]api.PrefixSpec{{
		CIDR: "10.1.0.0/16", Candidates: []string{"a", "b"}, Mode: api.ModeECMP,
		Selection: []api.PeerWeight{{Peer: "a"}, {Peer: "b"}},
	}}, testIDs, map[SteeringKey]SlotTable{key: prevT})
	if es[0].Slots != prevT {
		t.Error("same selection with prev changed the table")
	}

	bad := []struct {
		name string
		spec api.PrefixSpec
	}{
		{"v6", single("fd00::/64", "a")},
		{"garbage", single("nope", "a")},
		{"unknown peer", single("10.1.0.0/16", "zzz")},
	}
	for _, b := range bad {
		if _, err := EntriesFromSpec([]api.PrefixSpec{b.spec}, testIDs, nil); err == nil {
			t.Errorf("%s: no error", b.name)
		}
	}
	if _, err := EntriesFromSpec([]api.PrefixSpec{single("10.1.0.0/16", "a"), single("10.1.0.5/16", "b")}, testIDs, nil); err == nil {
		t.Error("duplicate canonical prefix accepted")
	}
}

func TestToWeighted(t *testing.T) {
	w, err := ToWeighted([]api.PeerWeight{{Peer: "a"}, {Peer: "c", Weight: 5}}, testIDs)
	if err != nil || len(w) != 2 || w[0] != (WeightedPeer{1, 1}) || w[1] != (WeightedPeer{3, 5}) {
		t.Fatalf("ToWeighted = %v, %v", w, err)
	}
	if _, err := ToWeighted([]api.PeerWeight{{Peer: "x"}}, testIDs); err == nil {
		t.Error("unknown name accepted")
	}
}

// The userspace pump selects exactly what BPF would: Lookup(dst) +
// Entry.Pick(flowkey).
func TestPickParityAndSpread(t *testing.T) {
	es := mustEntries(t, []api.PrefixSpec{{CIDR: "10.20.0.0/24", Candidates: []string{"a", "b", "c"}, Mode: api.ModeECMP}})
	e := es[0]
	count := map[uint32]int{}
	for port := uint16(1); port <= 3000; port++ {
		k := FlowKey{SAddr: 0x0200c60a, DAddr: 0x0a00140a, SPort: port, DPort: 0x5000, Proto: 6}
		p := e.Pick(k)
		if p != e.Slots[Hash(k)&(Slots-1)] || p == NoPeer {
			t.Fatalf("pick %d inconsistent", p)
		}
		count[p]++
	}
	for id := uint32(1); id <= 3; id++ {
		if count[id] < 700 || count[id] > 1300 {
			t.Errorf("peer %d got %d/3000 flows, spread too skewed: %v", id, count[id], count)
		}
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
