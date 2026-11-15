package steer

import (
	"fmt"
	"testing"
)

func wp(ids ...uint32) []WeightedPeer {
	out := make([]WeightedPeer, len(ids))
	for i, id := range ids {
		out[i] = WeightedPeer{ID: id, Weight: 1}
	}
	return out
}

func moved(a, b SlotTable) int {
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}

func TestBuildSlotsEmpty(t *testing.T) {
	for _, sel := range [][]WeightedPeer{nil, {}, {{ID: NoPeer, Weight: 3}}} {
		got := BuildSlots(nil, sel)
		if got != (SlotTable{}) {
			t.Errorf("sel %v: not all NoPeer: %v", sel, got)
		}
	}
	prev := BuildSlots(nil, wp(1, 2))
	if got := BuildSlots(&prev, nil); got != (SlotTable{}) {
		t.Error("empty sel with prev not all NoPeer")
	}
}

func TestBuildSlotsSingle(t *testing.T) {
	got := BuildSlots(nil, []WeightedPeer{{ID: 7, Weight: 100}})
	for i, id := range got {
		if id != 7 {
			t.Fatalf("slot %d = %d", i, id)
		}
	}
}

func TestBuildSlotsProportional(t *testing.T) {
	cases := []struct {
		name string
		sel  []WeightedPeer
		want map[uint32]int
	}{
		{"2:1", []WeightedPeer{{1, 2}, {2, 1}}, map[uint32]int{1: 43, 2: 21}},
		{"1:2", []WeightedPeer{{1, 1}, {2, 2}}, map[uint32]int{1: 21, 2: 43}},
		{"equal 3 (tie -> earlier)", wp(1, 2, 3), map[uint32]int{1: 22, 2: 21, 3: 21}},
		{"equal 2", wp(1, 2), map[uint32]int{1: 32, 2: 32}},
		{"zero weight = 1", []WeightedPeer{{1, 0}, {2, 1}}, map[uint32]int{1: 32, 2: 32}},
		{"min one slot", []WeightedPeer{{1, 1000}, {2, 1}}, map[uint32]int{1: 63, 2: 1}},
		{"min one slot x2", []WeightedPeer{{1, 1000}, {2, 1}, {3, 1}}, map[uint32]int{1: 62, 2: 1, 3: 1}},
		{"3:1", []WeightedPeer{{1, 3}, {2, 1}}, map[uint32]int{1: 48, 2: 16}},
	}
	for _, c := range cases {
		got := BuildSlots(nil, c.sel).Share()
		total := 0
		for id, n := range got {
			total += n
			if c.want[id] != n {
				t.Errorf("%s: share %v, want %v", c.name, got, c.want)
				break
			}
		}
		if total != Slots {
			t.Errorf("%s: %d slots used", c.name, total)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: share %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildSlotsDeterministic(t *testing.T) {
	sel := []WeightedPeer{{1, 5}, {2, 3}, {3, 7}, {4, 1}}
	a := BuildSlots(nil, sel)
	prev := BuildSlots(nil, wp(1, 2))
	b1 := BuildSlots(&prev, sel)
	for i := 0; i < 20; i++ {
		if BuildSlots(nil, sel) != a {
			t.Fatal("nondeterministic without prev")
		}
		if BuildSlots(&prev, sel) != b1 {
			t.Fatal("nondeterministic with prev")
		}
	}
	// Same selection with prev == result is a fixed point.
	if again := BuildSlots(&a, sel); again != a {
		t.Error("rebuilding the same selection moved slots")
	}
}

func TestBuildSlotsRemoveOneOfThreeMovesOnlyItsSlots(t *testing.T) {
	prev := BuildSlots(nil, wp(1, 2, 3))
	next := BuildSlots(&prev, wp(1, 3))
	for i := range prev {
		if prev[i] != 2 && next[i] != prev[i] {
			t.Errorf("slot %d of staying peer moved %d -> %d", i, prev[i], next[i])
		}
		if next[i] == 2 {
			t.Errorf("removed peer still owns slot %d", i)
		}
	}
	if sh := next.Share(); sh[1] != 32 || sh[3] != 32 {
		t.Errorf("share after removal = %v", sh)
	}
	if m := moved(prev, next); m != 21 {
		t.Errorf("moved %d slots, want exactly the removed peer's 21", m)
	}
}

func TestBuildSlotsAddPeerMinimalMoves(t *testing.T) {
	prev := BuildSlots(nil, wp(1, 2))
	next := BuildSlots(&prev, wp(1, 2, 3))
	sh := next.Share()
	if sh[3] != 21 || sh[1]+sh[2]+sh[3] != Slots {
		t.Fatalf("share = %v", sh)
	}
	// Every changed slot went to the new peer; nobody else swapped.
	for i := range prev {
		if next[i] != prev[i] && next[i] != 3 {
			t.Errorf("slot %d moved %d -> %d, not to the new peer", i, prev[i], next[i])
		}
	}
	if moved(prev, next) != 21 {
		t.Errorf("moved %d, want 21", moved(prev, next))
	}
	// The new peer took slots from both old peers (22/21 split).
	lost1, lost2 := 32-sh[1], 32-sh[2]
	if lost1+lost2 != 21 || lost1 < 10 || lost2 < 10 {
		t.Errorf("new peer took %d from peer1, %d from peer2", lost1, lost2)
	}
}

func TestBuildSlotsWeightChangeMinimalMoves(t *testing.T) {
	prev := BuildSlots(nil, []WeightedPeer{{1, 1}, {2, 1}})
	next := BuildSlots(&prev, []WeightedPeer{{1, 3}, {2, 1}}) // 48/16
	sh := next.Share()
	if sh[1] != 48 || sh[2] != 16 {
		t.Fatalf("share = %v", sh)
	}
	if m := moved(prev, next); m != 16 {
		t.Errorf("moved %d slots, want 16", m)
	}
	for i := range prev {
		if next[i] != prev[i] && next[i] != 1 {
			t.Errorf("slot %d moved to %d", i, next[i])
		}
	}
	// peer 2 keeps its LOWEST-indexed slots.
	lastKept, firstLost := -1, Slots
	for i := range prev {
		if prev[i] != 2 {
			continue
		}
		if next[i] == 2 {
			lastKept = i
		} else if i < firstLost {
			firstLost = i
		}
	}
	if lastKept > firstLost {
		t.Errorf("peer 2 kept slot %d but lost lower slot %d", lastKept, firstLost)
	}
}

func TestBuildSlotsReplacePeerAndHoles(t *testing.T) {
	prev := BuildSlots(nil, wp(1))
	next := BuildSlots(&prev, wp(2))
	if sh := next.Share(); sh[2] != 64 {
		t.Errorf("share = %v", sh)
	}
	var holes SlotTable
	holes[3] = 1
	got := BuildSlots(&holes, wp(1, 2))
	if got[3] != 1 {
		t.Errorf("kept slot lost: %v", got)
	}
}

func TestBuildSlotsDuplicatesMerged(t *testing.T) {
	got := BuildSlots(nil, []WeightedPeer{{1, 1}, {2, 1}, {1, 2}}).Share()
	// peer 1 weight 3 vs 1 -> 48/16.
	if got[1] != 48 || got[2] != 16 {
		t.Errorf("share = %v", got)
	}
}

func TestBuildSlotsManyPeers(t *testing.T) {
	for _, n := range []int{64, 65, 200} {
		sel := make([]WeightedPeer, n)
		for i := range sel {
			sel[i] = WeightedPeer{ID: uint32(i + 1), Weight: 1}
		}
		sh := BuildSlots(nil, sel).Share()
		if len(sh) != Slots {
			t.Errorf("n=%d: %d peers realized, want %d", n, len(sh), Slots)
		}
		for id, c := range sh {
			if c != 1 {
				t.Errorf("n=%d: peer %d has %d slots", n, id, c)
			}
		}
	}
	// >64 peers: the heaviest 64 win; ties by sel order.
	var sel []WeightedPeer
	for i := 1; i <= 66; i++ {
		w := uint32(1)
		if i == 66 {
			w = 9
		}
		sel = append(sel, WeightedPeer{ID: uint32(i), Weight: w})
	}
	sh := BuildSlots(nil, sel).Share()
	if sh[66] != 1 || sh[65] != 0 || sh[64] != 0 || sh[63] != 1 {
		t.Errorf("heaviest-first selection wrong: 66=%d 65=%d 64=%d 63=%d", sh[66], sh[65], sh[64], sh[63])
	}
}

// Randomized invariants over many chained selections.
func TestBuildSlotsInvariants(t *testing.T) {
	seed := uint32(12345)
	rnd := func(n uint32) uint32 {
		seed = seed*1664525 + 1013904223
		return (seed >> 8) % n
	}
	var prev *SlotTable
	for it := 0; it < 500; it++ {
		n := int(rnd(8)) + 1
		var sel []WeightedPeer
		used := map[uint32]bool{}
		for len(sel) < n {
			id := rnd(12) + 1
			if used[id] {
				continue
			}
			used[id] = true
			sel = append(sel, WeightedPeer{ID: id, Weight: rnd(20)})
		}
		got := BuildSlots(prev, sel)
		sh := got.Share()
		total := 0
		var tw uint64
		for _, w := range sel {
			if sh[w.ID] < 1 {
				t.Fatalf("it %d: peer %d starved: %v", it, w.ID, sel)
			}
			total += sh[w.ID]
			if w.Weight == 0 {
				w.Weight = 1
			}
			tw += uint64(w.Weight)
		}
		if total != Slots {
			t.Fatalf("it %d: %d slots assigned", it, total)
		}
		for id := range sh {
			if !used[id] {
				t.Fatalf("it %d: unselected peer %d owns slots", it, id)
			}
		}
		for _, w := range sel {
			ww := w.Weight
			if ww == 0 {
				ww = 1
			}
			ideal := float64(ww) * Slots / float64(tw)
			if d := float64(sh[w.ID]) - ideal; d > 1.0001 || d < -float64(len(sel)) {
				t.Fatalf("it %d: peer %d got %d, ideal %.2f", it, w.ID, sh[w.ID], ideal)
			}
		}
		prev = &got
	}
}

func ExampleBuildSlots() {
	t := BuildSlots(nil, []WeightedPeer{{ID: 1, Weight: 2}, {ID: 2, Weight: 1}})
	fmt.Println(t.Share()[1], t.Share()[2])
	// Output: 43 21
}
