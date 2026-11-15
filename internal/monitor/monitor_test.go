package monitor

import (
	"context"
	"errors"
	"io"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

const maxAge = 150 * time.Second

// peer builds a PeerState whose handshake is `age` old (age < 0:
// never handshaked).
func peer(name string, age time.Duration) api.PeerState {
	p := api.PeerState{Name: name}
	if age >= 0 {
		p.LastHandshake = t0.Add(-age)
	}
	return p
}

func sel(pairs ...interface{}) []api.PeerWeight {
	var out []api.PeerWeight
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, api.PeerWeight{Peer: pairs[i].(string), Weight: uint32(pairs[i+1].(int))})
	}
	return out
}

func singleState(current string, peers ...api.PeerState) api.State {
	return api.State{Peers: peers, Prefixes: []api.PrefixState{{
		CIDR: "10.20.0.10/32", Candidates: []string{"a", "b", "c"}, Mode: api.ModeSingle,
		Selection: sel(current, 1),
	}}}
}

func ecmpState(current []api.PeerWeight, peers ...api.PeerState) api.State {
	return api.State{Peers: peers, Prefixes: []api.PrefixState{{
		CIDR: "10.20.0.10/32", Candidates: []string{"a", "b", "c"}, Mode: api.ModeECMP,
		Selection: current,
	}}}
}

func settings(configured []api.PeerWeight) Settings {
	return Settings{MaxAge: maxAge, Prefixes: map[string][]api.PeerWeight{"10.20.0.10/32": configured}}
}

func setActs(r Result) []Action {
	var out []Action
	for _, a := range r.Actions {
		if a.Kind == ActSetSelection {
			out = append(out, a)
		}
	}
	return out
}

func flushed(r Result) []string {
	var out []string
	for _, a := range r.Actions {
		if a.Kind == ActFlushPeer {
			out = append(out, a.Peer)
		}
	}
	return out
}

func TestSingleHealthyNoAction(t *testing.T) {
	st := singleState("a", peer("a", 10*time.Second), peer("b", 10*time.Second), peer("c", 10*time.Second))
	r := Evaluate(st, settings(nil), map[string]bool{"a": true, "b": true, "c": true}, t0)
	if len(r.Actions) != 0 {
		t.Fatalf("actions = %+v", r.Actions)
	}
}

func TestSingleFailoverToFirstHealthyThenFlush(t *testing.T) {
	st := singleState("a", peer("a", 300*time.Second), peer("b", 200*time.Second), peer("c", 5*time.Second))
	r := Evaluate(st, settings(nil), map[string]bool{"a": true, "b": true, "c": true}, t0)
	// b is stale too, so c (first HEALTHY in candidate order) wins.
	sets := setActs(r)
	if len(sets) != 1 || !reflect.DeepEqual(sets[0].Selection, sel("c", 1)) || sets[0].CIDR != "10.20.0.10/32" {
		t.Fatalf("set actions = %+v", sets)
	}
	if got := flushed(r); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("flushed = %v", got)
	}
	// Selection change is ordered before the flushes.
	if r.Actions[0].Kind != ActSetSelection {
		t.Errorf("first action = %s, want set_selection before flushes", r.Actions[0].Kind)
	}
}

func TestSingleNoPreemption(t *testing.T) {
	// a recovered but b is selected and healthy: do nothing.
	st := singleState("b", peer("a", 1*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r := Evaluate(st, settings(nil), map[string]bool{"a": false, "b": true, "c": true}, t0)
	if len(r.Actions) != 0 {
		t.Fatalf("preempted: %+v", r.Actions)
	}
	if !r.Health["a"] {
		t.Error("a should be recorded healthy again")
	}
}

func TestAllUnhealthyKeepsCurrent(t *testing.T) {
	st := singleState("a", peer("a", 400*time.Second), peer("b", -1), peer("c", 999*time.Second))
	r := Evaluate(st, settings(nil), map[string]bool{"a": true, "b": true, "c": true}, t0)
	if len(setActs(r)) != 0 {
		t.Fatalf("changed selection with nothing healthy: %+v", r.Actions)
	}
	if got := flushed(r); len(got) != 3 {
		t.Fatalf("flushed = %v (transitions still flush)", got)
	}
	// ecmp too
	st = ecmpState(sel("a", 1, "b", 1), peer("a", 400*time.Second), peer("b", 400*time.Second), peer("c", 400*time.Second))
	r = Evaluate(st, settings(sel("a", 1, "b", 1)), nil, t0)
	if len(setActs(r)) != 0 {
		t.Fatalf("ecmp changed selection with nothing healthy: %+v", r.Actions)
	}
}

func TestFlushExactlyOncePerTransition(t *testing.T) {
	set := settings(nil)
	st := singleState("a", peer("a", 400*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r1 := Evaluate(st, set, map[string]bool{"a": true, "b": true, "c": true}, t0)
	if got := flushed(r1); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("pass1 flushed = %v", got)
	}
	// Daemon applied the selection; a is still dead on the next pass.
	st = singleState("b", peer("a", 410*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r2 := Evaluate(st, set, r1.Health, t0.Add(10*time.Second))
	if len(r2.Actions) != 0 {
		t.Fatalf("pass2 actions = %+v, want none", r2.Actions)
	}
	// a recovers, then dies again: a NEW transition flushes again.
	st = singleState("b", peer("a", 1*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r3 := Evaluate(st, set, r2.Health, t0.Add(20*time.Second))
	if len(r3.Actions) != 0 || !r3.Health["a"] {
		t.Fatalf("pass3 = %+v", r3)
	}
	st = singleState("b", peer("a", 500*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r4 := Evaluate(st, set, r3.Health, t0.Add(30*time.Second))
	if got := flushed(r4); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("pass4 flushed = %v", got)
	}
}

func TestFirstObservationUnhealthyFlushes(t *testing.T) {
	// A freshly started monitor (nil prev) treats an already-dead
	// peer as a transition once: pins to it may predate the monitor.
	st := singleState("b", peer("a", 400*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	r := Evaluate(st, settings(nil), nil, t0)
	if got := flushed(r); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("flushed = %v", got)
	}
	r2 := Evaluate(st, settings(nil), r.Health, t0)
	if len(flushed(r2)) != 0 {
		t.Fatalf("second pass flushed again: %v", flushed(r2))
	}
}

func TestECMPRemovalAndReAddWithWeights(t *testing.T) {
	configured := sel("a", 3, "b", 1, "c", 2)
	set := settings(configured)
	all := []api.PeerState{peer("a", 1*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second)}

	// Everything healthy and selection matches: nothing to do.
	r := Evaluate(ecmpState(configured, all...), set, map[string]bool{"a": true, "b": true, "c": true}, t0)
	if len(r.Actions) != 0 {
		t.Fatalf("steady state actions = %+v", r.Actions)
	}

	// c dies: removed from the selection, weights of the others kept.
	down := []api.PeerState{peer("a", 1*time.Second), peer("b", 1*time.Second), peer("c", 600*time.Second)}
	r = Evaluate(ecmpState(configured, down...), set, r.Health, t0)
	sets := setActs(r)
	if len(sets) != 1 || !reflect.DeepEqual(sets[0].Selection, sel("a", 3, "b", 1)) {
		t.Fatalf("removal = %+v", r.Actions)
	}
	if got := flushed(r); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("flushed = %v", got)
	}

	// Next pass, daemon now has {a:3,b:1}; c still dead: no actions.
	reduced := sel("a", 3, "b", 1)
	r2 := Evaluate(ecmpState(reduced, down...), set, r.Health, t0)
	if len(r2.Actions) != 0 {
		t.Fatalf("pass2 = %+v", r2.Actions)
	}

	// c recovers: re-added with its CONFIGURED weight; no flush.
	r3 := Evaluate(ecmpState(reduced, all...), set, r2.Health, t0)
	sets = setActs(r3)
	if len(sets) != 1 || !reflect.DeepEqual(sets[0].Selection, sel("a", 3, "b", 1, "c", 2)) {
		t.Fatalf("re-add = %+v", r3.Actions)
	}
	if len(flushed(r3)) != 0 {
		t.Fatalf("flush on recovery: %v", flushed(r3))
	}
}

func TestECMPConfiguredSubsetAndDefaultWeights(t *testing.T) {
	// Configured only a and b; c is a candidate but not selected,
	// and must not be added just because it is healthy.
	set := settings(sel("a", 1, "b", 1))
	all := []api.PeerState{peer("a", 1*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second)}
	r := Evaluate(ecmpState(sel("a", 1, "b", 1), all...), set, map[string]bool{"a": true, "b": true, "c": true}, t0)
	if len(r.Actions) != 0 {
		t.Fatalf("actions = %+v", r.Actions)
	}
	// No configured selection at all: every healthy candidate, weight 1.
	set = settings(nil)
	r = Evaluate(ecmpState(sel("a", 1), all...), set, map[string]bool{"a": true, "b": true, "c": true}, t0)
	sets := setActs(r)
	if len(sets) != 1 || !reflect.DeepEqual(sets[0].Selection, sel("a", 1, "b", 1, "c", 1)) {
		t.Fatalf("actions = %+v", r.Actions)
	}
}

func TestECMPWeightZeroEqualsOne(t *testing.T) {
	set := settings([]api.PeerWeight{{Peer: "a"}, {Peer: "b", Weight: 1}})
	all := []api.PeerState{peer("a", 1*time.Second), peer("b", 1*time.Second)}
	cur := []api.PeerWeight{{Peer: "a", Weight: 1}, {Peer: "b"}}
	r := Evaluate(ecmpState(cur, all...), set, map[string]bool{"a": true, "b": true}, t0)
	if len(r.Actions) != 0 {
		t.Fatalf("0-vs-1 weight caused a change: %+v", r.Actions)
	}
}

func TestPeerMissingFromState(t *testing.T) {
	// c is a candidate but the daemon does not know it: unhealthy,
	// never selected, and never flushed (it would error).
	st := singleState("a", peer("a", 400*time.Second), peer("b", 400*time.Second))
	r := Evaluate(st, settings(nil), nil, t0)
	if len(setActs(r)) != 0 {
		t.Fatalf("selected a non-existent peer: %+v", r.Actions)
	}
	for _, p := range flushed(r) {
		if p == "c" {
			t.Fatal("flushed a peer missing from State")
		}
	}
	if _, ok := r.Health["c"]; ok {
		t.Error("missing peer recorded in health")
	}
	// Selected peer missing from state: move to the first healthy one.
	st = singleState("zz", peer("a", 1*time.Second), peer("b", 1*time.Second))
	r = Evaluate(st, settings(nil), nil, t0)
	if sets := setActs(r); len(sets) != 1 || sets[0].Selection[0].Peer != "a" {
		t.Fatalf("actions = %+v", r.Actions)
	}
}

func TestUnmonitoredPrefixIgnored(t *testing.T) {
	st := singleState("a", peer("a", 400*time.Second), peer("b", 1*time.Second))
	set := Settings{MaxAge: maxAge, Prefixes: map[string][]api.PeerWeight{"192.0.2.0/24": nil}}
	r := Evaluate(st, set, nil, t0)
	if len(r.Actions) != 0 || len(r.Health) != 0 {
		t.Fatalf("unmonitored prefix acted on: %+v", r)
	}
}

func TestSettingsFromConfig(t *testing.T) {
	cfg := &config.Mux{
		Failover: config.Failover{HandshakeMaxAge: 90},
		EffectivePrefixes: []config.Prefix{
			{CIDR: "10.0.0.1/32", Candidates: []string{"a", "b"}, Mode: config.ModeECMP, Policy: config.PolicyFailover, Weights: map[string]int{"a": 2, "b": 1}},
			{CIDR: "10.0.0.2/32", Candidates: []string{"a", "b"}, Mode: config.ModeSingle, Policy: config.PolicyStatic, Active: "a"},
		},
	}
	s := SettingsFromConfig(cfg)
	if s.MaxAge != 90*time.Second || len(s.Prefixes) != 1 {
		t.Fatalf("settings = %+v", s)
	}
	if !reflect.DeepEqual(s.Prefixes["10.0.0.1/32"], sel("a", 2, "b", 1)) {
		t.Errorf("selection = %+v", s.Prefixes["10.0.0.1/32"])
	}
}

// --- Monitor.Tick against a fake client ---

type fakeClient struct {
	st        api.State
	stErr     error
	setErr    error
	sets      []api.SetSelectionRequest
	flushes   []string
	flushErr  error
	callOrder []string
}

func (f *fakeClient) State(ctx context.Context, mux string) (api.State, error) { return f.st, f.stErr }
func (f *fakeClient) SetSelection(ctx context.Context, r api.SetSelectionRequest) error {
	f.callOrder = append(f.callOrder, "set")
	if f.setErr != nil {
		return f.setErr
	}
	f.sets = append(f.sets, r)
	return nil
}
func (f *fakeClient) FlushPeer(ctx context.Context, r api.FlushPeerRequest) error {
	f.callOrder = append(f.callOrder, "flush:"+r.Peer)
	if f.flushErr != nil {
		return f.flushErr
	}
	f.flushes = append(f.flushes, r.Peer)
	return nil
}

func newTestMonitor(fc *fakeClient) *Monitor {
	m := &Monitor{mux: "wg-mux", set: settings(nil), client: fc, logger: log.New(io.Discard, "", 0), now: func() time.Time { return t0 }}
	return m
}

func TestTickExecutesAndRetries(t *testing.T) {
	fc := &fakeClient{st: singleState("a", peer("a", 400*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))}
	m := newTestMonitor(fc)

	fc.setErr = errors.New("boom")
	if err := m.Tick(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	// Health memory did not advance: the retry repeats the transition.
	fc.setErr = nil
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fc.sets) != 1 || fc.sets[0].Mux != "wg-mux" || fc.sets[0].Selection[0].Peer != "b" {
		t.Fatalf("sets = %+v", fc.sets)
	}
	if !reflect.DeepEqual(fc.flushes, []string{"a"}) {
		t.Fatalf("flushes = %v", fc.flushes)
	}
	// Now committed: a third pass over the (updated) state is quiet.
	fc.st = singleState("b", peer("a", 410*time.Second), peer("b", 1*time.Second), peer("c", 1*time.Second))
	before := len(fc.callOrder)
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fc.callOrder) != before {
		t.Fatalf("extra calls: %v", fc.callOrder[before:])
	}
	// Order within the successful pass: set before flush.
	if fc.callOrder[len(fc.callOrder)-2] != "set" || fc.callOrder[len(fc.callOrder)-1] != "flush:a" {
		t.Errorf("call order = %v", fc.callOrder)
	}
}

func TestTickStateError(t *testing.T) {
	fc := &fakeClient{stErr: errors.New("daemon down")}
	if err := newTestMonitor(fc).Tick(context.Background()); err == nil {
		t.Fatal("expected state error")
	}
}
