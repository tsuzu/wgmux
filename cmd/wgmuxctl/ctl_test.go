package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

func TestParseSelection(t *testing.T) {
	sel, err := parseSelection([]string{"a", "b=3"})
	if err != nil || !reflect.DeepEqual(sel, []api.PeerWeight{{Peer: "a", Weight: 1}, {Peer: "b", Weight: 3}}) {
		t.Fatalf("sel=%+v err=%v", sel, err)
	}
	for _, bad := range [][]string{{"a=0"}, {"a=x"}, {"=2"}, {"a", "a"}, {"a=-1"}} {
		if _, err := parseSelection(bad); err == nil {
			t.Errorf("parseSelection(%v) accepted", bad)
		}
	}
}

type fakeSel struct {
	st      api.State
	sets    []api.SetSelectionRequest
	flushes []string
}

func (f *fakeSel) State(ctx context.Context, mux string) (api.State, error) { return f.st, nil }
func (f *fakeSel) SetSelection(ctx context.Context, r api.SetSelectionRequest) error {
	f.sets = append(f.sets, r)
	return nil
}
func (f *fakeSel) FlushPeer(ctx context.Context, r api.FlushPeerRequest) error {
	f.flushes = append(f.flushes, r.Peer)
	return nil
}

func ecmpFake() *fakeSel {
	return &fakeSel{st: api.State{Prefixes: []api.PrefixState{{
		CIDR: "10.20.0.10/32", Candidates: []string{"a", "b", "c"}, Mode: api.ModeECMP,
		Selection: []api.PeerWeight{{Peer: "a", Weight: 1}, {Peer: "b", Weight: 1}},
	}}}}
}

func TestChangeSelectionFlushesLeavers(t *testing.T) {
	f := ecmpFake()
	// a stays, b leaves, c joins: flush only b.
	_, err := changeSelection(context.Background(), f, "m", "10.20.0.10/32",
		[]api.PeerWeight{{Peer: "a", Weight: 2}, {Peer: "c", Weight: 1}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 1 || !reflect.DeepEqual(f.flushes, []string{"b"}) {
		t.Fatalf("sets=%+v flushes=%v", f.sets, f.flushes)
	}
	// Without -flush nothing is flushed.
	f = ecmpFake()
	if _, err := changeSelection(context.Background(), f, "m", "10.20.0.10/32", []api.PeerWeight{{Peer: "c", Weight: 1}}, false); err != nil {
		t.Fatal(err)
	}
	if len(f.flushes) != 0 {
		t.Fatalf("flushed without -flush: %v", f.flushes)
	}
}

func TestChangeSelectionValidation(t *testing.T) {
	f := ecmpFake()
	if _, err := changeSelection(context.Background(), f, "m", "10.20.0.10/32", []api.PeerWeight{{Peer: "ghost", Weight: 1}}, true); err == nil {
		t.Error("non-candidate accepted")
	}
	if _, err := changeSelection(context.Background(), f, "m", "192.0.2.0/24", []api.PeerWeight{{Peer: "a", Weight: 1}}, true); err == nil {
		t.Error("unknown prefix accepted")
	}
	// Host bits are canonicalized: 10.20.0.10/24 would be 10.20.0.0/24.
	if len(f.sets) != 0 || len(f.flushes) != 0 {
		t.Fatalf("calls made on invalid input: %+v %v", f.sets, f.flushes)
	}
}

func TestBuildSpecCarriesModeAndSelection(t *testing.T) {
	mux := &config.Mux{
		Name:  "wg-mux",
		Front: config.Front{Address: "10.200.0.2/24"},
		Peers: []config.Peer{{Name: "a", ID: 1, PrivateKey: "k", PublicKey: "p"}, {Name: "b", ID: 2, PrivateKey: "k", PublicKey: "p"}},
		EffectivePrefixes: []config.Prefix{
			{CIDR: "10.20.0.10/32", Candidates: []string{"a", "b"}, Mode: config.ModeECMP, Policy: config.PolicyFailover, Weights: map[string]int{"a": 3, "b": 1}},
			{CIDR: "10.30.0.0/24", Candidates: []string{"a", "b"}, Mode: config.ModeSingle, Policy: config.PolicyStatic, Active: "b"},
		},
	}
	spec, err := buildSpec(mux)
	if err != nil {
		t.Fatal(err)
	}
	e, s := spec.Prefixes[0], spec.Prefixes[1]
	if e.Mode != api.ModeECMP || e.Policy != api.PolicyFailover || !reflect.DeepEqual(e.Selection, []api.PeerWeight{{Peer: "a", Weight: 3}, {Peer: "b", Weight: 1}}) {
		t.Errorf("ecmp prefix = %+v", e)
	}
	if s.Mode != api.ModeSingle || s.Policy != api.PolicyStatic || !reflect.DeepEqual(s.Selection, []api.PeerWeight{{Peer: "b", Weight: 1}}) {
		t.Errorf("single prefix = %+v", s)
	}
}

func TestCheckDaemonAPIVersion(t *testing.T) {
	if err := checkDaemon(api.DaemonInfo{APIVersion: api.Version + 1, Engine: "kernel"}, config.CreationSpec{}); err == nil {
		t.Error("mismatched api version accepted")
	}
	if err := checkDaemon(api.DaemonInfo{APIVersion: api.Version, Engine: "kernel"}, config.CreationSpec{}); err != nil {
		t.Error(err)
	}
}
