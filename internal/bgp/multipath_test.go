package bgp

import (
	"context"
	"reflect"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// A multipath fixture in the shape of `show ip bgp json` with
// multipath enabled: both neighbors carry multipath=true, one of
// them is also the best path; a third path is neither.
const frrMultipathJSON = `{"routes": {
	"10.20.0.10/32": [
		{"peerId": "10.200.0.12", "multipath": true},
		{"peerId": "10.200.0.11", "bestpath": {"overall": true, "selectionReason": "Router ID"}, "multipath": true},
		{"peerId": "10.200.0.13", "valid": true}
	],
	"192.168.10.0/24": [
		{"peerId": "10.200.0.12", "bestpath": {"overall": true}},
		{"peerId": "10.200.0.11"}
	]
}}`

func TestParseFRRMultipath(t *testing.T) {
	cfg := testCfg()
	cfg.BGP.Neighbors = append(cfg.BGP.Neighbors, config.BGPNeighbor{Address: "10.200.0.13", WgPeer: "site-c"})
	got, err := ParseFRRBestPaths(cfg, []byte(frrMultipathJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := []Decision{
		// best path's peer first, then the other multipath members;
		// the non-best, non-multipath path (site-c) is excluded.
		{Prefix: "10.20.0.10/32", WgPeers: []string{"site-a", "site-b"}},
		{Prefix: "192.168.10.0/24", WgPeers: []string{"site-b"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decisions = %+v, want %+v", got, want)
	}
}

func TestParseFRRMultipathUnmappedBest(t *testing.T) {
	raw := []byte(`{"routes": {"10.20.0.10/32": [
		{"peerId": "10.200.0.99", "bestpath": {"overall": true}, "multipath": true},
		{"peerId": "10.200.0.12", "multipath": true}
	]}}`)
	got, err := ParseFRRBestPaths(testCfg(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].WgPeers, []string{"site-b"}) {
		t.Fatalf("decisions = %+v", got)
	}
}

func prefixState(mode, policy string) api.PrefixState {
	return api.PrefixState{
		CIDR: "10.20.0.10/32", Candidates: []string{"site-a", "site-b"},
		Mode: mode, Policy: policy,
		Selection: []api.PeerWeight{{Peer: "site-a", Weight: 1}},
	}
}

func TestSelectionFor(t *testing.T) {
	d := Decision{Prefix: "10.20.0.10/32", WgPeers: []string{"site-b", "site-a", "site-b"}}

	sel, err := SelectionFor(prefixState(api.ModeSingle, api.PolicyBGP), d)
	if err != nil || !reflect.DeepEqual(sel, []api.PeerWeight{{Peer: "site-b", Weight: 1}}) {
		t.Errorf("single: sel=%+v err=%v", sel, err)
	}
	sel, err = SelectionFor(prefixState(api.ModeECMP, api.PolicyBGP), d)
	if err != nil || !reflect.DeepEqual(sel, []api.PeerWeight{{Peer: "site-b", Weight: 1}, {Peer: "site-a", Weight: 1}}) {
		t.Errorf("ecmp: sel=%+v err=%v", sel, err)
	}
	// Non-candidates dropped; none left -> error.
	sel, err = SelectionFor(prefixState(api.ModeECMP, api.PolicyBGP), Decision{WgPeers: []string{"ghost", "site-a"}})
	if err != nil || len(sel) != 1 || sel[0].Peer != "site-a" {
		t.Errorf("non-candidate filtering: sel=%+v err=%v", sel, err)
	}
	if _, err := SelectionFor(prefixState(api.ModeECMP, api.PolicyBGP), Decision{WgPeers: []string{"ghost"}}); err == nil {
		t.Error("decision with no candidate peer accepted")
	}
	// Prefix not owned by bgp.
	if _, err := SelectionFor(prefixState(api.ModeSingle, api.PolicyFailover), d); err == nil {
		t.Error("decision for failover prefix accepted")
	}
}

type fakeClient struct {
	st   api.State
	sets []api.SetSelectionRequest
}

func (f *fakeClient) State(ctx context.Context, mux string) (api.State, error) { return f.st, nil }
func (f *fakeClient) SetSelection(ctx context.Context, r api.SetSelectionRequest) error {
	f.sets = append(f.sets, r)
	return nil
}

func TestApplyDecisionSkipsNoOps(t *testing.T) {
	fc := &fakeClient{st: api.State{Prefixes: []api.PrefixState{prefixState(api.ModeECMP, api.PolicyBGP)}}}
	// Already selecting site-a only: a decision for [site-a] is a no-op.
	if err := applyDecision(context.Background(), "wg-mux", fc, Decision{Prefix: "10.20.0.10/32", WgPeers: []string{"site-a"}}); err != nil {
		t.Fatal(err)
	}
	if len(fc.sets) != 0 {
		t.Fatalf("redundant SetSelection: %+v", fc.sets)
	}
	if err := applyDecision(context.Background(), "wg-mux", fc, Decision{Prefix: "10.20.0.10/32", WgPeers: []string{"site-a", "site-b"}}); err != nil {
		t.Fatal(err)
	}
	if len(fc.sets) != 1 || len(fc.sets[0].Selection) != 2 || fc.sets[0].Mux != "wg-mux" {
		t.Fatalf("sets = %+v", fc.sets)
	}
	if err := applyDecision(context.Background(), "wg-mux", fc, Decision{Prefix: "172.16.0.0/24", WgPeers: []string{"site-a"}}); err == nil {
		t.Error("unmanaged prefix accepted")
	}
}
