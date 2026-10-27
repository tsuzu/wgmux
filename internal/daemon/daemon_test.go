package daemon

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/engine"
)

// fakeEngine records calls; two instances must stay independent.
type fakeEngine struct {
	kind    string
	mu      sync.Mutex
	applied *api.ApplySpec
	active  map[string]uint32
	closed  bool
}

func (f *fakeEngine) Kind() string { return f.kind }

func (f *fakeEngine) CreationParams() api.CreateParams {
	return api.CreateParams{Engine: f.kind}
}

func (f *fakeEngine) Apply(spec api.ApplySpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := spec
	f.applied = &s
	return nil
}

func (f *fakeEngine) SetActive(prefix *net.IPNet, peerID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applied == nil {
		return fmt.Errorf("nothing applied")
	}
	if f.active == nil {
		f.active = map[string]uint32{}
	}
	f.active[prefix.String()] = peerID
	return nil
}

func (f *fakeEngine) State() (api.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applied == nil {
		return api.State{}, fmt.Errorf("nothing applied")
	}
	st := api.State{Engine: f.kind}
	for _, p := range f.applied.Prefixes {
		ps := api.PrefixState{CIDR: p.CIDR, CandidateIDs: p.CandidateIDs, ActiveID: p.ActiveID, Policy: p.Policy}
		if id, ok := f.active[p.CIDR]; ok {
			ps.ActiveID = id
		}
		st.Prefixes = append(st.Prefixes, ps)
	}
	return st, nil
}

func (f *fakeEngine) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.applied = nil
	return nil
}

func fakeFactory(params api.CreateParams) (engine.Engine, error) {
	if params.Engine == "bogus" {
		return nil, fmt.Errorf("unknown engine %q", params.Engine)
	}
	return &fakeEngine{kind: params.Engine}, nil
}

func spec(cidr string, ids ...uint32) api.ApplySpec {
	return api.ApplySpec{
		Front:    api.FrontSpec{Address: "10.200.0.2/24", MTU: 1420},
		Prefixes: []api.PrefixSpec{{CIDR: cidr, CandidateIDs: ids, ActiveID: ids[0], Policy: "active"}},
	}
}

func TestRegistryTwoInstancesIndependent(t *testing.T) {
	d := NewWithFactory(fakeFactory)
	if err := d.Create(api.CreateParams{Mux: "a", Engine: "kernel"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(api.CreateParams{Mux: "b", Engine: "userspace"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(api.CreateParams{Mux: "a", Engine: "kernel"}); err == nil {
		t.Fatal("duplicate create accepted")
	}
	if err := d.Create(api.CreateParams{Mux: "c", Engine: "bogus"}); err == nil {
		t.Fatal("bogus engine accepted")
	}

	if err := d.Apply(api.ApplyRequest{Mux: "a", Spec: spec("10.20.0.10/32", 1, 2)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(api.ApplyRequest{Mux: "b", Spec: spec("10.20.0.10/32", 7, 8)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(api.ApplyRequest{Mux: "ghost", Spec: spec("10.0.0.0/8", 1)}); err == nil {
		t.Fatal("apply to unknown mux accepted")
	}

	// Flip a only; b's state must not move.
	if err := d.SetActive(api.SetActiveRequest{Mux: "a", CIDR: "10.20.0.10/32", PeerID: 2}); err != nil {
		t.Fatal(err)
	}
	sa, err := d.State(api.MuxRequest{Mux: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if sa.Engine != "kernel" || len(sa.Prefixes) != 1 || sa.Prefixes[0].ActiveID != 2 {
		t.Errorf("state a = %+v", sa)
	}
	sb, err := d.State(api.MuxRequest{Mux: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Engine != "userspace" || sb.Prefixes[0].ActiveID != 7 {
		t.Errorf("state b = %+v (a's SetActive leaked into b?)", sb)
	}

	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Mux != "a" || list[1].Mux != "b" {
		t.Errorf("list = %+v", list)
	}

	// Destroy a; b must keep working.
	if err := d.Destroy(api.MuxRequest{Mux: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.State(api.MuxRequest{Mux: "a"}); err == nil {
		t.Error("state on destroyed mux accepted")
	}
	if err := d.Destroy(api.MuxRequest{Mux: "a"}); err == nil {
		t.Error("second destroy accepted")
	}
	if _, err := d.State(api.MuxRequest{Mux: "b"}); err != nil {
		t.Errorf("b broke after destroying a: %v", err)
	}
	// The name is free again after destroy.
	if err := d.Create(api.CreateParams{Mux: "a", Engine: "userspace"}); err != nil {
		t.Errorf("recreate after destroy: %v", err)
	}
}
