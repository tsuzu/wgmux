package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/engine"
)

// fakeEngine records calls; two instances must stay independent.
// It optionally implements engine.Adopter (adoptOK) and can be
// told to fail Apply (applyErr).
type fakeEngine struct {
	mu       sync.Mutex
	applied  *api.ApplySpec
	active   map[string]uint32
	closed   bool
	adoptOK  bool
	applyErr error
	adopts   int
	applies  int
}

func (f *fakeEngine) Apply(spec api.ApplySpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.applyErr != nil {
		return f.applyErr
	}
	s := spec
	f.applied = &s
	return nil
}

func (f *fakeEngine) Adopt(spec api.ApplySpec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adopts++
	if !f.adoptOK {
		return false, nil
	}
	s := spec
	f.applied = &s
	return true, nil
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
	st := api.State{}
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

// fakeMaker builds factories with per-test engine behaviour.
type fakeMaker struct {
	adoptOK  bool
	applyErr error
	engines  []*fakeEngine
}

func (m *fakeMaker) factory(params api.CreateParams) (engine.Engine, error) {
	e := &fakeEngine{adoptOK: m.adoptOK, applyErr: m.applyErr}
	m.engines = append(m.engines, e)
	return e, nil
}

func spec(cidr string, ids ...uint32) api.ApplySpec {
	return api.ApplySpec{
		Front:    api.FrontSpec{Address: "10.200.0.2/24", MTU: 1420},
		Prefixes: []api.PrefixSpec{{CIDR: cidr, CandidateIDs: ids, ActiveID: ids[0], Policy: "active"}},
	}
}

func statusOf(t *testing.T, d *Daemon, name string) string {
	t.Helper()
	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range list {
		if info.Mux == name {
			return info.Status
		}
	}
	t.Fatalf("instance %q not listed: %+v", name, list)
	return ""
}

func TestRegistryTwoInstancesIndependent(t *testing.T) {
	maker := &fakeMaker{}
	d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
	if err := d.Create(api.CreateParams{Mux: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(api.CreateParams{Mux: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(api.CreateParams{Mux: "a"}); err == nil {
		t.Fatal("duplicate create accepted")
	}
	if err := d.Create(api.CreateParams{Mux: "bad/name"}); err == nil {
		t.Fatal("invalid mux name accepted")
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
	if sa.Engine != "kernel" || sa.Status != api.StatusActive || len(sa.Prefixes) != 1 || sa.Prefixes[0].ActiveID != 2 {
		t.Errorf("state a = %+v", sa)
	}
	sb, err := d.State(api.MuxRequest{Mux: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Prefixes[0].ActiveID != 7 {
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
	if err := d.Create(api.CreateParams{Mux: "a"}); err != nil {
		t.Errorf("recreate after destroy: %v", err)
	}
}

// seedStore runs a daemon over dir, creates+applies one instance,
// and returns — simulating a previous daemon process's lifetime.
func seedStore(t *testing.T, dir string, maker *fakeMaker, kind, name string) {
	t.Helper()
	d := NewWithFactory(maker.factory, Config{Engine: kind, StateDir: dir, Restore: true})
	if err := d.Create(api.CreateParams{Mux: name}); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(api.ApplyRequest{Mux: name, Spec: spec("10.20.0.10/32", 1, 2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", name+".json")); err != nil {
		t.Fatalf("store file not written: %v", err)
	}
}

func TestRestoreAdoptsWhenPossible(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, &fakeMaker{}, "kernel", "wg-mux")

	maker := &fakeMaker{adoptOK: true}
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusAdopted {
		t.Fatalf("status = %q, want adopted", got)
	}
	e := maker.engines[0]
	if e.adopts != 1 || e.applies != 0 {
		t.Errorf("adopt path: adopts=%d applies=%d, want 1/0", e.adopts, e.applies)
	}
	// The adopted instance serves decisions without any re-apply.
	if err := d.SetActive(api.SetActiveRequest{Mux: "wg-mux", CIDR: "10.20.0.10/32", PeerID: 2}); err != nil {
		t.Errorf("SetActive on adopted instance: %v", err)
	}
}

func TestRestoreRebuildsWhenNotAdoptable(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, &fakeMaker{}, "userspace", "wg-mux")

	maker := &fakeMaker{adoptOK: false}
	d := NewWithFactory(maker.factory, Config{Engine: "userspace", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusRestored {
		t.Fatalf("status = %q, want restored", got)
	}
	if maker.engines[0].applies != 1 {
		t.Errorf("rebuild applies = %d, want 1", maker.engines[0].applies)
	}
}

func TestRestoreOrphanedOnKindMismatch(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, &fakeMaker{}, "userspace", "wg-mux")

	d := NewWithFactory((&fakeMaker{}).factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusOrphaned {
		t.Fatalf("status = %q, want orphaned", got)
	}
	// The kernel daemon must not touch the userspace instance.
	if err := d.Apply(api.ApplyRequest{Mux: "wg-mux", Spec: spec("10.20.0.10/32", 1)}); err == nil {
		t.Error("apply to orphaned instance accepted")
	}
	if err := d.Destroy(api.MuxRequest{Mux: "wg-mux"}); err == nil {
		t.Error("destroy of orphaned instance accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", "wg-mux.json")); err != nil {
		t.Errorf("orphaned store entry was touched: %v", err)
	}
}

func TestRestoreDisabledLeavesStored(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, &fakeMaker{}, "kernel", "wg-mux")

	maker := &fakeMaker{}
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: false})
	if got := statusOf(t, d, "wg-mux"); got != api.StatusStored {
		t.Fatalf("status = %q, want stored", got)
	}
	if len(maker.engines) != 0 {
		t.Fatal("engine materialized despite restore=false")
	}
	// An explicit apply activates it.
	if err := d.Apply(api.ApplyRequest{Mux: "wg-mux", Spec: spec("10.20.0.10/32", 1, 2)}); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(t, d, "wg-mux"); got != api.StatusActive {
		t.Errorf("status after apply = %q, want active", got)
	}
}

func TestRestoreFailureRecordedDaemonContinues(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, &fakeMaker{}, "kernel", "wg-good")
	// A second stored instance whose restore will fail.
	store := NewStore(dir)
	bad := spec("10.20.0.10/32", 1)
	if err := store.Put(Record{Name: "wg-bad", Engine: "kernel", Spec: &bad}); err != nil {
		t.Fatal(err)
	}
	maker := &fakeMaker{}
	failBad := true
	failFactory := func(params api.CreateParams) (engine.Engine, error) {
		if params.Mux == "wg-bad" && failBad {
			return &fakeEngine{applyErr: fmt.Errorf("port taken")}, nil
		}
		return maker.factory(params)
	}
	d := NewWithFactory(failFactory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-bad"); got != api.StatusFailed {
		t.Fatalf("wg-bad status = %q, want failed", got)
	}
	if got := statusOf(t, d, "wg-good"); got != api.StatusRestored {
		t.Errorf("wg-good status = %q, want restored (one failure must not block others)", got)
	}
	st, err := d.State(api.MuxRequest{Mux: "wg-bad"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != api.StatusFailed || st.Error == "" {
		t.Errorf("failed state = %+v, want status + error", st)
	}
	// And a later explicit apply can still fix the failed instance
	// (once the underlying problem — here simulated — is gone).
	failBad = false
	if err := d.Apply(api.ApplyRequest{Mux: "wg-bad", Spec: spec("10.20.0.10/32", 1)}); err != nil {
		t.Errorf("apply after failed restore: %v", err)
	}
}

func TestDestroyDeletesStoreEntry(t *testing.T) {
	dir := t.TempDir()
	d := NewWithFactory((&fakeMaker{}).factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	if err := d.Create(api.CreateParams{Mux: "wg-mux"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(api.ApplyRequest{Mux: "wg-mux", Spec: spec("10.20.0.10/32", 1)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(api.MuxRequest{Mux: "wg-mux"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", "wg-mux.json")); !os.IsNotExist(err) {
		t.Errorf("store entry survived destroy: %v", err)
	}
}
