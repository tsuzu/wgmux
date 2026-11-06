package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/engine"
)

// fakeEngine records calls. It implements Adopter and Purger, and
// can be told to fail Apply or to block inside it.
type fakeEngine struct {
	maker *fakeMaker
	name  string

	mu      sync.Mutex
	applied *api.ApplySpec
	sel     map[string][]api.PeerWeight
	closed  bool
	adopts  int
	applies int
	flushed []string

	adoptSpec    *api.ApplySpec
	appliedSpecs []api.ApplySpec

	failApply int // fail this many next Applies (-1 = always)
	// block, if non-nil, makes Apply signal entered then wait for block.
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeEngine) log(ev string) {
	f.maker.mu.Lock()
	f.maker.events = append(f.maker.events, f.name+":"+ev)
	f.maker.mu.Unlock()
}

func (f *fakeEngine) Apply(spec api.ApplySpec) error {
	f.log("apply")
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.failApply != 0 {
		if f.failApply > 0 {
			f.failApply--
		}
		return fmt.Errorf("apply boom")
	}
	s := spec
	f.applied = &s
	f.appliedSpecs = append(f.appliedSpecs, spec)
	f.loadSel(spec)
	return nil
}

func (f *fakeEngine) loadSel(spec api.ApplySpec) {
	f.sel = map[string][]api.PeerWeight{}
	for _, p := range spec.Prefixes {
		f.sel[p.CIDR] = p.Selection
	}
}

func (f *fakeEngine) Adopt(spec api.ApplySpec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adopts++
	f.adoptSpec = &spec
	if !f.maker.adoptOK {
		return false, nil
	}
	s := spec
	f.applied = &s
	f.loadSel(spec)
	return true, nil
}

func (f *fakeEngine) Purge() error {
	f.log("purge")
	f.maker.mu.Lock()
	f.maker.purges[f.name]++
	f.maker.mu.Unlock()
	return nil
}

func (f *fakeEngine) SetSelection(prefix *net.IPNet, sel []api.PeerWeight) error {
	f.log("setsel")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applied == nil {
		return fmt.Errorf("nothing applied")
	}
	f.sel[prefix.String()] = sel
	return nil
}

func (f *fakeEngine) FlushPeer(peer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushed = append(f.flushed, peer)
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
		st.Prefixes = append(st.Prefixes, api.PrefixState{
			CIDR: p.CIDR, Candidates: p.Candidates, Mode: p.EffectiveMode(),
			Policy: p.Policy, Selection: f.sel[p.CIDR],
		})
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

// fakeMaker builds factories and tracks every engine it made.
type fakeMaker struct {
	adoptOK bool
	// prep, if set, configures each new engine before use.
	prep func(*fakeEngine)

	mu      sync.Mutex
	engines []*fakeEngine
	purges  map[string]int
	events  []string
}

func newMaker() *fakeMaker { return &fakeMaker{purges: map[string]int{}} }

func (m *fakeMaker) factory(params api.CreateParams) (engine.Engine, error) {
	e := &fakeEngine{maker: m, name: params.Mux}
	if m.prep != nil {
		m.prep(e)
	}
	m.mu.Lock()
	m.engines = append(m.engines, e)
	m.mu.Unlock()
	return e, nil
}

func (m *fakeMaker) last() *fakeEngine {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.engines[len(m.engines)-1]
}

func (m *fakeMaker) purgeCount(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.purges[name]
}

func (m *fakeMaker) eventLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.events...)
}

const cidrA = "10.20.0.0/24"

func peers() []api.PeerSpec {
	return []api.PeerSpec{
		{Name: "p1", ID: 1}, {Name: "p2", ID: 2}, {Name: "p3", ID: 3},
	}
}

// mkSpec builds a spec with one prefix over the given candidates.
func mkSpec(mode string, cands ...string) api.ApplySpec {
	return api.ApplySpec{
		Front: api.FrontSpec{Address: "10.200.0.2/24", MTU: 1420},
		Peers: peers(),
		Prefixes: []api.PrefixSpec{{
			CIDR: cidrA, Candidates: cands, Mode: mode, Policy: api.PolicyStatic,
		}},
	}
}

func one(peer string) []api.PeerWeight { return []api.PeerWeight{{Peer: peer, Weight: 1}} }

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

func selOf(t *testing.T, d *Daemon, mux string) []api.PeerWeight {
	t.Helper()
	st, err := d.State(api.MuxRequest{Mux: mux})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Prefixes) != 1 {
		t.Fatalf("prefixes = %+v", st.Prefixes)
	}
	return st.Prefixes[0].Selection
}

func mustApply(t *testing.T, d *Daemon, mux string, spec api.ApplySpec, reset bool) {
	t.Helper()
	if err := d.Apply(api.ApplyRequest{Mux: mux, Spec: spec, ResetSelections: reset}); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryTwoInstancesIndependent(t *testing.T) {
	maker := newMaker()
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
	mustApply(t, d, "a", mkSpec("single", "p1", "p2"), false)
	mustApply(t, d, "b", mkSpec("single", "p3", "p1"), false)
	if err := d.Apply(api.ApplyRequest{Mux: "ghost", Spec: mkSpec("single", "p1")}); err == nil {
		t.Fatal("apply to unknown mux accepted")
	}

	// Flip a only; b's state must not move.
	if err := d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: one("p2")}); err != nil {
		t.Fatal(err)
	}
	if got := selOf(t, d, "a"); !reflect.DeepEqual(got, one("p2")) {
		t.Errorf("a selection = %+v", got)
	}
	if got := selOf(t, d, "b"); !reflect.DeepEqual(got, one("p3")) {
		t.Errorf("b selection = %+v (a's SetSelection leaked into b?)", got)
	}
	sa, _ := d.State(api.MuxRequest{Mux: "a"})
	if sa.Engine != "kernel" || sa.Status != api.StatusActive {
		t.Errorf("state a = %+v", sa)
	}
	list, _ := d.List()
	if len(list) != 2 || list[0].Mux != "a" || list[1].Mux != "b" {
		t.Errorf("list = %+v", list)
	}

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
	if err := d.Create(api.CreateParams{Mux: "a"}); err != nil {
		t.Errorf("recreate after destroy: %v", err)
	}
}

func TestInfoAPIVersion(t *testing.T) {
	d := NewWithFactory(newMaker().factory, Config{Engine: "kernel"})
	info, err := d.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.APIVersion != api.Version || info.Engine != "kernel" {
		t.Errorf("info = %+v", info)
	}
}

func TestSetSelectionValidationAndCanonicalCIDR(t *testing.T) {
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
	d.Create(api.CreateParams{Mux: "a"})
	mustApply(t, d, "a", mkSpec("single", "p1", "p2"), false)
	e := maker.last()
	setsel := func(cidr string, sel []api.PeerWeight) error {
		return d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidr, Selection: sel})
	}
	for name, tc := range map[string]struct {
		cidr string
		sel  []api.PeerWeight
	}{
		"empty":         {cidrA, nil},
		"non-candidate": {cidrA, one("p3")},
		"unknown peer":  {cidrA, one("zz")},
		"single two":    {cidrA, []api.PeerWeight{{Peer: "p1"}, {Peer: "p2"}}},
		"dup":           {cidrA, []api.PeerWeight{{Peer: "p1"}, {Peer: "p1"}}},
		"bad cidr":      {"nonsense", one("p1")},
		"unknown cidr":  {"10.99.0.0/24", one("p1")},
	} {
		before := len(maker.eventLog())
		if err := setsel(tc.cidr, tc.sel); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(maker.eventLog()) != before {
			t.Errorf("%s: invalid selection reached the engine", name)
		}
	}
	// Non-canonical CIDR is canonicalized before reaching the engine.
	if err := setsel("10.20.0.7/24", one("p2")); err != nil {
		t.Fatal(err)
	}
	if got := e.sel[cidrA]; !reflect.DeepEqual(got, one("p2")) {
		t.Errorf("engine selection under canonical key = %+v (keys %v)", got, e.sel)
	}
}

func TestFlushPeer(t *testing.T) {
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
	d.Create(api.CreateParams{Mux: "a"})
	if err := d.FlushPeer(api.FlushPeerRequest{Mux: "a", Peer: "p1"}); err == nil {
		t.Error("flush before any apply accepted")
	}
	mustApply(t, d, "a", mkSpec("single", "p1", "p2"), false)
	if err := d.FlushPeer(api.FlushPeerRequest{Mux: "a", Peer: "nope"}); err == nil || !strings.Contains(err.Error(), "unknown peer") {
		t.Errorf("unknown peer flush err = %v", err)
	}
	if err := d.FlushPeer(api.FlushPeerRequest{Mux: "ghost", Peer: "p1"}); err == nil {
		t.Error("flush on unknown mux accepted")
	}
	if err := d.FlushPeer(api.FlushPeerRequest{Mux: "a", Peer: "p2"}); err != nil {
		t.Fatal(err)
	}
	if got := maker.last().flushed; !reflect.DeepEqual(got, []string{"p2"}) {
		t.Errorf("flushed = %v", got)
	}
}

func TestSelectionPersistenceAcrossReapply(t *testing.T) {
	ecmp2 := []api.PeerWeight{{Peer: "p1", Weight: 3}, {Peer: "p2", Weight: 1}}
	cases := []struct {
		name      string
		first     api.ApplySpec
		override  []api.PeerWeight
		second    api.ApplySpec
		reset     bool
		wantKept  bool
		wantOther []api.PeerWeight // expected selection when dropped
	}{
		{"kept when prefix unchanged", mkSpec("single", "p1", "p2"), one("p2"), mkSpec("single", "p1", "p2"), false, true, nil},
		{"kept ecmp", mkSpec("ecmp", "p1", "p2", "p3"), ecmp2, mkSpec("ecmp", "p1", "p2", "p3"), false, true, nil},
		{"dropped candidates changed", mkSpec("single", "p1", "p2"), one("p2"), mkSpec("single", "p1", "p2", "p3"), false, false, one("p1")},
		{"dropped candidates reordered", mkSpec("single", "p1", "p2"), one("p2"), mkSpec("single", "p2", "p1"), false, false, one("p2")},
		{"dropped mode changed", mkSpec("single", "p1", "p2"), one("p2"), mkSpec("ecmp", "p1", "p2"), false, false,
			[]api.PeerWeight{{Peer: "p1", Weight: 1}, {Peer: "p2", Weight: 1}}},
		{"dropped with reset", mkSpec("single", "p1", "p2"), one("p2"), mkSpec("single", "p1", "p2"), true, false, one("p1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			maker := newMaker()
			d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir})
			d.Create(api.CreateParams{Mux: "a"})
			mustApply(t, d, "a", tc.first, false)
			if err := d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: tc.override}); err != nil {
				t.Fatal(err)
			}
			mustApply(t, d, "a", tc.second, tc.reset)
			want := tc.wantOther
			if tc.wantKept {
				want = tc.override
			}
			// What the ENGINE was told in the re-apply.
			e := maker.last()
			got := e.appliedSpecs[len(e.appliedSpecs)-1].Prefixes[0].Selection
			if !reflect.DeepEqual(got, want) {
				t.Errorf("engine got selection %+v, want %+v", got, want)
			}
			if got := selOf(t, d, "a"); !reflect.DeepEqual(got, want) {
				t.Errorf("state selection %+v, want %+v", got, want)
			}
			rec, err := NewStore(dir).Load("a")
			if err != nil {
				t.Fatal(err)
			}
			_, has := rec.Selections[cidrA]
			if has != tc.wantKept {
				t.Errorf("persisted override present = %v, want %v (%+v)", has, tc.wantKept, rec.Selections)
			}
		})
	}

	t.Run("dropped when configured selection changed", func(t *testing.T) {
		maker := newMaker()
		d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
		d.Create(api.CreateParams{Mux: "a"})
		first := mkSpec("ecmp", "p1", "p2")
		first.Prefixes[0].Selection = []api.PeerWeight{{Peer: "p1", Weight: 1}, {Peer: "p2", Weight: 1}}
		mustApply(t, d, "a", first, false)
		d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: one("p2")})
		second := mkSpec("ecmp", "p1", "p2")
		second.Prefixes[0].Selection = []api.PeerWeight{{Peer: "p1", Weight: 5}, {Peer: "p2", Weight: 1}}
		mustApply(t, d, "a", second, false)
		if got := selOf(t, d, "a"); !reflect.DeepEqual(got, second.Prefixes[0].Selection) {
			t.Errorf("selection = %+v, want configured %+v", got, second.Prefixes[0].Selection)
		}
	})

	t.Run("canonical cidr spelling keeps override", func(t *testing.T) {
		maker := newMaker()
		d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
		d.Create(api.CreateParams{Mux: "a"})
		mustApply(t, d, "a", mkSpec("single", "p1", "p2"), false)
		d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: one("p2")})
		again := mkSpec("single", "p1", "p2")
		again.Prefixes[0].CIDR = "10.20.0.9/24"
		mustApply(t, d, "a", again, false)
		if got := selOf(t, d, "a"); !reflect.DeepEqual(got, one("p2")) {
			t.Errorf("selection = %+v, want p2", got)
		}
	})
}

func TestApplyRejectsInvalidSpecBeforeEngine(t *testing.T) {
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
	d.Create(api.CreateParams{Mux: "a"})
	bad := mkSpec("single", "p1", "p2")
	bad.Prefixes[0].Selection = one("p3") // not a candidate
	if err := d.Apply(api.ApplyRequest{Mux: "a", Spec: bad}); err == nil {
		t.Fatal("invalid configured selection accepted")
	}
	bad = mkSpec("single", "p1", "ghost")
	if err := d.Apply(api.ApplyRequest{Mux: "a", Spec: bad}); err == nil {
		t.Fatal("candidate that is not a peer accepted")
	}
	if len(maker.eventLog()) != 0 {
		t.Errorf("engine was called: %v", maker.eventLog())
	}
}

// seedStore runs a daemon over dir, creates+applies one instance,
// optionally sets a selection, and returns — a previous daemon
// process's lifetime.
func seedStore(t *testing.T, dir, kind, name string, spec api.ApplySpec, override []api.PeerWeight) {
	t.Helper()
	d := NewWithFactory(newMaker().factory, Config{Engine: kind, StateDir: dir})
	if err := d.Create(api.CreateParams{Mux: name}); err != nil {
		t.Fatal(err)
	}
	mustApply(t, d, name, spec, false)
	if override != nil {
		if err := d.SetSelection(api.SetSelectionRequest{Mux: name, CIDR: cidrA, Selection: override}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", name+".json")); err != nil {
		t.Fatalf("store file not written: %v", err)
	}
}

func TestRestoreAdoptsWithMergedSpec(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "kernel", "wg-mux", mkSpec("single", "p1", "p2"), one("p2"))

	maker := newMaker()
	maker.adoptOK = true
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusAdopted {
		t.Fatalf("status = %q, want adopted", got)
	}
	e := maker.last()
	if e.adopts != 1 || e.applies != 0 {
		t.Errorf("adopt path: adopts=%d applies=%d, want 1/0", e.adopts, e.applies)
	}
	if got := e.adoptSpec.Prefixes[0].Selection; !reflect.DeepEqual(got, one("p2")) {
		t.Errorf("Adopt got selection %+v, want the persisted override p2", got)
	}
	// Adopted instance serves decisions without any re-apply.
	if err := d.SetSelection(api.SetSelectionRequest{Mux: "wg-mux", CIDR: cidrA, Selection: one("p1")}); err != nil {
		t.Errorf("SetSelection on adopted instance: %v", err)
	}
	// And the persisted override follows.
	rec, _ := NewStore(dir).Load("wg-mux")
	if !reflect.DeepEqual(rec.Selections[cidrA], one("p1")) {
		t.Errorf("persisted = %+v", rec.Selections)
	}
}

func TestRestoreRebuildsWithMergedSpec(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "userspace", "wg-mux", mkSpec("single", "p1", "p2"), one("p2"))

	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "userspace", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusRestored {
		t.Fatalf("status = %q, want restored", got)
	}
	e := maker.last()
	if e.applies != 1 {
		t.Fatalf("rebuild applies = %d, want 1", e.applies)
	}
	if got := e.appliedSpecs[0].Prefixes[0].Selection; !reflect.DeepEqual(got, one("p2")) {
		t.Errorf("Apply got selection %+v, want persisted override p2", got)
	}
	if got := selOf(t, d, "wg-mux"); !reflect.DeepEqual(got, one("p2")) {
		t.Errorf("selection after restore = %+v", got)
	}
}

func TestRestoreDropsInvalidStoredOverride(t *testing.T) {
	dir := t.TempDir()
	spec := mkSpec("single", "p1", "p2")
	if err := NewStore(dir).Put(Record{
		Version: StoreVersion, Name: "wg-mux", Engine: "kernel", Spec: &spec,
		Selections: map[string][]api.PeerWeight{cidrA: one("zz")},
	}); err != nil {
		t.Fatal(err)
	}
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := selOf(t, d, "wg-mux"); !reflect.DeepEqual(got, one("p1")) {
		t.Errorf("selection = %+v, want configured default p1", got)
	}
}

func TestRestoreOrphanedOnKindMismatch(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "userspace", "wg-mux", mkSpec("single", "p1", "p2"), nil)

	d := NewWithFactory(newMaker().factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-mux"); got != api.StatusOrphaned {
		t.Fatalf("status = %q, want orphaned", got)
	}
	if err := d.Apply(api.ApplyRequest{Mux: "wg-mux", Spec: mkSpec("single", "p1")}); err == nil {
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
	seedStore(t, dir, "kernel", "wg-mux", mkSpec("single", "p1", "p2"), nil)

	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: false})
	if got := statusOf(t, d, "wg-mux"); got != api.StatusStored {
		t.Fatalf("status = %q, want stored", got)
	}
	if len(maker.engines) != 0 {
		t.Fatal("engine materialized despite restore=false")
	}
	mustApply(t, d, "wg-mux", mkSpec("single", "p1", "p2"), false)
	if got := statusOf(t, d, "wg-mux"); got != api.StatusActive {
		t.Errorf("status after apply = %q, want active", got)
	}
}

func TestApplyOnStoredInstancePurgesFirst(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "kernel", "wg-mux", mkSpec("single", "p1", "p2"), nil)
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir})
	mustApply(t, d, "wg-mux", mkSpec("single", "p1", "p2"), false)
	if n := maker.purgeCount("wg-mux"); n != 1 {
		t.Fatalf("purges = %d, want 1", n)
	}
	ev := maker.eventLog()
	if len(ev) < 2 || ev[0] != "wg-mux:purge" || ev[1] != "wg-mux:apply" {
		t.Errorf("events = %v, want purge then apply", ev)
	}
	// A second apply on the now-live engine must not purge again.
	mustApply(t, d, "wg-mux", mkSpec("single", "p1", "p2"), false)
	if n := maker.purgeCount("wg-mux"); n != 1 {
		t.Errorf("purges after live re-apply = %d, want 1", n)
	}
}

func TestDestroyStoredInstancePurges(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "kernel", "wg-mux", mkSpec("single", "p1", "p2"), nil)
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir})
	if err := d.Destroy(api.MuxRequest{Mux: "wg-mux"}); err != nil {
		t.Fatal(err)
	}
	if n := maker.purgeCount("wg-mux"); n != 1 {
		t.Errorf("purges = %d, want 1 (stored instance leaked its datapath)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", "wg-mux.json")); !os.IsNotExist(err) {
		t.Errorf("store entry survived destroy: %v", err)
	}
}

func TestDestroyDeletesStoreEntry(t *testing.T) {
	dir := t.TempDir()
	d := NewWithFactory(newMaker().factory, Config{Engine: "kernel", StateDir: dir})
	d.Create(api.CreateParams{Mux: "wg-mux"})
	mustApply(t, d, "wg-mux", mkSpec("single", "p1"), false)
	if err := d.Destroy(api.MuxRequest{Mux: "wg-mux"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "instances", "wg-mux.json")); !os.IsNotExist(err) {
		t.Errorf("store entry survived destroy: %v", err)
	}
}

func TestRestoreFailureRecordedDaemonContinues(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, "kernel", "wg-good", mkSpec("single", "p1", "p2"), nil)
	seedStore(t, dir, "kernel", "wg-bad", mkSpec("single", "p1", "p2"), nil)
	maker := newMaker()
	maker.prep = func(e *fakeEngine) {
		if e.name == "wg-bad" {
			e.failApply = 1
		}
	}
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir, Restore: true})
	d.Restore()
	if got := statusOf(t, d, "wg-bad"); got != api.StatusFailed {
		t.Fatalf("wg-bad status = %q, want failed", got)
	}
	if got := statusOf(t, d, "wg-good"); got != api.StatusRestored {
		t.Errorf("wg-good status = %q, want restored", got)
	}
	st, err := d.State(api.MuxRequest{Mux: "wg-bad"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != api.StatusFailed || st.Error == "" {
		t.Errorf("failed state = %+v, want status + error", st)
	}
	// A later explicit apply fixes the failed instance (and purges
	// whatever the failed restore left).
	maker.prep = nil
	mustApply(t, d, "wg-bad", mkSpec("single", "p1", "p2"), false)
	if maker.purgeCount("wg-bad") != 1 {
		t.Errorf("purges = %d, want 1", maker.purgeCount("wg-bad"))
	}
}

func TestApplyFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel", StateDir: dir})
	d.Create(api.CreateParams{Mux: "a"})
	good := mkSpec("single", "p1", "p2")
	mustApply(t, d, "a", good, false)
	d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: one("p2")})
	e := maker.last()

	e.mu.Lock()
	e.failApply = 1 // the new apply fails, the rollback succeeds
	e.mu.Unlock()
	next := mkSpec("single", "p3", "p1")
	err := d.Apply(api.ApplyRequest{Mux: "a", Spec: next})
	if err == nil {
		t.Fatal("failed apply returned nil")
	}
	st, serr := d.State(api.MuxRequest{Mux: "a"})
	if serr != nil {
		t.Fatal(serr)
	}
	if st.Status != api.StatusActive || !strings.Contains(st.Error, "apply failed (rolled back)") {
		t.Errorf("status=%q error=%q", st.Status, st.Error)
	}
	// Engine is back on the previous spec with the override.
	last := e.appliedSpecs[len(e.appliedSpecs)-1]
	if !reflect.DeepEqual(last.Prefixes[0].Candidates, []string{"p1", "p2"}) || !reflect.DeepEqual(last.Prefixes[0].Selection, one("p2")) {
		t.Errorf("rolled-back spec = %+v", last.Prefixes[0])
	}
	// Store keeps the last good spec.
	rec, _ := NewStore(dir).Load("a")
	if !reflect.DeepEqual(rec.Spec.Prefixes[0].Candidates, []string{"p1", "p2"}) {
		t.Errorf("store spec = %+v", rec.Spec.Prefixes[0])
	}

	// A successful apply clears the error.
	mustApply(t, d, "a", good, false)
	st, _ = d.State(api.MuxRequest{Mux: "a"})
	if st.Error != "" {
		t.Errorf("error not cleared: %q", st.Error)
	}

	// Rollback failing too -> failed.
	e.mu.Lock()
	e.failApply = -1
	e.mu.Unlock()
	if err := d.Apply(api.ApplyRequest{Mux: "a", Spec: next}); err == nil {
		t.Fatal("apply with failing rollback returned nil")
	}
	st, _ = d.State(api.MuxRequest{Mux: "a"})
	if st.Status != api.StatusFailed || !strings.Contains(st.Error, "rollback failed") {
		t.Errorf("status=%q error=%q", st.Status, st.Error)
	}
	rec, _ = NewStore(dir).Load("a")
	if !reflect.DeepEqual(rec.Spec.Prefixes[0].Candidates, []string{"p1", "p2"}) {
		t.Errorf("store spec after double failure = %+v", rec.Spec.Prefixes[0])
	}
	// The failed instance can be re-applied (fresh engine + purge).
	maker.prep = nil
	mustApply(t, d, "a", good, false)
	if got := statusOf(t, d, "a"); got != api.StatusActive {
		t.Errorf("status after recovery = %q", got)
	}
	// One purge when the rollback failed, one before the rebuild.
	if maker.purgeCount("a") != 2 {
		t.Errorf("purges = %d, want 2 (failed instance purged before rebuild)", maker.purgeCount("a"))
	}
}

func TestPerInstanceLocking(t *testing.T) {
	maker := newMaker()
	d := NewWithFactory(maker.factory, Config{Engine: "kernel"})
	if err := d.Create(api.CreateParams{Mux: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(api.CreateParams{Mux: "b"}); err != nil {
		t.Fatal(err)
	}
	mustApply(t, d, "a", mkSpec("single", "p1", "p2"), false)
	mustApply(t, d, "b", mkSpec("single", "p1", "p2"), false)

	var ea *fakeEngine
	for _, e := range maker.engines {
		if e.name == "a" {
			ea = e
		}
	}
	ea.block = make(chan struct{})
	ea.entered = make(chan struct{}, 1)

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- d.Apply(api.ApplyRequest{Mux: "a", Spec: mkSpec("single", "p2", "p1")})
	}()
	select {
	case <-ea.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply on a never reached the engine")
	}

	others := make(chan error, 4)
	go func() {
		others <- d.SetSelection(api.SetSelectionRequest{Mux: "b", CIDR: cidrA, Selection: one("p2")})
		_, err := d.State(api.MuxRequest{Mux: "b"})
		others <- err
		others <- d.FlushPeer(api.FlushPeerRequest{Mux: "b", Peer: "p1"})
		_, err = d.List()
		others <- err
	}()
	for i := 0; i < 4; i++ {
		select {
		case err := <-others:
			if err != nil {
				t.Errorf("op on b: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("operation on mux b blocked behind a long Apply on mux a")
		}
	}
	// Operations on a itself wait for the Apply.
	aDone := make(chan error, 1)
	go func() {
		aDone <- d.SetSelection(api.SetSelectionRequest{Mux: "a", CIDR: cidrA, Selection: one("p1")})
	}()
	select {
	case <-aDone:
		t.Error("SetSelection on a did not wait for its in-flight Apply")
	case <-time.After(100 * time.Millisecond):
	}
	close(ea.block)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-aDone; err != nil {
		t.Errorf("queued SetSelection on a: %v", err)
	}
}

func TestMergeSpecDuplicatePrefix(t *testing.T) {
	spec := mkSpec("single", "p1", "p2")
	spec.Prefixes = append(spec.Prefixes, api.PrefixSpec{CIDR: "10.20.0.5/24", Candidates: []string{"p1"}})
	if _, _, _, err := mergeSpec(nil, nil, spec, false); err == nil {
		t.Error("two spellings of one prefix accepted")
	}
}
