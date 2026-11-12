// Package daemon is the data-plane daemon (wgmuxd): the
// api.Handler implementation. It is a registry of mux instances of
// ONE engine kind — the kind is a daemon-startup choice, and the
// factory builds instances of that kind only. Create builds one
// engine.Engine per mux name; Apply / SetSelection / FlushPeer /
// State delegate to the addressed instance. The daemon keeps no
// policy of its own — every selection decision arrives from a
// control-plane process.
//
// Locking: the registry mutex guards the name -> instance map only;
// every instance has its own operation mutex, so a long Apply on one
// instance never blocks SetSelection or State on another.
//
// Persistence: every create/apply/SetSelection is recorded in a spec
// store (see store.go): the last successfully applied (configured)
// spec plus the runtime selection overrides. On startup the daemon
// restores from the store: kernel instances whose kernel objects
// survived (and were left by a completed apply of the same spec) are
// adopted untouched; the rest are rebuilt; store entries belonging to
// the other engine kind are reported as orphaned and left alone.
// Stopping the daemon never tears anything down — destruction is only
// ever the explicit Destroy.
package daemon

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/engine"
)

// Config is the daemon's startup configuration: everything here is
// fixed for the process lifetime (see docs/design.md, the
// configuration-lifecycle table).
type Config struct {
	Engine       string // kernel | userspace — the daemon's one kind
	Interconnect string // kernel startup setting
	Attach       string // kernel startup setting
	PinRoot      string // kernel startup setting (bpffs base)
	StateDir     string // spec store location; "" disables persistence
	Restore      bool   // activate stored instances at startup
}

type instance struct {
	// op serializes every operation on this instance (Apply,
	// Destroy, SetSelection, FlushPeer, State, restore).
	op   sync.Mutex
	dead bool // destroyed; guarded by op

	// meta guards status/errMsg so List can read them while a long
	// operation holds op.
	meta   sync.RWMutex
	status string // api.Status*
	errMsg string

	// The fields below are guarded by op.
	eng        engine.Engine // nil while stored / failed / orphaned
	createdAt  time.Time
	create     api.CreateParams
	spec       *api.ApplySpec              // last successfully applied spec (configured selections)
	selections map[string][]api.PeerWeight // runtime overrides by canonical CIDR
}

func (i *instance) setStatus(status, errMsg string) {
	i.meta.Lock()
	i.status, i.errMsg = status, errMsg
	i.meta.Unlock()
}

func (i *instance) getStatus() (string, string) {
	i.meta.RLock()
	defer i.meta.RUnlock()
	return i.status, i.errMsg
}

type Daemon struct {
	mu        sync.Mutex // guards instances (the map only)
	cfg       Config
	factory   engine.Factory
	store     *Store
	instances map[string]*instance
}

// New builds a Daemon with the production engine factory for
// cfg.Engine, then restores stored instances (see package doc).
func New(cfg Config) (*Daemon, error) {
	factory, err := engine.NewFactory(cfg.Engine, engine.DaemonOptions{
		Interconnect: cfg.Interconnect,
		Attach:       cfg.Attach,
		PinRoot:      cfg.PinRoot,
	})
	if err != nil {
		return nil, err
	}
	d := NewWithFactory(factory, cfg)
	if cfg.Restore {
		d.Restore()
	}
	return d, nil
}

// NewWithFactory builds a Daemon on an injected engine factory
// (tests use fakes that touch no kernel state). cfg.Engine still
// names the daemon's kind for reporting and orphan detection. The
// store is loaded (instances registered), but activation happens
// only when Restore is called.
func NewWithFactory(f engine.Factory, cfg Config) *Daemon {
	d := &Daemon{cfg: cfg, factory: f, instances: map[string]*instance{}}
	if cfg.StateDir != "" {
		d.store = NewStore(cfg.StateDir)
		d.loadStored()
	}
	return d
}

// loadStored registers every stored instance as stored / orphaned
// / failed(corrupt), without activating anything.
func (d *Daemon) loadStored() {
	names, err := d.store.Names()
	if err != nil {
		fmt.Printf("wgmuxd: warning: read spec store: %v\n", err)
		return
	}
	for _, name := range names {
		rec, err := d.store.Load(name)
		if err == nil && rec.Version != StoreVersion {
			err = fmt.Errorf("stored instance %q has format version %d, this daemon needs %d; destroy it and re-apply", name, rec.Version, StoreVersion)
		}
		if err != nil {
			d.instances[name] = &instance{
				status:    api.StatusFailed,
				errMsg:    err.Error(),
				createdAt: time.Now(),
				create:    api.CreateParams{Mux: name},
			}
			continue
		}
		inst := &instance{
			status:     api.StatusStored,
			createdAt:  rec.UpdatedAt,
			create:     api.CreateParams{Mux: name, BackendAddress: rec.BackendAddress},
			spec:       rec.Spec,
			selections: rec.Selections,
		}
		if rec.Engine != "" && rec.Engine != d.cfg.Engine {
			inst.status = api.StatusOrphaned
		}
		d.instances[name] = inst
	}
}

// Restore activates stored instances: kernel instances are adopted
// when their kernel objects are still there and complete, everything
// else is rebuilt from its stored spec. A failed activation is
// recorded on the instance and never blocks the others (or daemon
// startup).
func (d *Daemon) Restore() {
	d.mu.Lock()
	names := make([]string, 0, len(d.instances))
	for name := range d.instances {
		names = append(names, name)
	}
	d.mu.Unlock()
	sort.Strings(names)
	for _, name := range names {
		d.mu.Lock()
		inst := d.instances[name]
		d.mu.Unlock()
		if inst == nil {
			continue
		}
		inst.op.Lock()
		if status, _ := inst.getStatus(); !inst.dead && status == api.StatusStored && inst.spec != nil {
			d.activateLocked(inst)
		}
		inst.op.Unlock()
	}
}

// activateLocked materializes an instance from its stored spec and
// selections (merged): adoption first (kernel engines), rebuild
// otherwise. Caller holds inst.op.
func (d *Daemon) activateLocked(inst *instance) {
	_, eff, sel, err := mergeSpec(inst.spec, inst.selections, *inst.spec, false)
	if err != nil {
		inst.setStatus(api.StatusFailed, fmt.Sprintf("restore: %v", err))
		return
	}
	eng, err := d.factory(inst.create)
	if err != nil {
		inst.setStatus(api.StatusFailed, err.Error())
		return
	}
	if ad, ok := eng.(engine.Adopter); ok {
		if adopted, _ := ad.Adopt(eff); adopted {
			inst.eng = eng
			inst.selections = sel
			inst.setStatus(api.StatusAdopted, "")
			return
		}
	}
	if err := eng.Apply(eff); err != nil {
		inst.setStatus(api.StatusFailed, fmt.Sprintf("restore: %v", err))
		return
	}
	inst.eng = eng
	inst.selections = sel
	inst.setStatus(api.StatusRestored, "")
}

// validMuxName reports whether name can name a mux instance. The
// mux name is also the front interface's name, so it must be a
// legal interface name.
func validMuxName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if r == '/' || r == ':' || r == ' ' || r == '\t' || r == '\n' {
			return false
		}
	}
	return true
}

func (d *Daemon) Create(params api.CreateParams) error {
	if !validMuxName(params.Mux) {
		return fmt.Errorf("create: mux name %q is not a valid interface name (1-15 chars, no '/' or whitespace)", params.Mux)
	}
	d.mu.Lock()
	if _, exists := d.instances[params.Mux]; exists {
		d.mu.Unlock()
		return fmt.Errorf("mux %q already exists (creation parameters are immutable; destroy it first to change them)", params.Mux)
	}
	eng, err := d.factory(params)
	if err != nil {
		d.mu.Unlock()
		return err
	}
	inst := &instance{
		eng:       eng,
		status:    api.StatusActive,
		createdAt: time.Now(),
		create:    params,
	}
	// Hold the instance's op lock from before it becomes visible, so
	// a concurrent Destroy cannot interleave with the initial persist.
	inst.op.Lock()
	defer inst.op.Unlock()
	d.instances[params.Mux] = inst
	d.mu.Unlock()
	return d.persistLocked(inst)
}

// lockInst finds the instance and acquires its operation lock. The
// registry mutex is NOT held while waiting for it.
func (d *Daemon) lockInst(mux string) (*instance, error) {
	d.mu.Lock()
	inst, ok := d.instances[mux]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no mux instance %q (create it first)", mux)
	}
	inst.op.Lock()
	if inst.dead {
		inst.op.Unlock()
		return nil, fmt.Errorf("no mux instance %q (create it first)", mux)
	}
	return inst, nil
}

func orphanErr(mux string) error {
	return fmt.Errorf("mux %q is orphaned: its stored spec belongs to a daemon of a different engine kind; this daemon leaves it untouched", mux)
}

// live returns the instance's engine if it has one.
func live(inst *instance) (engine.Engine, error) {
	if status, _ := inst.getStatus(); status == api.StatusOrphaned {
		return nil, orphanErr(inst.create.Mux)
	}
	if inst.eng == nil {
		status, _ := inst.getStatus()
		return nil, fmt.Errorf("mux %q is %s and has no live engine", inst.create.Mux, status)
	}
	return inst.eng, nil
}

// leftoverPurge asks a Purger engine to remove whatever the
// instance name left behind. Non-Purger engines have nothing to do.
func leftoverPurge(eng engine.Engine) error {
	if pg, ok := eng.(engine.Purger); ok {
		return pg.Purge()
	}
	return nil
}

func (d *Daemon) Apply(req api.ApplyRequest) error {
	inst, err := d.lockInst(req.Mux)
	if err != nil {
		return err
	}
	defer inst.op.Unlock()
	if status, _ := inst.getStatus(); status == api.StatusOrphaned {
		return orphanErr(req.Mux)
	}
	base, eff, sel, err := mergeSpec(inst.spec, inst.selections, req.Spec, req.ResetSelections)
	if err != nil {
		return fmt.Errorf("apply %s: %w", req.Mux, err)
	}
	eng := inst.eng
	fresh := eng == nil
	if fresh {
		// Stored / failed instance: build its engine for this apply
		// and clear whatever a previous process or a failed attempt
		// left under its name, so we neither collide with nor leak it.
		eng, err = d.factory(inst.create)
		if err != nil {
			return err
		}
		if err := leftoverPurge(eng); err != nil {
			return fmt.Errorf("apply %s: purge leftovers: %w", req.Mux, err)
		}
	}
	if err := eng.Apply(eff); err != nil {
		return d.applyFailed(inst, eng, fresh, err)
	}
	inst.eng = eng
	inst.spec = &base
	inst.selections = sel
	inst.setStatus(api.StatusActive, "")
	return d.persistLocked(inst)
}

// applyFailed handles a failed engine Apply: a fresh engine is
// discarded (instance unchanged); a live one is rolled back to the
// last good spec. The store is never touched — it keeps the last
// successful spec.
func (d *Daemon) applyFailed(inst *instance, eng engine.Engine, fresh bool, applyErr error) error {
	if fresh {
		eng.Close()
		leftoverPurge(eng)
		return applyErr
	}
	if inst.spec == nil {
		return applyErr // created but never applied: nothing to roll back to
	}
	_, prevEff, _, rerr := mergeSpec(inst.spec, inst.selections, *inst.spec, false)
	if rerr == nil {
		rerr = eng.Apply(prevEff)
	}
	if rerr == nil {
		inst.setStatus(api.StatusActive, fmt.Sprintf("apply failed (rolled back): %v", applyErr))
		return applyErr
	}
	eng.Close()
	leftoverPurge(eng)
	inst.eng = nil
	inst.setStatus(api.StatusFailed, fmt.Sprintf("apply failed and rollback failed: %v (rollback: %v)", applyErr, rerr))
	return applyErr
}

func (d *Daemon) Destroy(req api.MuxRequest) error {
	inst, err := d.lockInst(req.Mux)
	if err != nil {
		return err
	}
	defer inst.op.Unlock()
	if status, _ := inst.getStatus(); status == api.StatusOrphaned {
		return fmt.Errorf("mux %q is orphaned (owned by a daemon of a different engine kind); not destroying it", req.Mux)
	}
	if inst.eng != nil {
		cerr := inst.eng.Close()
		if perr := leftoverPurge(inst.eng); cerr == nil {
			cerr = perr
		}
		if cerr != nil {
			return fmt.Errorf("destroy %s: %w", req.Mux, cerr)
		}
	} else {
		// No live engine (stored / failed): the datapath may still
		// exist. A Purger removes it by name.
		eng, err := d.factory(inst.create)
		if err != nil {
			return err
		}
		if err := leftoverPurge(eng); err != nil {
			return fmt.Errorf("destroy %s: purge: %w", req.Mux, err)
		}
	}
	if d.store != nil {
		if err := d.store.Delete(req.Mux); err != nil {
			return err
		}
	}
	inst.dead = true
	d.mu.Lock()
	delete(d.instances, req.Mux)
	d.mu.Unlock()
	return nil
}

// peerKnown reports whether the spec has a peer of that name.
func peerKnown(spec *api.ApplySpec, name string) bool {
	for _, p := range spec.Peers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// SetSelection is the decision point every control-plane policy uses.
func (d *Daemon) SetSelection(req api.SetSelectionRequest) error {
	inst, err := d.lockInst(req.Mux)
	if err != nil {
		return err
	}
	defer inst.op.Unlock()
	eng, err := live(inst)
	if err != nil {
		return err
	}
	if inst.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", req.Mux)
	}
	cidr, ipnet, err := canonCIDR(req.CIDR)
	if err != nil {
		return err
	}
	var ps *api.PrefixSpec
	for i := range inst.spec.Prefixes {
		if inst.spec.Prefixes[i].CIDR == cidr {
			ps = &inst.spec.Prefixes[i]
			break
		}
	}
	if ps == nil {
		return fmt.Errorf("mux %q: prefix %s is not steered by the applied spec", req.Mux, cidr)
	}
	if err := validateSelection(inst.spec, *ps, req.Selection); err != nil {
		return err
	}
	sel := append([]api.PeerWeight(nil), req.Selection...)
	if err := eng.SetSelection(ipnet, sel); err != nil {
		return err
	}
	if inst.selections == nil {
		inst.selections = map[string][]api.PeerWeight{}
	}
	inst.selections[cidr] = sel
	if err := d.persistLocked(inst); err != nil {
		return fmt.Errorf("selection applied but not persisted: %w", err)
	}
	return nil
}

// FlushPeer invalidates every flow pin to one peer.
func (d *Daemon) FlushPeer(req api.FlushPeerRequest) error {
	inst, err := d.lockInst(req.Mux)
	if err != nil {
		return err
	}
	defer inst.op.Unlock()
	eng, err := live(inst)
	if err != nil {
		return err
	}
	if inst.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", req.Mux)
	}
	if !peerKnown(inst.spec, req.Peer) {
		return fmt.Errorf("mux %q: unknown peer %q", req.Mux, req.Peer)
	}
	return eng.FlushPeer(req.Peer)
}

func (d *Daemon) State(req api.MuxRequest) (api.State, error) {
	inst, err := d.lockInst(req.Mux)
	if err != nil {
		return api.State{}, err
	}
	defer inst.op.Unlock()
	status, errMsg := inst.getStatus()
	st := api.State{
		Mux:    req.Mux,
		Engine: d.cfg.Engine,
		Status: status,
		Error:  errMsg,
	}
	if inst.eng == nil {
		return st, nil
	}
	es, err := inst.eng.State()
	if err != nil {
		return st, err
	}
	es.Mux = req.Mux
	es.Engine = d.cfg.Engine
	es.Status = status
	es.Error = errMsg
	return es, nil
}

func (d *Daemon) List() ([]api.InstanceInfo, error) {
	d.mu.Lock()
	insts := make(map[string]*instance, len(d.instances))
	for name, inst := range d.instances {
		insts[name] = inst
	}
	d.mu.Unlock()
	out := make([]api.InstanceInfo, 0, len(insts))
	for name, inst := range insts {
		status, errMsg := inst.getStatus()
		out = append(out, api.InstanceInfo{
			Mux:            name,
			Engine:         d.cfg.Engine,
			Status:         status,
			Error:          errMsg,
			BackendAddress: inst.create.BackendAddress,
			CreatedAt:      inst.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mux < out[j].Mux })
	return out, nil
}

func (d *Daemon) Info() (api.DaemonInfo, error) {
	return api.DaemonInfo{
		APIVersion:   api.Version,
		Engine:       d.cfg.Engine,
		Interconnect: d.cfg.Interconnect,
		Attach:       d.cfg.Attach,
		PinRoot:      d.cfg.PinRoot,
		StateDir:     d.cfg.StateDir,
		Restore:      d.cfg.Restore,
	}, nil
}

// persistLocked writes the instance's record to the spec store.
// Persistence failures are surfaced: a silently unpersisted
// instance would silently not come back. Caller holds inst.op.
func (d *Daemon) persistLocked(inst *instance) error {
	if d.store == nil {
		return nil
	}
	return d.store.Put(Record{
		Version:        StoreVersion,
		Name:           inst.create.Mux,
		Engine:         d.cfg.Engine,
		BackendAddress: inst.create.BackendAddress,
		Spec:           inst.spec,
		Selections:     inst.selections,
		UpdatedAt:      time.Now(),
	})
}

// ---- spec merging -------------------------------------------------

// canonCIDR parses a CIDR and returns its canonical (masked) text.
func canonCIDR(s string) (string, *net.IPNet, error) {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", nil, fmt.Errorf("prefix %q: %w", s, err)
	}
	return n.String(), n, nil
}

// validateSelection validates sel for a prefix of spec: the api
// rules (non-empty, candidates, no duplicates, single = one peer)
// plus every peer must exist in the spec.
func validateSelection(spec *api.ApplySpec, p api.PrefixSpec, sel []api.PeerWeight) error {
	if err := p.ValidateSelection(sel); err != nil {
		return err
	}
	for _, w := range sel {
		if !peerKnown(spec, w.Peer) {
			return fmt.Errorf("prefix %s: peer %q is not in the spec", p.CIDR, w.Peer)
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameSelection(a, b []api.PeerWeight) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Peer != b[i].Peer || a[i].EffectiveWeight() != b[i].EffectiveWeight() {
			return false
		}
	}
	return true
}

// mergeSpec turns a requested spec into (base, effective, kept):
//
//   - base is next with canonical CIDRs: what the store records as
//     the configured spec;
//   - effective is base with every prefix's Selection resolved and
//     validated (never empty) — what engines get. A prefix keeps its
//     runtime override from prevSel iff the override exists, reset is
//     false, the prefix existed in prev with equal Candidates, mode
//     and configured Selection, and the override still validates;
//     otherwise the configured EffectiveSelection is used and the
//     override dropped;
//   - kept holds the surviving overrides.
//
// It is pure: errors leave nothing changed.
func mergeSpec(prev *api.ApplySpec, prevSel map[string][]api.PeerWeight, next api.ApplySpec, reset bool) (base, eff api.ApplySpec, kept map[string][]api.PeerWeight, err error) {
	prevPrefix := map[string]api.PrefixSpec{}
	if prev != nil {
		for _, p := range prev.Prefixes {
			if c, _, cerr := canonCIDR(p.CIDR); cerr == nil {
				prevPrefix[c] = p
			}
		}
	}
	base = next
	base.Peers = append([]api.PeerSpec(nil), next.Peers...)
	base.Prefixes = make([]api.PrefixSpec, 0, len(next.Prefixes))
	eff = base
	eff.Prefixes = make([]api.PrefixSpec, 0, len(next.Prefixes))
	kept = map[string][]api.PeerWeight{}
	seen := map[string]bool{}
	for _, p := range next.Prefixes {
		cidr, _, cerr := canonCIDR(p.CIDR)
		if cerr != nil {
			return base, eff, nil, cerr
		}
		if seen[cidr] {
			return base, eff, nil, fmt.Errorf("prefix %s listed twice", cidr)
		}
		seen[cidr] = true
		p.CIDR = cidr
		p.Candidates = append([]string(nil), p.Candidates...)
		p.Selection = append([]api.PeerWeight(nil), p.Selection...)
		if len(p.Selection) == 0 {
			p.Selection = nil
		}
		for _, c := range p.Candidates {
			if !peerKnown(&next, c) {
				return base, eff, nil, fmt.Errorf("prefix %s: candidate %q is not a peer in the spec", cidr, c)
			}
		}
		if len(p.Selection) > 0 {
			if verr := validateSelection(&next, p, p.Selection); verr != nil {
				return base, eff, nil, fmt.Errorf("configured selection: %w", verr)
			}
		}
		sel := p.EffectiveSelection()
		if verr := validateSelection(&next, p, sel); verr != nil {
			return base, eff, nil, verr
		}
		if ov, ok := prevSel[cidr]; ok && !reset {
			if pp, ok := prevPrefix[cidr]; ok &&
				sameStrings(pp.Candidates, p.Candidates) &&
				pp.EffectiveMode() == p.EffectiveMode() &&
				sameSelection(pp.Selection, p.Selection) &&
				validateSelection(&next, p, ov) == nil {
				sel = ov
				kept[cidr] = append([]api.PeerWeight(nil), ov...)
			}
		}
		base.Prefixes = append(base.Prefixes, p)
		ep := p
		ep.Selection = append([]api.PeerWeight(nil), sel...)
		eff.Prefixes = append(eff.Prefixes, ep)
	}
	return base, eff, kept, nil
}
