// Package daemon is the data-plane daemon (wgmuxd): the
// api.Handler implementation. It is a registry of mux instances of
// ONE engine kind — the kind is a daemon-startup choice, and the
// factory builds instances of that kind only. Create builds one
// engine.Engine per mux name; Apply / SetActive / State delegate to
// the addressed instance. The daemon keeps no policy of its own —
// every selection decision arrives from a control-plane process.
//
// Persistence: every create/apply is recorded in a spec store
// (see store.go). On startup the daemon restores from the store:
// kernel instances whose kernel objects survived are adopted
// untouched; the rest are rebuilt from their stored specs; store
// entries belonging to the other engine kind are reported as
// orphaned and left alone. Stopping the daemon never tears
// anything down — destruction is only ever the explicit Destroy.
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
	eng       engine.Engine // nil while stored / failed / orphaned
	status    string        // api.Status*
	errMsg    string
	createdAt time.Time
	create    api.CreateParams
	spec      *api.ApplySpec
}

type Daemon struct {
	mu        sync.Mutex
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
	d.restore()
	return d, nil
}

// NewWithFactory builds a Daemon on an injected engine factory
// (tests use fakes that touch no kernel state). cfg.Engine still
// names the daemon's kind for reporting and orphan detection. The
// store is loaded (instances registered), but activation happens
// only when cfg.Restore is set — call Restore to run it.
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
			status:    api.StatusStored,
			createdAt: rec.UpdatedAt,
			create:    api.CreateParams{Mux: name, BackendAddress: rec.BackendAddress},
			spec:      rec.Spec,
		}
		if rec.Engine != "" && rec.Engine != d.cfg.Engine {
			inst.status = api.StatusOrphaned
		}
		d.instances[name] = inst
	}
}

// Restore activates stored instances: kernel instances are adopted
// when their kernel objects are still there, everything else is
// rebuilt from its stored spec. A failed activation is recorded on
// the instance and never blocks the others (or daemon startup).
func (d *Daemon) Restore() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.restoreLocked()
}

func (d *Daemon) restore() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg.Restore {
		d.restoreLocked()
	}
}

func (d *Daemon) restoreLocked() {
	names := make([]string, 0, len(d.instances))
	for name := range d.instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		inst := d.instances[name]
		if inst.status != api.StatusStored || inst.spec == nil {
			continue // orphaned, failed, or nothing applied yet
		}
		d.activateLocked(inst, *inst.spec)
	}
}

// activateLocked materializes an instance from a spec: adoption
// first (kernel engines), rebuild otherwise. Caller holds d.mu.
func (d *Daemon) activateLocked(inst *instance, spec api.ApplySpec) {
	eng, err := d.factory(inst.create)
	if err != nil {
		inst.status = api.StatusFailed
		inst.errMsg = err.Error()
		return
	}
	if ad, ok := eng.(engine.Adopter); ok {
		if adopted, _ := ad.Adopt(spec); adopted {
			inst.eng = eng
			inst.status = api.StatusAdopted
			inst.errMsg = ""
			return
		}
	}
	if err := eng.Apply(spec); err != nil {
		inst.status = api.StatusFailed
		inst.errMsg = fmt.Sprintf("restore: %v", err)
		return
	}
	inst.eng = eng
	inst.status = api.StatusRestored
	inst.errMsg = ""
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
	defer d.mu.Unlock()
	if _, exists := d.instances[params.Mux]; exists {
		return fmt.Errorf("mux %q already exists (creation parameters are immutable; destroy it first to change them)", params.Mux)
	}
	eng, err := d.factory(params)
	if err != nil {
		return err
	}
	inst := &instance{
		eng:       eng,
		status:    api.StatusActive,
		createdAt: time.Now(),
		create:    params,
	}
	d.instances[params.Mux] = inst
	return d.persistLocked(inst)
}

func (d *Daemon) get(mux string) (*instance, error) {
	inst, ok := d.instances[mux]
	if !ok {
		return nil, fmt.Errorf("no mux instance %q (create it first)", mux)
	}
	return inst, nil
}

// live returns the instance's engine if it has one. Orphaned
// instances are not this daemon's to touch.
func (d *Daemon) live(inst *instance) (engine.Engine, error) {
	if inst.status == api.StatusOrphaned {
		return nil, fmt.Errorf("mux %q is orphaned: its stored spec belongs to a daemon of a different engine kind; this daemon leaves it untouched", inst.create.Mux)
	}
	if inst.eng == nil {
		return nil, fmt.Errorf("mux %q is %s and has no live engine", inst.create.Mux, inst.status)
	}
	return inst.eng, nil
}

func (d *Daemon) Apply(req api.ApplyRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst, err := d.get(req.Mux)
	if err != nil {
		return err
	}
	eng, err := d.live(inst)
	if err != nil {
		if inst.status == api.StatusOrphaned {
			return err
		}
		// Stored / failed instance: build its engine fresh for
		// this apply (its stored creation parameters).
		fresh, ferr := d.factory(inst.create)
		if ferr != nil {
			return ferr
		}
		eng = fresh
	}
	if err := eng.Apply(req.Spec); err != nil {
		return err
	}
	inst.eng = eng
	specCopy := req.Spec
	inst.spec = &specCopy
	inst.status = api.StatusActive
	inst.errMsg = ""
	return d.persistLocked(inst)
}

func (d *Daemon) Destroy(req api.MuxRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst, err := d.get(req.Mux)
	if err != nil {
		return err
	}
	if inst.status == api.StatusOrphaned {
		return fmt.Errorf("mux %q is orphaned (owned by a daemon of a different engine kind); not destroying it", req.Mux)
	}
	var closeErr error
	if inst.eng != nil {
		closeErr = inst.eng.Close()
	}
	delete(d.instances, req.Mux)
	if d.store != nil {
		if err := d.store.Delete(req.Mux); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

// SetActive is the decision point every control-plane policy uses.
func (d *Daemon) SetActive(req api.SetActiveRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst, err := d.get(req.Mux)
	if err != nil {
		return err
	}
	eng, err := d.live(inst)
	if err != nil {
		return err
	}
	_, ipnet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return err
	}
	return eng.SetActive(ipnet, req.PeerID)
}

func (d *Daemon) State(req api.MuxRequest) (api.State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst, err := d.get(req.Mux)
	if err != nil {
		return api.State{}, err
	}
	st := api.State{
		Mux:    req.Mux,
		Engine: d.cfg.Engine,
		Status: inst.status,
		Error:  inst.errMsg,
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
	es.Status = inst.status
	es.Error = inst.errMsg
	return es, nil
}

func (d *Daemon) List() ([]api.InstanceInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]api.InstanceInfo, 0, len(d.instances))
	for name, inst := range d.instances {
		out = append(out, api.InstanceInfo{
			Mux:            name,
			Engine:         d.cfg.Engine,
			Status:         inst.status,
			Error:          inst.errMsg,
			BackendAddress: inst.create.BackendAddress,
			CreatedAt:      inst.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mux < out[j].Mux })
	return out, nil
}

func (d *Daemon) Info() (api.DaemonInfo, error) {
	return api.DaemonInfo{
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
// instance would silently not come back.
func (d *Daemon) persistLocked(inst *instance) error {
	if d.store == nil {
		return nil
	}
	return d.store.Put(Record{
		Name:           inst.create.Mux,
		Engine:         d.cfg.Engine,
		BackendAddress: inst.create.BackendAddress,
		Spec:           inst.spec,
		UpdatedAt:      time.Now(),
	})
}
