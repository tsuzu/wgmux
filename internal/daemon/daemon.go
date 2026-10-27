// Package daemon is the data-plane daemon (wgmuxd): the api.Handler
// implementation. It is a registry of mux instances: Create builds
// one engine.Engine per mux name from construction parameters that
// stay fixed for the instance's lifetime; Apply / SetActive / State
// are then delegated to the addressed instance. The daemon keeps no
// policy of its own — every selection decision arrives from a
// control-plane process.
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

type instance struct {
	eng       engine.Engine
	createdAt time.Time
}

type Daemon struct {
	mu        sync.Mutex
	factory   engine.Factory
	instances map[string]*instance
}

// New builds a Daemon with the production engine factory. pinRoot
// is a daemon-startup setting (wgmuxd -pin-root): the bpffs base
// from which kernel instances derive their pin dirs. The engine
// kind is NOT a daemon setting — it is per-instance, fixed at
// Create.
func New(pinRoot string) *Daemon {
	return NewWithFactory(engine.New(pinRoot))
}

// NewWithFactory builds a Daemon on an injected engine factory
// (tests use fakes that touch no kernel state).
func NewWithFactory(f engine.Factory) *Daemon {
	return &Daemon{factory: f, instances: map[string]*instance{}}
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
	d.instances[params.Mux] = &instance{eng: eng, createdAt: time.Now()}
	return nil
}

func (d *Daemon) instance(mux string) (engine.Engine, error) {
	inst, ok := d.instances[mux]
	if !ok {
		return nil, fmt.Errorf("no mux instance %q (create it first)", mux)
	}
	return inst.eng, nil
}

func (d *Daemon) Apply(req api.ApplyRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	eng, err := d.instance(req.Mux)
	if err != nil {
		return err
	}
	return eng.Apply(req.Spec)
}

func (d *Daemon) Destroy(req api.MuxRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	eng, err := d.instance(req.Mux)
	if err != nil {
		return err
	}
	err = eng.Close()
	delete(d.instances, req.Mux)
	return err
}

// SetActive is the decision point every control-plane policy uses.
func (d *Daemon) SetActive(req api.SetActiveRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	eng, err := d.instance(req.Mux)
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
	eng, err := d.instance(req.Mux)
	if err != nil {
		return api.State{}, err
	}
	return eng.State()
}

func (d *Daemon) List() ([]api.InstanceInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]api.InstanceInfo, 0, len(d.instances))
	for name, inst := range d.instances {
		cp := inst.eng.CreationParams()
		out = append(out, api.InstanceInfo{
			Mux:       name,
			Engine:    inst.eng.Kind(),
			Kernel:    cp.Kernel,
			CreatedAt: inst.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mux < out[j].Mux })
	return out, nil
}
