// Package daemon is the data-plane daemon (wgmuxd): the api.Handler
// implementation. It is the only component that touches the kernel.
// It keeps no policy of its own — every selection decision arrives as
// an ApplySpec or a SetActive call from a control-plane process.
package daemon

import (
	"fmt"
	"net"
	"sync"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/datapath"
	"github.com/tsuzu/wgmux/internal/engine"
	"github.com/tsuzu/wgmux/internal/steer"
	"github.com/tsuzu/wgmux/internal/topology"
)

type Daemon struct {
	mu   sync.Mutex
	spec *api.ApplySpec
	topo *topology.Topology
	eng  engine.Engine
}

func New() *Daemon { return &Daemon{} }

// Apply reconciles the datapath to the desired spec by rebuilding it.
// (Rebuild is the honest v1 semantic: peers are cheap to recreate, and
// the steering maps are repopulated before re-attach.)
func (d *Daemon) Apply(spec api.ApplySpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.spec != nil {
		if err := d.destroyLocked(); err != nil {
			return fmt.Errorf("replace existing state: %w", err)
		}
	}
	topo, err := topology.Open(spec)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		topo.Teardown()
		return err
	}
	mtu := spec.MTU
	if mtu == 0 {
		mtu = 1420
	}
	eng, err := engine.New(spec.Engine, &engine.Context{
		BackendNS:     spec.BackendNS,
		BackendHandle: topo.BackendNsHandle(),
		Main:          topo.Main,
		Backend:       topo.Backend,
		MTU:           mtu,
	})
	if err != nil {
		return fail(err)
	}
	info, err := topo.BuildInterconnect()
	if err != nil {
		eng.Close()
		return fail(err)
	}
	for _, peer := range spec.Peers {
		ref, err := eng.AddPeer(peer)
		if err != nil {
			eng.Close()
			return fail(fmt.Errorf("add peer %s: %w", peer.Name, err))
		}
		info.PeerIfindex[peer.ID] = ref.Ifindex
		info.PeerDevice[peer.ID] = ref.DeviceName
	}
	entries, err := entriesFromSpec(spec)
	if err != nil {
		eng.Close()
		return fail(err)
	}
	if err := datapath.Apply(spec, *info, entries); err != nil {
		eng.Close()
		return fail(err)
	}
	if spec.ManageRoutes {
		if err := topo.AddRoutes(); err != nil {
			eng.Close()
			return fail(err)
		}
	}
	d.topo = topo
	d.eng = eng
	specCopy := spec
	d.spec = &specCopy
	return nil
}

func entriesFromSpec(spec api.ApplySpec) ([]steer.Entry, error) {
	out := make([]steer.Entry, 0, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return nil, err
		}
		ones, _ := ipnet.Mask.Size()
		e := steer.Entry{PrefixLen: uint32(ones), Addr: steer.WireAddr(ipnet.IP)}
		for i, id := range p.CandidateIDs {
			if i >= steer.MaxCandidates {
				return nil, fmt.Errorf("prefix %s: too many candidates", p.CIDR)
			}
			e.PeerIDs[i] = id
			if id == p.ActiveID {
				e.Active = uint8(i)
			}
		}
		e.Count = uint8(len(p.CandidateIDs))
		if p.Policy == "hash" {
			e.Policy = steer.PolicyHash
		}
		out = append(out, e)
	}
	return out, nil
}

func (d *Daemon) Destroy() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.spec == nil {
		return fmt.Errorf("nothing applied")
	}
	return d.destroyLocked()
}

func (d *Daemon) destroyLocked() error {
	pinDir := d.spec.PinDir
	// Engine first for the userspace engine (its peers are processes
	// state); kernel peers die with the namespace in Teardown anyway.
	var firstErr error
	if d.eng != nil {
		firstErr = d.eng.Close()
	}
	if err := datapath.Unpin(pinDir); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := d.topo.Teardown(); err != nil && firstErr == nil {
		firstErr = err
	}
	d.spec = nil
	d.topo = nil
	d.eng = nil
	return firstErr
}

// SetActive is the decision point every control-plane policy uses.
func (d *Daemon) SetActive(req api.SetActiveRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.spec == nil {
		return fmt.Errorf("nothing applied")
	}
	_, ipnet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return err
	}
	return datapath.SetActive(d.spec.PinDir, ipnet, req.PeerID)
}

func (d *Daemon) State() (api.State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.spec == nil {
		return api.State{}, fmt.Errorf("nothing applied")
	}
	st := api.State{Engine: d.spec.Engine}
	peers, err := d.eng.Peers()
	if err != nil {
		return st, err
	}
	st.Peers = peers
	snap, err := datapath.SteeringSnapshot(d.spec.PinDir)
	if err != nil {
		return st, err
	}
	for _, p := range d.spec.Prefixes {
		ps := api.PrefixState{CIDR: p.CIDR, CandidateIDs: p.CandidateIDs, ActiveID: p.ActiveID, Policy: p.Policy}
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err == nil {
			ones, _ := ipnet.Mask.Size()
			key := steer.SteeringKey{PrefixLen: uint32(ones), Addr: steer.WireAddr(ipnet.IP)}
			if val, ok := snap[key]; ok {
				if int(val.Active) < len(val.PeerIDs) {
					ps.ActiveID = val.PeerIDs[val.Active]
				}
				if val.Policy == steer.PolicyHash {
					ps.Policy = "hash"
				} else {
					ps.Policy = "active"
				}
			}
		}
		st.Prefixes = append(st.Prefixes, ps)
	}
	return st, nil
}
