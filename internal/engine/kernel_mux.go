package engine

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/vishvananda/netns"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/datapath"
	"github.com/tsuzu/wgmux/internal/steer"
	"github.com/tsuzu/wgmux/internal/topology"
)

// kernelParams are the kernel engine's per-instance parameters.
// Everything here is either a daemon-startup setting (interconnect,
// attach, pin root) or derived from the instance name (backend ns,
// pin dir) — the user configures none of it directly. The single
// per-instance creation input is the backend-address override.
type kernelParams struct {
	BackendNS      string // wgmux-<name>
	Interconnect   string // daemon startup
	Attach         string // daemon startup
	PinDir         string // <pin root>/wgmux/<name>
	BackendAddress string // creation override; "" = derive at first Apply
}

// kernelMux is the kernel Engine: one mux instance realized as
// per-peer in-tree WireGuard devices in a per-instance backend
// namespace, steered by the BPF datapath. It owns the topology, the
// peer devices and the pinned maps; teardown is "delete the whole
// namespace".
type kernelMux struct {
	name string
	kp   kernelParams

	mu              sync.Mutex
	spec            *api.ApplySpec
	topo            *topology.Topology
	peers           *kernelPeers
	resolvedBackend string
	sel             map[string][]api.PeerWeight // canonical CIDR -> current selection
}

func newKernelMux(params api.CreateParams, opts DaemonOptions) *kernelMux {
	return &kernelMux{
		name: params.Mux,
		kp: kernelParams{
			BackendNS:      "wgmux-" + params.Mux,
			Interconnect:   opts.Interconnect,
			Attach:         opts.Attach,
			PinDir:         filepath.Join(opts.PinRoot, "wgmux", params.Mux),
			BackendAddress: params.BackendAddress,
		},
	}
}

// frontName resolves the front interface name: the spec's, else the
// instance name (they are the same by construction).
func (m *kernelMux) frontName(spec *api.ApplySpec) string {
	if spec.Front.Name != "" {
		return spec.Front.Name
	}
	return m.name
}

// backendAddress resolves the interconnect's backend-end address:
// the construction parameter if set, else derived ONCE from the
// first applied front address (the first host address of the front
// subnet, or the second when the front itself is the first) and
// memoized — it is a creation parameter, so it must not drift
// across re-applies.
func (m *kernelMux) backendAddress(front string) (string, error) {
	if m.kp.BackendAddress != "" {
		return m.kp.BackendAddress, nil
	}
	defer func() {
		if m.resolvedBackend != "" {
			m.kp.BackendAddress = m.resolvedBackend
		}
	}()
	ip, ipnet, err := net.ParseCIDR(front)
	if err != nil {
		return "", fmt.Errorf("front address %q: %w", front, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return "", fmt.Errorf("cannot derive a backend address from front %q; set the kernel backend_address construction parameter", front)
	}
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	cand := base + 1
	if cand == binary.BigEndian.Uint32(ip.To4()) {
		cand = base + 2
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], cand)
	m.resolvedBackend = fmt.Sprintf("%s/%d", net.IPv4(b[0], b[1], b[2], b[3]), ones)
	return m.resolvedBackend, nil
}

// canonCIDR returns the canonical (masked) text of a CIDR.
func canonCIDR(s string) (string, *net.IPNet, error) {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", nil, fmt.Errorf("prefix %q: %w", s, err)
	}
	return n.String(), n, nil
}

// specHash is the completed-apply marker written to runtime_cfg: FNV-1a
// 64 over the JSON of the spec with every prefix Selection cleared
// (selections change at runtime without re-applying, so they are not
// part of the identity). 0 is reserved for "apply in progress", so a
// zero hash maps to 1.
func specHash(spec api.ApplySpec) uint64 {
	c := spec
	c.Prefixes = make([]api.PrefixSpec, len(spec.Prefixes))
	for i, p := range spec.Prefixes {
		p.Selection = nil
		c.Prefixes[i] = p
	}
	raw, err := json.Marshal(c)
	if err != nil {
		raw = []byte(err.Error())
	}
	h := fnv.New64a()
	h.Write(raw)
	if v := h.Sum64(); v != 0 {
		return v
	}
	return 1
}

func (m *kernelMux) mtu(spec *api.ApplySpec) int {
	if spec.Front.MTU == 0 {
		return 1420
	}
	return spec.Front.MTU
}

// prefixCIDRs returns the canonical CIDR of every prefix.
func prefixCIDRs(spec *api.ApplySpec) ([]string, error) {
	out := make([]string, 0, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		c, _, err := canonCIDR(p.CIDR)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// loadSelections records the in-memory selection of every prefix
// from a (merged) spec.
func (m *kernelMux) loadSelections(spec *api.ApplySpec) {
	m.sel = map[string][]api.PeerWeight{}
	for _, p := range spec.Prefixes {
		if c, _, err := canonCIDR(p.CIDR); err == nil {
			m.sel[c] = append([]api.PeerWeight(nil), p.EffectiveSelection()...)
		}
	}
}

// inPlaceOK reports whether next differs from cur only in prefixes
// (candidates/modes/selections), so the programs, devices and
// namespace can stay untouched.
func inPlaceOK(cur, next *api.ApplySpec) bool {
	return reflect.DeepEqual(cur.Front, next.Front) &&
		cur.ManageRoutes == next.ManageRoutes &&
		reflect.DeepEqual(cur.Peers, next.Peers)
}

// Apply reconciles the instance to the desired spec. When only the
// prefixes changed it updates the steering map in place (no device,
// namespace or program churn; flow pins survive); otherwise it
// rebuilds. The spec-hash marker is written last, so an interrupted
// apply is never adoptable.
func (m *kernelMux) Apply(spec api.ApplySpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := specHash(spec)
	if m.spec != nil && m.topo != nil && inPlaceOK(m.spec, &spec) {
		return m.applyInPlaceLocked(spec, h)
	}
	if m.spec != nil {
		if err := m.teardownLocked(); err != nil {
			return fmt.Errorf("replace existing state: %w", err)
		}
	} else if err := m.purgeLocked(); err != nil {
		return fmt.Errorf("purge leftovers: %w", err)
	}
	return m.rebuildLocked(spec, h)
}

func (m *kernelMux) applyInPlaceLocked(spec api.ApplySpec, h uint64) error {
	cidrs, err := prefixCIDRs(&spec)
	if err != nil {
		return err
	}
	if err := datapath.SetSpecHash(m.kp.PinDir, 0); err != nil {
		return fmt.Errorf("mark apply in progress: %w", err)
	}
	prev, err := datapath.SteeringSnapshot(m.kp.PinDir)
	if err != nil {
		return fmt.Errorf("read steering map: %w", err)
	}
	entries, err := steer.EntriesFromSpec(spec.Prefixes, PeerIDs(spec), prev)
	if err != nil {
		return err
	}
	if err := datapath.ReplaceSteering(m.kp.PinDir, entries); err != nil {
		return fmt.Errorf("replace steering: %w", err)
	}
	if spec.ManageRoutes {
		if err := m.topo.SetPrefixes(cidrs); err != nil {
			return err
		}
	}
	if err := datapath.SetSpecHash(m.kp.PinDir, h); err != nil {
		return fmt.Errorf("mark apply complete: %w", err)
	}
	specCopy := spec
	m.spec = &specCopy
	m.loadSelections(&spec)
	return nil
}

func (m *kernelMux) rebuildLocked(spec api.ApplySpec, h uint64) error {
	backendAddr, err := m.backendAddress(spec.Front.Address)
	if err != nil {
		return err
	}
	mtu := m.mtu(&spec)
	cidrs, err := prefixCIDRs(&spec)
	if err != nil {
		return err
	}
	topo, err := topology.Open(topology.Params{
		BackendNS:      m.kp.BackendNS,
		Interconnect:   m.kp.Interconnect,
		FrontName:      m.frontName(&spec),
		FrontAddress:   spec.Front.Address,
		BackendAddress: backendAddr,
		MTU:            mtu,
		ManageRoutes:   spec.ManageRoutes,
		Prefixes:       cidrs,
	})
	if err != nil {
		return err
	}
	fail := func(err error) error {
		datapath.Unpin(m.kp.PinDir)
		os.Remove(filepath.Join(m.kp.PinDir, datapath.MapDebug))
		os.Remove(m.kp.PinDir)
		topo.Teardown()
		return err
	}
	peers := newKernelPeers(&Context{
		BackendNS:     m.kp.BackendNS,
		BackendHandle: topo.BackendNsHandle(),
		Main:          topo.Main,
		Backend:       topo.Backend,
		MTU:           mtu,
	})
	info, err := topo.BuildInterconnect()
	if err != nil {
		return fail(err)
	}
	for _, peer := range spec.Peers {
		ref, err := peers.AddPeer(peer)
		if err != nil {
			return fail(fmt.Errorf("add peer %s: %w", peer.Name, err))
		}
		info.PeerIfindex[peer.ID] = ref.Ifindex
		info.PeerDevice[peer.ID] = ref.DeviceName
	}
	entries, err := steer.EntriesFromSpec(spec.Prefixes, PeerIDs(spec), nil)
	if err != nil {
		return fail(err)
	}
	if err := datapath.Apply(datapath.Params{
		BackendNS:    m.kp.BackendNS,
		Interconnect: m.kp.Interconnect,
		Attach:       m.kp.Attach,
		PinDir:       m.kp.PinDir,
	}, *info, entries); err != nil {
		return fail(err)
	}
	if spec.ManageRoutes {
		if err := topo.AddRoutes(); err != nil {
			return fail(err)
		}
	}
	// Very last: the completed-apply marker.
	if err := datapath.SetSpecHash(m.kp.PinDir, h); err != nil {
		return fail(fmt.Errorf("mark apply complete: %w", err))
	}
	m.topo = topo
	m.peers = peers
	specCopy := spec
	m.spec = &specCopy
	m.loadSelections(&spec)
	return nil
}

func (m *kernelMux) teardownLocked() error {
	// Peers die with the namespace in Teardown anyway; unpin the
	// datapath first so nothing references the maps.
	var firstErr error
	if err := datapath.Unpin(m.kp.PinDir); err != nil {
		firstErr = err
	}
	os.Remove(filepath.Join(m.kp.PinDir, datapath.MapDebug))
	os.Remove(m.kp.PinDir)
	if err := m.topo.Teardown(); err != nil && firstErr == nil {
		firstErr = err
	}
	m.spec = nil
	m.topo = nil
	m.peers = nil
	m.sel = nil
	return firstErr
}

// Purge removes everything derived from the instance name without
// needing live handles: pinned maps/links (all of them, debug map
// included), the backend namespace, and the main-namespace front
// link — the latter only if it is a veth/netkit. Idempotent.
func (m *kernelMux) Purge() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.purgeLocked()
}

func (m *kernelMux) purgeLocked() error {
	front := m.name
	if m.spec != nil {
		front = m.frontName(m.spec)
	}
	var errs []error
	if err := datapath.Unpin(m.kp.PinDir); err != nil {
		errs = append(errs, err)
	}
	if err := os.Remove(filepath.Join(m.kp.PinDir, datapath.MapDebug)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := os.Remove(m.kp.PinDir); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := topology.Purge(m.kp.BackendNS, front); err != nil {
		errs = append(errs, err)
	}
	if m.topo != nil {
		m.topo.Backend.Close()
		m.topo.Main.Close()
		nsh := m.topo.BackendNsHandle()
		nsh.Close()
	}
	m.spec, m.topo, m.peers, m.sel = nil, nil, nil, nil
	return errors.Join(errs...)
}

// SetSelection compiles the new selection against the live slot
// table (so only the slots that must move do) and writes it. Pins
// are untouched: established flows stay (graceful).
func (m *kernelMux) SetSelection(prefix *net.IPNet, sel []api.PeerWeight) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", m.name)
	}
	cidr := prefix.String()
	var ps *api.PrefixSpec
	for i := range m.spec.Prefixes {
		if c, _, err := canonCIDR(m.spec.Prefixes[i].CIDR); err == nil && c == cidr {
			ps = &m.spec.Prefixes[i]
			break
		}
	}
	if ps == nil {
		return fmt.Errorf("mux %q: prefix %s is not steered", m.name, cidr)
	}
	one := *ps
	one.CIDR = cidr
	one.Selection = sel
	prev, err := datapath.SteeringSnapshot(m.kp.PinDir)
	if err != nil {
		return fmt.Errorf("read steering map: %w", err)
	}
	entries, err := steer.EntriesFromSpec([]api.PrefixSpec{one}, PeerIDs(*m.spec), prev)
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("compile selection for %s: got %d entries", cidr, len(entries))
	}
	if err := datapath.SetSlots(m.kp.PinDir, entries[0].Key(), entries[0].Slots); err != nil {
		return err
	}
	m.sel[cidr] = append([]api.PeerWeight(nil), sel...)
	return nil
}

// FlushPeer invalidates every flow pin to the peer (generation bump).
func (m *kernelMux) FlushPeer(peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", m.name)
	}
	id, ok := PeerIDs(*m.spec)[peer]
	if !ok {
		return fmt.Errorf("mux %q: unknown peer %q", m.name, peer)
	}
	return datapath.BumpPeerGen(m.kp.PinDir, id)
}

func (m *kernelMux) State() (api.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := api.State{Mux: m.name}
	if m.spec == nil {
		return st, fmt.Errorf("mux %q: nothing applied", m.name)
	}
	peers, err := m.peers.Peers()
	if err != nil {
		return st, err
	}
	st.Peers = peers
	names := map[uint32]string{}
	for _, p := range m.spec.Peers {
		names[p.ID] = p.Name
	}
	snap, snapErr := datapath.SteeringSnapshot(m.kp.PinDir)
	for _, p := range m.spec.Prefixes {
		cidr, ipnet, cerr := canonCIDR(p.CIDR)
		sel := p.EffectiveSelection()
		if cerr == nil {
			if s, ok := m.sel[cidr]; ok {
				sel = s
			}
		}
		ps := api.PrefixState{
			CIDR: p.CIDR, Candidates: p.Candidates, Mode: p.EffectiveMode(),
			Policy: p.Policy, Selection: append([]api.PeerWeight(nil), sel...),
		}
		if cerr == nil && snapErr == nil {
			if table, ok := snap[steer.KeyOf(ipnet)]; ok {
				ps.Slots = map[string]int{}
				for id, n := range table.Share() {
					name, known := names[id]
					if !known {
						name = fmt.Sprintf("id%d", id)
					}
					ps.Slots[name] = n
				}
			}
		}
		st.Prefixes = append(st.Prefixes, ps)
	}
	if counters, err := datapath.Counters(m.kp.PinDir); err == nil {
		st.Counters = counters
	}
	return st, nil
}

func (m *kernelMux) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return nil
	}
	return m.teardownLocked()
}

// Adopt re-attaches this instance to kernel objects a previous
// daemon process left behind (see docs/design.md, "Persistence and
// recovery"). It probes first — backend namespace present, pin dir
// present, steering map readable — and requires the spec-hash marker
// in runtime_cfg to equal the hash of spec, proving the objects are
// the product of a COMPLETED apply of this same spec (not a crash
// mid-apply, nor a different spec). Only then does it wire up
// in-memory handles, peer spec table and selections (from the
// merged spec). It never calls datapath.Apply and never reconfigures
// a device. (false, nil) means not adoptable; the caller rebuilds.
func (m *kernelMux) Adopt(spec api.ApplySpec) (bool, error) {
	h, err := netns.GetFromName(m.kp.BackendNS)
	if err != nil {
		return false, nil
	}
	h.Close()
	if _, err := os.Stat(m.kp.PinDir); err != nil {
		return false, nil
	}
	sm, err := datapath.OpenPinnedSteering(m.kp.PinDir)
	if err != nil {
		return false, nil
	}
	sm.Close()
	if _, err := datapath.SteeringSnapshot(m.kp.PinDir); err != nil {
		return false, nil
	}
	got, err := datapath.SpecHash(m.kp.PinDir)
	if err != nil || got == 0 || got != specHash(spec) {
		return false, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec != nil {
		return true, nil // already live
	}
	backendAddr, err := m.backendAddress(spec.Front.Address)
	if err != nil {
		return false, nil
	}
	cidrs, err := prefixCIDRs(&spec)
	if err != nil {
		return false, nil
	}
	mtu := m.mtu(&spec)
	topo, err := topology.Open(topology.Params{
		BackendNS:      m.kp.BackendNS,
		Interconnect:   m.kp.Interconnect,
		FrontName:      m.frontName(&spec),
		FrontAddress:   spec.Front.Address,
		BackendAddress: backendAddr,
		MTU:            mtu,
		ManageRoutes:   spec.ManageRoutes,
		Prefixes:       cidrs,
	})
	if err != nil {
		return false, nil
	}
	peers := newKernelPeers(&Context{
		BackendNS:     m.kp.BackendNS,
		BackendHandle: topo.BackendNsHandle(),
		Main:          topo.Main,
		Backend:       topo.Backend,
		MTU:           mtu,
	})
	peers.adoptSpecs(spec.Peers)
	m.topo = topo
	m.peers = peers
	specCopy := spec
	m.spec = &specCopy
	m.loadSelections(&spec)
	return true, nil
}
