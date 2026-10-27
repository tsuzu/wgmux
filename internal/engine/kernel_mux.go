package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Apply reconciles the instance to the desired spec by rebuilding
// it. (Rebuild is the honest v1 semantic: peers are cheap to
// recreate, and the steering maps are repopulated before re-attach.)
func (m *kernelMux) Apply(spec api.ApplySpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec != nil {
		if err := m.teardownLocked(); err != nil {
			return fmt.Errorf("replace existing state: %w", err)
		}
	}
	backendAddr, err := m.backendAddress(spec.Front.Address)
	if err != nil {
		return err
	}
	mtu := spec.Front.MTU
	if mtu == 0 {
		mtu = 1420
	}
	prefixCIDRs := make([]string, 0, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		prefixCIDRs = append(prefixCIDRs, p.CIDR)
	}
	topo, err := topology.Open(topology.Params{
		BackendNS:      m.kp.BackendNS,
		Interconnect:   m.kp.Interconnect,
		FrontName:      m.frontName(&spec),
		FrontAddress:   spec.Front.Address,
		BackendAddress: backendAddr,
		MTU:            mtu,
		ManageRoutes:   spec.ManageRoutes,
		Prefixes:       prefixCIDRs,
	})
	if err != nil {
		return err
	}
	fail := func(err error) error {
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
	entries, err := steer.EntriesFromSpec(spec.Prefixes)
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
	m.topo = topo
	m.peers = peers
	specCopy := spec
	m.spec = &specCopy
	return nil
}

func (m *kernelMux) teardownLocked() error {
	// Peers die with the namespace in Teardown anyway; unpin the
	// datapath first so nothing references the maps.
	var firstErr error
	if err := datapath.Unpin(m.kp.PinDir); err != nil {
		firstErr = err
	}
	if err := m.topo.Teardown(); err != nil && firstErr == nil {
		firstErr = err
	}
	m.spec = nil
	m.topo = nil
	m.peers = nil
	return firstErr
}

func (m *kernelMux) SetActive(prefix *net.IPNet, peerID uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", m.name)
	}
	return datapath.SetActive(m.kp.PinDir, prefix, peerID)
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
	snap, err := datapath.SteeringSnapshot(m.kp.PinDir)
	if err != nil {
		return st, err
	}
	for _, p := range m.spec.Prefixes {
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
// present, steering map openable — and only then wires up in-memory
// handles (topology handles, peer spec table). It never calls
// datapath.Apply and never reconfigures a device: the datapath is
// not touched. (false, nil) means the objects are not (fully)
// there; the caller falls back to a rebuild Apply.
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

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec != nil {
		return true, nil // already live
	}
	backendAddr, err := m.backendAddress(spec.Front.Address)
	if err != nil {
		return false, nil
	}
	mtu := spec.Front.MTU
	if mtu == 0 {
		mtu = 1420
	}
	prefixCIDRs := make([]string, 0, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		prefixCIDRs = append(prefixCIDRs, p.CIDR)
	}
	topo, err := topology.Open(topology.Params{
		BackendNS:      m.kp.BackendNS,
		Interconnect:   m.kp.Interconnect,
		FrontName:      m.frontName(&spec),
		FrontAddress:   spec.Front.Address,
		BackendAddress: backendAddr,
		MTU:            mtu,
		ManageRoutes:   spec.ManageRoutes,
		Prefixes:       prefixCIDRs,
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
	return true, nil
}
