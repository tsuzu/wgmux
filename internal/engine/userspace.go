package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/steer"
)

// userspaceMux is the userspace Engine: one mux instance realized
// as wireguard-go devices hosted by this process. There is no
// network namespace and no BPF: the front is a single TUN device in
// the main namespace, each peer is a wireguard-go device.Device
// over an in-memory chanTUN, and a Go pump steers plaintext packets
// between them using the same steering entries (internal/steer) the
// kernel engine programs into its BPF maps.
//
// The daemon is the crypto datapath here and must keep running —
// the asymmetry with the kernel engine is inherent to where the
// crypto lives, not a difference in the Engine contract.
type userspaceMux struct {
	name string

	mu       sync.Mutex
	spec     *api.ApplySpec
	front    tun.Device
	main     *netlink.Handle
	routes   []*netlink.Route
	peers    map[uint32]*userspacePeer // by peer ID
	byName   map[string]*userspacePeer
	table    *steer.Table
	flows    *flowTable
	sel      map[string][]api.PeerWeight // canonical CIDR -> current selection
	counters pumpCounters
	stop     chan struct{}
	wg       sync.WaitGroup
}

type userspacePeer struct {
	id   uint32
	gen  atomic.Uint32 // pin generation; FlushPeer bumps it
	spec api.PeerSpec
	dev  *device.Device
	vt   *chanTUN
}

func newUserspaceMux(name string) *userspaceMux {
	return &userspaceMux{name: name}
}

// frontName resolves the front TUN's name: the applied spec's,
// else the instance name (the same by construction).
func (m *userspaceMux) frontName() string {
	if m.spec != nil && m.spec.Front.Name != "" {
		return m.spec.Front.Name
	}
	return m.name
}

func (m *userspaceMux) Apply(spec api.ApplySpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec != nil && reflect.DeepEqual(m.spec.Front, spec.Front) &&
		m.spec.ManageRoutes == spec.ManageRoutes &&
		reflect.DeepEqual(m.spec.Peers, spec.Peers) {
		return m.applyInPlaceLocked(spec)
	}
	if m.spec != nil {
		if err := m.closeLocked(); err != nil {
			return fmt.Errorf("replace existing state: %w", err)
		}
	}
	mtu := spec.Front.MTU
	if mtu == 0 {
		mtu = 1420
	}
	entries, err := steer.EntriesFromSpec(spec.Prefixes, PeerIDs(spec), nil)
	if err != nil {
		return err
	}
	sel, err := selectionsOf(spec)
	if err != nil {
		return err
	}
	table := steer.NewTable(entries)
	flows := newFlowTable(65536)

	frontName := spec.Front.Name
	if frontName == "" {
		frontName = m.name
	}
	front, err := tun.CreateTUN(frontName, mtu)
	if err != nil {
		return fmt.Errorf("create front TUN %s: %w", frontName, err)
	}
	// fail unwinds everything built so far, in local variables.
	var (
		main   *netlink.Handle
		routes []*netlink.Route
		peers  = map[uint32]*userspacePeer{}
		byName = map[string]*userspacePeer{}
	)
	fail := func(err error) error {
		for _, p := range peers {
			p.dev.Close()
		}
		if main != nil {
			for _, r := range routes {
				main.RouteDel(r)
			}
			main.Close()
		}
		front.Close()
		return err
	}
	main, err = netlink.NewHandle()
	if err != nil {
		return fail(fmt.Errorf("netlink handle: %w", err))
	}
	link, err := main.LinkByName(frontName)
	if err != nil {
		return fail(fmt.Errorf("find front TUN %s: %w", frontName, err))
	}
	addr, err := netlink.ParseAddr(spec.Front.Address)
	if err != nil {
		return fail(fmt.Errorf("front address %q: %w", spec.Front.Address, err))
	}
	if err := main.AddrAdd(link, addr); err != nil {
		return fail(fmt.Errorf("assign front address: %w", err))
	}
	if err := main.LinkSetUp(link); err != nil {
		return fail(fmt.Errorf("up front TUN: %w", err))
	}
	if spec.ManageRoutes {
		for _, p := range spec.Prefixes {
			_, dst, err := net.ParseCIDR(p.CIDR)
			if err != nil {
				return fail(err)
			}
			// Dev-only route: the front TUN is point-to-point, so
			// there is no gateway (the kernel engine's route via
			// the backend address is its interconnect's shape).
			r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
			if err := main.RouteReplace(r); err != nil {
				return fail(fmt.Errorf("route %s via front: %w", p.CIDR, err))
			}
			routes = append(routes, r)
		}
	}
	for _, pspec := range spec.Peers {
		vt := newChanTUN("wgmux-go-"+pspec.Name, mtu)
		p := &userspacePeer{id: pspec.ID, spec: pspec, vt: vt}
		vt.onWrite = func(pkt []byte) { m.fromPeer(front, flows, p, pkt) }
		dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wgmux-go "+pspec.Name+": "))
		uapi, err := buildUAPI(pspec)
		if err != nil {
			dev.Close()
			return fail(err)
		}
		if err := dev.IpcSet(uapi); err != nil {
			dev.Close()
			return fail(fmt.Errorf("configure wireguard-go %s: %w", pspec.Name, err))
		}
		if err := dev.Up(); err != nil {
			dev.Close()
			return fail(fmt.Errorf("up wireguard-go %s: %w", pspec.Name, err))
		}
		p.dev = dev
		peers[pspec.ID] = p
		byName[pspec.Name] = p
	}

	m.front = front
	m.main = main
	m.routes = routes
	m.peers = peers
	m.byName = byName
	m.table = table
	m.flows = flows
	m.sel = sel
	m.stop = make(chan struct{})
	m.wg.Add(1)
	go m.frontLoop(front, peers, table, flows, m.stop)
	specCopy := spec
	m.spec = &specCopy
	return nil
}

// forwardFromFront steers one plaintext packet read from the front
// TUN to its peer, mirroring the BPF mux_from_front + select_peer:
// a flow pin wins if it is valid (its peer exists and the peer's
// generation still equals the pin's), else the steering table
// decides and the choice is pinned with the peer's current
// generation. Unsteered destinations are dropped (the front is a
// dead end; the kernel datapath passes such packets into a backend
// stack that has nowhere for them either).
func (m *userspaceMux) forwardFromFront(pkt []byte, peers map[uint32]*userspacePeer, table *steer.Table, flows *flowTable) {
	m.counters.frontEntries.Add(1)
	fk, ok := parseFlow(pkt)
	if !ok {
		m.counters.frontUnsteered.Add(1)
		return
	}
	var p *userspacePeer
	if pin, found := flows.get(fk); found {
		if pp := peers[pin.peer]; pp != nil && pp.gen.Load() == pin.gen {
			p = pp
			m.counters.frontPinHits.Add(1)
		} else {
			m.counters.frontPinStale.Add(1)
		}
	}
	if p == nil {
		entry, ok := table.Lookup(net.IP(pkt[16:20]))
		if !ok {
			m.counters.frontUnsteered.Add(1)
			return
		}
		p = peers[entry.Pick(fk)]
		if p == nil { // NoPeer slot or unknown peer ID
			m.counters.frontNoPeer.Add(1)
			return
		}
		flows.put(fk, flowVal{peer: p.id, gen: p.gen.Load()})
	}
	if !p.vt.enqueue(pkt) {
		m.counters.frontDrops.Add(1)
		return
	}
	m.counters.frontRedirects.Add(1)
}

// tunWriteHeadroom is the scratch space a native TUN may require
// in front of the packet on Write: a vnet-hdr TUN reads a virtio-net
// header at [offset-10:offset) and fails the write without it.
// Zeroes are a valid header (GSO_NONE — one unfragmented packet),
// and a TUN without vnet-hdr simply skips the offset. (wireguard-go's
// own device passes its TUN writes with headroom for this reason;
// offset 0 works for Read but NOT for Write.)
const tunWriteHeadroom = 16

// fromPeer handles one decrypted packet arriving from a peer: pin
// the reverse flow to the peer with its current generation (as
// mux_from_wg does) and write the packet to the front TUN.
func (m *userspaceMux) fromPeer(front tun.Device, flows *flowTable, p *userspacePeer, pkt []byte) {
	m.counters.wgEntries.Add(1)
	if fk, ok := parseFlow(pkt); ok {
		flows.put(fk.Reverse(), flowVal{peer: p.id, gen: p.gen.Load()})
	}
	buf := make([]byte, tunWriteHeadroom+len(pkt))
	copy(buf[tunWriteHeadroom:], pkt)
	if _, err := front.Write([][]byte{buf}, tunWriteHeadroom); err != nil {
		m.counters.wgDrops.Add(1)
		return
	}
	m.counters.wgRedirects.Add(1)
}

func (m *userspaceMux) frontLoop(front tun.Device, peers map[uint32]*userspacePeer, table *steer.Table, flows *flowTable, stop chan struct{}) {
	defer m.wg.Done()
	batch := front.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := front.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			// A read error outside shutdown (should not happen for
			// a TUN we own): back off briefly instead of spinning.
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		for i := 0; i < n; i++ {
			pkt := append([]byte(nil), bufs[i][:sizes[i]]...)
			m.forwardFromFront(pkt, peers, table, flows)
		}
	}
}

// selectionsOf records every prefix's effective selection by
// canonical CIDR.
func selectionsOf(spec api.ApplySpec) (map[string][]api.PeerWeight, error) {
	out := make(map[string][]api.PeerWeight, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return nil, fmt.Errorf("prefix %q: %w", p.CIDR, err)
		}
		out[ipnet.String()] = append([]api.PeerWeight(nil), p.EffectiveSelection()...)
	}
	return out, nil
}

// prevSlots snapshots the table's current slot tables by key.
func prevSlots(t *steer.Table) map[steer.SteeringKey]steer.SlotTable {
	out := map[steer.SteeringKey]steer.SlotTable{}
	for _, e := range t.Entries() {
		out[e.Key()] = e.Slots
	}
	return out
}

// applyInPlaceLocked re-applies a spec whose Front, ManageRoutes
// and Peers are unchanged: only the steering entries (compiled
// against the current slots, so staying peers keep their slots) and
// the routes of added/removed prefixes change. No device, TUN or
// pump churn; flow pins survive. Caller holds m.mu.
func (m *userspaceMux) applyInPlaceLocked(spec api.ApplySpec) error {
	entries, err := steer.EntriesFromSpec(spec.Prefixes, PeerIDs(spec), prevSlots(m.table))
	if err != nil {
		return err
	}
	sel, err := selectionsOf(spec)
	if err != nil {
		return err
	}
	if spec.ManageRoutes && m.main != nil {
		if err := m.syncRoutesLocked(spec.Prefixes); err != nil {
			return err
		}
	}
	m.table.Replace(entries)
	m.sel = sel
	specCopy := spec
	m.spec = &specCopy
	return nil
}

// syncRoutesLocked makes the front TUN's routes match prefixes:
// routes for added prefixes first (rolled back on failure), then
// removal of routes for dropped ones (best-effort).
func (m *userspaceMux) syncRoutesLocked(prefixes []api.PrefixSpec) error {
	link, err := m.main.LinkByName(m.frontName())
	if err != nil {
		return fmt.Errorf("find front TUN %s: %w", m.frontName(), err)
	}
	want := map[string]*net.IPNet{}
	var order []string
	for _, p := range prefixes {
		_, dst, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return err
		}
		if _, dup := want[dst.String()]; !dup {
			order = append(order, dst.String())
		}
		want[dst.String()] = dst
	}
	have := map[string]*netlink.Route{}
	for _, r := range m.routes {
		have[r.Dst.String()] = r
	}
	var added []*netlink.Route
	for _, k := range order {
		if _, ok := have[k]; ok {
			continue
		}
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: want[k]}
		if err := m.main.RouteReplace(r); err != nil {
			for _, a := range added {
				m.main.RouteDel(a)
			}
			return fmt.Errorf("route %s via front: %w", k, err)
		}
		added = append(added, r)
	}
	var routes []*netlink.Route
	for _, r := range m.routes {
		if _, ok := want[r.Dst.String()]; ok {
			routes = append(routes, r)
		} else {
			m.main.RouteDel(r) // best effort, as in teardown
		}
	}
	m.routes = append(routes, added...)
	return nil
}

func (m *userspaceMux) SetSelection(prefix *net.IPNet, sel []api.PeerWeight) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", m.name)
	}
	key := steer.KeyOf(prefix)
	prev, ok := prevSlots(m.table)[key]
	if !ok {
		return fmt.Errorf("prefix %s is not steered by mux %q", prefix, m.name)
	}
	wp, err := steer.ToWeighted(sel, PeerIDs(*m.spec))
	if err != nil {
		return err
	}
	if err := m.table.SetSlots(key, steer.BuildSlots(&prev, wp)); err != nil {
		return err
	}
	canon := &net.IPNet{IP: prefix.IP.Mask(prefix.Mask), Mask: prefix.Mask}
	m.sel[canon.String()] = append([]api.PeerWeight(nil), sel...)
	return nil
}

// FlushPeer bumps the peer's pin generation: every flow pinned to it
// is stale from its next packet on and re-steers through the table.
func (m *userspaceMux) FlushPeer(peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return fmt.Errorf("mux %q: nothing applied", m.name)
	}
	p := m.byName[peer]
	if p == nil {
		return fmt.Errorf("mux %q: unknown peer %q", m.name, peer)
	}
	p.gen.Add(1)
	return nil
}

func (m *userspaceMux) State() (api.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := api.State{Mux: m.name, Engine: api.EngineUserspace}
	if m.spec == nil {
		return st, fmt.Errorf("mux %q: nothing applied", m.name)
	}
	names := map[uint32]string{}
	for _, pspec := range m.spec.Peers {
		names[pspec.ID] = pspec.Name
		p := m.byName[pspec.Name]
		pst := api.PeerState{Name: pspec.Name, ID: pspec.ID}
		if p != nil && p.dev != nil {
			dump, err := p.dev.IpcGet()
			if err != nil {
				return st, fmt.Errorf("ipcget %s: %w", pspec.Name, err)
			}
			parseUAPIState(dump, &pst)
		}
		st.Peers = append(st.Peers, pst)
	}
	slots := prevSlots(m.table)
	for _, ps := range m.spec.Prefixes {
		_, ipnet, err := net.ParseCIDR(ps.CIDR)
		if err != nil {
			continue
		}
		pst := api.PrefixState{
			CIDR:       ipnet.String(),
			Candidates: append([]string(nil), ps.Candidates...),
			Mode:       ps.EffectiveMode(),
			Policy:     ps.Policy,
			Selection:  append([]api.PeerWeight(nil), m.sel[ipnet.String()]...),
		}
		if pst.Policy == "" {
			pst.Policy = api.PolicyStatic
		}
		if tbl, ok := slots[steer.KeyOf(ipnet)]; ok {
			pst.Slots = map[string]int{}
			for id, n := range tbl.Share() {
				if name, ok := names[id]; ok {
					pst.Slots[name] = n
				}
			}
		}
		st.Prefixes = append(st.Prefixes, pst)
	}
	st.Counters = m.counters.snapshot()
	return st, nil
}

func (m *userspaceMux) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spec == nil {
		return nil
	}
	return m.closeLocked()
}

// closeLocked stops the pump and tears the instance down. Caller
// holds m.mu and has checked m.spec != nil.
func (m *userspaceMux) closeLocked() error {
	close(m.stop)
	// Closing the front unblocks the pump's Read and fails peer
	// writes toward it; then wait for the pump to exit.
	m.front.Close()
	m.wg.Wait()
	var firstErr error
	for _, p := range m.peers {
		p.dev.Close()
	}
	// Route cleanup is best-effort only: the front link is deleted
	// right below, which flushes its routes anyway, and a route the
	// kernel no longer has (deleted externally, or an attribute
	// mismatch on delete) must not fail the teardown.
	for _, r := range m.routes {
		m.main.RouteDel(r)
	}
	if link, err := m.main.LinkByName(m.frontName()); err == nil {
		m.main.LinkDel(link)
	}
	m.main.Close()
	m.spec = nil
	m.front = nil
	m.main = nil
	m.routes = nil
	m.peers = nil
	m.byName = nil
	m.table = nil
	m.flows = nil
	m.sel = nil
	return firstErr
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

// buildUAPI renders a PeerSpec as wireguard-go UAPI configuration text.
// Keys are hex in UAPI (base64 in our API/config).
func buildUAPI(spec api.PeerSpec) (string, error) {
	priv, err := keyHex(spec.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("peer %q private key: %w", spec.Name, err)
	}
	pub, err := keyHex(spec.PublicKey)
	if err != nil {
		return "", fmt.Errorf("peer %q public key: %w", spec.Name, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if spec.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", spec.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if spec.PresharedKey != "" {
		psk, err := keyHex(spec.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("peer %q preshared key: %w", spec.Name, err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	if spec.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", spec.Endpoint)
	}
	if spec.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", spec.PersistentKeepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, cidr := range spec.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}
	return b.String(), nil
}

func parseUAPIState(dump string, st *api.PeerState) {
	var sec, nsec int64
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "endpoint":
			st.Endpoint = v
		case "rx_bytes":
			st.BytesReceived, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.BytesSent, _ = strconv.ParseUint(v, 10, 64)
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if sec > 0 {
		st.LastHandshake = time.Unix(sec, nsec)
	}
}
