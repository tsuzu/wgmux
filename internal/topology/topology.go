// Package topology builds the namespace plumbing the datapath lives
// in — the one part that is neither engine nor steering:
//
//   - the hidden backend network namespace,
//   - the single interconnect pair (veth or netkit) whose front end is
//     the only interface visible in the main namespace,
//   - optionally, the main-namespace routes toward the front (unless an
//     external routing daemon such as FRR/zebra owns them).
package topology

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/datapath"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

// BackName is the backend end of the interconnect pair.
const BackName = "mux-b"

// Params describes one mux instance's topology: the kernel engine
// resolves it from its construction parameters plus the applied
// front spec.
type Params struct {
	BackendNS      string
	Interconnect   string // config.InterconnectVeth | config.InterconnectNetkit
	FrontName      string
	FrontAddress   string // CIDR
	BackendAddress string // CIDR
	MTU            int
	ManageRoutes   bool
	Prefixes       []string // steered prefix CIDRs, for the main-ns routes
}

// Topology holds the namespace handles for a built topology.
type Topology struct {
	p       Params
	Main    *netlink.Handle
	Backend *netlink.Handle
	nsH     netns.NsHandle
}

// Open creates the backend namespace and returns handles to both
// namespaces.
func Open(spec Params) (*Topology, error) {
	main, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	nsH, err := netnsutil.CreateNamed(spec.BackendNS)
	if err != nil {
		main.Close()
		return nil, err
	}
	backend, err := netlink.NewHandleAt(nsH)
	if err != nil {
		nsH.Close()
		main.Close()
		return nil, err
	}
	if lo, err := backend.LinkByName("lo"); err == nil {
		backend.LinkSetUp(lo)
	}
	if spec.Interconnect == config.InterconnectVeth {
		// Veth mode only: packets returning from a Peer's wg
		// device take one stack hop through the backend (see
		// mux_from_wg in bpf/mux.c for why the redirect cannot
		// be used in this direction). That needs forwarding on
		// and rp_filter off (return sources are the steered
		// prefixes, which the backend has no routes for).
		err := netnsutil.WithNetNS(spec.BackendNS, func() error {
			for path, val := range map[string]string{
				"/proc/sys/net/ipv4/ip_forward":             "1",
				"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
				"/proc/sys/net/ipv4/conf/default/rp_filter": "0",
			} {
				if err := os.WriteFile(path, []byte(val), 0o644); err != nil {
					return fmt.Errorf("backend sysctl %s: %w", path, err)
				}
			}
			return nil
		})
		if err != nil {
			nsH.Close()
			main.Close()
			return nil, err
		}
	}
	return &Topology{p: spec, Main: main, Backend: backend, nsH: nsH}, nil
}

// BackendHandle exposes the namespace handle (engines need it to move
// devices in and to create TUNs).
func (t *Topology) BackendNsHandle() netns.NsHandle { return t.nsH }

// BuildInterconnect creates the pair and fills the datapath Info with
// everything except the peers (engines provide those separately).
func (t *Topology) BuildInterconnect() (*datapath.Info, error) {
	spec := t.p
	mtu := spec.MTU
	if mtu == 0 {
		mtu = 1420
	}
	front, err := t.Main.LinkByName(spec.FrontName)
	if err == nil {
		// Never adopt an unrelated interface that happens to carry
		// the front's name.
		if !isPairLink(front) {
			return nil, fmt.Errorf("refusing to use existing interface %q (type %q) as the mux front: it is not a veth/netkit pair; remove or rename it", spec.FrontName, front.Type())
		}
	} else {
		switch spec.Interconnect {
		case config.InterconnectVeth:
			veth := &netlink.Veth{
				LinkAttrs:     netlink.LinkAttrs{Name: spec.FrontName, MTU: mtu},
				PeerName:      BackName,
				PeerNamespace: netlink.NsFd(int(t.nsH)),
			}
			if err := t.Main.LinkAdd(veth); err != nil {
				return nil, fmt.Errorf("create veth pair: %w", err)
			}
		case config.InterconnectNetkit:
			nk := &netlink.Netkit{
				LinkAttrs:  netlink.LinkAttrs{Name: spec.FrontName, MTU: mtu},
				Mode:       netlink.NETKIT_MODE_L3,
				Policy:     netlink.NETKIT_POLICY_FORWARD,
				PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
			}
			nk.SetPeerAttrs(&netlink.LinkAttrs{
				Name:      BackName,
				MTU:       mtu,
				Namespace: netlink.NsFd(int(t.nsH)),
			})
			if err := t.Main.LinkAdd(nk); err != nil {
				return nil, fmt.Errorf("create netkit pair (kernel >= 6.7?): %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown interconnect %q", spec.Interconnect)
		}
		front, err = t.Main.LinkByName(spec.FrontName)
		if err != nil {
			return nil, err
		}
	}
	back, err := t.Backend.LinkByName(BackName)
	if err != nil {
		stray, lerr := t.Main.LinkByName(BackName)
		if lerr != nil || !isPairLink(stray) {
			return nil, fmt.Errorf("backend end %s not found in the backend namespace", BackName)
		}
		if err := t.Main.LinkSetNsFd(stray, int(t.nsH)); err != nil {
			return nil, fmt.Errorf("move %s to backend: %w", BackName, err)
		}
		back, err = t.Backend.LinkByName(BackName)
		if err != nil {
			return nil, err
		}
	}
	// NB: netlink.ParseAddr, not net.ParseCIDR's second return value:
	// the IPNet from ParseCIDR carries the masked network address
	// (10.200.0.0), which would assign the network address itself to
	// the interface instead of the host address (10.200.0.2).
	if addr, err := netlink.ParseAddr(spec.FrontAddress); err == nil {
		t.Main.AddrAdd(front, addr)
	}
	if addr, err := netlink.ParseAddr(spec.BackendAddress); err == nil {
		t.Backend.AddrAdd(back, addr)
	}
	if err := t.Main.LinkSetUp(front); err != nil {
		return nil, fmt.Errorf("up front: %w", err)
	}
	if err := t.Backend.LinkSetUp(back); err != nil {
		return nil, fmt.Errorf("up back: %w", err)
	}
	info := &datapath.Info{
		BackIfindex: back.Attrs().Index,
		PeerIfindex: map[uint32]int{},
		PeerDevice:  map[uint32]string{},
	}
	if spec.Interconnect == config.InterconnectVeth {
		copy(info.FrontMAC[:], front.Attrs().HardwareAddr)
		copy(info.BackMAC[:], back.Attrs().HardwareAddr)
	}
	return info, nil
}

// AddRoutes installs one route per prefix via the front interface
// (gateway = the backend end's address): a single FIB lookup in the
// main namespace, exactly as with a direct WireGuard device.
func (t *Topology) AddRoutes() error {
	front, err := t.Main.LinkByName(t.p.FrontName)
	if err != nil {
		return err
	}
	backendIP, _, err := net.ParseCIDR(t.p.BackendAddress)
	if err != nil {
		return err
	}
	for _, cidr := range t.p.Prefixes {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		route := &netlink.Route{
			LinkIndex: front.Attrs().Index,
			Dst:       dst,
			Gw:        backendIP,
		}
		if err := t.Main.RouteReplace(route); err != nil {
			return fmt.Errorf("route %s via front: %w", cidr, err)
		}
	}
	return nil
}

// Teardown removes routes, the front interface, and the backend
// namespace (destroying every device inside it, including engine
// peers that live there).
func (t *Topology) Teardown() error {
	if t.p.ManageRoutes {
		backendIP, _, _ := net.ParseCIDR(t.p.BackendAddress)
		for _, cidr := range t.p.Prefixes {
			_, dst, err := net.ParseCIDR(cidr)
			if err == nil {
				t.Main.RouteDel(&netlink.Route{Dst: dst, Gw: backendIP})
			}
		}
	}
	if front, err := t.Main.LinkByName(t.p.FrontName); err == nil && isPairLink(front) {
		t.Main.LinkDel(front)
	}
	err := netnsutil.DeleteNamed(t.p.BackendNS)
	t.Backend.Close()
	t.Main.Close()
	t.nsH.Close()
	return err
}

// isPairLink reports whether l is an interconnect-type link (veth or
// netkit) — the only link types wgmux ever creates as a front, and so
// the only ones it may delete or reuse.
func isPairLink(l netlink.Link) bool {
	t := l.Type()
	return t == "veth" || t == "netkit"
}

// Purge removes an instance's topology WITHOUT live handles: the
// main-namespace front link (only if it is a veth/netkit; any other
// same-named link is left alone) and the backend namespace. Routes
// via the front go away with the link. Idempotent.
func Purge(backendNS, frontName string) error {
	main, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer main.Close()
	if front, err := main.LinkByName(frontName); err == nil && isPairLink(front) {
		if err := main.LinkDel(front); err != nil {
			return fmt.Errorf("delete front %s: %w", frontName, err)
		}
	}
	return netnsutil.DeleteNamed(backendNS)
}

// SetPrefixes updates the set of steered prefixes the main-namespace
// routes follow (in-place re-apply): routes of removed prefixes are
// deleted, routes of the new set are (re)installed. Without
// ManageRoutes only the bookkeeping changes.
func (t *Topology) SetPrefixes(prefixes []string) error {
	old := t.p.Prefixes
	t.p.Prefixes = prefixes
	if !t.p.ManageRoutes {
		return nil
	}
	backendIP, _, _ := net.ParseCIDR(t.p.BackendAddress)
	keep := map[string]bool{}
	for _, c := range prefixes {
		if _, n, err := net.ParseCIDR(c); err == nil {
			keep[n.String()] = true
		}
	}
	for _, c := range old {
		_, dst, err := net.ParseCIDR(c)
		if err != nil || keep[dst.String()] {
			continue
		}
		t.Main.RouteDel(&netlink.Route{Dst: dst, Gw: backendIP})
	}
	return t.AddRoutes()
}
