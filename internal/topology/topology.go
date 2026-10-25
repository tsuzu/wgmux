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

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/datapath"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

// BackName is the backend end of the interconnect pair.
const BackName = "mux-b"

// Topology holds the namespace handles for a built topology.
type Topology struct {
	spec    api.ApplySpec
	Main    *netlink.Handle
	Backend *netlink.Handle
	nsH     netns.NsHandle
}

// Open creates the backend namespace and returns handles to both
// namespaces.
func Open(spec api.ApplySpec) (*Topology, error) {
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
	return &Topology{spec: spec, Main: main, Backend: backend, nsH: nsH}, nil
}

// BackendHandle exposes the namespace handle (engines need it to move
// devices in and to create TUNs).
func (t *Topology) BackendNsHandle() netns.NsHandle { return t.nsH }

// BuildInterconnect creates the pair and fills the datapath Info with
// everything except the peers (engines provide those separately).
func (t *Topology) BuildInterconnect() (*datapath.Info, error) {
	spec := t.spec
	mtu := spec.MTU
	if mtu == 0 {
		mtu = 1420
	}
	front, err := t.Main.LinkByName(spec.FrontName)
	if err != nil {
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
		if lerr != nil {
			return nil, fmt.Errorf("backend end %s not found in either namespace", BackName)
		}
		if err := t.Main.LinkSetNsFd(stray, int(t.nsH)); err != nil {
			return nil, fmt.Errorf("move %s to backend: %w", BackName, err)
		}
		back, err = t.Backend.LinkByName(BackName)
		if err != nil {
			return nil, err
		}
	}
	if _, ipnet, err := net.ParseCIDR(spec.FrontAddress); err == nil {
		t.Main.AddrAdd(front, &netlink.Addr{IPNet: ipnet})
	}
	if _, ipnet, err := net.ParseCIDR(spec.BackendAddress); err == nil {
		t.Backend.AddrAdd(back, &netlink.Addr{IPNet: ipnet})
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
	front, err := t.Main.LinkByName(t.spec.FrontName)
	if err != nil {
		return err
	}
	backendIP, _, err := net.ParseCIDR(t.spec.BackendAddress)
	if err != nil {
		return err
	}
	for _, p := range t.spec.Prefixes {
		_, dst, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return err
		}
		route := &netlink.Route{
			LinkIndex: front.Attrs().Index,
			Dst:       dst,
			Gw:        backendIP,
		}
		if err := t.Main.RouteReplace(route); err != nil {
			return fmt.Errorf("route %s via front: %w", p.CIDR, err)
		}
	}
	return nil
}

// Teardown removes routes, the front interface, and the backend
// namespace (destroying every device inside it, including engine
// peers that live there).
func (t *Topology) Teardown() error {
	if t.spec.ManageRoutes {
		backendIP, _, _ := net.ParseCIDR(t.spec.BackendAddress)
		for _, p := range t.spec.Prefixes {
			_, dst, err := net.ParseCIDR(p.CIDR)
			if err == nil {
				t.Main.RouteDel(&netlink.Route{Dst: dst, Gw: backendIP})
			}
		}
	}
	if front, err := t.Main.LinkByName(t.spec.FrontName); err == nil {
		t.Main.LinkDel(front)
	}
	err := netnsutil.DeleteNamed(t.spec.BackendNS)
	t.Backend.Close()
	t.Main.Close()
	t.nsH.Close()
	return err
}
