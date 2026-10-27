package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

// Context gives the kernel peer provisioner the namespace handles
// of one built topology.
type Context struct {
	BackendNS     string
	BackendHandle netns.NsHandle
	Main          *netlink.Handle
	Backend       *netlink.Handle
	MTU           int
}

// peerRef points at a provisioned peer's device in the backend
// namespace — the steering attachment point the BPF datapath needs.
type peerRef struct {
	DeviceName string
	Ifindex    int
}

// kernelPeers provisions in-tree WireGuard devices inside one
// backend namespace: a device per peer, created in the main
// namespace (its UDP sockets' birth namespace) and moved into the
// backend. It is the kernel mux engine's peer layer; steering is
// the BPF datapath's job.
type kernelPeers struct {
	ctx   *Context
	specs map[string]api.PeerSpec
}

func newKernelPeers(ctx *Context) *kernelPeers {
	return &kernelPeers{ctx: ctx, specs: map[string]api.PeerSpec{}}
}

// adoptSpecs registers peer specs WITHOUT creating or configuring
// any device: the devices already exist (daemon-restart adoption),
// and Peers() only needs the name/ID table to read their state.
func (e *kernelPeers) adoptSpecs(peers []api.PeerSpec) {
	for _, spec := range peers {
		e.specs[spec.Name] = spec
	}
}

func (e *kernelPeers) AddPeer(spec api.PeerSpec) (peerRef, error) {
	name := DeviceName(spec.Name)
	if len(name) >= 16 {
		return peerRef{}, fmt.Errorf("peer %q: device name %q exceeds IFNAMSIZ", spec.Name, name)
	}
	main := e.ctx.Main
	link, err := main.LinkByName(name)
	if err != nil {
		gl := &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{Name: name, MTU: e.ctx.MTU},
			LinkType:  "wireguard",
		}
		if err := main.LinkAdd(gl); err != nil {
			return peerRef{}, fmt.Errorf("create %s: %w", name, err)
		}
		link = gl
	}
	if err := e.configure(name, spec); err != nil {
		return peerRef{}, err
	}
	// Move to the backend; the UDP sockets keep main as birth namespace.
	if err := main.LinkSetNsFd(link, int(e.ctx.BackendHandle)); err != nil {
		return peerRef{}, fmt.Errorf("move %s to backend: %w", name, err)
	}
	blink, err := e.ctx.Backend.LinkByName(name)
	if err != nil {
		return peerRef{}, fmt.Errorf("find %s in backend: %w", name, err)
	}
	if err := e.ctx.Backend.LinkSetUp(blink); err != nil {
		return peerRef{}, fmt.Errorf("up %s: %w", name, err)
	}
	e.specs[spec.Name] = spec
	return peerRef{DeviceName: name, Ifindex: blink.Attrs().Index}, nil
}

func (e *kernelPeers) configure(name string, spec api.PeerSpec) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer client.Close()

	priv, err := wgtypes.ParseKey(spec.PrivateKey)
	if err != nil {
		return fmt.Errorf("peer %q private key: %w", spec.Name, err)
	}
	pub, err := wgtypes.ParseKey(spec.PublicKey)
	if err != nil {
		return fmt.Errorf("peer %q public key: %w", spec.Name, err)
	}
	allowed, err := ParseAllowedIPs(spec.AllowedIPs)
	if err != nil {
		return err
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         pub,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowed,
	}
	if spec.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(spec.PresharedKey)
		if err != nil {
			return fmt.Errorf("peer %q preshared key: %w", spec.Name, err)
		}
		pc.PresharedKey = &psk
	}
	if spec.Endpoint != "" {
		udp, err := net.ResolveUDPAddr("udp", spec.Endpoint)
		if err != nil {
			return fmt.Errorf("peer %q endpoint: %w", spec.Name, err)
		}
		pc.Endpoint = udp
	}
	if spec.PersistentKeepalive > 0 {
		d := time.Duration(spec.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &d
	}
	wcfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{pc},
	}
	if spec.ListenPort != 0 {
		wcfg.ListenPort = &spec.ListenPort
	}
	if err := client.ConfigureDevice(name, wcfg); err != nil {
		return fmt.Errorf("configure %s: %w", name, err)
	}
	return nil
}

func (e *kernelPeers) RemovePeer(name string) error {
	device := DeviceName(name)
	link, err := e.ctx.Backend.LinkByName(device)
	if err != nil {
		return fmt.Errorf("find %s in backend: %w", device, err)
	}
	if err := e.ctx.Backend.LinkDel(link); err != nil {
		return fmt.Errorf("delete %s: %w", device, err)
	}
	delete(e.specs, name)
	return nil
}

// Peers reads device state from inside the backend namespace.
func (e *kernelPeers) Peers() ([]api.PeerState, error) {
	var out []api.PeerState
	err := netnsutil.WithNetNS(e.ctx.BackendNS, func() error {
		client, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer client.Close()
		devices, err := client.Devices()
		if err != nil {
			return err
		}
		byDevice := map[string]*wgtypes.Device{}
		for _, d := range devices {
			byDevice[d.Name] = d
		}
		for _, spec := range e.specs {
			st := api.PeerState{Name: spec.Name, ID: spec.ID}
			if dev, ok := byDevice[DeviceName(spec.Name)]; ok {
				for _, p := range dev.Peers {
					st.LastHandshake = p.LastHandshakeTime
					st.BytesReceived += uint64(p.ReceiveBytes)
					st.BytesSent += uint64(p.TransmitBytes)
					if p.Endpoint != nil {
						st.Endpoint = p.Endpoint.String()
					}
				}
			}
			out = append(out, st)
		}
		return nil
	})
	return out, err
}

func (e *kernelPeers) Close() error { return nil }
