// Package engine abstracts the peer datapath: what a "peer tunnel" is
// made of. Two implementations provide identical peers to the shared
// eBPF steering layer:
//
//   - kernel: in-tree WireGuard devices, created in the main namespace
//     (their UDP sockets' birth namespace) and moved to the backend.
//     Forwarding survives the daemon.
//   - userspace: wireguard-go devices hosted by the daemon process,
//     each bound to a TUN device created inside the backend namespace
//     while their UDP sockets are opened in the main namespace — the
//     same birth-namespace split, one level up. Forwarding lasts as
//     long as the daemon process.
//
// In both cases the steering programs attach to an ordinary L3 netdev
// in the backend namespace (the wg device, or the TUN device), so the
// datapath does not know or care which engine a peer came from.
package engine

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// DeviceName is the netdev name for a peer in the backend namespace.
func DeviceName(peerName string) string {
	return "wg-" + peerName
}

// Context gives an engine what it needs to build peers.
type Context struct {
	BackendNS     string
	BackendHandle netns.NsHandle
	Main          *netlink.Handle
	Backend       *netlink.Handle
	MTU           int
}

// Ref points at a peer's steering attachment point.
type Ref struct {
	DeviceName string
	Ifindex    int // in the backend namespace
}

// Engine provisions peer tunnels and reports their state.
type Engine interface {
	AddPeer(spec api.PeerSpec) (Ref, error)
	RemovePeer(name string) error
	Peers() ([]api.PeerState, error)
	Close() error
}

// New constructs the engine named by config (kernel | userspace).
func New(kind string, ctx *Context) (Engine, error) {
	switch kind {
	case config.EngineKernel:
		return newKernel(ctx), nil
	case config.EngineUserspace:
		return newUserspace(ctx), nil
	default:
		return nil, fmt.Errorf("unknown engine %q", kind)
	}
}

// ParseAllowedIPs is shared spec plumbing.
func ParseAllowedIPs(cidrs []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("allowed_ip %q: %w", s, err)
		}
		out = append(out, *ipnet)
	}
	return out, nil
}
