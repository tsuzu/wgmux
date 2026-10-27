// Package engine defines the one interface both datapath
// implementations sit behind. An Engine is a single mux instance:
// created through the daemon's factory (the daemon is started with
// ONE engine kind; the factory builds instances of that kind only),
// it accepts desired state (Apply), single selection changes
// (SetActive) and reports snapshots (State), without the caller
// knowing which implementation it is:
//
//   - kernel: in-tree WireGuard devices, one per peer, in a hidden
//     per-instance backend network namespace, steered by the eBPF
//     programs in bpf/mux.c. Forwarding survives the daemon.
//   - userspace: wireguard-go devices hosted by the daemon process,
//     each bound to an in-memory channel TUN; a Go packet pump in
//     the daemon steers between the front TUN and the peers. No
//     network namespace is involved.
//
// The contract sits above datapath mechanics on purpose: peer specs,
// lifecycle and steering decisions in, state out. How forwarding is
// realized — BPF redirect inside a netns, or a userspace pump — is
// each engine's own business.
package engine

import (
	"fmt"
	"net"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// Engine is one mux instance's datapath.
type Engine interface {
	// Apply reconciles the instance to the desired spec,
	// rebuilding whatever it already had.
	Apply(spec api.ApplySpec) error
	// SetActive retargets one prefix to a different candidate peer.
	SetActive(prefix *net.IPNet, peerID uint32) error
	// State snapshots peers, current selections and counters.
	State() (api.State, error)
	// Close tears the instance's datapath down. Idempotent.
	Close() error
}

// Adopter is implemented by engines whose instances can survive
// the daemon process (the kernel engine): at startup the daemon
// offers the stored spec, and Adopt re-attaches to the still-live
// kernel objects WITHOUT touching the datapath, reporting true.
// (false, nil) means "not adoptable — rebuild me instead".
type Adopter interface {
	Adopt(spec api.ApplySpec) (bool, error)
}

// DaemonOptions are the daemon-startup settings an engine factory
// closes over: for the kernel engine, the interconnect/attach shape
// shared by every instance and the bpffs pin root instance pin
// dirs derive from.
type DaemonOptions struct {
	Interconnect string // kernel: veth | netkit
	Attach       string // kernel: tcx | tc
	PinRoot      string // kernel: bpffs base, default /sys/fs/bpf
}

// Factory creates Engine instances of one kind from creation
// parameters. The daemon's registry is built on a Factory so tests
// can inject fakes.
type Factory func(params api.CreateParams) (Engine, error)

// NewFactory returns the production factory for one engine kind —
// the daemon's startup kind. Every instance it creates is of that
// kind; there is no per-instance kind choice.
func NewFactory(kind string, opts DaemonOptions) (Factory, error) {
	if opts.PinRoot == "" {
		opts.PinRoot = "/sys/fs/bpf"
	}
	if opts.Interconnect == "" {
		opts.Interconnect = config.InterconnectVeth
	}
	if opts.Attach == "" {
		opts.Attach = config.AttachTCX
	}
	switch kind {
	case config.EngineKernel:
		return func(params api.CreateParams) (Engine, error) {
			return newKernelMux(params, opts), nil
		}, nil
	case config.EngineUserspace:
		return func(params api.CreateParams) (Engine, error) {
			return newUserspaceMux(params.Mux), nil
		}, nil
	default:
		return nil, fmt.Errorf("unknown engine %q", kind)
	}
}

// DeviceName is the netdev name for a peer in the backend namespace
// (kernel engine only).
func DeviceName(peerName string) string {
	return "wg-" + peerName
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
