// Package engine defines the one interface both datapath
// implementations sit behind. An Engine is a single mux instance:
// created once with its kind and engine-private construction
// parameters (api.CreateParams), which stay fixed for its lifetime,
// it then accepts desired state (Apply), single selection changes
// (SetActive) and reports snapshots (State) without the caller
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
	// Kind reports the engine kind ("kernel" | "userspace").
	Kind() string
	// CreationParams returns the instance's construction
	// parameters with defaults resolved. They are immutable for
	// the instance's lifetime.
	CreationParams() api.CreateParams
	// Apply reconciles the instance to the desired spec, rebuilding
	// whatever it already had.
	Apply(spec api.ApplySpec) error
	// SetActive retargets one prefix to a different candidate peer.
	SetActive(prefix *net.IPNet, peerID uint32) error
	// State snapshots peers, current selections and counters.
	State() (api.State, error)
	// Close tears the instance's datapath down. Idempotent.
	Close() error
}

// Factory creates an Engine instance from construction parameters.
// The daemon's registry is built on a Factory so tests can inject
// fakes.
type Factory func(params api.CreateParams) (Engine, error)

// New is the production factory constructor. pinRoot is the
// daemon-startup bpffs base (wgmuxd -pin-root, default /sys/fs/bpf)
// from which kernel instances derive their per-instance pin dirs.
func New(pinRoot string) Factory {
	if pinRoot == "" {
		pinRoot = "/sys/fs/bpf"
	}
	return func(params api.CreateParams) (Engine, error) {
		switch params.Engine {
		case config.EngineKernel:
			return newKernelMux(params, pinRoot), nil
		case config.EngineUserspace:
			return newUserspaceMux(params), nil
		default:
			return nil, fmt.Errorf("unknown engine %q", params.Engine)
		}
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
