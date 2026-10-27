package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// buildCreate translates a mux definition into instance-creation
// parameters: the name, plus the one per-instance creation input —
// the kernel backend-address override. The engine kind is NOT
// here: it is the daemon's startup choice.
func buildCreate(mux *config.Mux) api.CreateParams {
	return api.CreateParams{
		Mux:            mux.Name,
		BackendAddress: mux.Kernel.BackendAddress,
	}
}

// buildSpec translates a mux definition into the data plane's
// desired state: names become IDs, keys are resolved, endpoints are
// pinned to IPs (resolution happens here, in the control plane),
// and decision policies (failover, bgp) are normalised to the
// datapath's "active" form; the control plane drives them
// afterwards with SetActive calls.
func buildSpec(mux *config.Mux) (api.ApplySpec, error) {
	spec := api.ApplySpec{
		Front: api.FrontSpec{
			Address: mux.Front.Address,
			MTU:     mux.Front.MTU,
		},
		ManageRoutes: mux.RoutesManaged(),
	}
	for i := range mux.Peers {
		peer := &mux.Peers[i]
		priv, err := mux.ResolvePrivateKey(peer)
		if err != nil {
			return spec, err
		}
		ps := api.PeerSpec{
			Name:                peer.Name,
			ID:                  uint32(peer.ID),
			PrivateKey:          priv,
			PublicKey:           peer.PublicKey,
			PresharedKey:        peer.PresharedKey,
			ListenPort:          peer.ListenPort,
			PersistentKeepalive: peer.PersistentKeepalive,
			AllowedIPs:          mux.AllowedIPsFor(peer.Name),
		}
		if peer.Endpoint != "" {
			ep, err := resolveEndpoint(peer)
			if err != nil {
				return spec, err
			}
			ps.Endpoint = ep
		}
		spec.Peers = append(spec.Peers, ps)
	}
	for _, prefix := range mux.EffectivePrefixes {
		pfx := api.PrefixSpec{CIDR: prefix.CIDR, Policy: "active"}
		if prefix.Policy == config.PolicyHash {
			pfx.Policy = "hash"
		}
		for _, name := range prefix.Candidates {
			p := mux.PeerByName(name)
			pfx.CandidateIDs = append(pfx.CandidateIDs, uint32(p.ID))
			if name == prefix.Active {
				pfx.ActiveID = uint32(p.ID)
			}
		}
		spec.Prefixes = append(spec.Prefixes, pfx)
	}
	return spec, nil
}

// checkDaemon verifies the apply's engine-kind and kernel-shape
// assumptions (config.CreationSpec tracks which were actually
// specified) against the daemon's STARTUP configuration. Engine
// kind, interconnect and attach are chosen when wgmuxd starts; an
// apply that assumes different ones is rejected here with the
// reason, instead of silently building something else.
func checkDaemon(info api.DaemonInfo, intent config.CreationSpec) error {
	if intent.EngineSet && intent.Engine != info.Engine {
		return fmt.Errorf("this apply assumes engine %q, but the daemon was started with -engine %s (engine kind is a wgmuxd startup setting; use the daemon started for %q, with its own -socket)",
			intent.Engine, info.Engine, intent.Engine)
	}
	if intent.InterconnectSet && info.Interconnect != "" && intent.Interconnect != info.Interconnect {
		return fmt.Errorf("this apply assumes interconnect %q, but the daemon was started with -interconnect %s (a wgmuxd startup setting)",
			intent.Interconnect, info.Interconnect)
	}
	if intent.AttachSet && info.Attach != "" && intent.Attach != info.Attach {
		return fmt.Errorf("this apply assumes attach %q, but the daemon was started with -attach %s (a wgmuxd startup setting)",
			intent.Attach, info.Attach)
	}
	return nil
}

// checkImmutable verifies an apply against an existing instance is
// not trying to change its creation parameters. The one per-instance
// creation parameter is the backend-address override; specifying a
// different one (or introducing one after the fact) for an instance
// that already exists is rejected — destroy + recreate is the way
// to change it.
func checkImmutable(info api.InstanceInfo, intent config.CreationSpec) error {
	if info.Status == api.StatusOrphaned {
		return fmt.Errorf("mux %q is orphaned: its stored spec belongs to a daemon of a different engine kind, and this daemon leaves it untouched", info.Mux)
	}
	if intent.BackendAddressSet && intent.BackendAddress != info.BackendAddress {
		return fmt.Errorf("mux %q already exists with backend_address=%q, but this apply specifies %q: creation parameters are immutable — destroy the instance first to change them",
			info.Mux, info.BackendAddress, intent.BackendAddress)
	}
	return nil
}

func resolveEndpoint(peer *config.Peer) (string, error) {
	host, port, err := net.SplitHostPort(peer.Endpoint)
	if err != nil {
		return "", err
	}
	if peer.EndpointIP != "" {
		return net.JoinHostPort(peer.EndpointIP, port), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("peer %q: resolve endpoint host %q: %w", peer.Name, host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("peer %q: endpoint host %q resolved to nothing", peer.Name, host)
	}
	if _, err := strconv.Atoi(port); err != nil {
		p, err := net.LookupPort("udp", port)
		if err != nil {
			return "", err
		}
		port = strconv.Itoa(p)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
