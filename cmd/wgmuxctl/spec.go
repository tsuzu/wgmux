package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// buildCreate translates a mux definition into instance-creation
// parameters. These are fixed for the instance's lifetime.
func buildCreate(mux *config.Mux) api.CreateParams {
	return api.CreateParams{
		Mux:    mux.Name,
		Engine: mux.Engine,
		Kernel: api.KernelParams{
			BackendNS:      mux.Kernel.BackendNS,
			Interconnect:   mux.Kernel.Interconnect,
			Attach:         mux.Kernel.Attach,
			PinDir:         mux.Kernel.PinDir,
			BackendAddress: mux.Kernel.BackendAddress,
		},
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

// checkImmutable verifies an apply against an existing instance is
// not trying to change its creation parameters. Only parameters
// the user actually specified in this invocation (config.CreationSpec
// tracks presence) are checked; unspecified ones accept whatever
// the instance already has.
func checkImmutable(info api.InstanceInfo, intent config.CreationSpec) error {
	mismatch := func(field, have, want string) error {
		return fmt.Errorf("mux %q already exists with %s=%q, but this apply specifies %q: creation parameters are immutable — destroy the instance first to change them",
			info.Mux, field, have, want)
	}
	if intent.EngineSet && intent.Engine != info.Engine {
		return mismatch("engine", info.Engine, intent.Engine)
	}
	if intent.InterconnectSet && info.Kernel.Interconnect != "" && intent.Interconnect != info.Kernel.Interconnect {
		return mismatch("interconnect", info.Kernel.Interconnect, intent.Interconnect)
	}
	if intent.AttachSet && info.Kernel.Attach != "" && intent.Attach != info.Kernel.Attach {
		return mismatch("attach", info.Kernel.Attach, intent.Attach)
	}
	if intent.BackendNSSet && info.Kernel.BackendNS != "" && intent.BackendNS != info.Kernel.BackendNS {
		return mismatch("backend_ns", info.Kernel.BackendNS, intent.BackendNS)
	}
	if intent.PinDirSet && info.Kernel.PinDir != "" && intent.PinDir != info.Kernel.PinDir {
		return mismatch("pin_dir", info.Kernel.PinDir, intent.PinDir)
	}
	if intent.BackendAddressSet && info.Kernel.BackendAddress != "" && intent.BackendAddress != info.Kernel.BackendAddress {
		return mismatch("backend_address", info.Kernel.BackendAddress, intent.BackendAddress)
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
