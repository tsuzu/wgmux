package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// buildSpec translates the control-plane config into the data plane's
// desired-state spec: names become IDs, keys are resolved, endpoints
// are pinned to IPs (resolution must happen here — after devices move
// into the backend namespace, DNS is not reliably available there),
// and decision policies (failover, bgp) are normalised to the
// datapath's "active" form; the control plane drives them afterwards
// with SetActive calls.
func buildSpec(cfg *config.Config) (api.ApplySpec, error) {
	spec := api.ApplySpec{
		Engine:         cfg.Engine,
		BackendNS:      cfg.BackendNS,
		Interconnect:   cfg.Interconnect,
		Attach:         cfg.Attach,
		PinDir:         cfg.PinDir,
		ManageRoutes:   cfg.RoutesManaged(),
		FrontName:      cfg.Front.Name,
		FrontAddress:   cfg.Front.Address,
		BackendAddress: cfg.Front.BackendAddress,
		MTU:            cfg.Front.MTU,
	}
	for i := range cfg.Peers {
		peer := &cfg.Peers[i]
		priv, err := cfg.ResolvePrivateKey(peer)
		if err != nil {
			return spec, err
		}
		ps := api.PeerSpec{
			Name:                peer.Name,
			ID:                  uint32(peer.ID),
			PrivateKey:          priv,
			PublicKey:           peer.PublicKey,
			ListenPort:          peer.ListenPort,
			PersistentKeepalive: peer.PersistentKeepalive,
		}
		if peer.Endpoint != "" {
			ep, err := resolveEndpoint(peer)
			if err != nil {
				return spec, err
			}
			ps.Endpoint = ep
		}
		for _, ipnet := range cfg.AllowedIPsFor(peer.Name) {
			ps.AllowedIPs = append(ps.AllowedIPs, ipnet.String())
		}
		spec.Peers = append(spec.Peers, ps)
	}
	for _, prefix := range cfg.Prefixes {
		pfx := api.PrefixSpec{CIDR: prefix.CIDR, Policy: "active"}
		if prefix.Policy == config.PolicyHash {
			pfx.Policy = "hash"
		}
		for _, name := range prefix.Candidates {
			p := cfg.PeerByName(name)
			pfx.CandidateIDs = append(pfx.CandidateIDs, uint32(p.ID))
			if name == prefix.Active {
				pfx.ActiveID = uint32(p.ID)
			}
		}
		spec.Prefixes = append(spec.Prefixes, pfx)
	}
	return spec, nil
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
