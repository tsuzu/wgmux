// Package bgp implements the BGP selection source: for prefixes with
// policy "bgp", the active wgmux peer follows BGP best paths — the
// neighbor a prefix's best path arrived from is mapped (by neighbor IP,
// from config) to the wgmux peer whose tunnel carries that neighbor.
//
// Two backends feed the same Decision stream:
//
//   - gobgp: an embedded GoBGP server in the control-plane process.
//     Best-path changes arrive via GoBGP's watch API.
//   - frr: an external FRRouting daemon, polled through
//     `vtysh -c 'show ip bgp json'`. (Its Forwarding Plane Manager
//     protocol is the planned lower-latency alternative; polling JSON
//     is the portable first step.)
//
// Origination is the mirror image and lives with the backends:
// prefixes can be announced toward a neighbor only while its mapped
// peer is the active one (see GoBGP's Announce/Withdraw helpers). FRR
// users typically let FRR/zebra own the main-namespace FIB and set
// manage_routes=false in the wgmux config.
package bgp

import (
	"context"
	"fmt"
	"log"
	"net"

	wgmuxapi "github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// Decision is a best-path outcome: prefix should now be reached via
// the named wgmux peer. Withdrawal of the best path produces no
// Decision (the prefix keeps its last peer until a new best path or
// an operator decision replaces it).
type Decision struct {
	Prefix string // CIDR
	WgPeer string
}

// Source produces Decisions until its context ends.
type Source interface {
	Run(ctx context.Context, out chan<- Decision) error
}

// NewSource builds the source configured by cfg.BGP.Mode.
func NewSource(cfg *config.Mux) (Source, error) {
	switch cfg.BGP.Mode {
	case config.BGPModeGoBGP:
		return &GoBGPSource{cfg: cfg}, nil
	case config.BGPModeFRR:
		return &FRRSource{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("bgp mode %q has no source", cfg.BGP.Mode)
	}
}

// NeighborPeer maps a BGP neighbor IP to its wgmux peer name.
func NeighborPeer(cfg *config.Mux, neighborIP string) (string, bool) {
	for _, n := range cfg.BGP.Neighbors {
		if n.Address == neighborIP {
			return n.WgPeer, true
		}
	}
	return "", false
}

// Run consumes Decisions from src and forwards the valid ones to the
// data plane as SetActive calls. A Decision is valid only for a
// prefix whose policy is bgp and whose candidates include the peer —
// BGP can never steer a prefix somewhere the operator did not allow.
func Run(ctx context.Context, cfg *config.Mux, src Source, client *wgmuxapi.Client) error {
	decisions := make(chan Decision, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, decisions) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case d := <-decisions:
			if err := applyDecision(ctx, cfg, client, d); err != nil {
				log.Printf("wgmux bgp: %v", err)
			}
		}
	}
}

func applyDecision(ctx context.Context, cfg *config.Mux, client *wgmuxapi.Client, d Decision) error {
	_, ipnet, err := net.ParseCIDR(d.Prefix)
	if err != nil {
		return fmt.Errorf("decision for unparseable prefix %q ignored", d.Prefix)
	}
	var prefix *config.Prefix
	for i := range cfg.EffectivePrefixes {
		if cfg.EffectivePrefixes[i].CIDR == ipnet.String() {
			prefix = &cfg.EffectivePrefixes[i]
			break
		}
	}
	if prefix == nil {
		return fmt.Errorf("decision for unmanaged prefix %s ignored", ipnet)
	}
	if prefix.Policy != config.PolicyBGP {
		return fmt.Errorf("decision for prefix %s ignored: policy is %s, not bgp", ipnet, prefix.Policy)
	}
	candidate := false
	for _, c := range prefix.Candidates {
		if c == d.WgPeer {
			candidate = true
		}
	}
	if !candidate {
		return fmt.Errorf("decision for prefix %s via %s ignored: not a candidate", ipnet, d.WgPeer)
	}
	peer := cfg.PeerByName(d.WgPeer)
	if peer == nil {
		return fmt.Errorf("decision names unknown peer %q", d.WgPeer)
	}
	log.Printf("wgmux bgp: %s best path now via %s", ipnet, d.WgPeer)
	return client.SetActive(ctx, wgmuxapi.SetActiveRequest{Mux: cfg.Name, CIDR: ipnet.String(), PeerID: uint32(peer.ID)})
}
