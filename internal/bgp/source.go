// Package bgp implements the BGP selection source: for prefixes with
// policy "bgp", the selected wgmux peer(s) follow BGP paths — the
// neighbor a prefix's path arrived from is mapped (by neighbor IP,
// from config) to the wgmux peer whose tunnel carries that neighbor.
//
// A single-mode prefix follows the BGP best path. An ecmp-mode
// prefix follows the whole multipath set (equal weight): every
// neighbor FRR marks as bestpath or multipath for the prefix.
//
// Two backends feed the same Decision stream:
//
//   - gobgp: an embedded GoBGP server in the control-plane process.
//     Best-path changes arrive via GoBGP's watch API. GoBGP's API
//     exposes only the single best path to watchers (multipath is
//     applied inside GoBGP when it programs a FIB, and is not
//     reported through the table watch), so with gobgp an ecmp
//     prefix follows the best path only: its selection is one peer.
//     Use frr when real multipath is needed.
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
	"strings"
	"time"

	wgmuxapi "github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// Decision is a path-set outcome: prefix should now be reached via
// the named wgmux peers. WgPeers[0] is the best path's peer; further
// entries are equal-cost multipath members. Withdrawal of every path
// produces no Decision (the prefix keeps its last selection until a
// new path or an operator decision replaces it).
type Decision struct {
	Prefix  string // CIDR
	WgPeers []string
}

// key identifies a decision's content for change detection.
func (d Decision) key() string { return strings.Join(d.WgPeers, ",") }

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

// Client is the slice of *api.Client the BGP runner uses.
type Client interface {
	State(ctx context.Context, mux string) (wgmuxapi.State, error)
	SetSelection(ctx context.Context, req wgmuxapi.SetSelectionRequest) error
}

// reassertInterval: the latest decision per prefix is re-applied
// periodically (a no-op when the daemon already agrees), so a failed
// call, a daemon restart or a re-apply that reset selections heals
// without waiting for the next BGP change.
const reassertInterval = 10 * time.Second

// Run consumes Decisions from src and forwards the valid ones to the
// data plane as SetSelection calls. A Decision is valid only for a
// prefix the DAEMON reports with policy bgp, and only its candidate
// peers count — BGP can never steer a prefix somewhere the operator
// did not allow.
func Run(ctx context.Context, cfg *config.Mux, src Source, client Client) error {
	decisions := make(chan Decision, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, decisions) }()
	latest := map[string]Decision{}
	tick := time.NewTicker(reassertInterval)
	defer tick.Stop()
	apply := func(d Decision) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := applyDecision(cctx, cfg.Name, client, d); err != nil {
			log.Printf("wgmux bgp: %v", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case d := <-decisions:
			if _, ipnet, err := net.ParseCIDR(d.Prefix); err == nil {
				d.Prefix = ipnet.String()
			}
			latest[d.Prefix] = d
			apply(d)
		case <-tick.C:
			for _, d := range latest {
				apply(d)
			}
		}
	}
}

// SelectionFor turns a Decision into the selection to apply to a
// prefix, validated against the daemon-reported prefix state: peers
// that are not candidates are dropped (and reported), duplicates
// collapse; single mode takes the first remaining peer, ecmp all of
// them at equal weight. It returns an error when nothing valid is
// left or the prefix is not bgp-driven.
func SelectionFor(ps wgmuxapi.PrefixState, d Decision) ([]wgmuxapi.PeerWeight, error) {
	if ps.Policy != wgmuxapi.PolicyBGP {
		return nil, fmt.Errorf("decision for prefix %s ignored: policy is %q, not bgp", ps.CIDR, ps.Policy)
	}
	cand := map[string]bool{}
	for _, c := range ps.Candidates {
		cand[c] = true
	}
	var peers []string
	seen := map[string]bool{}
	for _, p := range d.WgPeers {
		if !cand[p] {
			log.Printf("wgmux bgp: prefix %s: path via %s ignored: not a candidate", ps.CIDR, p)
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		peers = append(peers, p)
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("decision for prefix %s via %v ignored: no candidate peer", ps.CIDR, d.WgPeers)
	}
	if ps.Mode != wgmuxapi.ModeECMP {
		peers = peers[:1]
	}
	sel := make([]wgmuxapi.PeerWeight, 0, len(peers))
	for _, p := range peers {
		sel = append(sel, wgmuxapi.PeerWeight{Peer: p, Weight: 1})
	}
	return sel, nil
}

func sameSelection(a, b []wgmuxapi.PeerWeight) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]uint32{}
	for _, w := range a {
		m[w.Peer] = w.EffectiveWeight()
	}
	for _, w := range b {
		if v, ok := m[w.Peer]; !ok || v != w.EffectiveWeight() {
			return false
		}
	}
	return true
}

func applyDecision(ctx context.Context, mux string, client Client, d Decision) error {
	_, ipnet, err := net.ParseCIDR(d.Prefix)
	if err != nil {
		return fmt.Errorf("decision for unparseable prefix %q ignored", d.Prefix)
	}
	st, err := client.State(ctx, mux)
	if err != nil {
		return fmt.Errorf("mux %s: state: %w", mux, err)
	}
	var ps *wgmuxapi.PrefixState
	for i := range st.Prefixes {
		if st.Prefixes[i].CIDR == ipnet.String() {
			ps = &st.Prefixes[i]
			break
		}
	}
	if ps == nil {
		return fmt.Errorf("decision for unmanaged prefix %s ignored", ipnet)
	}
	sel, err := SelectionFor(*ps, d)
	if err != nil {
		return err
	}
	if sameSelection(sel, ps.Selection) {
		return nil
	}
	log.Printf("wgmux bgp: mux %s: %s now via %s", mux, ipnet, strings.Join(peerNames(sel), ","))
	return client.SetSelection(ctx, wgmuxapi.SetSelectionRequest{Mux: mux, CIDR: ipnet.String(), Selection: sel})
}

func peerNames(sel []wgmuxapi.PeerWeight) []string {
	out := make([]string, len(sel))
	for i, w := range sel {
		out[i] = w.Peer
	}
	return out
}
