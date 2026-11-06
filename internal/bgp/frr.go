package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"time"

	"github.com/tsuzu/wgmux/internal/config"
)

// FRRSource polls an external FRRouting daemon through vtysh JSON
// output and turns its best paths into Decisions.
//
// Scope note: FRR's Forwarding Plane Manager (FPM) protocol would be
// the event-driven integration (FRR pushes RIB updates to an external
// datapath), and zebra can own the main-namespace FIB directly when
// manage_routes=false. Polling `show ip bgp json` is the portable
// first backend; the Decision contract is identical either way.
type FRRSource struct {
	cfg *config.Mux
	// Exec runs vtysh and returns stdout; overridable in tests.
	Exec func(ctx context.Context) ([]byte, error)
}

func (s *FRRSource) Run(ctx context.Context, out chan<- Decision) error {
	execFn := s.Exec
	if execFn == nil {
		execFn = func(ctx context.Context) ([]byte, error) {
			cmd := exec.CommandContext(ctx, s.cfg.BGP.VtyshPath, "-c", "show ip bgp json")
			return cmd.Output()
		}
	}
	interval := time.Duration(s.cfg.BGP.PollInterval) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	last := map[string]string{} // prefix -> decision key, to emit only changes
	poll := func() error {
		raw, err := execFn(ctx)
		if err != nil {
			return fmt.Errorf("vtysh show ip bgp: %w", err)
		}
		decisions, err := ParseFRRBestPaths(s.cfg, raw)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, d := range decisions {
			seen[d.Prefix] = true
			if last[d.Prefix] != d.key() {
				last[d.Prefix] = d.key()
				select {
				case out <- d:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		// Forget prefixes whose best path vanished, so a later new
		// best path is emitted even if it selects the same peer.
		for p := range last {
			if !seen[p] {
				delete(last, p)
			}
		}
		return nil
	}
	if err := poll(); err != nil {
		return err
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := poll(); err != nil {
				// Transient FRR errors must not kill the source;
				// the next poll retries.
				continue
			}
		}
	}
}

// frrBGPTable mirrors the subset of `show ip bgp json` we consume:
//
//	{ "routes": { "10.20.0.10/32": [ { "path": "...", "peerId": "192.0.2.1",
//	    "bestpath": {"overall": true}, ... } ] } }
//
// FRR versions differ: some emit an array of route objects per prefix
// (used here), others a {"paths": [...]} object, and "bestpath" may be
// a plain bool. The parser tolerates all three shapes.
type frrPath struct {
	PeerID   string          `json:"peerId"`
	BestPath json.RawMessage `json:"bestpath"`
	BestRaw  *bool           `json:"bestPath"`
	// Multipath is true on every member of the ECMP set (FRR sets
	// it on the best path too when multipath is in effect).
	Multipath bool `json:"multipath"`
	Nexthops  []struct {
		IP string `json:"ip"`
	} `json:"nexthops"`
}

func isBest(p frrPath) bool {
	if p.BestRaw != nil {
		return *p.BestRaw
	}
	if len(p.BestPath) > 0 {
		var obj struct {
			Overall bool `json:"overall"`
		}
		if err := json.Unmarshal(p.BestPath, &obj); err == nil {
			return obj.Overall
		}
		var b bool
		if err := json.Unmarshal(p.BestPath, &b); err == nil {
			return b
		}
	}
	return false
}

// ParseFRRBestPaths extracts (prefix, wg peers) decisions from vtysh
// JSON output. For each prefix it collects every path marked
// bestpath or multipath whose neighbor maps to a wgmux peer: the
// best path's peer first, the other multipath members after it in
// name order, duplicates removed. Output is sorted by prefix.
// Pure; unit-tested with fixtures.
func ParseFRRBestPaths(cfg *config.Mux, raw []byte) ([]Decision, error) {
	var top struct {
		Routes map[string]json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("parse frr bgp json: %w", err)
	}
	var out []Decision
	for prefix, rawRoutes := range top.Routes {
		var paths []frrPath
		var asArray []frrPath
		if err := json.Unmarshal(rawRoutes, &asArray); err == nil {
			paths = asArray
		} else {
			var asObj struct {
				Paths []frrPath `json:"paths"`
			}
			if err := json.Unmarshal(rawRoutes, &asObj); err != nil {
				continue
			}
			paths = asObj.Paths
		}
		neighborOf := func(p frrPath) (string, bool) {
			n := p.PeerID
			if n == "" && len(p.Nexthops) > 0 {
				n = p.Nexthops[0].IP
			}
			return NeighborPeer(cfg, n)
		}
		var best string
		var multi []string
		seen := map[string]bool{}
		for _, p := range paths {
			isB, isM := isBest(p), p.Multipath
			if !isB && !isM {
				continue
			}
			peer, ok := neighborOf(p)
			if !ok || seen[peer] {
				continue
			}
			seen[peer] = true
			if isB {
				best = peer
			} else {
				multi = append(multi, peer)
			}
		}
		sort.Strings(multi)
		var peers []string
		if best != "" {
			peers = append(peers, best)
		}
		peers = append(peers, multi...)
		if len(peers) > 0 {
			out = append(out, Decision{Prefix: prefix, WgPeers: peers})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out, nil
}
