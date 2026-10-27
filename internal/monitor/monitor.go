// Package monitor is a control-plane policy: it watches WireGuard
// handshake ages (via the data-plane API) for prefixes with
// policy=failover and asks the data plane to flip the active candidate
// when the current one goes stale. It is one of several decision
// makers that all funnel into api.SetActive.
package monitor

import (
	"context"
	"log"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// Run polls the named mux instance until stop is closed.
func Run(cfg *config.Mux, client *api.Client, stop <-chan struct{}, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	tick := time.NewTicker(time.Duration(cfg.Failover.Interval) * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if err := EvaluateOnce(cfg, client); err != nil {
				logger.Printf("wgmux monitor: %v", err)
			}
		}
	}
}

// EvaluateOnce performs a single failover evaluation pass.
func EvaluateOnce(cfg *config.Mux, client *api.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := client.State(ctx, cfg.Name)
	if err != nil {
		return err
	}
	handshakes := map[string]time.Time{}
	for _, p := range st.Peers {
		handshakes[p.Name] = p.LastHandshake
	}
	active := map[string]uint32{}
	for _, p := range st.Prefixes {
		active[p.CIDR] = p.ActiveID
	}
	maxAge := time.Duration(cfg.Failover.HandshakeMaxAge) * time.Second
	now := time.Now()
	for _, prefix := range cfg.EffectivePrefixes {
		if prefix.Policy != config.PolicyFailover {
			continue
		}
		activeID, ok := active[prefix.CIDR]
		if !ok {
			continue
		}
		activePeer := peerByID(cfg, activeID)
		if activePeer == nil {
			continue
		}
		if t, ok := handshakes[activePeer.Name]; ok && !t.IsZero() && now.Sub(t) <= maxAge {
			continue // healthy
		}
		for _, candName := range prefix.Candidates {
			if candName == activePeer.Name {
				continue
			}
			t, ok := handshakes[candName]
			if !ok || t.IsZero() || now.Sub(t) > maxAge {
				continue
			}
			cand := cfg.PeerByName(candName)
			if cand == nil {
				continue
			}
			log.Printf("wgmux: failover %s: %s -> %s", prefix.CIDR, activePeer.Name, candName)
			if err := client.SetActive(ctx, api.SetActiveRequest{Mux: cfg.Name, CIDR: prefix.CIDR, PeerID: uint32(cand.ID)}); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func peerByID(cfg *config.Mux, id uint32) *config.Peer {
	for i := range cfg.Peers {
		if uint32(cfg.Peers[i].ID) == id {
			return &cfg.Peers[i]
		}
	}
	return nil
}
