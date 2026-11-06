// Package monitor is a control-plane policy: it watches WireGuard
// handshake ages (via the data-plane API) for prefixes with
// policy=failover and asks the data plane to flip the active candidate
// when the current one goes stale. It is one of several decision
// makers that all funnel into api.SetActive.
package monitor

import (
	"fmt"
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
	return fmt.Errorf("monitor v2: not implemented yet") // control-plane workstream
}
