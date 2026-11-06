// Package monitor is the failover policy: it watches WireGuard
// handshake ages (via the data-plane API) for prefixes with
// policy=failover and changes their selection when a selected peer
// goes stale. It is one of several decision makers that funnel into
// api.SetSelection.
//
// The monitor reads everything it acts on from the DAEMON's State
// (peer names, candidates, current selection) and never from config
// peer IDs; the config supplies only thresholds, the set of
// failover-owned prefixes and the configured ECMP weights. That
// keeps it correct across re-applies that reorder or renumber peers.
//
// The decision logic is the pure function Evaluate; Monitor is the
// thin loop that feeds it State and executes the returned actions.
package monitor

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
)

// Settings is the configuration slice Evaluate needs.
type Settings struct {
	// MaxAge: a peer whose last handshake is older (or missing) is
	// unhealthy.
	MaxAge time.Duration
	// Prefixes are the failover-owned prefixes (canonical CIDR) ->
	// their CONFIGURED selection (the ECMP weights; ignored for
	// single-mode prefixes).
	Prefixes map[string][]api.PeerWeight
}

// SettingsFromConfig extracts the settings from a mux config.
func SettingsFromConfig(cfg *config.Mux) Settings {
	s := Settings{
		MaxAge:   time.Duration(cfg.Failover.HandshakeMaxAge) * time.Second,
		Prefixes: map[string][]api.PeerWeight{},
	}
	for _, p := range cfg.EffectivePrefixes {
		if p.Policy == config.PolicyFailover {
			s.Prefixes[p.CIDR] = p.Selection()
		}
	}
	return s
}

// Action kinds.
const (
	ActSetSelection = "set_selection"
	ActFlushPeer    = "flush_peer"
)

// Action is one call the monitor wants made on the data plane.
type Action struct {
	Kind      string
	CIDR      string           // ActSetSelection
	Selection []api.PeerWeight // ActSetSelection
	Peer      string           // ActFlushPeer
}

// Result is one evaluation's outcome.
type Result struct {
	// Health is the new health map (peer name -> healthy) over the
	// peers that exist in the State and are candidates of a
	// monitored prefix. Pass it as `prev` to the next evaluation.
	Health map[string]bool
	// Actions are ordered: every SetSelection first, then the
	// FlushPeer calls (flush after the selection change, so
	// re-steered flows land on the new selection).
	Actions []Action
}

func healthy(p api.PeerState, set Settings, now time.Time) bool {
	return !p.LastHandshake.IsZero() && now.Sub(p.LastHandshake) <= set.MaxAge
}

// Evaluate decides what to do given the daemon's State, the config
// slice, the previous health map and the current time. It is pure.
//
//   - healthy(peer) = last handshake within MaxAge.
//   - single prefix: the selected peer unhealthy and a healthy
//     candidate exists -> select the first healthy candidate (State's
//     candidate order). No preemption: a recovered peer is not
//     switched back to.
//   - ecmp prefix: desired = configured selection restricted to
//     healthy candidates; if none is healthy keep the current
//     selection; set it when it differs.
//   - a peer that was healthy (or never seen: first observation) and
//     now is not gets exactly one FlushPeer per transition. Peers
//     missing from the State are unhealthy but cannot be flushed.
func Evaluate(st api.State, set Settings, prev map[string]bool, now time.Time) Result {
	byName := map[string]api.PeerState{}
	for _, p := range st.Peers {
		byName[p.Name] = p
	}
	res := Result{Health: map[string]bool{}}
	isHealthy := func(name string) bool {
		p, ok := byName[name]
		return ok && healthy(p, set, now)
	}

	for _, ps := range st.Prefixes {
		cfgSel, monitored := set.Prefixes[ps.CIDR]
		if !monitored {
			continue
		}
		for _, c := range ps.Candidates {
			if _, ok := byName[c]; ok {
				res.Health[c] = isHealthy(c)
			}
		}
		if act, ok := evalPrefix(ps, cfgSel, isHealthy); ok {
			res.Actions = append(res.Actions, act)
		}
	}

	var flush []string
	for name, h := range res.Health {
		was, known := prev[name]
		if !known {
			was = true
		}
		if was && !h {
			flush = append(flush, name)
		}
	}
	sort.Strings(flush)
	for _, name := range flush {
		res.Actions = append(res.Actions, Action{Kind: ActFlushPeer, Peer: name})
	}
	return res
}

func evalPrefix(ps api.PrefixState, cfgSel []api.PeerWeight, isHealthy func(string) bool) (Action, bool) {
	if ps.Mode == api.ModeECMP {
		configured := cfgSel
		if len(configured) == 0 {
			for _, c := range ps.Candidates {
				configured = append(configured, api.PeerWeight{Peer: c, Weight: 1})
			}
		}
		weightOf := map[string]uint32{}
		for _, w := range configured {
			weightOf[w.Peer] = w.EffectiveWeight()
		}
		var desired []api.PeerWeight
		for _, c := range ps.Candidates { // State order, deterministic
			if w, ok := weightOf[c]; ok && isHealthy(c) {
				desired = append(desired, api.PeerWeight{Peer: c, Weight: w})
			}
		}
		if len(desired) == 0 || sameSelection(desired, ps.Selection) {
			return Action{}, false
		}
		return Action{Kind: ActSetSelection, CIDR: ps.CIDR, Selection: desired}, true
	}

	// single
	if len(ps.Selection) > 0 && isHealthy(ps.Selection[0].Peer) {
		return Action{}, false
	}
	for _, c := range ps.Candidates {
		if isHealthy(c) {
			return Action{Kind: ActSetSelection, CIDR: ps.CIDR, Selection: []api.PeerWeight{{Peer: c, Weight: 1}}}, true
		}
	}
	return Action{}, false // all unhealthy: keep current
}

// sameSelection compares selections as peer -> effective weight sets.
func sameSelection(a, b []api.PeerWeight) bool {
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

// Client is the slice of *api.Client the monitor uses.
type Client interface {
	State(ctx context.Context, mux string) (api.State, error)
	SetSelection(ctx context.Context, req api.SetSelectionRequest) error
	FlushPeer(ctx context.Context, req api.FlushPeerRequest) error
}

// Monitor runs Evaluate in a loop and executes its actions. It owns
// the health memory used to detect transitions.
type Monitor struct {
	mux    string
	set    Settings
	client Client
	logger *log.Logger
	now    func() time.Time
	prev   map[string]bool
}

// New builds a monitor for one mux config.
func New(cfg *config.Mux, client Client, logger *log.Logger) *Monitor {
	if logger == nil {
		logger = log.Default()
	}
	return &Monitor{mux: cfg.Name, set: SettingsFromConfig(cfg), client: client, logger: logger, now: time.Now}
}

// Tick performs one evaluation pass. The health memory advances
// only when every action succeeded, so a failed SetSelection or
// FlushPeer is retried on the next pass. Flushes are skipped after a
// failed SetSelection, so each transition flushes once.
func (m *Monitor) Tick(ctx context.Context) error {
	if len(m.set.Prefixes) == 0 {
		return nil
	}
	st, err := m.client.State(ctx, m.mux)
	if err != nil {
		return fmt.Errorf("mux %s: state: %w", m.mux, err)
	}
	res := Evaluate(st, m.set, m.prev, m.now())
	var firstErr error
	for _, a := range res.Actions {
		var err error
		switch a.Kind {
		case ActSetSelection:
			m.logger.Printf("wgmux monitor: mux %s: %s selection -> %s", m.mux, a.CIDR, formatSel(a.Selection))
			err = m.client.SetSelection(ctx, api.SetSelectionRequest{Mux: m.mux, CIDR: a.CIDR, Selection: a.Selection})
		case ActFlushPeer:
			if firstErr != nil {
				// Flushes follow the selection change; if that
				// failed, retry the whole transition next pass.
				continue
			}
			m.logger.Printf("wgmux monitor: mux %s: peer %s went unhealthy, flushing its flows", m.mux, a.Peer)
			err = m.client.FlushPeer(ctx, api.FlushPeerRequest{Mux: m.mux, Peer: a.Peer})
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("mux %s: %s: %w", m.mux, a.Kind, err)
		}
	}
	if firstErr == nil {
		m.prev = res.Health
	}
	return firstErr
}

func formatSel(sel []api.PeerWeight) string {
	s := ""
	for i, w := range sel {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%s=%d", w.Peer, w.EffectiveWeight())
	}
	return s
}

// Run evaluates every Failover.Interval seconds until stop is closed.
func Run(cfg *config.Mux, client Client, stop <-chan struct{}, logger *log.Logger) {
	m := New(cfg, client, logger)
	interval := time.Duration(cfg.Failover.Interval) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()
	pass := func() {
		cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
		defer ccancel()
		if err := m.Tick(cctx); err != nil && ctx.Err() == nil {
			m.logger.Printf("wgmux monitor: %v", err)
		}
	}
	pass()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			pass()
		}
	}
}
