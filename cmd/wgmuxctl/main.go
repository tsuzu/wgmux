// Command wgmuxctl is the wgmux control plane. It owns the config
// file and every selection policy (manual activation, handshake
// failover, BGP), and drives the data plane (wgmuxd) exclusively
// through internal/api. It never touches netlink or BPF itself.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/bgp"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/datapath"
	"github.com/tsuzu/wgmux/internal/monitor"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "apply":
		err = cmdApply(os.Args[2:])
	case "destroy":
		err = cmdDestroy(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "activate":
		err = cmdActivate(os.Args[2:])
	case "monitor":
		err = cmdMonitor(os.Args[2:])
	case "bgp":
		err = cmdBGP(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wgmuxctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: wgmuxctl <command> [flags]

commands:
  apply     [-c config] [--monitor] [--bgp]  send desired state to wgmuxd
  destroy   [-c config]                      tear the datapath down
  status    [-c config]                      show peers and current selections
  activate  [-c config] <cidr> <peer>        make peer the active selection for a prefix
  monitor   [-c config]                      run the failover policy in the foreground
  bgp       [-c config]                      run the BGP selection source in the foreground
  validate  [-c config]                      check a config file only`)
}

func loadCfg(args []string, extra func(fs *flag.FlagSet)) (*config.Config, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("wgmuxctl", flag.ContinueOnError)
	path := fs.String("c", "wgmux.yaml", "config file")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, fs, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return nil, fs, err
	}
	return cfg, fs, nil
}

func clientFor(cfg *config.Config) *api.Client {
	return &api.Client{SocketPath: cfg.APISocket}
}

func cmdApply(args []string) error {
	var withMonitor, withBGP bool
	cfg, _, err := loadCfg(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&withMonitor, "monitor", false, "also run the failover policy in the foreground")
		fs.BoolVar(&withBGP, "bgp", false, "also run the BGP selection source in the foreground")
	})
	if err != nil {
		return err
	}
	spec, err := buildSpec(cfg)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := clientFor(cfg).Apply(ctx, spec); err != nil {
		return err
	}
	fmt.Printf("wgmuxctl: applied via wgmuxd (engine=%s, %d peers, interconnect=%s, attach=%s)\n",
		spec.Engine, len(spec.Peers), spec.Interconnect, spec.Attach)
	if withMonitor || withBGP {
		return runPolicies(cfg, withMonitor, withBGP)
	}
	return nil
}

func cmdDestroy(args []string) error {
	cfg, _, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	if err := clientFor(cfg).Destroy(context.Background()); err != nil {
		return err
	}
	fmt.Println("wgmuxctl: destroyed")
	return nil
}

func cmdStatus(args []string) error {
	cfg, _, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	st, err := clientFor(cfg).State(context.Background())
	if err != nil {
		return err
	}
	nameByID := map[uint32]string{}
	for i := range cfg.Peers {
		nameByID[uint32(cfg.Peers[i].ID)] = cfg.Peers[i].Name
	}
	fmt.Printf("engine: %s\npeers:\n", st.Engine)
	for _, p := range st.Peers {
		hs := "never"
		if !p.LastHandshake.IsZero() {
			hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
		}
		fmt.Printf("  %-16s dev %-16s ifindex %-3d handshake %-12s rx %d tx %d\n",
			p.Name, p.Device, p.Ifindex, hs, p.BytesReceived, p.BytesSent)
	}
	fmt.Println("prefixes:")
	for _, p := range st.Prefixes {
		fmt.Printf("  %-18s policy %-6s active %s (candidates:", p.CIDR, p.Policy, nameByID[p.ActiveID])
		for _, id := range p.CandidateIDs {
			fmt.Printf(" %s", nameByID[id])
		}
		fmt.Println(")")
	}
	if dbg, err := datapath.DebugSnapshot(cfg.PinDir); err == nil {
		fmt.Printf("datapath: entries %d framed %d strips %d redirects %d last_len %d last_word0 %08x after_len %d after_word0 %08x\n",
			dbg[0], dbg[1], dbg[2], dbg[7], dbg[3], dbg[4], dbg[5], dbg[6])
		fmt.Printf("datapath-wg: entries %d cfg_fail %d grow_fail %d store_fail %d redirects %d\n",
			dbg[8], dbg[9], dbg[10], dbg[11], dbg[12])
	}
	return nil
}

func cmdActivate(args []string) error {
	cfg, fs, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: wgmuxctl activate [-c config] <cidr> <peer>")
	}
	if _, _, err := net.ParseCIDR(fs.Arg(0)); err != nil {
		return err
	}
	peer := cfg.PeerByName(fs.Arg(1))
	if peer == nil {
		return fmt.Errorf("unknown peer %q", fs.Arg(1))
	}
	err = clientFor(cfg).SetActive(context.Background(), api.SetActiveRequest{CIDR: fs.Arg(0), PeerID: uint32(peer.ID)})
	if err != nil {
		return err
	}
	fmt.Printf("wgmuxctl: %s now selects %s\n", fs.Arg(0), peer.Name)
	return nil
}

func cmdMonitor(args []string) error {
	cfg, _, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	return runPolicies(cfg, true, false)
}

func cmdBGP(args []string) error {
	cfg, _, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	if cfg.BGP.Mode == config.BGPModeNone {
		return fmt.Errorf("bgp.mode is none in this config")
	}
	return runPolicies(cfg, false, true)
}

// runPolicies runs the long-lived control-plane decision makers
// (failover monitor and/or BGP source) until interrupted. Both funnel
// into api.SetActive; an arbiter is unnecessary because they own
// disjoint prefix sets by policy (failover vs bgp prefixes).
func runPolicies(cfg *config.Config, withMonitor, withBGP bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()
	client := clientFor(cfg)
	errCh := make(chan error, 2)
	if withMonitor {
		stop := make(chan struct{})
		go func() {
			<-ctx.Done()
			close(stop)
		}()
		go func() {
			monitor.Run(cfg, client, stop, nil)
			errCh <- nil
		}()
		fmt.Println("wgmuxctl: failover monitor running")
	}
	if withBGP {
		src, err := bgp.NewSource(cfg)
		if err != nil {
			return err
		}
		go func() {
			errCh <- bgp.Run(ctx, cfg, src, client)
		}()
		fmt.Printf("wgmuxctl: BGP selection source running (mode %s)\n", cfg.BGP.Mode)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func cmdValidate(args []string) error {
	cfg, _, err := loadCfg(args, nil)
	if err != nil {
		return err
	}
	if _, err := buildSpec(cfg); err != nil {
		return err
	}
	fmt.Printf("wgmuxctl: config OK (%d peers, %d prefixes, engine=%s, interconnect=%s, attach=%s, bgp=%s)\n",
		len(cfg.Peers), len(cfg.Prefixes), cfg.Engine, cfg.Interconnect, cfg.Attach, cfg.BGP.Mode)
	return nil
}
