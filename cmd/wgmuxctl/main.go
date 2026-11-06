// Command wgmuxctl is the wgmux control plane. It drives the data
// plane (wgmuxd) exclusively through internal/api and never touches
// netlink or BPF itself.
//
// The basic use needs no config file at all — hand it the wg-quick
// files you already have:
//
//	wgmuxctl apply site-a.conf site-b.conf
//
// and the two tunnels become one aggregated interface (wg-mux).
// A YAML config (-c) is the optional overlay for policies
// (failover/bgp), ECMP prefixes, several muxes in one file, or
// inline peers;
// in YAML form a peer can reference a wg file with `wg_config:`.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/bgp"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/monitor"
)

const defaultSocket = "/run/wgmux/wgmuxd.sock"

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
	case "list":
		err = cmdList(os.Args[2:])
	case "activate":
		err = cmdActivate(os.Args[2:])
	case "select":
		err = cmdSelect(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, `usage: wgmuxctl <command> [flags] [args]

commands:
  apply     [flags] <wg.conf>...        aggregate wg-quick files into one mux
  apply     -c config.yaml              apply the mux(es) from a YAML config
  destroy   [-c config | -name mux]     tear mux instance(s) down
  status    [-c config | -name mux]     show instances, peers, selections, slots
  list      [-socket path]              list the daemon's mux instances
  activate  [-name mux] [-flush] <cidr> <peer>
                                        select exactly one peer for a prefix
  select    [-name mux] [-flush] <cidr> <peer>[=weight]...
                                        select several peers (ECMP), optionally weighted
  run       -c config [-name mux]       run the failover monitor + BGP source for
                                        every mux in the config (the policy runner;
                                        see contrib/wgmux-policy.service)
  monitor   -c config [-name mux]       run only the failover policy, one mux
  bgp       -c config [-name mux]       run only the BGP selection source, one mux
  validate  -c config | <wg.conf>...    check inputs only

selection changes are graceful by default: established flows keep their
peer. With -flush, flows pinned to a peer that was in the previous
selection and is not in the new one are moved immediately.

apply flags (direct wg-file mode):
  -name wg-mux        instance name (= front interface name; default wg-mux)
  -backend-address A  interconnect backend address (creation parameter, kernel only)
  -front-address A    override the front address derived from the conf files
  -manage-routes      install routes to the front interface (default true)
  -reset-selections   drop runtime selections; go back to the configured ones
  -monitor, -bgp      also run the policy daemons in the foreground`)
}

// commonFlags are the flags every config/daemon command shares.
type commonFlags struct {
	configPath *string
	socket     *string
	name       *string
}

func addCommon(fs *flag.FlagSet) *commonFlags {
	return &commonFlags{
		configPath: fs.String("c", "", "YAML config file"),
		socket:     fs.String("socket", "", "wgmuxd socket (default: config's api_socket, else "+defaultSocket+")"),
		name:       fs.String("name", "", "mux instance name"),
	}
}

func socketFor(cf *commonFlags, cfg *config.Config) string {
	if *cf.socket != "" {
		return *cf.socket
	}
	if cfg != nil && cfg.APISocket != "" {
		return cfg.APISocket
	}
	return defaultSocket
}

func clientFor(cf *commonFlags, cfg *config.Config) *api.Client {
	return &api.Client{SocketPath: socketFor(cf, cfg)}
}

func loadYAML(cf *commonFlags) (*config.Config, error) {
	if *cf.configPath == "" {
		return nil, fmt.Errorf("this command needs -c <config.yaml>")
	}
	return config.Load(*cf.configPath)
}

// selectMuxes returns the config's muxes, or only the named one.
func selectMuxes(cfg *config.Config, name string) ([]*config.Mux, error) {
	if name == "" {
		return cfg.Muxes, nil
	}
	m := cfg.MuxByName(name)
	if m == nil {
		return nil, fmt.Errorf("config has no mux named %q", name)
	}
	return []*config.Mux{m}, nil
}

func selectOneMux(cfg *config.Config, name string) (*config.Mux, error) {
	muxes, err := selectMuxes(cfg, name)
	if err != nil {
		return nil, err
	}
	if len(muxes) != 1 {
		return nil, fmt.Errorf("config defines %d muxes; select one with -name", len(muxes))
	}
	return muxes[0], nil
}

// ensureAndApply checks the daemon's API version, creates the
// instance if the daemon does not have it yet (verifying
// creation-parameter immutability if it does), then applies the
// desired state. It returns the daemon's engine kind.
func ensureAndApply(ctx context.Context, client *api.Client, mux *config.Mux, intent config.CreationSpec, resetSelections bool) (string, error) {
	dinfo, err := client.Info(ctx)
	if err != nil {
		return "", err
	}
	if err := checkDaemon(dinfo); err != nil {
		return "", err
	}
	spec, err := buildSpec(mux)
	if err != nil {
		return "", err
	}
	// The front's name is the instance name.
	spec.Front.Name = mux.Name
	infos, err := client.List(ctx)
	if err != nil {
		return "", err
	}
	exists := false
	for _, info := range infos {
		if info.Mux == mux.Name {
			exists = true
			if err := checkImmutable(info, intent); err != nil {
				return "", err
			}
		}
	}
	if !exists {
		if err := client.Create(ctx, buildCreate(mux)); err != nil {
			return "", err
		}
	}
	if err := client.Apply(ctx, api.ApplyRequest{Mux: mux.Name, Spec: spec, ResetSelections: resetSelections}); err != nil {
		return "", err
	}
	return dinfo.Engine, nil
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	cf := addCommon(fs)
	backendAddr := fs.String("backend-address", "", "interconnect backend address (creation parameter, kernel engine)")
	frontAddr := fs.String("front-address", "", "override the derived front address")
	frontMTU := fs.Int("front-mtu", 0, "override the front MTU")
	manageRoutes := fs.Bool("manage-routes", true, "install main-namespace routes to the front interface")
	resetSel := fs.Bool("reset-selections", false, "drop runtime selections (activate/select/failover/bgp) and go back to the configured ones")
	withMonitor := fs.Bool("monitor", false, "also run the failover policy in the foreground")
	withBGP := fs.Bool("bgp", false, "also run the BGP selection source in the foreground")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	ctx := context.Background()

	if len(files) > 0 {
		// Direct mode: build the mux from the wg files themselves.
		if *cf.configPath != "" {
			return fmt.Errorf("give either -c <config.yaml> or wg .conf files, not both (in YAML mode, reference the files with wg_config: instead)")
		}
		mux, err := config.MuxFromWGFiles(*cf.name, files)
		if err != nil {
			return err
		}
		for _, w := range mux.Warnings {
			fmt.Fprintf(os.Stderr, "wgmux: warning: %s\n", w)
		}
		intent := config.CreationSpec{}
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		if visited["backend-address"] {
			mux.Kernel.BackendAddress = *backendAddr
			intent.BackendAddress, intent.BackendAddressSet = *backendAddr, true
		}
		if visited["front-address"] {
			mux.Front.Address = *frontAddr
		}
		if visited["front-mtu"] {
			mux.Front.MTU = *frontMTU
		}
		if visited["manage-routes"] {
			mux.ManageRoutes = manageRoutes
		}
		client := clientFor(cf, nil)
		kind, err := ensureAndApply(ctx, client, mux, intent, *resetSel)
		if err != nil {
			return err
		}
		fmt.Printf("wgmuxctl: applied mux %s (engine=%s, %d peers, %d prefixes)\n",
			mux.Name, kind, len(mux.Peers), len(mux.EffectivePrefixes))
		if *withMonitor || *withBGP {
			return runPolicies(mux, client, *withMonitor, *withBGP)
		}
		return nil
	}

	// YAML mode.
	cfg, err := loadYAML(cf)
	if err != nil {
		return fmt.Errorf("no wg .conf files given: %w", err)
	}
	muxes, err := selectMuxes(cfg, *cf.name)
	if err != nil {
		return err
	}
	client := clientFor(cf, cfg)
	for _, mux := range muxes {
		kind, err := ensureAndApply(ctx, client, mux, mux.CreationSpec(), *resetSel)
		if err != nil {
			return err
		}
		fmt.Printf("wgmuxctl: applied mux %s (engine=%s, %d peers, %d prefixes)\n",
			mux.Name, kind, len(mux.Peers), len(mux.EffectivePrefixes))
	}
	if *withMonitor || *withBGP {
		mux, err := selectOneMux(cfg, *cf.name)
		if err != nil {
			return err
		}
		return runPolicies(mux, client, *withMonitor, *withBGP)
	}
	return nil
}

func cmdDestroy(args []string) error {
	fs := flag.NewFlagSet("destroy", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	var cfg *config.Config
	var targets []string
	if *cf.configPath != "" {
		var err error
		cfg, err = loadYAML(cf)
		if err != nil {
			return err
		}
		muxes, err := selectMuxes(cfg, *cf.name)
		if err != nil {
			return err
		}
		for _, m := range muxes {
			targets = append(targets, m.Name)
		}
	}
	client := clientFor(cf, cfg)
	if len(targets) == 0 {
		if *cf.name != "" {
			targets = []string{*cf.name}
		} else {
			infos, err := client.List(ctx)
			if err != nil {
				return err
			}
			for _, info := range infos {
				targets = append(targets, info.Mux)
			}
		}
	}
	var errs []error
	for _, name := range targets {
		if err := client.Destroy(ctx, name); err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Printf("wgmuxctl: destroyed mux %s\n", name)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	var cfg *config.Config
	if *cf.configPath != "" {
		var err error
		cfg, err = loadYAML(cf)
		if err != nil {
			return err
		}
	}
	client := clientFor(cf, cfg)
	var names []string
	created := map[string]time.Time{}
	infos, err := client.List(ctx)
	if err != nil {
		return err
	}
	for _, info := range infos {
		created[info.Mux] = info.CreatedAt
	}
	if cfg != nil {
		muxes, err := selectMuxes(cfg, *cf.name)
		if err != nil {
			return err
		}
		for _, m := range muxes {
			names = append(names, m.Name)
		}
	} else if *cf.name != "" {
		names = []string{*cf.name}
	} else {
		for _, info := range infos {
			names = append(names, info.Mux)
		}
	}
	for _, name := range names {
		st, err := client.State(ctx, name)
		if err != nil {
			return err
		}
		printState(st, created[name])
	}
	return nil
}

func printState(st api.State, createdAt time.Time) {
	head := fmt.Sprintf("mux %s (engine %s, status %s", st.Mux, st.Engine, st.Status)
	if !createdAt.IsZero() {
		head += ", created " + createdAt.Format(time.RFC3339)
	}
	fmt.Println(head + ")")
	if st.Error != "" {
		fmt.Printf("  error: %s\n", st.Error)
	}
	nameByID := map[uint32]string{}
	for _, p := range st.Peers {
		nameByID[p.ID] = p.Name
	}
	fmt.Println("  peers:")
	for _, p := range st.Peers {
		hs := "never"
		if !p.LastHandshake.IsZero() {
			hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
		}
		ep := p.Endpoint
		if ep == "" {
			ep = "-"
		}
		fmt.Printf("    %-16s handshake %-12s rx %-10d tx %-10d endpoint %s\n",
			p.Name, hs, p.BytesReceived, p.BytesSent, ep)
	}
	fmt.Println("  prefixes:")
	for _, p := range st.Prefixes {
		fmt.Printf("    %-18s mode %-6s policy %-8s selection %s\n",
			p.CIDR, orDash(p.Mode), orDash(p.Policy), formatSelection(p.Selection))
		fmt.Printf("    %-18s candidates %s\n", "", strings.Join(p.Candidates, ", "))
		if len(p.Slots) > 0 {
			fmt.Printf("    %-18s slots %s\n", "", formatSlots(p.Slots))
		}
	}
	if len(st.Counters) > 0 {
		keys := make([]string, 0, len(st.Counters))
		for k := range st.Counters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("  counters:")
		for _, k := range keys {
			fmt.Printf("    %s %d\n", k, st.Counters[k])
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// formatSelection renders a selection as "a:1,b:3".
func formatSelection(sel []api.PeerWeight) string {
	if len(sel) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(sel))
	for _, w := range sel {
		parts = append(parts, fmt.Sprintf("%s:%d", w.Peer, w.EffectiveWeight()))
	}
	return strings.Join(parts, ",")
}

// formatSlots renders the datapath's slot ownership as
// "a=48 b=16" (peer names sorted).
func formatSlots(slots map[string]int) string {
	names := make([]string, 0, len(slots))
	for n := range slots {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", n, slots[n]))
	}
	return strings.Join(parts, " ")
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := clientFor(cf, nil)
	infos, err := client.List(context.Background())
	if err != nil {
		return err
	}
	for _, info := range infos {
		line := fmt.Sprintf("%s\tengine=%s\tstatus=%s\tcreated=%s", info.Mux, info.Engine, info.Status, info.CreatedAt.Format(time.RFC3339))
		if info.BackendAddress != "" {
			line += "\tbackend_address=" + info.BackendAddress
		}
		if info.Error != "" {
			line += "\terror=" + info.Error
		}
		fmt.Println(line)
	}
	return nil
}

// muxNameFor resolves the target mux of a runtime command: -name,
// else the config's only mux, else the default name.
func muxNameFor(cf *commonFlags, cfg *config.Config) (string, error) {
	if *cf.name != "" {
		return *cf.name, nil
	}
	if cfg != nil {
		m, err := selectOneMux(cfg, "")
		if err != nil {
			return "", err
		}
		return m.Name, nil
	}
	return config.DefaultMuxName, nil
}

func cmdActivate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ContinueOnError)
	cf := addCommon(fs)
	flush := fs.Bool("flush", false, "also move established flows off the previously selected peer(s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: wgmuxctl activate [-name mux] [-flush] <cidr> <peer>")
	}
	return runSelect(cf, fs.Arg(0), []string{fs.Arg(1)}, *flush)
}

func cmdSelect(args []string) error {
	fs := flag.NewFlagSet("select", flag.ContinueOnError)
	cf := addCommon(fs)
	flush := fs.Bool("flush", false, "also move established flows off peers that leave the selection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: wgmuxctl select [-name mux] [-flush] <cidr> <peer>[=weight]...")
	}
	return runSelect(cf, fs.Arg(0), fs.Args()[1:], *flush)
}

func runSelect(cf *commonFlags, cidr string, specs []string, flush bool) error {
	sel, err := parseSelection(specs)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var cfg *config.Config
	if *cf.configPath != "" {
		cfg, err = loadYAML(cf)
		if err != nil {
			return err
		}
	}
	muxName, err := muxNameFor(cf, cfg)
	if err != nil {
		return err
	}
	res, err := changeSelection(ctx, clientFor(cf, cfg), muxName, cidr, sel, flush)
	if err != nil {
		return err
	}
	fmt.Printf("wgmuxctl: mux %s: %s now selects %s\n", muxName, res.CIDR, formatSelection(sel))
	for _, peer := range res.Flushed {
		fmt.Printf("wgmuxctl: mux %s: flushed flows of %s\n", muxName, peer)
	}
	return nil
}

// parseSelection parses "peer" / "peer=weight" arguments.
func parseSelection(specs []string) ([]api.PeerWeight, error) {
	var sel []api.PeerWeight
	seen := map[string]bool{}
	for _, sp := range specs {
		name, wtxt, hasW := strings.Cut(sp, "=")
		if name == "" {
			return nil, fmt.Errorf("bad selection %q: empty peer name", sp)
		}
		if seen[name] {
			return nil, fmt.Errorf("peer %q given twice", name)
		}
		seen[name] = true
		w := uint64(1)
		if hasW {
			var err error
			w, err = strconv.ParseUint(wtxt, 10, 32)
			if err != nil || w == 0 {
				return nil, fmt.Errorf("bad weight in %q: want a positive integer", sp)
			}
		}
		sel = append(sel, api.PeerWeight{Peer: name, Weight: uint32(w)})
	}
	return sel, nil
}

type selectionClient interface {
	State(ctx context.Context, mux string) (api.State, error)
	SetSelection(ctx context.Context, req api.SetSelectionRequest) error
	FlushPeer(ctx context.Context, req api.FlushPeerRequest) error
}

type selectionResult struct {
	CIDR    string
	Flushed []string
}

// changeSelection reads the daemon's State (peer and prefix names
// are resolved there, so this works the same for wg-file and YAML
// muxes), sets the new selection, and with flush calls FlushPeer for
// every peer of the PREVIOUS selection that is not in the new one.
func changeSelection(ctx context.Context, client selectionClient, mux, cidr string, sel []api.PeerWeight, flush bool) (selectionResult, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return selectionResult{}, err
	}
	canon := ipnet.String()
	st, err := client.State(ctx, mux)
	if err != nil {
		return selectionResult{}, err
	}
	var ps *api.PrefixState
	for i := range st.Prefixes {
		if st.Prefixes[i].CIDR == canon {
			ps = &st.Prefixes[i]
		}
	}
	if ps == nil {
		return selectionResult{}, fmt.Errorf("mux %s has no prefix %s", mux, canon)
	}
	if err := (api.PrefixSpec{CIDR: canon, Candidates: ps.Candidates, Mode: ps.Mode}).ValidateSelection(sel); err != nil {
		return selectionResult{}, fmt.Errorf("%w (candidates: %s)", err, strings.Join(ps.Candidates, ", "))
	}
	if err := client.SetSelection(ctx, api.SetSelectionRequest{Mux: mux, CIDR: canon, Selection: sel}); err != nil {
		return selectionResult{}, err
	}
	res := selectionResult{CIDR: canon}
	if !flush {
		return res, nil
	}
	staying := map[string]bool{}
	for _, w := range sel {
		staying[w.Peer] = true
	}
	for _, w := range ps.Selection {
		if staying[w.Peer] {
			continue
		}
		if err := client.FlushPeer(ctx, api.FlushPeerRequest{Mux: mux, Peer: w.Peer}); err != nil {
			return res, fmt.Errorf("selection changed, but flushing %s failed: %w", w.Peer, err)
		}
		res.Flushed = append(res.Flushed, w.Peer)
	}
	return res, nil
}

func cmdMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadYAML(cf)
	if err != nil {
		return err
	}
	mux, err := selectOneMux(cfg, *cf.name)
	if err != nil {
		return err
	}
	return runPolicies(mux, clientFor(cf, cfg), true, false)
}

func cmdBGP(args []string) error {
	fs := flag.NewFlagSet("bgp", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadYAML(cf)
	if err != nil {
		return err
	}
	mux, err := selectOneMux(cfg, *cf.name)
	if err != nil {
		return err
	}
	if mux.BGP.Mode == config.BGPModeNone {
		return fmt.Errorf("mux %q: bgp.mode is none in this config", mux.Name)
	}
	return runPolicies(mux, clientFor(cf, cfg), false, true)
}

// runPolicies runs the long-lived control-plane decision makers
// (failover monitor and/or BGP source) for one mux until
// interrupted. Both funnel into api.SetSelection; an arbiter is
// unnecessary because they own disjoint prefix sets by policy
// (failover vs bgp prefixes).
func runPolicies(mux *config.Mux, client *api.Client, withMonitor, withBGP bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()
	errCh := make(chan error, 2)
	if withMonitor {
		stop := make(chan struct{})
		go func() {
			<-ctx.Done()
			close(stop)
		}()
		go func() {
			monitor.Run(mux, client, stop, nil)
			errCh <- nil
		}()
		fmt.Printf("wgmuxctl: failover monitor running (mux %s)\n", mux.Name)
	}
	if withBGP {
		src, err := bgp.NewSource(mux)
		if err != nil {
			return err
		}
		go func() {
			errCh <- bgp.Run(ctx, mux, src, client)
		}()
		fmt.Printf("wgmuxctl: BGP selection source running (mux %s, mode %s)\n", mux.Name, mux.BGP.Mode)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadYAML(cf)
	if err != nil {
		return err
	}
	muxes, err := selectMuxes(cfg, *cf.name)
	if err != nil {
		return err
	}
	client := clientFor(cf, cfg)
	ctx, cancel := signalContext()
	defer cancel()

	var wg sync.WaitGroup
	started := 0
	for _, mux := range muxes {
		mux := mux
		var failover, bgpPrefix bool
		for _, p := range mux.EffectivePrefixes {
			failover = failover || p.Policy == config.PolicyFailover
			bgpPrefix = bgpPrefix || p.Policy == config.PolicyBGP
		}
		if failover {
			started++
			fmt.Printf("wgmuxctl: mux %s: failover monitor running\n", mux.Name)
			stop := make(chan struct{})
			go func() { <-ctx.Done(); close(stop) }()
			wg.Add(1)
			go func() {
				defer wg.Done()
				monitor.Run(mux, client, stop, nil)
			}()
		}
		if bgpPrefix && mux.BGP.Mode != config.BGPModeNone {
			started++
			fmt.Printf("wgmuxctl: mux %s: BGP selection source running (mode %s)\n", mux.Name, mux.BGP.Mode)
			wg.Add(1)
			go func() {
				defer wg.Done()
				superviseBGP(ctx, mux, client)
			}()
		}
		if !failover && !bgpPrefix {
			fmt.Printf("wgmuxctl: mux %s: no failover or bgp prefixes, nothing to run\n", mux.Name)
		}
	}
	if started == 0 {
		return fmt.Errorf("nothing to run: no mux has a failover or bgp prefix")
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// superviseBGP keeps a mux's BGP source alive: when it exits with an
// error (or panics), it is restarted with exponential backoff (1s up
// to 30s; the backoff resets after a run longer than a minute).
func superviseBGP(ctx context.Context, mux *config.Mux, client *api.Client) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := runBGPOnce(ctx, mux, client)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		fmt.Fprintf(os.Stderr, "wgmuxctl: mux %s: BGP source stopped (%v); restarting in %s\n", mux.Name, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func runBGPOnce(ctx context.Context, mux *config.Mux, client *api.Client) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	src, err := bgp.NewSource(mux)
	if err != nil {
		return err
	}
	return bgp.Run(ctx, mux, src, client)
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) > 0 {
		mux, err := config.MuxFromWGFiles(*cf.name, files)
		if err != nil {
			return err
		}
		for _, w := range mux.Warnings {
			fmt.Fprintf(os.Stderr, "wgmux: warning: %s\n", w)
		}
		if _, err := buildSpec(mux); err != nil {
			return err
		}
		fmt.Printf("wgmuxctl: wg files OK (mux %s, %d peers, %d prefixes, front %s)\n",
			mux.Name, len(mux.Peers), len(mux.EffectivePrefixes), mux.Front.Address)
		return nil
	}
	cfg, err := loadYAML(cf)
	if err != nil {
		return err
	}
	for _, mux := range cfg.Muxes {
		if _, err := buildSpec(mux); err != nil {
			return err
		}
		fmt.Printf("wgmuxctl: mux %s OK (%d peers, %d prefixes, bgp=%s)\n",
			mux.Name, len(mux.Peers), len(mux.EffectivePrefixes), mux.BGP.Mode)
	}
	return nil
}
