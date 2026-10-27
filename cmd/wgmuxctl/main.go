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
// (failover/bgp/hash), several muxes in one file, or inline peers;
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
	"strings"
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
  status    [-c config | -name mux]     show instances, peers and selections
  list      [-socket path]              list the daemon's mux instances
  activate  [-name mux] <cidr> <peer>   make peer the active selection for a prefix
  monitor   -c config [-name mux]       run the failover policy in the foreground
  bgp       -c config [-name mux]       run the BGP selection source in the foreground
  validate  -c config | <wg.conf>...    check inputs only

apply flags (direct wg-file mode):
  -name wg-mux        instance name (= front interface name; default wg-mux)
  -engine kernel      assert the daemon's engine kind (a wgmuxd startup setting)
  -interconnect veth  assert the daemon's interconnect (kernel, startup setting)
  -attach tcx         assert the daemon's attach mode (kernel, startup setting)
  -backend-address A  interconnect backend address (creation parameter, kernel only)
  -front-address A    override the front address derived from the conf files
  -manage-routes      install routes to the front interface (default true)
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

// ensureAndApply checks the apply's daemon-level assumptions
// (engine kind, kernel shape — startup settings), creates the
// instance if the daemon does not have it yet (verifying
// creation-parameter immutability if it does), then applies the
// desired state. It returns the daemon's engine kind (the config's
// own engine field is only a guard, never the source of truth).
func ensureAndApply(ctx context.Context, client *api.Client, mux *config.Mux, intent config.CreationSpec) (string, error) {
	dinfo, err := client.Info(ctx)
	if err != nil {
		return "", err
	}
	if err := checkDaemon(dinfo, intent); err != nil {
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
	if err := client.Apply(ctx, mux.Name, spec); err != nil {
		return "", err
	}
	return dinfo.Engine, nil
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	cf := addCommon(fs)
	engine := fs.String("engine", "", "assert the daemon's engine kind: kernel | userspace (a wgmuxd startup setting)")
	interconnect := fs.String("interconnect", "", "assert the daemon's interconnect: veth | netkit (startup setting)")
	attach := fs.String("attach", "", "assert the daemon's attach mode: tcx | tc (startup setting)")
	backendAddr := fs.String("backend-address", "", "interconnect backend address (creation parameter, kernel engine)")
	frontAddr := fs.String("front-address", "", "override the derived front address")
	frontMTU := fs.Int("front-mtu", 0, "override the front MTU")
	manageRoutes := fs.Bool("manage-routes", true, "install main-namespace routes to the front interface")
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
		if visited["engine"] {
			mux.Engine = *engine
			intent.Engine, intent.EngineSet = *engine, true
		}
		if visited["interconnect"] {
			mux.Kernel.Interconnect = *interconnect
			intent.Interconnect, intent.InterconnectSet = *interconnect, true
		}
		if visited["attach"] {
			mux.Kernel.Attach = *attach
			intent.Attach, intent.AttachSet = *attach, true
		}
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
		kind, err := ensureAndApply(ctx, client, mux, intent)
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
		kind, err := ensureAndApply(ctx, client, mux, mux.CreationSpec())
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
		var cands []string
		for _, id := range p.CandidateIDs {
			cands = append(cands, nameByID[id])
		}
		fmt.Printf("    %-18s policy %-6s active %s (candidates: %s)\n",
			p.CIDR, p.Policy, nameByID[p.ActiveID], strings.Join(cands, ", "))
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

func cmdActivate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ContinueOnError)
	cf := addCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: wgmuxctl activate [-name mux] <cidr> <peer>")
	}
	if _, _, err := net.ParseCIDR(fs.Arg(0)); err != nil {
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
	muxName := *cf.name
	if muxName == "" && cfg != nil {
		m, err := selectOneMux(cfg, "")
		if err != nil {
			return err
		}
		muxName = m.Name
	}
	if muxName == "" {
		muxName = config.DefaultMuxName
	}
	// Resolve the peer name against the daemon's live state: this
	// works the same whether the mux came from wg files or YAML.
	st, err := client.State(ctx, muxName)
	if err != nil {
		return err
	}
	var peerID uint32
	found := false
	for _, p := range st.Peers {
		if p.Name == fs.Arg(1) {
			peerID, found = p.ID, true
		}
	}
	if !found {
		return fmt.Errorf("mux %q has no peer %q", muxName, fs.Arg(1))
	}
	if err := client.SetActive(ctx, api.SetActiveRequest{Mux: muxName, CIDR: fs.Arg(0), PeerID: peerID}); err != nil {
		return err
	}
	fmt.Printf("wgmuxctl: mux %s: %s now selects %s\n", muxName, fs.Arg(0), fs.Arg(1))
	return nil
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
// interrupted. Both funnel into api.SetActive; an arbiter is
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
		fmt.Printf("wgmuxctl: mux %s OK (%d peers, %d prefixes, engine=%s, bgp=%s)\n",
			mux.Name, len(mux.Peers), len(mux.EffectivePrefixes), mux.Engine, mux.BGP.Mode)
	}
	return nil
}
