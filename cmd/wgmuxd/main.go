// Command wgmuxd is the wgmux data-plane daemon. It hosts mux
// instances and serves the control-plane API (internal/api) on a
// unix socket. It makes no routing decisions of its own.
//
// Everything about the daemon is fixed at startup (see
// docs/design.md): the socket, the ONE engine kind every instance
// uses, the kernel datapath shape (interconnect/attach/pin root),
// the spec-store directory, and whether stored instances are
// restored on boot. A systemd unit therefore fully describes a
// daemon.
//
// Stopping the daemon is detach-only: SIGTERM closes the listener
// and exits — kernel datapaths, BPF pins and the spec store are
// left untouched, and the next daemon adopts or rebuilds from
// them. (Userspace instances necessarily end with the process;
// they are rebuilt from the store on the next start.) Destruction
// is only ever the explicit API destroy.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/daemon"
)

func main() {
	socket := flag.String("socket", "/run/wgmux/wgmuxd.sock", "control socket path")
	engineKind := flag.String("engine", config.EngineKernel, "engine kind for every instance: kernel | userspace")
	interconnect := flag.String("interconnect", config.InterconnectVeth, "kernel engine: interconnect veth | netkit")
	attach := flag.String("attach", config.AttachTCX, "kernel engine: BPF attach tcx | tc")
	pinRoot := flag.String("pin-root", "/sys/fs/bpf", "kernel engine: bpffs base; instances pin under <pin-root>/wgmux/<mux>")
	stateDir := flag.String("state-dir", "/var/lib/wgmux", "spec store directory (instances persist under <state-dir>/instances)")
	restore := flag.Bool("restore", true, "restore stored instances at startup (kernel: adopt live objects, else rebuild)")
	flag.Parse()

	d, err := daemon.New(daemon.Config{
		Engine:       *engineKind,
		Interconnect: *interconnect,
		Attach:       *attach,
		PinRoot:      *pinRoot,
		StateDir:     *stateDir,
		Restore:      *restore,
	})
	if err != nil {
		fatal(err)
	}
	if infos, err := d.List(); err == nil {
		for _, info := range infos {
			fmt.Printf("wgmuxd: instance %s: %s\n", info.Mux, info.Status)
		}
	}

	if err := os.MkdirAll(filepath.Dir(*socket), 0o755); err != nil {
		fatal(err)
	}
	os.Remove(*socket) // stale socket from a previous run
	l, err := net.Listen("unix", *socket)
	if err != nil {
		fatal(err)
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		fatal(err)
	}
	fmt.Printf("wgmuxd: serving control API on %s (engine %s)\n", *socket, *engineKind)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		// Detach only: close the listener and exit. Instances,
		// pins and the store are deliberately left as they are.
		l.Close()
	}()
	if err := api.Serve(l, d); err != nil {
		fmt.Println("wgmuxd: listener closed (detached; datapath and store untouched)")
	}
	os.Remove(*socket)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wgmuxd:", err)
	os.Exit(1)
}
