// Command wgmuxd is the wgmux data-plane daemon. It hosts mux
// instances (namespaces, engines, BPF programs and maps) and serves
// the control-plane API (internal/api) on a unix socket. It makes
// no routing decisions of its own.
//
// Daemon-startup configuration is only the control socket and the
// BPF pin root: which engine an instance runs and how it is built
// are per-instance creation parameters, not daemon settings.
//
// The daemon must keep running for userspace (wireguard-go)
// instances; with the kernel engine an instance's datapath survives
// daemon exit, and a restarted daemon re-adopts it on the next
// apply to an instance of the same name and creation parameters.
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
	"github.com/tsuzu/wgmux/internal/daemon"
)

func main() {
	socket := flag.String("socket", "/run/wgmux/wgmuxd.sock", "control socket path")
	pinRoot := flag.String("pin-root", "/sys/fs/bpf", "bpffs base; kernel instances pin under <pin-root>/wgmux/<mux>")
	flag.Parse()

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
	fmt.Printf("wgmuxd: serving control API on %s\n", *socket)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		l.Close()
	}()
	if err := api.Serve(l, daemon.New(*pinRoot)); err != nil {
		fmt.Println("wgmuxd: listener closed")
	}
	os.Remove(*socket)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wgmuxd:", err)
	os.Exit(1)
}
