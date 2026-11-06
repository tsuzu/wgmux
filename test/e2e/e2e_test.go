//go:build e2e

// Package e2e runs wgmux end to end on a containerlab topology:
//
//	mux ── eth1 ── sitea        both sites own the SAME inner IP
//	     └─ eth2 ── siteb        10.20.0.10 (that's the point)
//
// The test drives the full configuration lifecycle on ONE daemon:
//
//	daemon start (engine kind + kernel shape + state dir, startup only)
//	  → apply wg-quick files → instance wg-mux  (front 10.200.0.2)
//	  → apply wg-quick files → instance wg-mux2 (front 10.201.0.2)
//	  → traffic works on BOTH fronts; an activate on one instance
//	    does not affect the other
//	  → re-apply with a changed desired state (no recreate)
//	  → applies assuming another engine / creation params REJECTED
//	  → daemon restart: kernel datapath keeps flowing while the
//	    daemon is down; the new daemon ADOPTS the instances (no
//	    re-apply) and decisions work immediately. (Userspace:
//	    instances are rebuilt from the spec store — "restored".)
//	  → ECMP on wg-mux2 (YAML: mode ecmp): many parallel short
//	    connections land on BOTH sites (told apart by the HTTP
//	    response); weights 3:1 show as 48/16 datapath slots; a
//	    re-apply keeps the runtime weights, -reset-selections drops
//	    them; weights survive a daemon restart
//	  → a runtime activate survives a re-apply of unchanged config
//	  → failover (wgmuxctl run) with an ESTABLISHED long-lived UDP
//	    flow pinned to site-a: when site-a dies the flow moves to
//	    site-b (FlushPeer), not just new connections
//	  → destroying wg-mux leaves wg-mux2 passing traffic
//
// Mux peers are defined by standard wg-quick .conf files handed to
// `wgmuxctl apply` directly (the primary UX); the YAML file is the
// overlay for ECMP (wg-mux2) and the failover policy (wg-mux).
//
// Run it with:
//
//	go test -tags e2e ./test/e2e/ -v -timeout 25m
//
// Environment knobs (daemon-startup settings, per the lifecycle):
//
//	WGMUX_E2E_ENGINE        kernel (default) | userspace
//	WGMUX_E2E_INTERCONNECT  veth (default) | netkit   (kernel daemon)
//	WGMUX_E2E_ATTACH        tcx (default) | tc        (kernel daemon)
//	WGMUX_E2E_KEEP          1 = leave the lab running after the test
//
// The test skips (does not fail) when docker or containerlab are not
// available, so it is safe in environments without them.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	labName   = "wgmux-e2e"
	muxNode   = "clab-wgmux-e2e-mux"
	siteANode = "clab-wgmux-e2e-sitea"
	siteBNode = "clab-wgmux-e2e-siteb"

	muxOuterA  = "198.51.100.1"
	siteOuterA = "198.51.100.2"
	muxOuterB  = "198.51.101.1"
	siteOuterB = "198.51.101.2"

	innerIP = "10.20.0.10"

	// Instance wg-mux (front 10.200.0.2) and wg-mux2 (10.201.0.2).
	mux1Inner = "10.200.0.2"
	mux2Inner = "10.201.0.2"

	mux1PortA = 51821 // wg-mux listen ports (per peer device)
	mux1PortB = 51822
	mux2PortA = 51823 // wg-mux2 listen ports
	mux2PortB = 51824

	sitePort1 = 51820 // each site's wg0 listen port (tunnel to wg-mux)
	sitePort2 = 51825 // each site's wg1 listen port (tunnel to wg-mux2)

	markerURL = "http://" + innerIP + ":8080/"

	mux1Files = "/etc/wgmux/mux1/site-a.conf /etc/wgmux/mux1/site-b.conf"

	udpPort       = 9000  // sites answer UDP datagrams with their name
	udpClientPort = 40000 // the long-lived flow's fixed source port
	cidr          = innerIP + "/32"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type lab struct {
	t                    *testing.T
	dir                  string // test/e2e directory
	mux1Priv, mux2Priv   wgtypes.Key
	siteAPriv, siteBPriv wgtypes.Key
	daemonEngine         string
	daemonInterconnect   string
	daemonAttach         string
}

func runCmd(t *testing.T, name string, args ...string) string {
	t.Helper()
	return runCmdDir(t, "", name, args...)
}

func runCmdDir(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func tryCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// exec runs a shell command inside a lab node and fails the test on
// error.
func (l *lab) exec(node, script string) string {
	l.t.Helper()
	return runCmd(l.t, "docker", "exec", node, "sh", "-c", script)
}

// execOK is exec for commands whose failure is expected sometimes
// (polling probes, negative tests).
func (l *lab) execOK(node, script string) (string, error) {
	return tryCmd("docker", "exec", node, "sh", "-c", script)
}

// execBg starts a detached command inside a node (daemons, servers).
func (l *lab) execBg(node, script string) {
	l.t.Helper()
	runCmd(l.t, "docker", "exec", "-d", node, "sh", "-c", script)
}

// ctl runs wgmuxctl on the mux node, logging the command line so
// the CI log shows the user-visible lifecycle walkthrough.
func (l *lab) ctl(args string) string {
	l.t.Helper()
	l.t.Logf("$ wgmuxctl %s", args)
	out, err := l.execOK(muxNode, "wgmuxctl "+args)
	l.t.Logf("  -> %s", strings.TrimSpace(out))
	if err != nil {
		l.t.Fatalf("wgmuxctl %s failed: %v", args, err)
	}
	return out
}

// waitFor polls cond every interval until timeout, then fails.
func waitFor(t *testing.T, what string, timeout, interval time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestE2E(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if _, err := exec.LookPath("containerlab"); err != nil {
		t.Skip("containerlab not available")
	}
	l := &lab{t: t}
	l.daemonEngine = envOr("WGMUX_E2E_ENGINE", "kernel")
	l.daemonInterconnect = envOr("WGMUX_E2E_INTERCONNECT", "veth")
	l.daemonAttach = envOr("WGMUX_E2E_ATTACH", "tcx")
	var err error
	l.dir, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	l.setup()
	defer l.teardown()

	l.setupSite(siteANode, "site-a", siteOuterA, l.siteAPriv, muxPortFor(l, true, true), muxPortFor(l, false, true), 4)
	l.setupSite(siteBNode, "site-b", siteOuterB, l.siteBPriv, muxPortFor(l, true, false), muxPortFor(l, false, false), 6)
	l.setupMux()

	// === UX walkthrough: one daemon, two instances ===
	// Both fronts carry traffic to the active site (site-a).
	l.waitMarkerDiag("site-a", 120*time.Second)
	l.waitMarker2("site-a", 60*time.Second)

	// The one per-instance creation parameter (backend-address
	// override) is immutable for an existing instance.
	l.t.Logf("$ wgmuxctl apply --name wg-mux --backend-address 10.200.0.99/24 /etc/wgmux/mux1/site-a.conf /etc/wgmux/mux1/site-b.conf  (must fail)")
	out, err := l.execOK(muxNode, "wgmuxctl apply --name wg-mux --backend-address 10.200.0.99/24"+
		" /etc/wgmux/mux1/site-a.conf /etc/wgmux/mux1/site-b.conf")
	if err == nil || !strings.Contains(out, "immutable") {
		l.t.Fatalf("backend-address change on existing instance not rejected: err=%v out=%s", err, out)
	}
	l.t.Logf("  -> rejected as expected: %s", strings.TrimSpace(out))

	// Runtime decision on wg-mux: flips wg-mux only; wg-mux2 is
	// unaffected.
	l.ctl("activate --name wg-mux " + cidr + " site-b")
	l.waitMarker("site-b", 90*time.Second)
	l.marker2MustBe("site-a")
	l.ctl("activate --name wg-mux " + cidr + " site-a")
	l.waitMarker("site-a", 90*time.Second)

	// Per-Apply change WITHOUT recreating wg-mux2: re-apply with
	// the conf files in the other order (default active = first
	// file). The instance's creation time must not move.
	createdBefore := l.instanceCreated("wg-mux2")
	l.ctl("apply --name wg-mux2 --manage-routes=false /etc/wgmux/mux2/site-b.conf /etc/wgmux/mux2/site-a.conf")
	l.routeMux2() // manage_routes=false: external routes are the operator's job
	l.waitMarker2("site-b", 90*time.Second)
	if got := l.instanceCreated("wg-mux2"); got != createdBefore {
		l.t.Fatalf("wg-mux2 was recreated by a re-apply: created %s -> %s", createdBefore, got)
	}
	l.t.Logf("wg-mux2 re-applied in place (created still %s)", createdBefore)

	// === ECMP on wg-mux2: the YAML overlay makes the prefix mode ecmp ===
	l.ctl("apply -c /etc/wgmux/wgmux.yaml --name wg-mux2")
	l.routeMux2()
	l.waitBothSites2(120 * time.Second)
	l.mustStatus("wg-mux2", "mode ecmp")
	l.mustStatus("wg-mux2", "slots site-a=32 site-b=32")
	// Weighted 3:1 -> 48/16 slots, and the traffic mix follows.
	l.ctl("select --name wg-mux2 " + cidr + " site-a=3 site-b=1")
	l.mustStatus("wg-mux2", "slots site-a=48 site-b=16")
	counts := l.sampleMarkers("-interface", 120)
	l.t.Logf("3:1 sample over 120 connections: %v", counts)
	if counts["site-a"] == 0 || counts["site-b"] == 0 || counts["site-a"] <= counts["site-b"] {
		l.t.Fatalf("3:1 ECMP mix wrong: %v", counts)
	}
	// A re-apply of the unchanged overlay keeps the runtime weights;
	// -reset-selections returns to the configured (equal) ones.
	l.ctl("apply -c /etc/wgmux/wgmux.yaml --name wg-mux2")
	l.routeMux2()
	l.mustStatus("wg-mux2", "slots site-a=48 site-b=16")
	l.ctl("apply -c /etc/wgmux/wgmux.yaml --name wg-mux2 --reset-selections")
	l.routeMux2()
	l.mustStatus("wg-mux2", "slots site-a=32 site-b=32")
	// Leave 3:1 in place: it must survive the daemon restart below.
	l.ctl("select --name wg-mux2 " + cidr + " site-a=3 site-b=1")
	l.mustStatus("wg-mux2", "slots site-a=48 site-b=16")

	// === Daemon restart: detach, survive (kernel), adopt/restore ===
	l.t.Logf("$ kill wgmuxd   (SIGTERM = detach only)")
	l.exec(muxNode, "pkill -x wgmuxd; sleep 1; test ! -S /run/wgmux/wgmuxd.sock")
	if l.daemonEngine == "kernel" {
		// The kernel datapath never noticed: traffic still flows
		// with NO daemon running.
		l.waitMarker("site-a", 30*time.Second)
		l.t.Logf("kernel datapath kept flowing with the daemon down")
	}
	l.startDaemon()
	wantStatus := "restored"
	if l.daemonEngine == "kernel" {
		wantStatus = "adopted"
	}
	for _, name := range []string{"wg-mux", "wg-mux2"} {
		if got := l.instanceStatus(name); got != wantStatus {
			l.t.Fatalf("instance %s status after restart = %q, want %q (list: %s)", name, got, wantStatus, l.ctl("list"))
		}
	}
	l.t.Logf("both instances %s after daemon restart, with no re-apply", wantStatus)
	// A userspace front TUN is recreated by the restore, which drops
	// the operator route tied to the old link; re-assert it (for the
	// kernel engine the front never went away and this is a no-op).
	l.routeMux2()
	// Adopted/restored instances serve traffic and decisions at once.
	l.waitMarker("site-a", 60*time.Second)
	// The runtime ECMP weights came back with the instance.
	l.mustStatus("wg-mux2", "slots site-a=48 site-b=16")
	l.waitBothSites2(60 * time.Second)
	l.ctl("activate --name wg-mux " + cidr + " site-b")
	l.waitMarker("site-b", 60*time.Second)
	// A re-apply of unchanged config keeps the runtime selection...
	l.ctl("apply --name wg-mux " + mux1Files)
	l.mustStatus("wg-mux", "selection site-b:1")
	l.waitMarker("site-b", 30*time.Second)
	// ...until it is explicitly reset to the configured one.
	l.ctl("apply --name wg-mux --reset-selections " + mux1Files)
	l.mustStatus("wg-mux", "selection site-a:1")
	l.waitMarker("site-a", 60*time.Second)

	// Failover on wg-mux, driven by the policy runner (`wgmuxctl
	// run`): killing site-a's wg-mux tunnel must move wg-mux flows to
	// site-b once the handshake ages past 150s — INCLUDING an
	// established long-lived flow, which only moves because the
	// runner flushes the dead peer's flow pins. Apply the overlay
	// first so the daemon reports policy failover (the selection,
	// site-a, is unchanged and kept).
	l.ctl("apply -c /etc/wgmux/wgmux.yaml --name wg-mux")
	l.mustStatus("wg-mux", "policy failover")
	l.mustStatus("wg-mux", "selection site-a:1")
	l.startUDPProbe()
	l.waitUDPTail("site-a", 60*time.Second)
	l.t.Logf("$ wgmuxctl run -c /etc/wgmux/wgmux.yaml &")
	l.execBg(muxNode, "nohup wgmuxctl run -c /etc/wgmux/wgmux.yaml >/var/log/policy.log 2>&1 &")
	l.exec(siteANode, "ip link set wg0 down")
	l.waitMarker("site-b", 300*time.Second)
	l.mustStatus("wg-mux", "selection site-b:1")
	l.waitUDPTail("site-b", 60*time.Second)
	l.t.Logf("established UDP flow moved to site-b after site-a died")
	l.exec(muxNode, "pkill -f '[u]dpprobe.py' || true")

	// Destroying wg-mux leaves wg-mux2 passing traffic.
	l.ctl("destroy --name wg-mux")
	l.waitBothSites2(60 * time.Second)
	if out, err := l.execOK(muxNode, "wgmuxctl status"); err != nil || strings.Contains(out, "mux wg-mux (") {
		l.t.Fatalf("wg-mux still listed after destroy: err=%v\n%s", err, out)
	}
	l.ctl("destroy --name wg-mux2")
}

// muxPortFor returns the mux-side listen port for (mux1?, siteA?).
func muxPortFor(l *lab, mux1, siteA bool) int {
	switch {
	case mux1 && siteA:
		return mux1PortA
	case mux1:
		return mux1PortB
	case siteA:
		return mux2PortA
	default:
		return mux2PortB
	}
}

func (l *lab) setup() {
	t := l.t
	repoRoot := filepath.Dir(filepath.Dir(l.dir))

	gen := func() wgtypes.Key {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	l.mux1Priv, l.mux2Priv, l.siteAPriv, l.siteBPriv = gen(), gen(), gen(), gen()

	// Build the binaries shipped in the node image.
	binDir := filepath.Join(l.dir, "bin")
	os.MkdirAll(binDir, 0o755)
	runCmdDir(t, repoRoot, "go", "build", "-o", filepath.Join(binDir, "wgmuxd"), "./cmd/wgmuxd")
	runCmdDir(t, repoRoot, "go", "build", "-o", filepath.Join(binDir, "wgmuxctl"), "./cmd/wgmuxctl")

	runCmd(t, "docker", "build", "-f", filepath.Join(l.dir, "Dockerfile.node"),
		"-t", "wgmux-node:e2e", l.dir)
	runCmd(t, "containerlab", "deploy", "-t", filepath.Join(l.dir, "topology.clab.yml"), "--reconfigure")
	for _, node := range []string{muxNode, siteANode, siteBNode} {
		node := node
		waitFor(t, "node "+node+" ready", 60*time.Second, 2*time.Second, func() bool {
			_, err := l.execOK(node, "true")
			return err == nil
		})
	}
}

func (l *lab) teardown() {
	if os.Getenv("WGMUX_E2E_KEEP") == "1" {
		l.t.Log("WGMUX_E2E_KEEP=1: leaving lab up")
		return
	}
	tryCmd("containerlab", "destroy", "-t", filepath.Join(l.dir, "topology.clab.yml"), "--cleanup")
}

// setupSite configures one site: outer address, TWO WireGuard
// devices (wg0 → instance wg-mux, wg1 → instance wg-mux2), each
// holding the SHARED inner IP, and a marker HTTP server on the
// inner IP that answers with the site's name.
func (l *lab) setupSite(node, name, outer string, priv wgtypes.Key, mux1Port, mux2Port, pingEvery int) {
	l.exec(node, fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", outer))
	muxOuter := muxOuterA
	if strings.HasSuffix(node, "siteb") {
		muxOuter = muxOuterB
	}
	l.exec(node, "ip link add wg0 type wireguard && ip link add wg1 type wireguard")
	l.exec(node, fmt.Sprintf("printf '%%s' '%s' > /tmp/priv && "+
		"wg set wg0 listen-port %d private-key /tmp/priv peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 5 && "+
		"wg set wg1 listen-port %d private-key /tmp/priv peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 5",
		priv.String(),
		sitePort1, l.mux1Priv.PublicKey().String(), mux1Inner, muxOuter, mux1Port,
		sitePort2, l.mux2Priv.PublicKey().String(), mux2Inner, muxOuter, mux2Port))
	l.exec(node, "ip addr add "+innerIP+"/32 dev wg0 && ip addr add "+innerIP+"/32 dev wg1 && ip link set wg0 up && ip link set wg1 up")
	// Raw `wg set` installs no routes (wg-quick would): without
	// these, traffic for the muxes' tunnel addresses leaves via the
	// management default route instead of the tunnels.
	l.exec(node, "ip route add "+mux1Inner+"/32 dev wg0 && ip route add "+mux2Inner+"/32 dev wg1")
	l.exec(node, "mkdir -p /srv && printf '"+name+"\\n' > /srv/index.html")
	// UDP responder (answers with the site name): the target of the
	// long-lived flow in the failover scenario.
	l.exec(node, "cat > /tmp/udpecho.py <<'EOF'\n"+
		"import socket\n"+
		"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"+
		fmt.Sprintf("s.bind((%q, %d))\n", innerIP, udpPort)+
		"while True:\n"+
		"    d, a = s.recvfrom(100)\n"+
		fmt.Sprintf("    s.sendto(b%q, a)\n", name+"\n")+
		"EOF")
	l.execBg(node, "nohup python3 /tmp/udpecho.py >/var/log/udpecho.log 2>&1 &")
	l.execBg(node, "nohup python3 -m http.server 8080 --bind "+innerIP+" --directory /srv >/var/log/http.log 2>&1 &")
	// Keep both tunnels warm so handshakes stay fresh: the failover
	// monitor judges candidates by handshake age. Only the SITES
	// initiate periodically (the mux peers have no persistent
	// keepalive), and the two sites use different periods (4s/6s):
	// with keepalives on BOTH ends at the same period, simultaneous
	// initiations can phase-lock and a pair's handshake never
	// completes (observed in CI: rounds of crossed initiations every
	// 5s, zero sessions). One-sided initiation cannot cross.
	l.execBg(node, fmt.Sprintf("nohup sh -c 'while true; do ping -c1 -W2 "+mux1Inner+" >/dev/null 2>&1; ping -c1 -W2 "+mux2Inner+" >/dev/null 2>&1; sleep %d; done' >/dev/null 2>&1 &", pingEvery))
}

// wgConf renders one standard wg-quick file for a mux peer.
func wgConf(listenPort int, priv wgtypes.Key, front string, sitePub wgtypes.Key, endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d
Address = %s/24

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s/32
`, priv.String(), listenPort, front, sitePub.String(), endpoint, innerIP)
}

// setupMux writes the wg-quick files + the monitor's YAML overlay
// into the mux node, starts the daemon (startup config only:
// socket + pin root), and applies both instances from the files.
func (l *lab) setupMux() {
	l.exec(muxNode, fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", muxOuterA))
	l.exec(muxNode, fmt.Sprintf("ip addr add %s/24 dev eth2 && ip link set eth2 up", muxOuterB))
	// bpffs for the pinned maps (privileged container: mount works).
	l.exec(muxNode, "mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true")
	l.exec(muxNode, "mkdir -p /etc/wgmux/mux1 /etc/wgmux/mux2 /run/wgmux")

	write := func(path, body string) {
		l.exec(muxNode, "cat > "+path+" <<'EOF'\n"+body+"EOF")
	}
	write("/etc/wgmux/mux1/site-a.conf", wgConf(mux1PortA, l.mux1Priv, mux1Inner, l.siteAPriv.PublicKey(), siteOuterA+":"+fmt.Sprint(sitePort1)))
	write("/etc/wgmux/mux1/site-b.conf", wgConf(mux1PortB, l.mux1Priv, mux1Inner, l.siteBPriv.PublicKey(), siteOuterB+":"+fmt.Sprint(sitePort1)))
	write("/etc/wgmux/mux2/site-a.conf", wgConf(mux2PortA, l.mux2Priv, mux2Inner, l.siteAPriv.PublicKey(), siteOuterA+":"+fmt.Sprint(sitePort2)))
	write("/etc/wgmux/mux2/site-b.conf", wgConf(mux2PortB, l.mux2Priv, mux2Inner, l.siteBPriv.PublicKey(), siteOuterB+":"+fmt.Sprint(sitePort2)))

	// The YAML overlay: failover policy for wg-mux and an ECMP prefix
	// for wg-mux2. The instances themselves are first created from
	// the conf files below; the overlay is applied over them later.
	write("/etc/wgmux/wgmux.yaml", fmt.Sprintf(`api_socket: /run/wgmux/wgmuxd.sock
muxes:
  - name: wg-mux
    peers:
      - {name: site-a, wg_config: /etc/wgmux/mux1/site-a.conf}
      - {name: site-b, wg_config: /etc/wgmux/mux1/site-b.conf}
    prefixes:
      - {cidr: %s, policy: failover}
    failover:
      handshake_max_age_seconds: 150
      interval_seconds: 5
  - name: wg-mux2
    manage_routes: false
    peers:
      - {name: site-a, wg_config: /etc/wgmux/mux2/site-a.conf}
      - {name: site-b, wg_config: /etc/wgmux/mux2/site-b.conf}
    prefixes:
      - {cidr: %s, mode: ecmp}
`, cidr, cidr))

	l.startDaemon()

	l.ctl("apply --name wg-mux /etc/wgmux/mux1/site-a.conf /etc/wgmux/mux1/site-b.conf")
	l.ctl("apply --name wg-mux2 --manage-routes=false /etc/wgmux/mux2/site-a.conf /etc/wgmux/mux2/site-b.conf")
	l.routeMux2()
	l.ctl("status")
}

// routeMux2 installs the operator-owned route toward wg-mux2
// (source-based, so wg-mux's main-table route to the same inner IP
// is untouched). Re-applied instances may recreate the front link,
// so this uses replace and is re-run after re-applies.
func (l *lab) routeMux2() {
	route := "ip route replace " + innerIP + "/32 dev wg-mux2 table 202"
	if l.daemonEngine == "kernel" {
		// Same shape as the managed route: via the instance's
		// backend address. A bare dev route on the veth front would
		// make the stack ARP for the inner IP itself, which nothing
		// answers (the interconnect is a point-to-point pair, not a
		// LAN segment).
		route = "ip route replace " + innerIP + "/32 via 10.201.0.1 dev wg-mux2 table 202"
	}
	l.exec(muxNode, "ip rule add from "+mux2Inner+" lookup 202 2>/dev/null || true; "+route)
}

// startDaemon (re)starts wgmuxd with this job's startup settings:
// engine kind, kernel shape, pin root, state dir. Used for the
// initial start and for the restart/adoption phase.
func (l *lab) startDaemon() {
	flags := "-socket /run/wgmux/wgmuxd.sock -engine " + l.daemonEngine +
		" -pin-root /sys/fs/bpf -state-dir /var/lib/wgmux"
	if l.daemonEngine == "kernel" {
		flags += " -interconnect " + l.daemonInterconnect + " -attach " + l.daemonAttach
	}
	l.t.Logf("$ wgmuxd %s &", flags)
	l.execBg(muxNode, "nohup wgmuxd "+flags+" >>/var/log/wgmuxd.log 2>&1 &")
	waitFor(l.t, "wgmuxd socket", 30*time.Second, time.Second, func() bool {
		_, err := l.execOK(muxNode, "test -S /run/wgmux/wgmuxd.sock")
		return err == nil
	})
}

// instanceStatus reads an instance's lifecycle status from
// `wgmuxctl list`.
func (l *lab) instanceStatus(name string) string {
	out := l.ctl("list")
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, name+"\t") {
			for _, field := range strings.Split(line, "\t") {
				if strings.HasPrefix(field, "status=") {
					return strings.TrimPrefix(field, "status=")
				}
			}
		}
	}
	l.t.Fatalf("instance %s not in list output:\n%s", name, out)
	return ""
}

// instanceCreated reads an instance's creation timestamp from
// `wgmuxctl list`.
func (l *lab) instanceCreated(name string) string {
	out := l.ctl("list")
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, name+"\t") {
			for _, field := range strings.Split(line, "\t") {
				if strings.HasPrefix(field, "created=") {
					return strings.TrimPrefix(field, "created=")
				}
			}
		}
	}
	l.t.Fatalf("instance %s not in list output:\n%s", name, out)
	return ""
}

// marker fetches the marker document through the wg-mux front.
func (l *lab) marker() (string, error) {
	out, err := l.execOK(muxNode, "curl -s --max-time 5 "+markerURL)
	return strings.TrimSpace(out), err
}

// marker2 fetches the marker through the wg-mux2 front by binding
// the mux2 front address as the source (the policy rule routes it
// via table 202).
func (l *lab) marker2() (string, error) {
	out, err := l.execOK(muxNode, "curl -s --max-time 5 --interface "+mux2Inner+" "+markerURL)
	return strings.TrimSpace(out), err
}

func (l *lab) waitMarker(want string, timeout time.Duration) {
	l.t.Helper()
	waitFor(l.t, "wg-mux marker == "+want, timeout, 3*time.Second, func() bool {
		got, err := l.marker()
		if err == nil && got == want {
			return true
		}
		l.t.Logf("wg-mux marker poll: got %q err %v (want %q)", got, err, want)
		return false
	})
}

func (l *lab) waitMarker2(want string, timeout time.Duration) {
	l.t.Helper()
	waitFor(l.t, "wg-mux2 marker == "+want, timeout, 3*time.Second, func() bool {
		got, err := l.marker2()
		if err == nil && got == want {
			return true
		}
		l.t.Logf("wg-mux2 marker poll: got %q err %v (want %q)", got, err, want)
		return false
	})
}

func (l *lab) marker2MustBe(want string) {
	l.t.Helper()
	got, err := l.marker2()
	if err != nil || got != want {
		l.t.Fatalf("wg-mux2 marker = %q err %v, want %q (instance isolation broken?)", got, err, want)
	}
}

// mustStatus asserts `wgmuxctl status --name <mux>` contains want
// (polling briefly: selections settle asynchronously on userspace).
func (l *lab) mustStatus(mux, want string) {
	l.t.Helper()
	var last string
	for i := 0; i < 10; i++ {
		out, err := l.execOK(muxNode, "wgmuxctl status --name "+mux)
		last = out
		if err == nil && strings.Contains(out, want) {
			return
		}
		time.Sleep(time.Second)
	}
	l.t.Fatalf("status of %s does not contain %q:\n%s", mux, want, last)
}

// sampleMarkers opens n short HTTP connections (20 in parallel,
// each a fresh source port, hence a fresh flow hash) and counts the
// responding sites. A non-empty bindIface means "through wg-mux2".
func (l *lab) sampleMarkers(bindIface string, n int) map[string]int {
	bind := ""
	if bindIface != "" {
		bind = "--interface " + mux2Inner + " "
	}
	script := fmt.Sprintf("seq 1 %d | xargs -P 20 -I{} sh -c 'curl -s --max-time 5 %s%s; echo'", n, bind, markerURL)
	out, _ := l.execOK(muxNode, script)
	counts := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			counts[line]++
		}
	}
	return counts
}

// waitBothSites2 waits until parallel connections through wg-mux2
// are answered by BOTH sites.
func (l *lab) waitBothSites2(timeout time.Duration) {
	l.t.Helper()
	waitFor(l.t, "wg-mux2 ECMP reaching both sites", timeout, 3*time.Second, func() bool {
		c := l.sampleMarkers("-interface", 60)
		l.t.Logf("wg-mux2 ECMP sample: %v", c)
		return c["site-a"] > 0 && c["site-b"] > 0
	})
}

// startUDPProbe starts the long-lived flow: one fixed 5-tuple
// (mux1 front address:udpClientPort -> inner IP:udpPort), one
// datagram every 500ms, each reply's site name appended to a log.
func (l *lab) startUDPProbe() {
	l.t.Helper()
	l.exec(muxNode, "cat > /tmp/udpprobe.py <<'EOF'\n"+
		"import socket, time\n"+
		"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"+
		fmt.Sprintf("s.bind((%q, %d))\n", mux1Inner, udpClientPort)+
		"s.settimeout(0.4)\n"+
		"while True:\n"+
		fmt.Sprintf("    s.sendto(b'x', (%q, %d))\n", innerIP, udpPort)+
		"    try:\n"+
		"        r = s.recvfrom(100)[0].decode().strip()\n"+
		"    except socket.timeout:\n"+
		"        r = 'timeout'\n"+
		"    open('/tmp/udp.log', 'a').write(r + '\\n')\n"+
		"    time.sleep(0.1)\n"+
		"EOF")
	l.exec(muxNode, "rm -f /tmp/udp.log; touch /tmp/udp.log")
	l.execBg(muxNode, "nohup python3 /tmp/udpprobe.py >/var/log/udpprobe.log 2>&1 &")
}

// waitUDPTail waits until the long-lived flow's most recent replies
// all come from `want`.
func (l *lab) waitUDPTail(want string, timeout time.Duration) {
	l.t.Helper()
	waitFor(l.t, "long-lived UDP flow answered by "+want, timeout, 2*time.Second, func() bool {
		out, _ := l.execOK(muxNode, "tail -n 5 /tmp/udp.log")
		lines := strings.Fields(out)
		ok := len(lines) == 5
		for _, ln := range lines {
			if ln != want {
				ok = false
			}
		}
		if !ok {
			l.t.Logf("udp flow tail: %v (want all %s)", lines, want)
		}
		return ok
	})
}

// waitMarkerDiag is waitMarker plus, on timeout, a full datapath
// diagnostic dump (state + packet captures during a live probe) so
// a CI failure shows exactly which hop drops the traffic.
func (l *lab) waitMarkerDiag(want string, timeout time.Duration) {
	l.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, err := l.marker()
		if err == nil && got == want {
			return
		}
		time.Sleep(3 * time.Second)
	}
	l.diagnostics()
	l.t.Fatalf("timed out waiting for marker == %s (diagnostics above)", want)
}

func (l *lab) diagExec(node, label, cmd string) {
	out, err := l.execOK(node, cmd)
	l.t.Logf("--- diag %s (%s): err=%v\n%s", node, label, err, out)
}

func (l *lab) diagnostics() {
	l.t.Helper()
	l.diagExec(muxNode, "routes+rules+status",
		"ip route; echo; ip rule; echo; ip route show table 202; echo; wgmuxctl status 2>&1")
	l.diagExec(muxNode, "wg-mux backend (kernel engine only)",
		"ip netns exec wgmux-wg-mux ip addr; echo; ip netns exec wgmux-wg-mux ip -s link; echo; ip netns exec wgmux-wg-mux wg show all")
	l.diagExec(muxNode, "bpf pins",
		"ls -la /sys/fs/bpf/wgmux/ /sys/fs/bpf/wgmux/wg-mux/ 2>&1; echo; ip netns exec wgmux-wg-mux tc filter show dev mux-b ingress 2>&1 | head -3")
	l.diagExec(muxNode, "daemon log", "cat /var/log/wgmuxd.log")
	l.diagExec(siteANode, "site-a server+wg",
		"ss -tlnp 2>/dev/null | head; echo; cat /var/log/http.log 2>&1 | head -5; echo; wg show all")

	// Live probe with captures on every hop (kernel datapath hops
	// only exist for the kernel engine; missing ones just error).
	caps := []struct{ node, name, cmd string }{
		{muxNode, "front", "timeout 9 tcpdump -ni wg-mux -c 20 -xx"},
		{muxNode, "back", "timeout 9 ip netns exec wgmux-wg-mux tcpdump -ni mux-b -c 20 -xx"},
		{muxNode, "wga", "timeout 9 ip netns exec wgmux-wg-mux tcpdump -ni wg-site-a -c 20 -xx"},
		{muxNode, "eth1", "timeout 9 tcpdump -ni eth1 -c 20"},
		{siteANode, "wg0", "timeout 9 tcpdump -ni wg0 -c 20 -xx"},
		{siteANode, "eth1", "timeout 9 tcpdump -ni eth1 -c 20"},
	}
	for _, c := range caps {
		l.execBg(c.node, "nohup sh -c '"+c.cmd+" >/tmp/cap-"+c.name+".log 2>&1' >/dev/null 2>&1 &")
	}
	time.Sleep(time.Second)
	l.diagExec(muxNode, "probe ping inner", "ping -c2 -W2 "+innerIP+" 2>&1")
	l.diagExec(muxNode, "probe curl", "curl -v --max-time 4 "+markerURL+" 2>&1 | head -20")
	time.Sleep(9 * time.Second)
	for _, c := range caps {
		l.diagExec(c.node, "capture "+c.name, "cat /tmp/cap-"+c.name+".log")
	}
}
