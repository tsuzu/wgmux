//go:build e2e

// Package e2e runs wgmux end to end on a containerlab topology:
//
//	mux ── eth1 ── sitea        both sites own the SAME inner IP
//	     └─ eth2 ── siteb        10.20.0.10 (that's the point)
//
// The test brings the lab up, applies a two-peer wgmux config on the
// mux node, and asserts real traffic behaviour:
//
//  1. curl http://10.20.0.10:8080/ reaches the ACTIVE site's marker.
//  2. `wgmuxctl activate` flips subsequent flows to the other site.
//  3. With the failover monitor running, killing the active site's
//     WireGuard device flips flows to the surviving site.
//
// Run it with:
//
//	go test -tags e2e ./test/e2e/ -v -timeout 25m
//
// Environment knobs:
//
//	WGMUX_E2E_ENGINE        kernel (default) | userspace
//	WGMUX_E2E_INTERCONNECT  veth (default) | netkit
//	WGMUX_E2E_ATTACH        tcx (default) | tc
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

	innerIP   = "10.20.0.10"
	muxInner  = "10.200.0.2"
	muxPortA  = 51821 // mux's listen port for the site-a device
	muxPortB  = 51822
	sitePort  = 51820 // each site's own listen port
	markerURL = "http://" + innerIP + ":8080/"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type lab struct {
	t                             *testing.T
	dir                           string // test/e2e directory
	muxPriv, siteAPriv, siteBPriv wgtypes.Key
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
// (polling probes).
func (l *lab) execOK(node, script string) (string, error) {
	return tryCmd("docker", "exec", node, "sh", "-c", script)
}

// execBg starts a detached command inside a node (daemons, servers).
func (l *lab) execBg(node, script string) {
	l.t.Helper()
	runCmd(l.t, "docker", "exec", "-d", node, "sh", "-c", script)
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
	var err error
	l.dir, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	l.setup()
	defer l.teardown()

	l.setupSite(siteANode, "site-a", siteOuterA, l.siteAPriv, muxOuterA, muxPortA, l.muxPriv.PublicKey())
	l.setupSite(siteBNode, "site-b", siteOuterB, l.siteBPriv, muxOuterB, muxPortB, l.muxPriv.PublicKey())
	l.setupMux()

	// Both tunnels up; traffic lands on the active site (site-a).
	l.waitMarkerDiag("site-a", 120*time.Second)

	// Manual activation flips new flows to site-b and back.
	l.markerViaCtl("site-b")
	l.markerViaCtl("site-a")

	// Failover: with the monitor running, killing site-a's tunnel must
	// move flows to site-b once site-a's handshake ages past the
	// configured threshold (150s) — poll generously.
	l.execBg(muxNode, "nohup wgmuxctl monitor -c /etc/wgmux/wgmux.yaml >/var/log/monitor.log 2>&1 &")
	l.exec(siteANode, "ip link set wg0 down")
	l.waitMarker("site-b", 300*time.Second)
}

func (l *lab) setup() {
	t := l.t
	repoRoot := filepath.Dir(filepath.Dir(l.dir))

	// Keys for mux + both sites.
	gen := func() wgtypes.Key {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	l.muxPriv, l.siteAPriv, l.siteBPriv = gen(), gen(), gen()

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

// setupSite configures one site: outer address, a WireGuard device
// whose only address is the SHARED inner IP, a peer entry for the mux
// (allowed source = the mux's tunnel address), and a marker HTTP
// server on the inner IP that answers with the site's name.
func (l *lab) setupSite(node, name, outer string, priv wgtypes.Key, muxOuter string, muxPort int, muxPub wgtypes.Key) {
	l.exec(node, fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", outer))
	l.exec(node, "ip link add wg0 type wireguard")
	l.exec(node, fmt.Sprintf("printf '%%s' '%s' > /tmp/priv && wg set wg0 listen-port %d private-key /tmp/priv peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 5",
		priv.String(), sitePort, muxPub.String(), muxInner, muxOuter, muxPort))
	l.exec(node, "ip addr add "+innerIP+"/32 dev wg0 && ip link set wg0 up")
	// Raw `wg set` installs no routes (wg-quick would): without this,
	// traffic for the mux's tunnel address leaves via the management
	// default route instead of the tunnel — replies included.
	l.exec(node, "ip route add "+muxInner+"/32 dev wg0")
	l.exec(node, "mkdir -p /srv && printf '"+name+"\\n' > /srv/index.html")
	l.execBg(node, "nohup python3 -m http.server 8080 --bind "+innerIP+" --directory /srv >/var/log/http.log 2>&1 &")
	// Keep the tunnel to the mux warm so handshakes stay fresh: the
	// failover monitor judges candidates by handshake age.
	l.execBg(node, "nohup sh -c 'while true; do ping -c1 -W2 "+muxInner+" >/dev/null 2>&1; sleep 5; done' >/dev/null 2>&1 &")
}

// setupMux writes the wgmux config into the mux node and applies it.
func (l *lab) setupMux() {
	l.exec(muxNode, fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", muxOuterA))
	l.exec(muxNode, fmt.Sprintf("ip addr add %s/24 dev eth2 && ip link set eth2 up", muxOuterB))
	// bpffs for the pinned maps (privileged container: mount works).
	l.exec(muxNode, "mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true")
	l.exec(muxNode, "mkdir -p /etc/wgmux /run/wgmux")
	l.exec(muxNode, fmt.Sprintf("printf '%%s' '%s' > /etc/wgmux/private.key", l.muxPriv.String()))

	cfg := fmt.Sprintf(`front:
  name: wg-mux
  address: 10.200.0.2/24
  backend_address: 10.200.0.1/24
backend_ns: wgmux
engine: %s
interconnect: %s
attach: %s
api_socket: /run/wgmux/wgmuxd.sock
identity:
  private_key_file: /etc/wgmux/private.key
peers:
  - name: site-a
    listen_port: %d
    public_key: "%s"
    endpoint: %s:%d
    persistent_keepalive: 5
  - name: site-b
    listen_port: %d
    public_key: "%s"
    endpoint: %s:%d
    persistent_keepalive: 5
prefixes:
  - cidr: %s/32
    candidates: [site-a, site-b]
    active: site-a
    policy: failover
failover:
  handshake_max_age_seconds: 150
  interval_seconds: 5
`,
		envOr("WGMUX_E2E_ENGINE", "kernel"),
		envOr("WGMUX_E2E_INTERCONNECT", "veth"),
		envOr("WGMUX_E2E_ATTACH", "tcx"),
		muxPortA, l.siteAPriv.PublicKey().String(), siteOuterA, sitePort,
		muxPortB, l.siteBPriv.PublicKey().String(), siteOuterB, sitePort,
		innerIP)
	l.exec(muxNode, "cat > /etc/wgmux/wgmux.yaml <<'EOF'\n"+cfg+"EOF")
	l.execBg(muxNode, "nohup wgmuxd -socket /run/wgmux/wgmuxd.sock >/var/log/wgmuxd.log 2>&1 &")
	waitFor(l.t, "wgmuxd socket", 30*time.Second, time.Second, func() bool {
		_, err := l.execOK(muxNode, "test -S /run/wgmux/wgmuxd.sock")
		return err == nil
	})
	out, err := l.execOK(muxNode, "wgmuxctl apply -c /etc/wgmux/wgmux.yaml")
	if err != nil {
		diag, _ := l.execOK(muxNode, "echo '--- ip link'; ip link; "+
			"echo '--- netns'; ip netns list; "+
			"echo '--- backend links'; ip -n wgmux link 2>&1; "+
			"echo '--- wg'; wg show all 2>&1; "+
			"echo '--- bpf pins'; ls -laR /sys/fs/bpf 2>&1 | head -30; "+
			"echo '--- wgmuxd log'; cat /var/log/wgmuxd.log")
		l.t.Fatalf("apply failed: %v\n%s\ndiagnostics:\n%s", err, out, diag)
	}
	l.t.Logf("apply: %s", strings.TrimSpace(out))
}

// marker fetches the marker document through the muxed IP from inside
// the mux node.
func (l *lab) marker() (string, error) {
	out, err := l.execOK(muxNode, "curl -s --max-time 5 "+markerURL)
	return strings.TrimSpace(out), err
}

// waitMarkerDiag is waitMarker plus, on timeout, a full datapath
// diagnostic dump (state + packet captures during a live probe) so a
// CI failure shows exactly which hop drops the traffic.
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
	l.diagExec(muxNode, "routes+neigh+front stats",
		"ip route; echo; ip neigh; echo; ip -s link show wg-mux; echo; wgmuxctl status -c /etc/wgmux/wgmux.yaml 2>&1")
	l.diagExec(muxNode, "backend state",
		"ip netns exec wgmux ip addr; echo; ip netns exec wgmux ip -s link; echo; ip netns exec wgmux wg show all")
	l.diagExec(muxNode, "bpf pins",
		"ls -la /sys/fs/bpf/wgmux/ /sys/fs/bpf/wgmux/links/ 2>&1; echo; "+
			"tc filter show dev mux-b ingress 2>&1 | head -3; "+
			"ip netns exec wgmux tc filter show dev mux-b ingress 2>&1 | head -3")
	l.diagExec(siteANode, "site-a server+wg",
		"ss -tlnp 2>/dev/null | head; echo; cat /var/log/http.log 2>&1 | head -5; echo; "+
			"curl -s --max-time 3 http://"+innerIP+":8080/ ; echo; wg show all")

	// Live probe with captures on every hop. Hex dumps included:
	// the exact first bytes at the wg device decide between the
	// remaining hypotheses (header strip mis-fire vs parse offset).
	caps := []struct{ node, name, cmd string }{
		{muxNode, "front", "timeout 9 tcpdump -ni wg-mux -c 20 -xx"},
		{muxNode, "back", "timeout 9 ip netns exec wgmux tcpdump -ni mux-b -c 20 -xx"},
		{muxNode, "wga", "timeout 9 ip netns exec wgmux tcpdump -ni wg-site-a -c 20 -xx"},
		{muxNode, "eth1", "timeout 9 tcpdump -ni eth1 -c 20"},
		{siteANode, "wg0", "timeout 9 tcpdump -ni wg0 -c 20 -xx"},
		{siteANode, "eth1", "timeout 9 tcpdump -ni eth1 -c 20"},
	}
	for _, c := range caps {
		l.execBg(c.node, "nohup sh -c '"+c.cmd+" >/tmp/cap-"+c.name+".log 2>&1' >/dev/null 2>&1 &")
	}
	time.Sleep(time.Second)
	l.diagExec(muxNode, "probe ping gateway (no steering)", "ping -c2 -W2 10.200.0.1 2>&1")
	l.diagExec(muxNode, "probe ping inner", "ping -c2 -W2 "+innerIP+" 2>&1")
	l.diagExec(muxNode, "probe curl", "curl -v --max-time 4 "+markerURL+" 2>&1 | head -20")
	time.Sleep(9 * time.Second)
	for _, c := range caps {
		l.diagExec(c.node, "capture "+c.name, "cat /tmp/cap-"+c.name+".log")
	}
	l.diagExec(muxNode, "backend wg after probe", "ip netns exec wgmux wg show all")
}

func (l *lab) waitMarker(want string, timeout time.Duration) {
	l.t.Helper()
	waitFor(l.t, "marker == "+want, timeout, 3*time.Second, func() bool {
		got, err := l.marker()
		if err == nil && got == want {
			return true
		}
		l.t.Logf("marker poll: got %q err %v (want %q)", got, err, want)
		return false
	})
}

// markerViaCtl activates a peer through the control plane and waits
// for traffic to land there.
func (l *lab) markerViaCtl(site string) {
	l.t.Helper()
	l.exec(muxNode, "wgmuxctl activate -c /etc/wgmux/wgmux.yaml "+innerIP+"/32 "+site)
	l.waitMarker(site, 90*time.Second)
}
