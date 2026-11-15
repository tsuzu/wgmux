//go:build integration

// Package integration is a single-host integration test of the wgmux
// data plane. It needs no containerlab: everything runs inside one
// privileged Linux container with network namespaces.
//
//	main ns (wgmuxd in-process, front 10.200.0.2)
//	   |-- veth 192.168.1.0/30 --- ns it-site-a (wg0, owns 10.20.0.10)
//	   '-- veth 192.168.2.0/30 --- ns it-site-b (wg0, owns 10.20.0.10)
//
// Both sites own the SAME inner address 10.20.0.10 and answer TCP/UDP
// with their site name. The daemon is driven in-process through its
// api.Handler methods. Run (inside a privileged container with bpffs):
//
//	WGMUX_TEST_INTEGRATION=1 go test -tags integration -v -count=1 ./test/integration/
package integration

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/daemon"
	"github.com/tsuzu/wgmux/internal/engine"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

const (
	innerIP  = "10.20.0.10"
	frontIP  = "10.200.0.2"
	muxName  = "wgmuxit"
	sitePort = 51820
	muxPortA = 51821
	muxPortB = 51822
)

func sh(t testing.TB, script string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("sh %q: %v\n%s", script, err, out)
	}
	return string(out)
}

func shOK(script string) { exec.Command("sh", "-c", script).Run() }

// ---- sites ----------------------------------------------------------

type site struct {
	name   string
	ns     string
	outer  string // site underlay address
	mainIP string // main-ns end of the veth
	priv   wgtypes.Key
	tcp    net.Listener
	udp    net.PacketConn
}

func (s *site) pub() wgtypes.Key { return s.priv.PublicKey() }

// newSite builds the namespace, veth pair, wg device (created INSIDE
// the namespace so its UDP socket lives there), and marker servers.
func newSite(t *testing.T, name string, idx int, muxPub wgtypes.Key, muxPort int, keepalive time.Duration) *site {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &site{name: name, ns: "it-" + name, priv: priv,
		mainIP: fmt.Sprintf("192.168.%d.1", idx), outer: fmt.Sprintf("192.168.%d.2", idx)}
	cleanup := func() {
		if s.tcp != nil {
			s.tcp.Close()
		}
		if s.udp != nil {
			s.udp.Close()
		}
		shOK("ip netns del " + s.ns)
		shOK(fmt.Sprintf("ip link del itv%d", idx))
	}
	t.Cleanup(cleanup)
	cleanup()
	sh(t, "ip netns add "+s.ns)
	sh(t, fmt.Sprintf("ip link add itv%d type veth peer name eth0 netns %s", idx, s.ns))
	sh(t, fmt.Sprintf("ip addr add %s/30 dev itv%d && ip link set itv%d up", s.mainIP, idx, idx))
	sh(t, fmt.Sprintf("ip netns exec %s sh -c 'ip link set lo up && ip addr add %s/30 dev eth0 && ip link set eth0 up'", s.ns, s.outer))
	sh(t, fmt.Sprintf("ip netns exec %s sh -c 'ip link add wg0 type wireguard && ip addr add %s/32 dev wg0'", s.ns, innerIP))
	err = netnsutil.WithNetNS(s.ns, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		_, ipn, _ := net.ParseCIDR(frontIP + "/32")
		port := sitePort
		ep := &net.UDPAddr{IP: net.ParseIP(s.mainIP), Port: muxPort}
		return c.ConfigureDevice("wg0", wgtypes.Config{
			PrivateKey: &priv,
			ListenPort: &port,
			Peers: []wgtypes.PeerConfig{{
				PublicKey:                   muxPub,
				Endpoint:                    ep,
				PersistentKeepaliveInterval: &keepalive,
				AllowedIPs:                  []net.IPNet{*ipn},
			}},
		})
	})
	if err != nil {
		t.Fatalf("configure %s wg0: %v", name, err)
	}
	sh(t, fmt.Sprintf("ip netns exec %s sh -c 'ip link set wg0 up && ip route add %s/32 dev wg0'", s.ns, frontIP))

	// Marker servers, bound inside the site namespace.
	err = netnsutil.WithNetNS(s.ns, func() error {
		var err error
		s.tcp, err = net.Listen("tcp", innerIP+":8080")
		if err != nil {
			return err
		}
		s.udp, err = net.ListenPacket("udp", innerIP+":8081")
		return err
	})
	if err != nil {
		t.Fatalf("site %s servers: %v", name, err)
	}
	go func() {
		for {
			c, err := s.tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					if _, err := c.Write([]byte(s.name + "\n")); err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		buf := make([]byte, 64)
		for {
			_, a, err := s.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			s.udp.WriteTo([]byte(s.name+"\n"), a)
		}
	}()
	return s
}

// ---- client helpers -------------------------------------------------

var portCounter atomic.Int32

func nextPort() int { return 20000 + int(portCounter.Add(1))%40000 }

func dialFront(timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(frontIP), Port: nextPort()},
	}
	return d.Dial("tcp", innerIP+":8080")
}

// conn is a client connection with a persistent reader.
type conn struct {
	net.Conn
	r *bufio.Reader
}

func dialConn(timeout time.Duration) (*conn, error) {
	c, err := dialFront(timeout)
	if err != nil {
		return nil, err
	}
	return &conn{c, bufio.NewReader(c)}, nil
}

// ping does one request/response on an open connection.
func (c *conn) ping(timeout time.Duration) (string, error) {
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte("x\n")); err != nil {
		return "", err
	}
	s, err := c.r.ReadString('\n')
	return strings.TrimSpace(s), err
}

// oneShot opens a fresh connection and returns the answering site.
func oneShot(timeout time.Duration) (string, error) {
	c, err := dialConn(timeout)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.ping(timeout)
}

func waitSite(t *testing.T, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	var got string
	var err error
	for time.Now().Before(deadline) {
		if got, err = oneShot(time.Second); err == nil && got == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("traffic never reached %s within %s (last: %q, %v)", want, d, got, err)
}

func waitAnySite(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if _, err = oneShot(time.Second); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no traffic within %s: %v", d, err)
}

// ---- lab ------------------------------------------------------------

type lab struct {
	t        *testing.T
	engine   string
	ic       string
	stateDir string
	muxPriv  wgtypes.Key
	a, b     *site
	d        *daemon.Daemon

	mu      sync.Mutex
	engines []engine.Engine // userspace: closed before a "restart"
}

func (l *lab) newDaemon() *daemon.Daemon {
	cfg := daemon.Config{Engine: l.engine, Interconnect: l.ic, Attach: "tcx", StateDir: l.stateDir, Restore: true}
	if l.engine == api.EngineKernel {
		d, err := daemon.New(cfg)
		if err != nil {
			l.t.Fatal(err)
		}
		return d
	}
	// Userspace engines live in this process and a "restart" must
	// release their TUN and ports, so track them.
	f, err := engine.NewFactory(cfg.Engine, engine.DaemonOptions{})
	if err != nil {
		l.t.Fatal(err)
	}
	d := daemon.NewWithFactory(func(p api.CreateParams) (engine.Engine, error) {
		e, err := f(p)
		if err == nil {
			l.mu.Lock()
			l.engines = append(l.engines, e)
			l.mu.Unlock()
		}
		return e, err
	}, cfg)
	d.Restore()
	return d
}

func (l *lab) closeUserspaceEngines() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.engines {
		e.Close()
	}
	l.engines = nil
}

func newLab(t *testing.T, eng, ic string) *lab {
	l := &lab{t: t, engine: eng, ic: ic, stateDir: t.TempDir()}
	var err error
	if l.muxPriv, err = wgtypes.GeneratePrivateKey(); err != nil {
		t.Fatal(err)
	}
	// Leftovers from an aborted earlier run.
	shOK("ip netns del wgmux-" + muxName)
	shOK("ip link del " + muxName)
	t.Cleanup(func() {
		if l.d != nil {
			l.d.Destroy(api.MuxRequest{Mux: muxName})
		}
		l.closeUserspaceEngines()
		shOK("ip netns del wgmux-" + muxName)
		shOK("ip link del " + muxName)
		shOK("rm -rf /sys/fs/bpf/wgmux/" + muxName)
	})
	l.a = newSite(t, "site-a", 1, l.muxPriv.PublicKey(), muxPortA, time.Second)
	l.b = newSite(t, "site-b", 2, l.muxPriv.PublicKey(), muxPortB, 2*time.Second)
	l.d = l.newDaemon()
	return l
}

func (l *lab) peer(name string, id uint32, s *site, port int) api.PeerSpec {
	return api.PeerSpec{
		Name: name, ID: id,
		PrivateKey: l.muxPriv.String(), PublicKey: s.pub().String(),
		ListenPort: port,
		Endpoint:   fmt.Sprintf("%s:%d", s.outer, sitePort),
		AllowedIPs: []string{innerIP + "/32"},
	}
}

func (l *lab) spec(mode string, sel ...api.PeerWeight) api.ApplySpec {
	return api.ApplySpec{
		Front:        api.FrontSpec{Name: muxName, Address: frontIP + "/24"},
		ManageRoutes: true,
		Peers: []api.PeerSpec{
			l.peer("site-a", 1, l.a, muxPortA),
			l.peer("site-b", 2, l.b, muxPortB),
		},
		Prefixes: []api.PrefixSpec{{
			CIDR: innerIP + "/32", Candidates: []string{"site-a", "site-b"},
			Mode: mode, Policy: api.PolicyStatic, Selection: sel,
		}},
	}
}

func (l *lab) apply(spec api.ApplySpec) error {
	return l.d.Apply(api.ApplyRequest{Mux: muxName, Spec: spec})
}

func (l *lab) state() api.State {
	l.t.Helper()
	st, err := l.d.State(api.MuxRequest{Mux: muxName})
	if err != nil {
		l.t.Fatalf("state: %v", err)
	}
	return st
}

func (l *lab) prefix() api.PrefixState {
	l.t.Helper()
	st := l.state()
	if len(st.Prefixes) != 1 {
		l.t.Fatalf("want 1 prefix, got %+v", st.Prefixes)
	}
	return st.Prefixes[0]
}

func (l *lab) info() api.InstanceInfo {
	l.t.Helper()
	list, err := l.d.List()
	if err != nil {
		l.t.Fatal(err)
	}
	for _, i := range list {
		if i.Mux == muxName {
			return i
		}
	}
	l.t.Fatalf("instance %s not listed: %+v", muxName, list)
	return api.InstanceInfo{}
}

func (l *lab) setSel(sel ...api.PeerWeight) {
	l.t.Helper()
	if err := l.d.SetSelection(api.SetSelectionRequest{Mux: muxName, CIDR: innerIP + "/32", Selection: sel}); err != nil {
		l.t.Fatalf("SetSelection: %v", err)
	}
}

func pw(peer string, w uint32) api.PeerWeight { return api.PeerWeight{Peer: peer, Weight: w} }

func frontIfindex(t *testing.T) int {
	t.Helper()
	ifc, err := net.InterfaceByName(muxName)
	if err != nil {
		t.Fatalf("front link %s: %v", muxName, err)
	}
	return ifc.Index
}

// spread opens n short connections from varying source ports.
func spread(t *testing.T, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		s, err := oneShot(3 * time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		got[s]++
	}
	return got
}

func waitHandshakes(t *testing.T, l *lab, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		// A rebuilt mux does not initiate on its own: a site with a
		// stale session only re-handshakes after ~15s. Traffic that
		// hashes to the peer makes the mux initiate right away.
		for i := 0; i < 4; i++ {
			oneShot(300 * time.Millisecond)
		}
		st, err := l.d.State(api.MuxRequest{Mux: muxName})
		if err == nil {
			n := 0
			for _, p := range st.Peers {
				if !p.LastHandshake.IsZero() {
					n++
				}
			}
			if n == len(st.Peers) && n > 0 {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("handshakes did not complete: %+v", l.state().Peers)
}

// ---- the scenarios ----------------------------------------------------

func TestKernelVeth(t *testing.T)   { runVariant(t, api.EngineKernel, "veth") }
func TestKernelNetkit(t *testing.T) { runVariant(t, api.EngineKernel, "netkit") }
func TestUserspace(t *testing.T)    { runVariant(t, api.EngineUserspace, "") }

func runVariant(t *testing.T, eng, ic string) {
	if os.Getenv("WGMUX_TEST_INTEGRATION") != "1" {
		t.Skip("set WGMUX_TEST_INTEGRATION=1 (needs a privileged Linux container)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	shOK("mount -t bpf bpf /sys/fs/bpf 2>/dev/null")
	l := newLab(t, eng, ic)
	if err := l.d.Create(api.CreateParams{Mux: muxName}); err != nil {
		t.Fatal(err)
	}
	if err := l.apply(l.spec(api.ModeSingle)); err != nil {
		if ic == "netkit" && strings.Contains(err.Error(), "netkit") {
			t.Skipf("netkit unsupported by this kernel: %v", err)
		}
		t.Fatal(err)
	}
	waitSite(t, "site-a", 30*time.Second)
	// Both tunnels must have handshaken before the selection games.
	waitHandshakes(t, l, 30*time.Second)

	t.Run("1_single_graceful_and_flush", l.scenarioSingle)
	t.Run("2_ecmp_weights", l.scenarioECMP)
	t.Run("3_inplace_reapply", l.scenarioInPlace)
	t.Run("4_selection_persistence", l.scenarioPersistence)
	t.Run("6_failed_apply_rollback", l.scenarioRollback)
	t.Run("5_destroy_cleans_up", l.scenarioDestroy)
}

func (l *lab) scenarioSingle(t *testing.T) {
	// Default single selection = first candidate.
	for i := 0; i < 5; i++ {
		if s, err := oneShot(3 * time.Second); err != nil || s != "site-a" {
			t.Fatalf("conn %d: %q %v, want site-a", i, s, err)
		}
	}
	checkUDP(t, "site-a")

	est, err := dialConn(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer est.Close()
	if s, err := est.ping(3 * time.Second); err != nil || s != "site-a" {
		t.Fatalf("established conn first ping: %q %v", s, err)
	}

	l.setSel(pw("site-b", 1))
	for i := 0; i < 10; i++ {
		if s, err := oneShot(3 * time.Second); err != nil || s != "site-b" {
			t.Fatalf("new conn %d after switch: %q %v, want site-b", i, s, err)
		}
	}
	// Graceful: the connection opened before the switch stays on site-a.
	for i := 0; i < 3; i++ {
		if s, err := est.ping(3 * time.Second); err != nil || s != "site-a" {
			t.Fatalf("established conn after SetSelection: %q %v, want site-a (graceful)", s, err)
		}
	}
	staleBefore := l.state().Counters["front_pin_stale"]

	if err := l.d.FlushPeer(api.FlushPeerRequest{Mux: muxName, Peer: "site-a"}); err != nil {
		t.Fatal(err)
	}
	// Next packet is re-steered to site-b (which has no such
	// connection and resets it); it must never be answered by site-a.
	s, err := est.ping(3 * time.Second)
	if err == nil && s == "site-a" {
		t.Fatalf("established conn still reached site-a after FlushPeer")
	}
	t.Logf("after FlushPeer: reply=%q err=%v", s, err)
	if after := l.state().Counters["front_pin_stale"]; after <= staleBefore {
		t.Errorf("front_pin_stale did not increase on flush: %d -> %d (counters %v)", staleBefore, after, l.state().Counters)
	}
}

func checkUDP(t *testing.T, want string) {
	t.Helper()
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(frontIP)}, &net.UDPAddr{IP: net.ParseIP(innerIP), Port: 8081})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 64)
	for i := 0; i < 3; i++ {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("udp: %v", err)
		}
		if got := strings.TrimSpace(string(buf[:n])); got != want {
			t.Fatalf("udp answered by %q, want %q", got, want)
		}
	}
}

func within(t *testing.T, what string, got, want, tol int) {
	t.Helper()
	if got < want-tol || got > want+tol {
		t.Errorf("%s: got %d, want %d +/- %d", what, got, want, tol)
	}
}

func (l *lab) scenarioECMP(t *testing.T) {
	if err := l.apply(l.spec(api.ModeECMP, pw("site-a", 1), pw("site-b", 1))); err != nil {
		t.Fatal(err)
	}
	waitHandshakes(t, l, 20*time.Second)
	ps := l.prefix()
	if ps.Mode != api.ModeECMP || ps.Slots["site-a"] != 32 || ps.Slots["site-b"] != 32 {
		t.Fatalf("1:1 state wrong: %+v", ps)
	}
	got := spread(t, 200)
	t.Logf("1:1 distribution: %v", got)
	within(t, "site-a share 1:1", got["site-a"], 100, 35)
	within(t, "site-b share 1:1", got["site-b"], 100, 35)

	l.setSel(pw("site-a", 3), pw("site-b", 1))
	ps = l.prefix()
	if ps.Slots["site-a"] != 48 || ps.Slots["site-b"] != 16 {
		t.Fatalf("3:1 slots wrong: %+v", ps.Slots)
	}
	got = spread(t, 200)
	t.Logf("3:1 distribution: %v", got)
	within(t, "site-a share 3:1", got["site-a"], 150, 30)
	within(t, "site-b share 3:1", got["site-b"], 50, 30)
}

func (l *lab) scenarioInPlace(t *testing.T) {
	// Open several established flows, remember where each lives.
	type flow struct {
		c    *conn
		site string
	}
	var flows []flow
	for i := 0; i < 12; i++ {
		c, err := dialConn(3 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		s, err := c.ping(3 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, flow{c, s})
	}
	idx := frontIfindex(t)
	createdBefore := l.info().CreatedAt

	// Same peers, changed configured weights.
	if err := l.apply(l.spec(api.ModeECMP, pw("site-a", 1), pw("site-b", 3))); err != nil {
		t.Fatal(err)
	}
	if got := frontIfindex(t); got != idx {
		t.Errorf("front link recreated: ifindex %d -> %d", idx, got)
	}
	if !l.info().CreatedAt.Equal(createdBefore) {
		t.Errorf("instance recreated")
	}
	ps := l.prefix()
	if ps.Slots["site-a"] != 16 || ps.Slots["site-b"] != 48 {
		t.Errorf("slots after reweight: %+v", ps.Slots)
	}
	for i, f := range flows {
		s, err := f.c.ping(3 * time.Second)
		if err != nil || s != f.site {
			t.Errorf("flow %d (%s) after in-place re-apply: %q %v", i, f.site, s, err)
		}
	}
}

func (l *lab) scenarioPersistence(t *testing.T) {
	// Runtime override on top of configured 1:3.
	l.setSel(pw("site-a", 3), pw("site-b", 1))
	want := func(stage string) {
		t.Helper()
		ps := l.prefix()
		if len(ps.Selection) != 2 || ps.Selection[0] != pw("site-a", 3) || ps.Selection[1] != pw("site-b", 1) {
			t.Fatalf("%s: selection %+v, want a=3,b=1", stage, ps.Selection)
		}
		if ps.Slots["site-a"] != 48 || ps.Slots["site-b"] != 16 {
			t.Fatalf("%s: slots %+v", stage, ps.Slots)
		}
	}
	want("after SetSelection")
	// Re-apply the SAME configured spec: the override must survive.
	if err := l.apply(l.spec(api.ModeECMP, pw("site-a", 1), pw("site-b", 3))); err != nil {
		t.Fatal(err)
	}
	want("after re-apply")

	// Daemon restart; kernel: traffic must never stop.
	var stop atomic.Bool
	var fails, total atomic.Int32
	var wg sync.WaitGroup
	if l.engine == api.EngineKernel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				total.Add(1)
				if _, err := oneShot(2 * time.Second); err != nil {
					fails.Add(1)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	l.closeUserspaceEngines() // userspace: the "old process" is gone
	l.d = l.newDaemon()
	wantStatus := api.StatusAdopted
	if l.engine == api.EngineUserspace {
		wantStatus = api.StatusRestored
	}
	info := l.info()
	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	if info.Status != wantStatus {
		t.Fatalf("status after restart = %q (%s), want %q", info.Status, info.Error, wantStatus)
	}
	if l.engine == api.EngineKernel {
		t.Logf("probe during restart: %d/%d failed", fails.Load(), total.Load())
		if fails.Load() != 0 {
			t.Errorf("traffic interrupted during adopt: %d/%d connections failed", fails.Load(), total.Load())
		}
	}
	want("after daemon restart")
	waitAnySite(t, 30*time.Second)
	waitHandshakes(t, l, 30*time.Second)
	got := spread(t, 100)
	t.Logf("after restart 3:1 distribution: %v", got)
	if got["site-a"] < got["site-b"] {
		t.Errorf("selection a=3,b=1 not in effect after restart: %v", got)
	}
}

func (l *lab) scenarioRollback(t *testing.T) {
	// Hold a UDP port the new third peer wants, so the engine fails
	// late (after the earlier peers were built).
	hold, err := net.ListenPacket("udp", "0.0.0.0:51899")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	spec := l.spec(api.ModeECMP, pw("site-a", 1), pw("site-b", 1))
	spec.Peers = append(spec.Peers, l.peer("site-c", 3, l.b, 51899))
	spec.Prefixes[0].Candidates = []string{"site-a", "site-b", "site-c"}
	err = l.apply(spec)
	if err == nil {
		t.Fatal("apply with a bound listen port unexpectedly succeeded")
	}
	t.Logf("apply error: %v", err)
	info := l.info()
	if info.Status != api.StatusActive || !strings.Contains(info.Error, "rolled back") {
		t.Fatalf("after failed apply: status=%q error=%q, want active + rolled back", info.Status, info.Error)
	}
	// The rollback rebuilt the previous spec: traffic flows again.
	waitAnySite(t, 30*time.Second)
	waitHandshakes(t, l, 30*time.Second)
	got := spread(t, 20)
	if got["site-a"]+got["site-b"] != 20 {
		t.Fatalf("traffic after rollback: %v", got)
	}
	if len(l.state().Peers) != 2 {
		t.Errorf("rollback left %d peers", len(l.state().Peers))
	}
}

func (l *lab) scenarioDestroy(t *testing.T) {
	if err := l.d.Destroy(api.MuxRequest{Mux: muxName}); err != nil {
		t.Fatal(err)
	}
	l.closeUserspaceEngines()
	if h, err := netns.GetFromName("wgmux-" + muxName); err == nil {
		h.Close()
		t.Errorf("backend netns wgmux-%s still exists", muxName)
	}
	if _, err := net.InterfaceByName(muxName); err == nil {
		t.Errorf("front link %s still exists", muxName)
	}
	if _, err := os.Stat("/sys/fs/bpf/wgmux/" + muxName); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pin dir still exists (err=%v)", err)
	}
	if _, err := os.Stat(l.stateDir + "/instances/" + muxName + ".json"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("store file still exists (err=%v)", err)
	}
	if _, err := l.d.State(api.MuxRequest{Mux: muxName}); err == nil {
		t.Errorf("State succeeds on a destroyed instance")
	}
	l.d = nil
}
