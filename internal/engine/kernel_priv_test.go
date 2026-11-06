//go:build linux

package engine

import (
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

// Privileged tests against the real kernel (netlink). Run with
// WGMUX_TEST_KERNEL=1 as root, e.g. in the wgmux-dev container with
// --privileged.
func needKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("WGMUX_TEST_KERNEL") != "1" {
		t.Skip("set WGMUX_TEST_KERNEL=1 (root) to run")
	}
}

func nsExists(name string) bool {
	h, err := netns.GetFromName(name)
	if err != nil {
		return false
	}
	h.Close()
	return true
}

func TestKernelPurge(t *testing.T) {
	needKernel(t)
	main, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	opts := DaemonOptions{Interconnect: config.InterconnectVeth, Attach: config.AttachTCX, PinRoot: t.TempDir()}

	// veth front + backend ns: Purge removes both.
	const vname = "wgmxpv"
	nsh, err := netnsutil.CreateNamed("wgmux-" + vname)
	if err != nil {
		t.Fatal(err)
	}
	defer nsh.Close()
	t.Cleanup(func() { netnsutil.DeleteNamed("wgmux-" + vname) })
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: vname},
		PeerName:      "mux-b",
		PeerNamespace: netlink.NsFd(int(nsh)),
	}
	if err := main.LinkAdd(veth); err != nil {
		t.Skipf("cannot create veth: %v", err)
	}
	t.Cleanup(func() {
		if l, err := main.LinkByName(vname); err == nil {
			main.LinkDel(l)
		}
	})
	m := newKernelMux(api.CreateParams{Mux: vname}, opts)
	if err := m.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := main.LinkByName(vname); err == nil {
		t.Error("veth front survived Purge")
	}
	if nsExists("wgmux-" + vname) {
		t.Error("backend ns survived Purge")
	}
	if err := m.Purge(); err != nil {
		t.Errorf("second Purge (idempotence): %v", err)
	}

	// An unrelated same-named dummy link must survive Purge.
	const dname = "wgmxpd"
	if err := main.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dname}}); err != nil {
		t.Skipf("cannot create dummy: %v", err)
	}
	t.Cleanup(func() {
		if l, err := main.LinkByName(dname); err == nil {
			main.LinkDel(l)
		}
	})
	d := newKernelMux(api.CreateParams{Mux: dname}, opts)
	if err := d.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := main.LinkByName(dname); err != nil {
		t.Errorf("Purge deleted an unrelated non-veth interface: %v", err)
	}
}

func TestKernelAddPeerTempName(t *testing.T) {
	needKernel(t)
	main, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	const nsName = "wgmux-wgmxpt"
	nsh, err := netnsutil.CreateNamed(nsName)
	if err != nil {
		t.Fatal(err)
	}
	defer nsh.Close()
	t.Cleanup(func() { netnsutil.DeleteNamed(nsName) })
	backend, err := netlink.NewHandleAt(nsh)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	// A main-ns interface named like the peer's device: must NOT be
	// stolen into the backend.
	if err := main.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wg-victim"}}); err != nil {
		t.Skipf("cannot create dummy: %v", err)
	}
	t.Cleanup(func() {
		if l, err := main.LinkByName("wg-victim"); err == nil {
			main.LinkDel(l)
		}
	})

	priv, _ := wgtypes.GeneratePrivateKey()
	peerPriv, _ := wgtypes.GeneratePrivateKey()
	kp := newKernelPeers(&Context{
		BackendNS: nsName, BackendHandle: nsh, Main: main, Backend: backend, MTU: 1420,
	})
	ref, err := kp.AddPeer(api.PeerSpec{
		Name: "victim", ID: 1, PrivateKey: priv.String(), PublicKey: peerPriv.PublicKey().String(),
		AllowedIPs: []string{"0.0.0.0/0"},
	})
	if err != nil {
		if _, lerr := main.LinkByName("wg-victim"); lerr == nil {
			// Distinguish "no wireguard module" from real failures.
			probe := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: "wgmxprobe"}, LinkType: "wireguard"}
			if perr := main.LinkAdd(probe); perr != nil {
				t.Skipf("wireguard not available: %v", perr)
			}
			main.LinkDel(probe)
		}
		t.Fatalf("AddPeer: %v", err)
	}
	if ref.DeviceName != "wg-victim" {
		t.Errorf("device name = %q", ref.DeviceName)
	}
	if l, err := backend.LinkByName("wg-victim"); err != nil || l.Type() != "wireguard" {
		t.Errorf("backend wg-victim = %v, %v", l, err)
	}
	if l, err := main.LinkByName("wg-victim"); err != nil || l.Type() != "dummy" {
		t.Errorf("main-ns wg-victim was disturbed: %v, %v", l, err)
	}
	// No temp-named leftovers anywhere.
	for _, h := range []*netlink.Handle{main, backend} {
		links, _ := h.LinkList()
		for _, l := range links {
			if len(l.Attrs().Name) >= 4 && l.Attrs().Name[:4] == "wgmt" {
				t.Errorf("leftover temp device %s", l.Attrs().Name)
			}
		}
	}
}
