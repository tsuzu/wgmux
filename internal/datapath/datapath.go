// Package datapath loads the wgmux BPF programs, attaches them inside
// the backend namespace and owns the shared maps.
//
// Persistence model: maps are pinned under the spec's PinDir and, for
// tcx, the links are pinned next to them, so with the kernel engine
// the datapath keeps running independently of any process. Runtime
// changes (peer activation by any control-plane policy) are writes to
// the pinned steering map, made through the daemon's SetActive.
package datapath

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/config"
	"github.com/tsuzu/wgmux/internal/netnsutil"
	"github.com/tsuzu/wgmux/internal/steer"
)

//go:generate clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -c ../../bpf/mux.c -o mux.o

// The compiled object is committed so the daemon builds with only a Go
// toolchain; regenerate it with `go generate ./internal/datapath/`.
//
//go:embed mux.o
var muxObj []byte

const (
	ProgFromFront = "mux_from_front"
	ProgFromWG    = "mux_from_wg"

	MapSteering   = "steering"
	MapFlowPeer   = "flow_peer"
	MapPeerDev    = "peer_dev"
	MapRuntimeCfg = "runtime_cfg"
)

// Info describes the already-built topology the datapath programs steer
// between. All ifindexes and MACs refer to the backend namespace's view.
type Info struct {
	BackIfindex int
	FrontMAC    [6]byte
	BackMAC     [6]byte
	// PeerIfindex maps datapath peer_id -> wg device ifindex (backend).
	PeerIfindex map[uint32]int
	// PeerDevice maps datapath peer_id -> wg device name (backend).
	PeerDevice map[uint32]string
}

func loadSpec(l2Mode bool, ownPeerID *uint32) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(muxObj))
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	// Constants are .rodata variables in cilium/ebpf v0.22 terms.
	set := func(name string, v interface{}) error {
		vs, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("BPF object has no constant %q", name)
		}
		return vs.Set(v)
	}
	if err := set("l2_mode", l2Mode); err != nil {
		return nil, fmt.Errorf("set l2_mode: %w", err)
	}
	if ownPeerID != nil {
		if err := set("own_peer_id", *ownPeerID); err != nil {
			return nil, fmt.Errorf("set own_peer_id: %w", err)
		}
	}
	return spec, nil
}

// Apply loads the programs, populates and pins the maps, and attaches
// everything inside the backend namespace. entries are the resolved
// steering decisions supplied by the control plane (via the daemon);
// this package never decides policy itself.
func Apply(spec api.ApplySpec, info Info, entries []steer.Entry) error {
	l2 := spec.Interconnect == config.InterconnectVeth
	if err := os.MkdirAll(spec.PinDir, 0o755); err != nil {
		return err
	}
	linksDir := filepath.Join(spec.PinDir, "links")
	if err := os.MkdirAll(linksDir, 0o755); err != nil {
		return err
	}

	// --- from_front collection: creates (and pins) the shared maps.
	bspec, err := loadSpec(l2, nil)
	if err != nil {
		return err
	}
	if spec.Attach == config.AttachTC {
		legacyAttach(bspec)
	}
	front, err := ebpf.NewCollectionWithOptions(bspec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: spec.PinDir},
	})
	if err != nil {
		return loadErr("load from_front collection", err)
	}
	defer front.Close()

	shared := map[string]*ebpf.Map{}
	for _, name := range []string{MapSteering, MapFlowPeer, MapPeerDev, MapRuntimeCfg} {
		m := front.Maps[name]
		if m == nil {
			return fmt.Errorf("BPF object is missing map %q", name)
		}
		shared[name] = m
	}

	// --- populate maps before attaching anything (no steering window).
	if err := populate(info, entries, shared); err != nil {
		return err
	}

	// --- one from_wg collection per peer, reusing the shared maps, with
	// its own own_peer_id constant.
	type attachment struct {
		prog    *ebpf.Program
		ifindex int
		name    string
	}
	attachments := []attachment{
		{front.Programs[ProgFromFront], info.BackIfindex, ProgFromFront},
	}
	collections := []*ebpf.Collection{}
	defer func() {
		for _, c := range collections {
			c.Close()
		}
	}()
	for peerID, ifindex := range info.PeerIfindex {
		bspec, err := loadSpec(l2, &peerID)
		if err != nil {
			return err
		}
		if spec.Attach == config.AttachTC {
			legacyAttach(bspec)
		}
		coll, err := ebpf.NewCollectionWithOptions(bspec, ebpf.CollectionOptions{
			MapReplacements: shared,
		})
		if err != nil {
			return loadErr(fmt.Sprintf("load from_wg collection for peer %d", peerID), err)
		}
		collections = append(collections, coll)
		attachments = append(attachments, attachment{
			coll.Programs[ProgFromWG], ifindex, fmt.Sprintf("%s_%s", ProgFromWG, info.PeerDevice[peerID]),
		})
	}

	// --- attach inside the backend namespace.
	return netnsutil.WithNetNS(spec.BackendNS, func() error {
		for _, att := range attachments {
			if att.prog == nil {
				return fmt.Errorf("BPF object is missing a program for %s", att.name)
			}
			switch spec.Attach {
			case config.AttachTCX:
				l, err := link.AttachTCX(link.TCXOptions{
					Interface: att.ifindex,
					Program:   att.prog,
					Attach:    ebpf.AttachTCXIngress,
				})
				if err != nil {
					return fmt.Errorf("attach tcx %s to ifindex %d: %w", att.name, att.ifindex, err)
				}
				if err := l.Pin(filepath.Join(linksDir, att.name)); err != nil {
					l.Close()
					return fmt.Errorf("pin link %s: %w", att.name, err)
				}
				// The pin keeps the link alive; do not Close it here.
			case config.AttachTC:
				if err := attachLegacyTC(spec.BackendNS, att.ifindex, att.prog, att.name); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func addrBE(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

// loadErr enriches a collection load failure with the tail of the
// kernel verifier log, which is where the actual reason lives.
func loadErr(what string, err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && len(ve.Log) > 0 {
		lines := ve.Log
		if len(lines) > 120 {
			lines = lines[len(lines)-120:]
		}
		return fmt.Errorf("%s: %w\nverifier log (tail):\n%s", what, err, strings.Join(lines, "\n"))
	}
	return fmt.Errorf("%s: %w", what, err)
}

func legacyAttach(spec *ebpf.CollectionSpec) {
	// A program loaded for the legacy tc path must not claim the tcx
	// attach type baked into its SEC("tcx/ingress") declaration.
	for _, p := range spec.Programs {
		p.AttachType = ebpf.AttachNone
	}
}

// attachLegacyTC installs the program as a direct-action tc filter in
// the backend namespace. Legacy tc filters persist without a daemon.
func attachLegacyTC(nsName string, ifindex int, prog *ebpf.Program, name string) error {
	handle, err := backendHandle(nsName)
	if err != nil {
		return err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := handle.FilterReplace(filter); err != nil {
		return fmt.Errorf("tc filter replace %s: %w", name, err)
	}
	return nil
}

func backendHandle(nsName string) (*netlink.Handle, error) {
	h, err := netns.GetFromName(nsName)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return netlink.NewHandleAt(h)
}

func populate(info Info, entries []steer.Entry, maps map[string]*ebpf.Map) error {
	for _, e := range entries {
		if err := maps[MapSteering].Put(e.MapKey(), e.MapVal()); err != nil {
			return fmt.Errorf("put steering entry: %w", err)
		}
	}
	for peerID, ifindex := range info.PeerIfindex {
		if err := maps[MapPeerDev].Put(peerID, uint32(ifindex)); err != nil {
			return fmt.Errorf("put peer_dev %d: %w", peerID, err)
		}
	}
	rc := steer.RuntimeCfg{BackIfindex: uint32(info.BackIfindex)}
	rc.FrontMAC = info.FrontMAC
	rc.BackMAC = info.BackMAC
	if err := maps[MapRuntimeCfg].Put(uint32(0), rc); err != nil {
		return fmt.Errorf("put runtime_cfg: %w", err)
	}
	return nil
}

// OpenPinnedSteering opens the pinned steering map for runtime updates.
func OpenPinnedSteering(pinDir string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, MapSteering), &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("open pinned steering map (is wgmux applied?): %w", err)
	}
	return m, nil
}

// SetActive flips the active candidate of one prefix in the pinned
// steering map. peerID identifies the candidate by its position in the
// entry's PeerIDs, so this works without the config file.
func SetActive(pinDir string, prefix *net.IPNet, peerID uint32) error {
	ones, _ := prefix.Mask.Size()
	key := steer.SteeringKey{
		PrefixLen: uint32(ones),
		Addr:      addrBE(prefix.IP),
	}
	m, err := OpenPinnedSteering(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()
	var val steer.SteeringVal
	if err := m.Lookup(key, &val); err != nil {
		return fmt.Errorf("prefix %s not in steering map: %w", prefix, err)
	}
	for i := 0; i < int(val.Count) && i < len(val.PeerIDs); i++ {
		if val.PeerIDs[i] == peerID {
			val.Active = uint8(i)
			if err := m.Put(key, val); err != nil {
				return fmt.Errorf("update steering map: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("peer %d is not a candidate for prefix %s", peerID, prefix)
}

// SteeringSnapshot reads all steering entries (for status display).
func SteeringSnapshot(pinDir string) (map[steer.SteeringKey]steer.SteeringVal, error) {
	m, err := OpenPinnedSteering(pinDir)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	out := map[steer.SteeringKey]steer.SteeringVal{}
	var key steer.SteeringKey
	var val steer.SteeringVal
	it := m.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Unpin removes pinned maps and links created by Apply.
func Unpin(pinDir string) error {
	var errs []error
	linksDir := filepath.Join(pinDir, "links")
	if entries, err := os.ReadDir(linksDir); err == nil {
		for _, e := range entries {
			p := filepath.Join(linksDir, e.Name())
			if l, err := link.LoadPinnedLink(p, &ebpf.LoadPinOptions{}); err == nil {
				l.Close()
			}
			if err := os.Remove(p); err != nil {
				errs = append(errs, err)
			}
		}
		os.Remove(linksDir)
	}
	for _, name := range []string{MapSteering, MapFlowPeer, MapPeerDev, MapRuntimeCfg} {
		if err := os.Remove(filepath.Join(pinDir, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	os.Remove(pinDir)
	return errors.Join(errs...)
}
