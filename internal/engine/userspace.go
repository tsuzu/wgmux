package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsuzu/wgmux/internal/api"
	"github.com/tsuzu/wgmux/internal/netnsutil"
)

type userspacePeer struct {
	spec api.PeerSpec
	dev  *device.Device
	ref  Ref
}

type userspaceEngine struct {
	ctx   *Context
	mu    sync.Mutex
	peers map[string]*userspacePeer
}

func newUserspace(ctx *Context) *userspaceEngine {
	return &userspaceEngine{ctx: ctx, peers: map[string]*userspacePeer{}}
}

// AddPeer creates the peer's TUN device inside the backend namespace
// (the TUN-creation ioctl resolves in the calling thread's namespace),
// then hosts a wireguard-go device on it from the main namespace, so
// its UDP sockets live in the main namespace — the userspace mirror of
// the kernel engine's birth-namespace arrangement.
func (e *userspaceEngine) AddPeer(spec api.PeerSpec) (Ref, error) {
	name := DeviceName(spec.Name)
	if len(name) >= 16 {
		return Ref{}, fmt.Errorf("peer %q: device name %q exceeds IFNAMSIZ", spec.Name, name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.peers[spec.Name]; exists {
		return Ref{}, fmt.Errorf("peer %q already exists in userspace engine", spec.Name)
	}

	var tunDev tun.Device
	err := netnsutil.WithNetNS(e.ctx.BackendNS, func() error {
		var err error
		tunDev, err = tun.CreateTUN(name, e.ctx.MTU)
		return err
	})
	if err != nil {
		return Ref{}, fmt.Errorf("create TUN %s in backend: %w", name, err)
	}

	// From here on we are back in the main namespace.
	logger := device.NewLogger(device.LogLevelError, "wgmux-go "+name+": ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	uapi, err := buildUAPI(spec)
	if err != nil {
		dev.Close()
		return Ref{}, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return Ref{}, fmt.Errorf("configure wireguard-go %s: %w", name, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return Ref{}, fmt.Errorf("up wireguard-go %s: %w", name, err)
	}
	link, err := e.ctx.Backend.LinkByName(name)
	if err != nil {
		dev.Close()
		return Ref{}, fmt.Errorf("find TUN %s in backend: %w", name, err)
	}
	if err := e.ctx.Backend.LinkSetUp(link); err != nil {
		dev.Close()
		return Ref{}, fmt.Errorf("up TUN %s: %w", name, err)
	}
	ref := Ref{DeviceName: name, Ifindex: link.Attrs().Index}
	e.peers[spec.Name] = &userspacePeer{spec: spec, dev: dev, ref: ref}
	return ref, nil
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

// buildUAPI renders a PeerSpec as wireguard-go UAPI configuration text.
// Keys are hex in UAPI (base64 in our API/config).
func buildUAPI(spec api.PeerSpec) (string, error) {
	priv, err := keyHex(spec.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("peer %q private key: %w", spec.Name, err)
	}
	pub, err := keyHex(spec.PublicKey)
	if err != nil {
		return "", fmt.Errorf("peer %q public key: %w", spec.Name, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if spec.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", spec.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if spec.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", spec.Endpoint)
	}
	if spec.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", spec.PersistentKeepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, cidr := range spec.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}
	return b.String(), nil
}

func (e *userspaceEngine) RemovePeer(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.peers[name]
	if !ok {
		return fmt.Errorf("peer %q not in userspace engine", name)
	}
	p.dev.Close() // also closes the TUN device
	delete(e.peers, name)
	return nil
}

// Peers parses each device's UAPI state dump.
func (e *userspaceEngine) Peers() ([]api.PeerState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]api.PeerState, 0, len(e.peers))
	for _, p := range e.peers {
		st := api.PeerState{Name: p.spec.Name, ID: p.spec.ID, Device: p.ref.DeviceName, Ifindex: p.ref.Ifindex}
		dump, err := p.dev.IpcGet()
		if err != nil {
			return nil, fmt.Errorf("ipcget %s: %w", p.ref.DeviceName, err)
		}
		parseUAPIState(dump, &st)
		out = append(out, st)
	}
	return out, nil
}

func parseUAPIState(dump string, st *api.PeerState) {
	var sec, nsec int64
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "endpoint":
			st.Endpoint = v
		case "rx_bytes":
			st.BytesReceived, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.BytesSent, _ = strconv.ParseUint(v, 10, 64)
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if sec > 0 {
		st.LastHandshake = time.Unix(sec, nsec)
	}
}

func (e *userspaceEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, p := range e.peers {
		p.dev.Close()
		delete(e.peers, name)
	}
	return nil
}
