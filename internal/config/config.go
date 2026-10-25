// Package config defines the wgmux configuration file format and its
// validation. The same Config drives every switchable axis of the system:
//
//   - Interconnect: "veth" (L2 pair, the BPF programs add/strip Ethernet)
//     or "netkit" (L3 pair, raw IP, requires kernel >= 6.7)
//   - Attach: "tcx" (default, kernel >= 6.6) or "tc" (legacy clsact)
//   - Per-prefix selection Policy: "active" (one chosen peer),
//     "hash" (per-flow consistent hash over candidates), or
//     "failover" (control plane flips the active peer when the
//     WireGuard handshake goes stale; the datapath behaves as "active")
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	InterconnectVeth   = "veth"
	InterconnectNetkit = "netkit"

	AttachTCX = "tcx"
	AttachTC  = "tc"

	PolicyActive   = "active"
	PolicyHash     = "hash"
	PolicyFailover = "failover"
	PolicyBGP      = "bgp"

	EngineKernel    = "kernel"
	EngineUserspace = "userspace"

	BGPModeNone  = "none"
	BGPModeGoBGP = "gobgp"
	BGPModeFRR   = "frr"
)

type Front struct {
	// Name of the only interface visible in the main namespace.
	Name string `yaml:"name"`
	// Address (CIDR) assigned to the front interface in the main namespace.
	// Its host part is this host's tunnel identity: inner packets keep this
	// source address whichever peer device carries them.
	Address string `yaml:"address"`
	// Address (CIDR) of the backend end of the interconnect pair. Only used
	// as the pair's local address; inner traffic is redirected by BPF, not
	// routed, so no gateway semantics are attached to it.
	BackendAddress string `yaml:"backend_address"`
	// MTU of the front interface. 0 means derive from the smallest peer MTU.
	MTU int `yaml:"mtu"`
}

type Identity struct {
	// Base64 WireGuard private key shared by all peer devices (the local
	// identity is the same on every device; sessions are per peer anyway).
	// Either PrivateKey or PrivateKeyFile must be set.
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyFile string `yaml:"private_key_file"`
}

type Peer struct {
	Name string `yaml:"name"`
	// ID is the datapath peer_id (index into the BPF maps). 0 means assign
	// automatically in declaration order, starting at 1.
	ID int `yaml:"id"`
	// ListenPort of this peer's WireGuard device. Devices live in the same
	// birth namespace (the main one), so ports must not collide. 0 lets
	// the kernel choose; only usable for peers we always initiate to.
	ListenPort int `yaml:"listen_port"`
	// PrivateKey overrides Identity for this device only.
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyFile string `yaml:"private_key_file"`
	PublicKey      string `yaml:"public_key"`
	// Endpoint as host:port. The host should be pre-resolved (see
	// EndpointIP): once the device moves into the backend namespace,
	// name resolution from there is not reliable.
	Endpoint string `yaml:"endpoint"`
	// EndpointIP optionally pins the resolved endpoint IP, so setup never
	// needs DNS after devices move namespaces.
	EndpointIP          string `yaml:"endpoint_ip"`
	PersistentKeepalive int    `yaml:"persistent_keepalive"`
}

type Prefix struct {
	CIDR string `yaml:"cidr"`
	// Candidates are peer names that all carry this prefix in their
	// AllowedIPs. The datapath selects exactly one of them per packet.
	Candidates []string `yaml:"candidates"`
	// Active names the initially selected candidate (policies active and
	// failover). Defaults to the first candidate.
	Active string `yaml:"active"`
	// Policy: active | hash | failover. Defaults to active.
	Policy string `yaml:"policy"`
}

type Failover struct {
	// A peer whose latest WireGuard handshake is older than this is
	// considered down by the failover monitor. Seconds.
	HandshakeMaxAge int `yaml:"handshake_max_age_seconds"`
	// How often the failover monitor re-evaluates. Seconds.
	Interval int `yaml:"interval_seconds"`
}

// BGP configures the routing-protocol selection source. Prefixes with
// policy "bgp" take their active peer from BGP best paths: the BGP
// neighbor a prefix's best path came from is mapped to a wgmux peer.
type BGP struct {
	Mode string `yaml:"mode"` // none | gobgp | frr

	// gobgp (embedded GoBGP in the control-plane process)
	LocalAS    uint32 `yaml:"local_as"`
	RouterID   string `yaml:"router_id"`
	ListenPort int32  `yaml:"listen_port"` // 0 -> 179, -1 -> do not listen

	// frr (external FRRouting, polled through vtysh JSON output)
	VtyshPath    string `yaml:"vtysh_path"`
	PollInterval int    `yaml:"poll_interval_seconds"`

	// Neighbors applies to both modes: a BGP neighbor (by IP) and the
	// wgmux peer whose tunnel that neighbor is reached through.
	Neighbors []BGPNeighbor `yaml:"neighbors"`
}

type BGPNeighbor struct {
	Address  string `yaml:"address"`
	RemoteAS uint32 `yaml:"remote_as"` // gobgp only
	WgPeer   string `yaml:"wg_peer"`
}

type Config struct {
	Front        Front    `yaml:"front"`
	BackendNS    string   `yaml:"backend_ns"`
	Interconnect string   `yaml:"interconnect"`
	Attach       string   `yaml:"attach"`
	PinDir       string   `yaml:"pin_dir"`
	Identity     Identity `yaml:"identity"`
	Peers        []Peer   `yaml:"peers"`
	Prefixes     []Prefix `yaml:"prefixes"`
	Failover     Failover `yaml:"failover"`

	// Engine selects the peer datapath implementation: "kernel"
	// (in-tree WireGuard devices) or "userspace" (wireguard-go).
	// Both engines expose identical peers to the same eBPF steering.
	Engine string `yaml:"engine"`
	// APISocket is the wgmuxd control socket the control plane (this
	// config's owner, wgmuxctl) talks to.
	APISocket string `yaml:"api_socket"`
	// ManageRoutes controls whether wgmuxd installs the main-namespace
	// routes toward the front interface. Leave unset (nil) for true;
	// set false when an external routing daemon (FRR/zebra) owns
	// those routes instead.
	ManageRoutes *bool `yaml:"manage_routes"`
	BGP          BGP   `yaml:"bgp"`
}

// RoutesManaged reports whether wgmuxd should install main-namespace
// routes (the default).
func (c *Config) RoutesManaged() bool {
	return c.ManageRoutes == nil || *c.ManageRoutes
}

// Load reads and validates a YAML config file, filling defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.BackendNS == "" {
		c.BackendNS = "wgmux"
	}
	if c.Interconnect == "" {
		c.Interconnect = InterconnectVeth
	}
	if c.Attach == "" {
		c.Attach = AttachTCX
	}
	if c.PinDir == "" {
		c.PinDir = "/sys/fs/bpf/wgmux"
	}
	if c.Failover.HandshakeMaxAge == 0 {
		c.Failover.HandshakeMaxAge = 150
	}
	if c.Failover.Interval == 0 {
		c.Failover.Interval = 15
	}
	if c.Engine == "" {
		c.Engine = EngineKernel
	}
	if c.APISocket == "" {
		c.APISocket = "/run/wgmux/wgmuxd.sock"
	}
	if c.BGP.Mode == "" {
		c.BGP.Mode = BGPModeNone
	}
	if c.BGP.VtyshPath == "" {
		c.BGP.VtyshPath = "vtysh"
	}
	if c.BGP.PollInterval == 0 {
		c.BGP.PollInterval = 10
	}
	if c.Front.Name == "" {
		c.Front.Name = "wg-mux"
	}
	// Peer IDs: assign in declaration order starting at 1 (0 is reserved
	// for "no peer" in the datapath).
	for i := range c.Peers {
		if c.Peers[i].ID == 0 {
			c.Peers[i].ID = i + 1
		}
	}
	for i := range c.Prefixes {
		if c.Prefixes[i].Policy == "" {
			c.Prefixes[i].Policy = PolicyActive
		}
		if c.Prefixes[i].Active == "" && len(c.Prefixes[i].Candidates) > 0 {
			c.Prefixes[i].Active = c.Prefixes[i].Candidates[0]
		}
	}
}

// PeerByName returns the named peer, or nil.
func (c *Config) PeerByName(name string) *Peer {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i]
		}
	}
	return nil
}

// AllowedIPsFor returns every prefix (as *net.IPNet) that lists peerName
// as a candidate: those are exactly the prefixes to program into that
// peer device's AllowedIPs.
func (c *Config) AllowedIPsFor(peerName string) []*net.IPNet {
	var out []*net.IPNet
	for _, p := range c.Prefixes {
		for _, cand := range p.Candidates {
			if cand == peerName {
				_, ipnet, err := net.ParseCIDR(p.CIDR)
				if err == nil {
					out = append(out, ipnet)
				}
			}
		}
	}
	return out
}

func checkKey(field, key string) error {
	if key == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%s is not a base64-encoded 32-byte WireGuard key", field)
	}
	return nil
}

func (c *Config) Validate() error {
	switch c.Interconnect {
	case InterconnectVeth, InterconnectNetkit:
	default:
		return fmt.Errorf("interconnect must be %q or %q, got %q", InterconnectVeth, InterconnectNetkit, c.Interconnect)
	}
	switch c.Attach {
	case AttachTCX, AttachTC:
	default:
		return fmt.Errorf("attach must be %q or %q, got %q", AttachTCX, AttachTC, c.Attach)
	}
	switch c.Engine {
	case EngineKernel, EngineUserspace:
	default:
		return fmt.Errorf("engine must be %q or %q, got %q", EngineKernel, EngineUserspace, c.Engine)
	}
	if err := c.validateBGP(); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(c.Front.Address); err != nil {
		return fmt.Errorf("front.address %q: %w", c.Front.Address, err)
	}
	if _, _, err := net.ParseCIDR(c.Front.BackendAddress); err != nil {
		return fmt.Errorf("front.backend_address %q: %w", c.Front.BackendAddress, err)
	}
	if err := checkKey("identity.private_key", c.Identity.PrivateKey); err != nil {
		return err
	}
	if c.Identity.PrivateKey == "" && c.Identity.PrivateKeyFile == "" {
		// Individual peers may still carry their own keys; that is checked
		// per peer below.
	} else if c.Identity.PrivateKey != "" && c.Identity.PrivateKeyFile != "" {
		return fmt.Errorf("identity: set only one of private_key / private_key_file")
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("no peers defined")
	}
	seenNames := map[string]bool{}
	seenIDs := map[int]string{}
	seenPorts := map[int]string{}
	for _, p := range c.Peers {
		if p.Name == "" {
			return fmt.Errorf("peer with empty name")
		}
		if seenNames[p.Name] {
			return fmt.Errorf("duplicate peer name %q", p.Name)
		}
		seenNames[p.Name] = true
		if prev, dup := seenIDs[p.ID]; dup {
			return fmt.Errorf("peer id %d used by both %q and %q", p.ID, prev, p.Name)
		}
		seenIDs[p.ID] = p.Name
		if p.ListenPort != 0 {
			if prev, dup := seenPorts[p.ListenPort]; dup {
				return fmt.Errorf("listen_port %d used by both %q and %q (devices share the main namespace for their UDP sockets)", p.ListenPort, prev, p.Name)
			}
			seenPorts[p.ListenPort] = p.Name
			if p.ListenPort < 0 || p.ListenPort > 65535 {
				return fmt.Errorf("peer %q: listen_port out of range", p.Name)
			}
		}
		if err := checkKey("peer "+p.Name+" public_key", p.PublicKey); err != nil {
			return err
		}
		if p.PublicKey == "" {
			return fmt.Errorf("peer %q: public_key is required", p.Name)
		}
		if err := checkKey("peer "+p.Name+" private_key", p.PrivateKey); err != nil {
			return err
		}
		if p.PrivateKey == "" && p.PrivateKeyFile == "" && c.Identity.PrivateKey == "" && c.Identity.PrivateKeyFile == "" {
			return fmt.Errorf("peer %q: no private key (set identity.private_key/_file or a per-peer key)", p.Name)
		}
		if p.Endpoint != "" {
			host, port, err := net.SplitHostPort(p.Endpoint)
			if err != nil || host == "" {
				return fmt.Errorf("peer %q: endpoint %q must be host:port", p.Name, p.Endpoint)
			}
			if _, err := strconv.Atoi(port); err != nil {
				return fmt.Errorf("peer %q: endpoint %q has non-numeric port", p.Name, p.Endpoint)
			}
		}
		if p.EndpointIP != "" && net.ParseIP(p.EndpointIP) == nil {
			return fmt.Errorf("peer %q: endpoint_ip %q is not an IP address", p.Name, p.EndpointIP)
		}
	}
	if len(c.Prefixes) == 0 {
		return fmt.Errorf("no prefixes defined")
	}
	seenCIDR := map[string]bool{}
	for _, p := range c.Prefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return fmt.Errorf("prefix %q: %w", p.CIDR, err)
		}
		if ipnet.IP.To4() == nil {
			return fmt.Errorf("prefix %q: only IPv4 is supported in this version", p.CIDR)
		}
		if seenCIDR[p.CIDR] {
			return fmt.Errorf("duplicate prefix %q", p.CIDR)
		}
		seenCIDR[p.CIDR] = true
		if len(p.Candidates) == 0 {
			return fmt.Errorf("prefix %q: no candidates", p.CIDR)
		}
		if len(p.Candidates) > 4 {
			return fmt.Errorf("prefix %q: at most 4 candidates (datapath limit)", p.CIDR)
		}
		for _, cand := range p.Candidates {
			if c.PeerByName(cand) == nil {
				return fmt.Errorf("prefix %q: candidate %q is not a defined peer", p.CIDR, cand)
			}
		}
		if c.PeerByName(p.Active) == nil {
			return fmt.Errorf("prefix %q: active peer %q is not defined", p.CIDR, p.Active)
		}
		activeOK := false
		for _, cand := range p.Candidates {
			if cand == p.Active {
				activeOK = true
			}
		}
		if !activeOK {
			return fmt.Errorf("prefix %q: active peer %q is not one of its candidates", p.CIDR, p.Active)
		}
		switch p.Policy {
		case PolicyActive, PolicyHash, PolicyFailover, PolicyBGP:
		default:
			return fmt.Errorf("prefix %q: policy must be active, hash, failover or bgp, got %q", p.CIDR, p.Policy)
		}
		if p.Policy == PolicyBGP && c.BGP.Mode == BGPModeNone {
			return fmt.Errorf("prefix %q: policy bgp but bgp.mode is none", p.CIDR)
		}
	}
	return nil
}

func (c *Config) validateBGP() error {
	switch c.BGP.Mode {
	case BGPModeNone:
		return nil
	case BGPModeGoBGP:
		if c.BGP.LocalAS == 0 {
			return fmt.Errorf("bgp.local_as is required for gobgp mode")
		}
		if net.ParseIP(c.BGP.RouterID) == nil {
			return fmt.Errorf("bgp.router_id %q is not an IP address", c.BGP.RouterID)
		}
	case BGPModeFRR:
	default:
		return fmt.Errorf("bgp.mode must be none, gobgp or frr, got %q", c.BGP.Mode)
	}
	if len(c.BGP.Neighbors) == 0 {
		return fmt.Errorf("bgp.neighbors is empty: neighbor -> wg_peer mapping is required")
	}
	for _, n := range c.BGP.Neighbors {
		if net.ParseIP(n.Address) == nil {
			return fmt.Errorf("bgp neighbor address %q is not an IP address", n.Address)
		}
		if c.PeerByName(n.WgPeer) == nil {
			return fmt.Errorf("bgp neighbor %s: wg_peer %q is not a defined peer", n.Address, n.WgPeer)
		}
		if c.BGP.Mode == BGPModeGoBGP && n.RemoteAS == 0 {
			return fmt.Errorf("bgp neighbor %s: remote_as is required for gobgp mode", n.Address)
		}
	}
	return nil
}

// ResolvePrivateKey returns the base64 private key for a peer, honouring
// per-peer overrides and *_file indirection.
func (c *Config) ResolvePrivateKey(p *Peer) (string, error) {
	key, file := p.PrivateKey, p.PrivateKeyFile
	if key == "" && file == "" {
		key, file = c.Identity.PrivateKey, c.Identity.PrivateKeyFile
	}
	if key != "" {
		return key, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read private key file for peer %q: %w", p.Name, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
