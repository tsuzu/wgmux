// Package config defines the wgmux configuration model and its
// validation, following the configuration lifecycle:
//
//   - A Mux is one mux instance. Its Name is both the instance name
//     in wgmuxd and its front interface's name.
//   - Creation parameters (engine kind, kernel options) are set
//     once per mux and stay fixed for the instance's lifetime.
//   - Everything else (peers, front address, prefix policies) is
//     per-Apply desired state and can change on re-apply.
//
// The YAML file is the OPTIONAL overlay form: it can define several
// muxes, inline peers, and policy overrides. The basic case needs
// no YAML at all — wgmuxctl can build a Mux directly from wg-quick
// .conf files (MuxFromWGFiles); in YAML form a peer can likewise
// reference one with `wg_config:`. Either way, steered prefixes are
// DERIVED from the peers' AllowedIPs and `prefixes:` entries only
// override policy/active/candidates per prefix.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	// DefaultMuxName is the instance (and front interface) name
	// used when none is given — the aggregated NIC's name.
	DefaultMuxName = "wg-mux"
)

// KernelOptions are the kernel engine's creation parameters for
// one mux (see api.KernelParams). They are meaningless for the
// userspace engine and ignored there.
type KernelOptions struct {
	BackendNS      string `yaml:"backend_ns"`
	Interconnect   string `yaml:"interconnect"`
	Attach         string `yaml:"attach"`
	PinDir         string `yaml:"pin_dir"`
	BackendAddress string `yaml:"backend_address"`
}

// Front is the mux's one visible interface. Its name is the mux
// name; only address and MTU live here.
type Front struct {
	// Address (CIDR) assigned to the front interface in the main
	// namespace. Its host part is this host's tunnel identity: inner
	// packets keep this source address whichever peer carries them.
	// May be derived from the wg_config files' [Interface] Address.
	Address string `yaml:"address"`
	// MTU of the front interface. 0 means derive from the smallest
	// wg_config MTU, else the engine default (1420).
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
	// ID is the datapath peer_id. 0 means assign automatically in
	// declaration order, starting at 1.
	ID int `yaml:"id"`
	// WgConfig points at a standard wg-quick .conf file (relative
	// to the YAML config file) that defines this peer as-is: its
	// [Interface] gives the device key/listen port, its single
	// [Peer] the remote site. Mutually exclusive with the inline
	// fields below (name, id and endpoint_ip may still be set).
	WgConfig string `yaml:"wg_config"`
	// ListenPort of this peer's device. Devices live in the same
	// birth namespace (the main one), so ports must not collide. 0
	// lets the implementation choose; only usable for peers we
	// always initiate to.
	ListenPort int `yaml:"listen_port"`
	// PrivateKey overrides Identity for this device only.
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyFile string `yaml:"private_key_file"`
	PublicKey      string `yaml:"public_key"`
	PresharedKey   string `yaml:"preshared_key"`
	// Endpoint as host:port. The host should be pre-resolved (see
	// EndpointIP): name resolution happens in the control plane.
	Endpoint string `yaml:"endpoint"`
	// EndpointIP optionally pins the resolved endpoint IP.
	EndpointIP          string `yaml:"endpoint_ip"`
	PersistentKeepalive int    `yaml:"persistent_keepalive"`
	// AllowedIPs declared inline. When empty (and no wg_config),
	// the peer's AllowedIPs are the prefixes listing it as a
	// candidate (the pre-derivation config form).
	AllowedIPs []string `yaml:"allowed_ips"`

	// Resolved during load (not YAML):
	allowed []string // final AllowedIPs, normalized CIDRs
	wgAddr  string   // first IPv4 [Interface] Address of the wg file
	wgMTU   int
}

// Allowed returns the peer's resolved AllowedIPs (normalized CIDR
// strings) — from its wg_config or inline declaration, or derived
// from the effective prefixes for the legacy inline form.
func (p *Peer) Allowed() []string { return p.allowed }

type Prefix struct {
	CIDR string `yaml:"cidr"`
	// Candidates are peer names that all carry this prefix in their
	// AllowedIPs. The datapath selects exactly one of them per packet.
	Candidates []string `yaml:"candidates"`
	// Active names the initially selected candidate (policies active and
	// failover). Defaults to the first candidate.
	Active string `yaml:"active"`
	// Policy: active | hash | failover | bgp. Defaults to active.
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

// Mux is one mux instance's configuration: creation parameters plus
// per-Apply desired state.
type Mux struct {
	// Name is the instance name in wgmuxd AND the front interface's
	// name. Defaults to DefaultMuxName.
	Name string `yaml:"name"`
	// Engine is the creation parameter selecting the datapath
	// implementation: "kernel" (in-tree WireGuard) or "userspace"
	// (wireguard-go). Fixed for the instance's lifetime.
	Engine string `yaml:"engine"`
	// Kernel holds the kernel engine's creation parameters.
	Kernel KernelOptions `yaml:"kernel"`

	Front    Front    `yaml:"front"`
	Identity Identity `yaml:"identity"`
	Peers    []Peer   `yaml:"peers"`
	// Prefixes are OVERRIDES over the prefixes derived from the
	// peers' AllowedIPs (subset of candidates, active, policy).
	// In the legacy inline form (no peer declares AllowedIPs) they
	// are the full prefix definitions instead.
	Prefixes []Prefix `yaml:"prefixes"`
	Failover Failover `yaml:"failover"`
	BGP      BGP      `yaml:"bgp"`
	// ManageRoutes controls whether the engine installs the
	// main-namespace routes toward the front interface. Leave
	// unset (nil) for true; set false when an external routing
	// daemon (FRR/zebra) owns those routes instead.
	ManageRoutes *bool `yaml:"manage_routes"`

	// Resolved during load (not YAML):
	EffectivePrefixes []Prefix `yaml:"-"`
	Warnings          []string `yaml:"-"`

	dir       string
	specified creationSpecified
}

// creationSpecified records which creation parameters were
// explicitly present in the source (YAML fields / CLI flags), as
// opposed to defaulted — the control plane uses it to check an
// apply against an existing instance's immutable creation
// parameters without flagging parameters the user never mentioned.
type creationSpecified struct {
	engine, interconnect, attach, backendNS, pinDir, backendAddr bool
}

// CreationSpec is a mux's creation-parameter intent: the values,
// plus which of them were explicitly specified.
type CreationSpec struct {
	Engine            string
	EngineSet         bool
	Interconnect      string
	InterconnectSet   bool
	Attach            string
	AttachSet         bool
	BackendNS         string
	BackendNSSet      bool
	PinDir            string
	PinDirSet         bool
	BackendAddress    string
	BackendAddressSet bool
}

// CreationSpec reports the mux's creation intent.
func (m *Mux) CreationSpec() CreationSpec {
	return CreationSpec{
		Engine: m.Engine, EngineSet: m.specified.engine,
		Interconnect: m.Kernel.Interconnect, InterconnectSet: m.specified.interconnect,
		Attach: m.Kernel.Attach, AttachSet: m.specified.attach,
		BackendNS: m.Kernel.BackendNS, BackendNSSet: m.specified.backendNS,
		PinDir: m.Kernel.PinDir, PinDirSet: m.specified.pinDir,
		BackendAddress: m.Kernel.BackendAddress, BackendAddressSet: m.specified.backendAddr,
	}
}

// captureSpecified snapshots which creation fields are explicitly
// set. Must run before finalize applies defaults.
func (m *Mux) captureSpecified() {
	m.specified = creationSpecified{
		engine:       m.Engine != "",
		interconnect: m.Kernel.Interconnect != "",
		attach:       m.Kernel.Attach != "",
		backendNS:    m.Kernel.BackendNS != "",
		pinDir:       m.Kernel.PinDir != "",
		backendAddr:  m.Kernel.BackendAddress != "",
	}
}

// RoutesManaged reports whether the engine should install
// main-namespace routes (the default).
func (m *Mux) RoutesManaged() bool {
	return m.ManageRoutes == nil || *m.ManageRoutes
}

// Config is a loaded YAML config file: the daemon socket plus one
// or more mux definitions.
type Config struct {
	APISocket string `yaml:"api_socket"`
	Muxes     []*Mux `yaml:"muxes"`
}

// MuxByName returns the named mux, or nil.
func (c *Config) MuxByName(name string) *Mux {
	for _, m := range c.Muxes {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// fileConfig is the on-disk YAML shape: either a `muxes:` list, or
// the legacy single-mux shorthand where the whole document is one
// mux (with the old flat kernel fields, mapped into the mux's
// kernel options).
type fileConfig struct {
	APISocket string `yaml:"api_socket"`
	Muxes     []*Mux `yaml:"muxes"`

	// Legacy single-mux shorthand:
	Front        legacyFront `yaml:"front"`
	BackendNS    string      `yaml:"backend_ns"`
	Interconnect string      `yaml:"interconnect"`
	Attach       string      `yaml:"attach"`
	PinDir       string      `yaml:"pin_dir"`
	Identity     Identity    `yaml:"identity"`
	Peers        []Peer      `yaml:"peers"`
	Prefixes     []Prefix    `yaml:"prefixes"`
	Failover     Failover    `yaml:"failover"`
	Engine       string      `yaml:"engine"`
	ManageRoutes *bool       `yaml:"manage_routes"`
	BGP          BGP         `yaml:"bgp"`
}

type legacyFront struct {
	Name           string `yaml:"name"`
	Address        string `yaml:"address"`
	BackendAddress string `yaml:"backend_address"`
	MTU            int    `yaml:"mtu"`
}

func (fc *fileConfig) hasLegacy() bool {
	return len(fc.Peers) > 0 || fc.Front.Address != "" || fc.Front.BackendAddress != "" ||
		fc.Identity.PrivateKey != "" || fc.Identity.PrivateKeyFile != "" || len(fc.Prefixes) > 0
}

// Load reads and validates a YAML config file, filling defaults and
// resolving all derivations (wg_config peers, front address,
// effective prefixes).
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fc fileConfig
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg := &Config{APISocket: fc.APISocket}
	if len(fc.Muxes) > 0 {
		if fc.hasLegacy() {
			return nil, fmt.Errorf("%s: muxes: and top-level single-mux fields are mutually exclusive", path)
		}
		cfg.Muxes = fc.Muxes
	} else {
		cfg.Muxes = []*Mux{{
			Name:   fc.Front.Name,
			Engine: fc.Engine,
			Kernel: KernelOptions{
				BackendNS:      fc.BackendNS,
				Interconnect:   fc.Interconnect,
				Attach:         fc.Attach,
				PinDir:         fc.PinDir,
				BackendAddress: fc.Front.BackendAddress,
			},
			Front:        Front{Address: fc.Front.Address, MTU: fc.Front.MTU},
			Identity:     fc.Identity,
			Peers:        fc.Peers,
			Prefixes:     fc.Prefixes,
			Failover:     fc.Failover,
			BGP:          fc.BGP,
			ManageRoutes: fc.ManageRoutes,
		}}
	}
	if cfg.APISocket == "" {
		cfg.APISocket = "/run/wgmux/wgmuxd.sock"
	}
	dir := filepath.Dir(path)
	seenNames := map[string]bool{}
	for _, m := range cfg.Muxes {
		m.captureSpecified()
		if err := m.finalize(dir); err != nil {
			return nil, err
		}
		if seenNames[m.Name] {
			return nil, fmt.Errorf("duplicate mux name %q", m.Name)
		}
		seenNames[m.Name] = true
		for _, w := range m.Warnings {
			fmt.Fprintf(os.Stderr, "wgmux: warning: %s\n", w)
		}
	}
	return cfg, nil
}

// MuxFromWGFiles builds a Mux directly from wg-quick .conf files —
// the no-YAML path. Peer names are the files' base names (sans
// extension). Paths are used as given (relative to the caller's
// working directory).
func MuxFromWGFiles(name string, paths []string) (*Mux, error) {
	m := &Mux{Name: name}
	seen := map[string]string{}
	for _, path := range paths {
		base := filepath.Base(path)
		pname := strings.TrimSuffix(base, filepath.Ext(base))
		if prev, dup := seen[pname]; dup {
			return nil, fmt.Errorf("wg config files %s and %s both map to peer name %q; rename one of them", prev, path, pname)
		}
		seen[pname] = path
		m.Peers = append(m.Peers, Peer{Name: pname, WgConfig: path})
	}
	if len(m.Peers) == 0 {
		return nil, fmt.Errorf("no wg config files given")
	}
	if err := m.finalize(""); err != nil {
		return nil, err
	}
	return m, nil
}

// finalize applies defaults, resolves wg_config peers, derives the
// front address/MTU and the effective prefixes, and validates.
func (m *Mux) finalize(dir string) error {
	m.dir = dir
	if m.Name == "" {
		m.Name = DefaultMuxName
	}
	if m.Engine == "" {
		m.Engine = EngineKernel
	}
	if m.Failover.HandshakeMaxAge == 0 {
		m.Failover.HandshakeMaxAge = 150
	}
	if m.Failover.Interval == 0 {
		m.Failover.Interval = 15
	}
	if m.BGP.Mode == "" {
		m.BGP.Mode = BGPModeNone
	}
	if m.BGP.VtyshPath == "" {
		m.BGP.VtyshPath = "vtysh"
	}
	if m.BGP.PollInterval == 0 {
		m.BGP.PollInterval = 10
	}
	// Peer IDs: assign in declaration order starting at 1 (0 is
	// reserved for "no peer" in the datapaths).
	for i := range m.Peers {
		if m.Peers[i].ID == 0 {
			m.Peers[i].ID = i + 1
		}
	}
	for i := range m.Peers {
		p := &m.Peers[i]
		var err error
		if p.WgConfig != "" {
			err = m.resolveWGPeer(p)
		} else if len(p.AllowedIPs) > 0 {
			p.allowed, err = normalizeCIDRs(p.AllowedIPs)
		}
		if err != nil {
			return err
		}
	}
	if err := m.deriveFront(); err != nil {
		return err
	}
	if err := m.resolvePrefixes(); err != nil {
		return err
	}
	return m.validate()
}

// resolveWGPeer merges one wg-quick file into the peer. The file is
// used as-is for everything it defines; inline peer fields (other
// than name/id/endpoint_ip) are rejected so there is never a
// question about which source won.
func (m *Mux) resolveWGPeer(p *Peer) error {
	if p.PrivateKey != "" || p.PrivateKeyFile != "" || p.PublicKey != "" || p.PresharedKey != "" ||
		p.ListenPort != 0 || p.Endpoint != "" || p.PersistentKeepalive != 0 || len(p.AllowedIPs) > 0 {
		return fmt.Errorf("peer %q: wg_config and inline peer fields are mutually exclusive (only name, id and endpoint_ip may accompany wg_config)", p.Name)
	}
	path := p.WgConfig
	if !filepath.IsAbs(path) {
		path = filepath.Join(m.dir, path)
	}
	f, err := parseWGFile(path)
	if err != nil {
		return fmt.Errorf("peer %q: %w", p.Name, err)
	}
	m.Warnings = append(m.Warnings, f.Warnings...)
	p.PrivateKey = f.PrivateKey
	p.ListenPort = f.ListenPort
	p.PublicKey = f.Peer.PublicKey
	p.PresharedKey = f.Peer.PresharedKey
	p.Endpoint = f.Peer.Endpoint
	p.PersistentKeepalive = f.Peer.PersistentKeepalive
	allowed, err := normalizeCIDRs(f.Peer.AllowedIPs)
	if err != nil {
		return fmt.Errorf("peer %q: wg_config AllowedIPs: %w", p.Name, err)
	}
	p.allowed = allowed
	p.wgMTU = f.MTU
	for _, a := range f.Addresses {
		if v := addrEntry(a); v != "" {
			p.wgAddr = v
			break
		}
	}
	return nil
}

// addrEntry normalizes one [Interface] Address entry to "ip/ones"
// form, or "" when it is not IPv4.
func addrEntry(a string) string {
	if strings.Contains(a, "/") {
		ip, _, err := net.ParseCIDR(a)
		if err != nil || ip.To4() == nil {
			return ""
		}
		_, ipnet, _ := net.ParseCIDR(a)
		ones, _ := ipnet.Mask.Size()
		return fmt.Sprintf("%s/%d", ip.String(), ones)
	}
	ip := net.ParseIP(a)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String() + "/32"
}

// deriveFront fills Front.Address from the wg files' [Interface]
// Address when the mux does not set one (all files must agree), and
// Front.MTU from the smallest wg MTU when unset.
func (m *Mux) deriveFront() error {
	if m.Front.Address == "" {
		var vals []string
		seen := map[string]bool{}
		for i := range m.Peers {
			if a := m.Peers[i].wgAddr; a != "" && !seen[a] {
				seen[a] = true
				vals = append(vals, a)
			}
		}
		switch {
		case len(vals) == 1:
			m.Front.Address = vals[0]
		case len(vals) > 1:
			return fmt.Errorf("mux %q: wg_config files disagree on [Interface] Address (%s); set front.address explicitly", m.Name, strings.Join(vals, " vs "))
		}
	}
	if m.Front.MTU == 0 {
		for i := range m.Peers {
			if mtu := m.Peers[i].wgMTU; mtu > 0 && (m.Front.MTU == 0 || mtu < m.Front.MTU) {
				m.Front.MTU = mtu
			}
		}
	}
	return nil
}

// resolvePrefixes derives the effective steered prefixes by
// grouping peers by their declared AllowedIPs, then applies the
// mux's prefix overrides. When no peer declares AllowedIPs (the
// legacy inline form), `prefixes:` is the definition instead.
func (m *Mux) resolvePrefixes() error {
	type claim struct {
		cidr  string
		peers []string
	}
	var claims []*claim
	byCIDR := map[string]*claim{}
	anyDeclared := false
	for i := range m.Peers {
		p := &m.Peers[i]
		if len(p.allowed) == 0 {
			continue
		}
		anyDeclared = true
		for _, cidr := range p.allowed {
			c := byCIDR[cidr]
			if c == nil {
				c = &claim{cidr: cidr}
				byCIDR[cidr] = c
				claims = append(claims, c)
			}
			c.peers = append(c.peers, p.Name)
		}
	}
	if !anyDeclared {
		m.EffectivePrefixes = m.Prefixes
		for i := range m.EffectivePrefixes {
			if m.EffectivePrefixes[i].Policy == "" {
				m.EffectivePrefixes[i].Policy = PolicyActive
			}
			if m.EffectivePrefixes[i].Active == "" && len(m.EffectivePrefixes[i].Candidates) > 0 {
				m.EffectivePrefixes[i].Active = m.EffectivePrefixes[i].Candidates[0]
			}
		}
		return nil
	}
	overrides := map[string]*Prefix{}
	for i := range m.Prefixes {
		ov := &m.Prefixes[i]
		_, ipnet, err := net.ParseCIDR(ov.CIDR)
		if err != nil {
			return fmt.Errorf("prefix override %q: %w", ov.CIDR, err)
		}
		key := ipnet.String()
		if overrides[key] != nil {
			return fmt.Errorf("duplicate prefix override %q", ov.CIDR)
		}
		ov.CIDR = key
		overrides[key] = ov
	}
	var eff []Prefix
	for _, c := range claims {
		np := Prefix{CIDR: c.cidr, Candidates: c.peers, Active: c.peers[0], Policy: PolicyActive}
		if ov, ok := overrides[c.cidr]; ok {
			delete(overrides, c.cidr)
			if len(ov.Candidates) > 0 {
				for _, cand := range ov.Candidates {
					found := false
					for _, claimed := range c.peers {
						if cand == claimed {
							found = true
						}
					}
					if !found {
						return fmt.Errorf("prefix %s: override candidate %q does not claim this prefix in its AllowedIPs", c.cidr, cand)
					}
				}
				np.Candidates = ov.Candidates
				np.Active = ov.Candidates[0]
			}
			if ov.Active != "" {
				np.Active = ov.Active
			}
			if ov.Policy != "" {
				np.Policy = ov.Policy
			}
		}
		eff = append(eff, np)
	}
	for key := range overrides {
		return fmt.Errorf("prefix override %s matches no peer's AllowedIPs", key)
	}
	m.EffectivePrefixes = eff
	return nil
}

// normalizeCIDRs validates and canonicalizes CIDR strings; a bare
// IP means a host prefix, as in wg-quick.
func normalizeCIDRs(list []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range list {
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("allowed_ip %q is not an IP address or CIDR", s)
			}
			if ip.To4() != nil {
				s += "/32"
			} else {
				s += "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("allowed_ip %q: %w", s, err)
		}
		key := ipnet.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out, nil
}

// PeerByName returns the named peer, or nil.
func (m *Mux) PeerByName(name string) *Peer {
	for i := range m.Peers {
		if m.Peers[i].Name == name {
			return &m.Peers[i]
		}
	}
	return nil
}

// AllowedIPsFor returns the peer's resolved AllowedIPs: its own
// declaration when it has one, else every effective prefix listing
// it as a candidate.
func (m *Mux) AllowedIPsFor(peerName string) []string {
	if p := m.PeerByName(peerName); p != nil && len(p.allowed) > 0 {
		return p.allowed
	}
	var out []string
	for _, pfx := range m.EffectivePrefixes {
		for _, cand := range pfx.Candidates {
			if cand == peerName {
				out = append(out, pfx.CIDR)
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

func (m *Mux) validate() error {
	if len(m.Name) > 15 {
		return fmt.Errorf("mux name %q exceeds 15 characters (it is also the front interface name)", m.Name)
	}
	switch m.Engine {
	case EngineKernel:
		switch m.Kernel.Interconnect {
		case "", InterconnectVeth, InterconnectNetkit:
		default:
			return fmt.Errorf("mux %q: kernel.interconnect must be %q or %q, got %q", m.Name, InterconnectVeth, InterconnectNetkit, m.Kernel.Interconnect)
		}
		switch m.Kernel.Attach {
		case "", AttachTCX, AttachTC:
		default:
			return fmt.Errorf("mux %q: kernel.attach must be %q or %q, got %q", m.Name, AttachTCX, AttachTC, m.Kernel.Attach)
		}
	case EngineUserspace:
	default:
		return fmt.Errorf("mux %q: engine must be %q or %q, got %q", m.Name, EngineKernel, EngineUserspace, m.Engine)
	}
	if err := m.validateBGP(); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(m.Front.Address); err != nil {
		return fmt.Errorf("mux %q: front.address %q: %w (set front.address, or give wg_config files that agree on [Interface] Address)", m.Name, m.Front.Address, err)
	}
	if ip, _, _ := net.ParseCIDR(m.Front.Address); ip.To4() == nil {
		return fmt.Errorf("mux %q: front.address %q: only IPv4 is supported in this version", m.Name, m.Front.Address)
	}
	if err := checkKey("identity.private_key", m.Identity.PrivateKey); err != nil {
		return err
	}
	if m.Identity.PrivateKey != "" && m.Identity.PrivateKeyFile != "" {
		return fmt.Errorf("mux %q: identity: set only one of private_key / private_key_file", m.Name)
	}
	if len(m.Peers) == 0 {
		return fmt.Errorf("mux %q: no peers defined", m.Name)
	}
	seenNames := map[string]bool{}
	seenIDs := map[int]string{}
	seenPorts := map[int]string{}
	for _, p := range m.Peers {
		if p.Name == "" {
			return fmt.Errorf("mux %q: peer with empty name", m.Name)
		}
		if seenNames[p.Name] {
			return fmt.Errorf("mux %q: duplicate peer name %q", m.Name, p.Name)
		}
		seenNames[p.Name] = true
		if prev, dup := seenIDs[p.ID]; dup {
			return fmt.Errorf("mux %q: peer id %d used by both %q and %q", m.Name, p.ID, prev, p.Name)
		}
		seenIDs[p.ID] = p.Name
		if p.ListenPort != 0 {
			if prev, dup := seenPorts[p.ListenPort]; dup {
				return fmt.Errorf("mux %q: listen_port %d used by both %q and %q (devices share the main namespace for their UDP sockets)", m.Name, p.ListenPort, prev, p.Name)
			}
			seenPorts[p.ListenPort] = p.Name
			if p.ListenPort < 0 || p.ListenPort > 65535 {
				return fmt.Errorf("mux %q: peer %q: listen_port out of range", m.Name, p.Name)
			}
		}
		if err := checkKey("peer "+p.Name+" public_key", p.PublicKey); err != nil {
			return err
		}
		if p.PublicKey == "" {
			return fmt.Errorf("mux %q: peer %q: public_key is required", m.Name, p.Name)
		}
		if err := checkKey("peer "+p.Name+" preshared_key", p.PresharedKey); err != nil {
			return err
		}
		if err := checkKey("peer "+p.Name+" private_key", p.PrivateKey); err != nil {
			return err
		}
		if p.PrivateKey == "" && p.PrivateKeyFile == "" && m.Identity.PrivateKey == "" && m.Identity.PrivateKeyFile == "" {
			return fmt.Errorf("mux %q: peer %q: no private key (set identity.private_key/_file, a per-peer key, or use wg_config)", m.Name, p.Name)
		}
		for _, cidr := range p.allowed {
			if ip, _, _ := net.ParseCIDR(cidr); ip.To4() == nil {
				return fmt.Errorf("mux %q: peer %q: allowed_ip %q: only IPv4 is supported in this version", m.Name, p.Name, cidr)
			}
		}
		if p.Endpoint != "" {
			host, port, err := net.SplitHostPort(p.Endpoint)
			if err != nil || host == "" {
				return fmt.Errorf("mux %q: peer %q: endpoint %q must be host:port", m.Name, p.Name, p.Endpoint)
			}
			if _, err := strconv.Atoi(port); err != nil {
				return fmt.Errorf("mux %q: peer %q: endpoint %q has non-numeric port", m.Name, p.Name, p.Endpoint)
			}
		}
		if p.EndpointIP != "" && net.ParseIP(p.EndpointIP) == nil {
			return fmt.Errorf("mux %q: peer %q: endpoint_ip %q is not an IP address", m.Name, p.Name, p.EndpointIP)
		}
	}
	if len(m.EffectivePrefixes) == 0 {
		return fmt.Errorf("mux %q: no prefixes defined (no peer AllowedIPs and no prefixes:)", m.Name)
	}
	seenCIDR := map[string]bool{}
	for _, p := range m.EffectivePrefixes {
		_, ipnet, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return fmt.Errorf("mux %q: prefix %q: %w", m.Name, p.CIDR, err)
		}
		if ipnet.IP.To4() == nil {
			return fmt.Errorf("mux %q: prefix %q: only IPv4 is supported in this version", m.Name, p.CIDR)
		}
		if seenCIDR[p.CIDR] {
			return fmt.Errorf("mux %q: duplicate prefix %q", m.Name, p.CIDR)
		}
		seenCIDR[p.CIDR] = true
		if len(p.Candidates) == 0 {
			return fmt.Errorf("mux %q: prefix %q: no candidates", m.Name, p.CIDR)
		}
		if len(p.Candidates) > 4 {
			return fmt.Errorf("mux %q: prefix %q: at most 4 candidates (datapath limit)", m.Name, p.CIDR)
		}
		for _, cand := range p.Candidates {
			if m.PeerByName(cand) == nil {
				return fmt.Errorf("mux %q: prefix %q: candidate %q is not a defined peer", m.Name, p.CIDR, cand)
			}
		}
		if m.PeerByName(p.Active) == nil {
			return fmt.Errorf("mux %q: prefix %q: active peer %q is not defined", m.Name, p.CIDR, p.Active)
		}
		activeOK := false
		for _, cand := range p.Candidates {
			if cand == p.Active {
				activeOK = true
			}
		}
		if !activeOK {
			return fmt.Errorf("mux %q: prefix %q: active peer %q is not one of its candidates", m.Name, p.CIDR, p.Active)
		}
		switch p.Policy {
		case PolicyActive, PolicyHash, PolicyFailover, PolicyBGP:
		default:
			return fmt.Errorf("mux %q: prefix %q: policy must be active, hash, failover or bgp, got %q", m.Name, p.CIDR, p.Policy)
		}
		if p.Policy == PolicyBGP && m.BGP.Mode == BGPModeNone {
			return fmt.Errorf("mux %q: prefix %q: policy bgp but bgp.mode is none", m.Name, p.CIDR)
		}
	}
	return nil
}

func (m *Mux) validateBGP() error {
	switch m.BGP.Mode {
	case BGPModeNone:
		return nil
	case BGPModeGoBGP:
		if m.BGP.LocalAS == 0 {
			return fmt.Errorf("mux %q: bgp.local_as is required for gobgp mode", m.Name)
		}
		if net.ParseIP(m.BGP.RouterID) == nil {
			return fmt.Errorf("mux %q: bgp.router_id %q is not an IP address", m.Name, m.BGP.RouterID)
		}
	case BGPModeFRR:
	default:
		return fmt.Errorf("mux %q: bgp.mode must be none, gobgp or frr, got %q", m.Name, m.BGP.Mode)
	}
	if len(m.BGP.Neighbors) == 0 {
		return fmt.Errorf("mux %q: bgp.neighbors is empty: neighbor -> wg_peer mapping is required", m.Name)
	}
	for _, n := range m.BGP.Neighbors {
		if net.ParseIP(n.Address) == nil {
			return fmt.Errorf("mux %q: bgp neighbor address %q is not an IP address", m.Name, n.Address)
		}
		if m.PeerByName(n.WgPeer) == nil {
			return fmt.Errorf("mux %q: bgp neighbor %s: wg_peer %q is not a defined peer", m.Name, n.Address, n.WgPeer)
		}
		if m.BGP.Mode == BGPModeGoBGP && n.RemoteAS == 0 {
			return fmt.Errorf("mux %q: bgp neighbor %s: remote_as is required for gobgp mode", m.Name, n.Address)
		}
	}
	return nil
}

// ResolvePrivateKey returns the base64 private key for a peer, honouring
// per-peer overrides and *_file indirection.
func (m *Mux) ResolvePrivateKey(p *Peer) (string, error) {
	key, file := p.PrivateKey, p.PrivateKeyFile
	if key == "" && file == "" {
		key, file = m.Identity.PrivateKey, m.Identity.PrivateKeyFile
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
