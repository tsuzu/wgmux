package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes, base64
	keyB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" // 32 0x01 bytes, base64
)

// validYAML is the legacy single-mux shorthand; it must keep working.
func validYAML() string {
	return `
front:
  address: 10.200.0.2/24
  backend_address: 10.200.0.1/24
identity:
  private_key: "` + keyA + `"
peers:
  - name: site-a
    listen_port: 51820
    public_key: "` + keyA + `"
    endpoint: 203.0.113.10:51820
  - name: site-b
    listen_port: 51821
    public_key: "` + keyA + `"
    endpoint: 203.0.113.11:51820
prefixes:
  - cidr: 10.20.0.10/32
    candidates: [site-a, site-b]
`
}

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wgmux.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLegacyShorthandDefaults(t *testing.T) {
	cfg, err := load(t, validYAML())
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(cfg.Muxes) != 1 {
		t.Fatalf("want 1 mux, got %d", len(cfg.Muxes))
	}
	m := cfg.Muxes[0]
	if m.Name != DefaultMuxName {
		t.Errorf("mux name = %q, want default %q", m.Name, DefaultMuxName)
	}
	if m.Engine != EngineKernel || m.Kernel.Interconnect != "" || m.Kernel.BackendAddress != "10.200.0.1/24" {
		t.Errorf("kernel options not carried: %+v", m.Kernel)
	}
	if m.Peers[0].ID != 1 || m.Peers[1].ID != 2 {
		t.Errorf("peer IDs not assigned in order: %d, %d", m.Peers[0].ID, m.Peers[1].ID)
	}
	p := m.EffectivePrefixes[0]
	if p.Policy != PolicyActive || p.Active != "site-a" {
		t.Errorf("prefix defaults wrong: policy=%q active=%q", p.Policy, p.Active)
	}
	if got := m.AllowedIPsFor("site-b"); len(got) != 1 || got[0] != "10.20.0.10/32" {
		t.Errorf("AllowedIPsFor(site-b) = %v", got)
	}
}

func TestMultiMuxYAML(t *testing.T) {
	body := `
muxes:
  - name: wg-a
    front: {address: 10.200.0.2/24}
    identity: {private_key: "` + keyA + `"}
    peers:
      - {name: site-a, listen_port: 51820, public_key: "` + keyA + `"}
    prefixes:
      - {cidr: 10.20.0.10/32, candidates: [site-a]}
  - name: wg-b
    engine: userspace
    front: {address: 10.201.0.2/24}
    identity: {private_key: "` + keyB + `"}
    peers:
      - {name: site-a, listen_port: 51830, public_key: "` + keyA + `"}
    prefixes:
      - {cidr: 10.20.0.10/32, candidates: [site-a]}
`
	cfg, err := load(t, body)
	if err != nil {
		t.Fatalf("multi-mux config rejected: %v", err)
	}
	if len(cfg.Muxes) != 2 || cfg.MuxByName("wg-b").Engine != EngineUserspace {
		t.Fatalf("muxes = %+v", cfg.Muxes)
	}
	dup := strings.Replace(body, "name: wg-b", "name: wg-a", 1)
	if _, err := load(t, dup); err == nil {
		t.Error("duplicate mux names accepted")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"bad interconnect": strings.Replace(validYAML(), "identity:", "interconnect: gre\nidentity:", 1),
		"unknown candidate": strings.Replace(validYAML(), "candidates: [site-a, site-b]",
			"candidates: [site-a, nowhere]", 1),
		"active not candidate": strings.Replace(validYAML(), "candidates: [site-a, site-b]",
			"candidates: [site-a]\n    active: site-b", 1),
		"duplicate listen port": strings.Replace(validYAML(), "listen_port: 51821", "listen_port: 51820", 1),
		"too many candidates": strings.Replace(validYAML(), "candidates: [site-a, site-b]",
			"candidates: [site-a, site-b, site-a, site-b, site-a]", 1),
		"bad policy": strings.Replace(validYAML(), "candidates: [site-a, site-b]",
			"candidates: [site-a, site-b]\n    policy: random", 1),
		"ipv6 prefix": strings.Replace(validYAML(), "10.20.0.10/32", "fd00::10/128", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, body); err == nil {
				t.Errorf("config accepted, want validation error")
			}
		})
	}
}

// wgConf writes a wg-quick file into dir and returns its path.
func wgConf(t *testing.T, dir, name, listenPort, address, peerPub, psk, allowed string) string {
	t.Helper()
	body := "[Interface]\n" +
		"PrivateKey = " + keyA + "\n" +
		"ListenPort = " + listenPort + "\n" +
		"Address = " + address + "\n" +
		"\n[Peer]\n" +
		"PublicKey = " + peerPub + "\n"
	if psk != "" {
		body += "PresharedKey = " + psk + "\n"
	}
	body += "Endpoint = 203.0.113.10:51820\n" +
		"AllowedIPs = " + allowed + "\n" +
		"PersistentKeepalive = 25\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMuxFromWGFilesDerivation(t *testing.T) {
	dir := t.TempDir()
	a := wgConf(t, dir, "site-a.conf", "51821", "10.200.0.2/24", keyB, "", "10.20.0.10/32, 192.168.10.0/24")
	b := wgConf(t, dir, "site-b.conf", "51822", "10.200.0.2/24", keyB, keyA, "10.20.0.10/32")
	m, err := MuxFromWGFiles("", []string{a, b})
	if err != nil {
		t.Fatalf("MuxFromWGFiles: %v", err)
	}
	if m.Name != DefaultMuxName {
		t.Errorf("mux name = %q", m.Name)
	}
	if m.Front.Address != "10.200.0.2/24" {
		t.Errorf("front address derived = %q, want 10.200.0.2/24", m.Front.Address)
	}
	if m.Peers[0].Name != "site-a" || m.Peers[1].Name != "site-b" {
		t.Errorf("peer names = %q, %q (want file base names)", m.Peers[0].Name, m.Peers[1].Name)
	}
	if m.Peers[1].PresharedKey != keyA {
		t.Errorf("preshared key not carried from wg file")
	}
	if len(m.EffectivePrefixes) != 2 {
		t.Fatalf("effective prefixes = %+v", m.EffectivePrefixes)
	}
	shared := m.EffectivePrefixes[0]
	if shared.CIDR != "10.20.0.10/32" || len(shared.Candidates) != 2 || shared.Active != "site-a" || shared.Policy != PolicyActive {
		t.Errorf("shared prefix = %+v", shared)
	}
	solo := m.EffectivePrefixes[1]
	if solo.CIDR != "192.168.10.0/24" || len(solo.Candidates) != 1 || solo.Candidates[0] != "site-a" {
		t.Errorf("solo prefix = %+v", solo)
	}
	// Default active is the FIRST file's peer; reordering the files
	// must flip the default active (per-Apply change, no recreate).
	m2, err := MuxFromWGFiles("", []string{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if m2.EffectivePrefixes[0].Active != "site-b" {
		t.Errorf("reordered default active = %q, want site-b", m2.EffectivePrefixes[0].Active)
	}
}

func TestWGFileErrors(t *testing.T) {
	dir := t.TempDir()
	good := wgConf(t, dir, "good.conf", "51821", "10.200.0.2/24", keyB, "", "10.20.0.10/32")

	t.Run("address disagreement", func(t *testing.T) {
		other := wgConf(t, dir, "other.conf", "51822", "10.200.0.3/24", keyB, "", "10.20.0.10/32")
		if _, err := MuxFromWGFiles("", []string{good, other}); err == nil {
			t.Error("address disagreement accepted")
		}
	})
	t.Run("duplicate listen port from files", func(t *testing.T) {
		dup := wgConf(t, dir, "dup.conf", "51821", "10.200.0.2/24", keyB, "", "10.20.0.10/32")
		if _, err := MuxFromWGFiles("", []string{good, dup}); err == nil {
			t.Error("duplicate listen port accepted")
		}
	})
	t.Run("peer name collision", func(t *testing.T) {
		sub := filepath.Join(dir, "sub")
		os.Mkdir(sub, 0o755)
		same := wgConf(t, sub, "good.conf", "51829", "10.200.0.2/24", keyB, "", "10.20.0.10/32")
		if _, err := MuxFromWGFiles("", []string{good, same}); err == nil {
			t.Error("peer name collision accepted")
		}
	})
}

func TestWGConfigInYAMLWithOverride(t *testing.T) {
	dir := t.TempDir()
	wgConf(t, dir, "site-a.conf", "51821", "10.200.0.2/24", keyB, "", "10.20.0.10/32")
	wgConf(t, dir, "site-b.conf", "51822", "10.200.0.2/24", keyB, "", "10.20.0.10/32")
	body := `
muxes:
  - name: wg-mux
    peers:
      - {name: site-a, wg_config: site-a.conf}
      - {name: site-b, wg_config: site-b.conf}
    prefixes:
      - {cidr: 10.20.0.10/32, policy: hash}
`
	path := filepath.Join(dir, "wgmux.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("yaml+wg_config rejected: %v", err)
	}
	m := cfg.Muxes[0]
	if m.Front.Address != "10.200.0.2/24" {
		t.Errorf("front derived = %q", m.Front.Address)
	}
	p := m.EffectivePrefixes[0]
	if p.Policy != PolicyHash || len(p.Candidates) != 2 {
		t.Errorf("override not applied: %+v", p)
	}

	// Override naming a peer that does not claim the prefix.
	bad := strings.Replace(body, "policy: hash", "candidates: [site-a, ghost], policy: hash", 1)
	os.WriteFile(path, []byte(bad), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("override with non-claiming candidate accepted")
	}
	// Inline fields alongside wg_config are rejected.
	bad2 := strings.Replace(body, "wg_config: site-a.conf", "wg_config: site-a.conf, listen_port: 9999", 1)
	os.WriteFile(path, []byte(bad2), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("wg_config + inline field accepted")
	}
}
