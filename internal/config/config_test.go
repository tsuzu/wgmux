package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes, base64

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

func TestValidConfigDefaults(t *testing.T) {
	cfg, err := load(t, validYAML())
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Interconnect != InterconnectVeth || cfg.Attach != AttachTCX {
		t.Errorf("defaults not applied: interconnect=%q attach=%q", cfg.Interconnect, cfg.Attach)
	}
	if cfg.Peers[0].ID != 1 || cfg.Peers[1].ID != 2 {
		t.Errorf("peer IDs not assigned in order: %d, %d", cfg.Peers[0].ID, cfg.Peers[1].ID)
	}
	p := cfg.Prefixes[0]
	if p.Policy != PolicyActive || p.Active != "site-a" {
		t.Errorf("prefix defaults wrong: policy=%q active=%q", p.Policy, p.Active)
	}
	if got := cfg.AllowedIPsFor("site-b"); len(got) != 1 || got[0].String() != "10.20.0.10/32" {
		t.Errorf("AllowedIPsFor(site-b) = %v", got)
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
