package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cand2 = "candidates: [site-a, site-b]"

func TestLegacyPolicyMapping(t *testing.T) {
	for policy, want := range map[string][2]string{
		"active": {ModeSingle, PolicyStatic},
		"hash":   {ModeECMP, PolicyStatic},
	} {
		body := strings.Replace(validYAML(), cand2, cand2+"\n    policy: "+policy, 1)
		cfg, err := load(t, body)
		if err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		p := cfg.Muxes[0].EffectivePrefixes[0]
		if p.Mode != want[0] || p.Policy != want[1] {
			t.Errorf("legacy %s -> mode %s policy %s, want %v", policy, p.Mode, p.Policy, want)
		}
	}
	// A legacy spelling contradicting an explicit mode is an error.
	body := strings.Replace(validYAML(), cand2, cand2+"\n    policy: hash\n    mode: single", 1)
	if _, err := load(t, body); err == nil {
		t.Error("policy hash + mode single accepted")
	}
}

func TestECMPWeightsAndSelection(t *testing.T) {
	body := strings.Replace(validYAML(), cand2,
		cand2+"\n    mode: ecmp\n    policy: failover\n    weights: {site-b: 3, site-a: 1}", 1)
	cfg, err := load(t, body)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Muxes[0].EffectivePrefixes[0]
	if p.Mode != ModeECMP || p.Policy != PolicyFailover || p.Active != "" {
		t.Fatalf("prefix = %+v", p)
	}
	sel := p.Selection()
	// candidate order, not map order
	if len(sel) != 2 || sel[0].Peer != "site-a" || sel[0].Weight != 1 || sel[1].Peer != "site-b" || sel[1].Weight != 3 {
		t.Errorf("selection = %+v", sel)
	}
	// ecmp without weights: every candidate, weight 1.
	cfg, err = load(t, strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp", 1))
	if err != nil {
		t.Fatal(err)
	}
	if sel := cfg.Muxes[0].EffectivePrefixes[0].Selection(); len(sel) != 2 || sel[1].Weight != 1 {
		t.Errorf("default ecmp selection = %+v", sel)
	}
	// weights on a subset: only those peers are initially selected.
	cfg, err = load(t, strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp\n    weights: {site-b: 2}", 1))
	if err != nil {
		t.Fatal(err)
	}
	if sel := cfg.Muxes[0].EffectivePrefixes[0].Selection(); len(sel) != 1 || sel[0].Peer != "site-b" || sel[0].Weight != 2 {
		t.Errorf("subset selection = %+v", sel)
	}
}

func TestSingleSelection(t *testing.T) {
	cfg, err := load(t, strings.Replace(validYAML(), cand2, cand2+"\n    active: site-b", 1))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Muxes[0].EffectivePrefixes[0]
	if p.Mode != ModeSingle || p.Policy != PolicyStatic {
		t.Errorf("defaults = %s/%s", p.Mode, p.Policy)
	}
	if sel := p.Selection(); len(sel) != 1 || sel[0].Peer != "site-b" {
		t.Errorf("selection = %+v", sel)
	}
}

func TestV2ValidationErrors(t *testing.T) {
	cases := map[string]string{
		"weights in single":      strings.Replace(validYAML(), cand2, cand2+"\n    weights: {site-a: 1}", 1),
		"weight non-candidate":   strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp\n    weights: {ghost: 1}", 1),
		"weight zero":            strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp\n    weights: {site-a: 0}", 1),
		"weight negative":        strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp\n    weights: {site-a: -2}", 1),
		"active in ecmp":         strings.Replace(validYAML(), cand2, cand2+"\n    mode: ecmp\n    active: site-a", 1),
		"bad mode":               strings.Replace(validYAML(), cand2, cand2+"\n    mode: anycast", 1),
		"duplicate candidate":    strings.Replace(validYAML(), cand2, "candidates: [site-a, site-a]", 1),
		"peer id too large":      strings.Replace(validYAML(), "- name: site-a", "- name: site-a\n    id: 256", 1),
		"bgp policy without bgp": strings.Replace(validYAML(), cand2, cand2+"\n    policy: bgp", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, body); err == nil {
				t.Errorf("config accepted, want validation error")
			}
		})
	}
}

func TestCandidateLimit(t *testing.T) {
	mk := func(n int) string {
		var peers, names []string
		for i := 0; i < n; i++ {
			nm := fmt.Sprintf("p%02d", i)
			peers = append(peers, fmt.Sprintf("  - {name: %s, listen_port: %d, public_key: \"%s\"}", nm, 40000+i, keyA))
			names = append(names, nm)
		}
		return "front: {address: 10.200.0.2/24}\nidentity: {private_key: \"" + keyA + "\"}\npeers:\n" +
			strings.Join(peers, "\n") +
			"\nprefixes:\n  - {cidr: 10.20.0.10/32, mode: ecmp, candidates: [" + strings.Join(names, ", ") + "]}\n"
	}
	if _, err := load(t, mk(64)); err != nil {
		t.Errorf("64 candidates rejected: %v", err)
	}
	if _, err := load(t, mk(65)); err == nil {
		t.Error("65 candidates accepted")
	}
}

func TestDerivedPrefixDefaultsAndOverrideWeights(t *testing.T) {
	dir := t.TempDir()
	wgConf(t, dir, "site-a.conf", "51821", "10.200.0.2/24", keyB, "", "10.20.0.10/32, 192.168.10.0/24")
	wgConf(t, dir, "site-b.conf", "51822", "10.200.0.2/24", keyB, "", "10.20.0.10/32, 192.168.10.0/24")
	body := `
muxes:
  - name: wg-mux
    peers:
      - {name: site-a, wg_config: site-a.conf}
      - {name: site-b, wg_config: site-b.conf}
    prefixes:
      - {cidr: 192.168.10.0/24, mode: ecmp, policy: failover, weights: {site-a: 2, site-b: 1}}
`
	path := filepath.Join(dir, "wgmux.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var plain, ecmp *Prefix
	for i := range cfg.Muxes[0].EffectivePrefixes {
		p := &cfg.Muxes[0].EffectivePrefixes[i]
		if p.CIDR == "10.20.0.10/32" {
			plain = p
		} else {
			ecmp = p
		}
	}
	if plain.Mode != ModeSingle || plain.Policy != PolicyStatic || plain.Active != "site-a" {
		t.Errorf("derived default = %+v", plain)
	}
	if ecmp.Mode != ModeECMP || ecmp.Policy != PolicyFailover || ecmp.Weights["site-a"] != 2 {
		t.Errorf("override = %+v", ecmp)
	}
}
