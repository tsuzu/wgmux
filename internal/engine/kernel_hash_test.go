package engine

import (
	"testing"

	"github.com/tsuzu/wgmux/internal/api"
)

func hashSpec() api.ApplySpec {
	return api.ApplySpec{
		Front:        api.FrontSpec{Name: "m", Address: "10.200.0.2/24", MTU: 1420},
		ManageRoutes: true,
		Peers: []api.PeerSpec{
			{Name: "p1", ID: 1, ListenPort: 51001, AllowedIPs: []string{"0.0.0.0/0"}},
			{Name: "p2", ID: 2, ListenPort: 51002, AllowedIPs: []string{"0.0.0.0/0"}},
		},
		Prefixes: []api.PrefixSpec{{
			CIDR: "10.20.0.0/24", Candidates: []string{"p1", "p2"}, Mode: api.ModeECMP,
			Selection: []api.PeerWeight{{Peer: "p1", Weight: 1}, {Peer: "p2", Weight: 1}},
		}},
	}
}

func TestSpecHash(t *testing.T) {
	base := hashSpec()
	h := specHash(base)
	if h == 0 {
		t.Fatal("hash is 0 (reserved for apply-in-progress)")
	}
	if specHash(hashSpec()) != h {
		t.Error("hash not deterministic")
	}

	sel := hashSpec()
	sel.Prefixes[0].Selection = []api.PeerWeight{{Peer: "p2", Weight: 7}}
	if specHash(sel) != h {
		t.Error("selection change altered the hash")
	}
	sel.Prefixes[0].Selection = nil
	if specHash(sel) != h {
		t.Error("cleared selection altered the hash")
	}
	// The input spec must not be mutated by hashing.
	if len(base.Prefixes[0].Selection) != 2 {
		t.Error("specHash mutated its argument")
	}

	for name, mut := range map[string]func(*api.ApplySpec){
		"peer key":      func(s *api.ApplySpec) { s.Peers[0].PublicKey = "x" },
		"peer port":     func(s *api.ApplySpec) { s.Peers[1].ListenPort++ },
		"peer removed":  func(s *api.ApplySpec) { s.Peers = s.Peers[:1] },
		"candidates":    func(s *api.ApplySpec) { s.Prefixes[0].Candidates = []string{"p1"} },
		"mode":          func(s *api.ApplySpec) { s.Prefixes[0].Mode = api.ModeSingle },
		"cidr":          func(s *api.ApplySpec) { s.Prefixes[0].CIDR = "10.21.0.0/24" },
		"front address": func(s *api.ApplySpec) { s.Front.Address = "10.201.0.2/24" },
		"manage routes": func(s *api.ApplySpec) { s.ManageRoutes = false },
	} {
		s := hashSpec()
		mut(&s)
		if specHash(s) == h {
			t.Errorf("%s change did not alter the hash", name)
		}
	}
}

func TestInPlaceOK(t *testing.T) {
	a, b := hashSpec(), hashSpec()
	b.Prefixes[0].Candidates = []string{"p1"}
	b.Prefixes = append(b.Prefixes, api.PrefixSpec{CIDR: "10.30.0.0/24", Candidates: []string{"p2"}})
	if !inPlaceOK(&a, &b) {
		t.Error("prefix-only change should be in place")
	}
	for name, mut := range map[string]func(*api.ApplySpec){
		"front":  func(s *api.ApplySpec) { s.Front.MTU = 1400 },
		"routes": func(s *api.ApplySpec) { s.ManageRoutes = false },
		"peers":  func(s *api.ApplySpec) { s.Peers[0].Endpoint = "1.2.3.4:5" },
	} {
		c := hashSpec()
		mut(&c)
		if inPlaceOK(&a, &c) {
			t.Errorf("%s change must rebuild", name)
		}
	}
}
