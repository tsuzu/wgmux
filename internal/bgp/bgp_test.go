package bgp

import (
	"testing"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/tsuzu/wgmux/internal/config"
)

func testCfg() *config.Mux {
	return &config.Mux{
		BGP: config.BGP{Neighbors: []config.BGPNeighbor{
			{Address: "10.200.0.11", WgPeer: "site-a"},
			{Address: "10.200.0.12", WgPeer: "site-b"},
		}},
	}
}

func TestParseFRRBestPathsArrayShape(t *testing.T) {
	raw := []byte(`{"routes": {
		"10.20.0.10/32": [
			{"peerId": "10.200.0.12", "bestpath": {"overall": false}},
			{"peerId": "10.200.0.11", "bestpath": {"overall": true}}
		],
		"192.168.10.0/24": [
			{"peerId": "10.200.0.12", "bestpath": true}
		],
		"198.51.100.0/24": [
			{"peerId": "10.200.0.99", "bestpath": {"overall": true}}
		]
	}}`)
	got, err := ParseFRRBestPaths(testCfg(), raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"10.20.0.10/32":   "site-a",
		"192.168.10.0/24": "site-b",
	}
	if len(got) != len(want) {
		t.Fatalf("decisions = %v, want %v", got, want)
	}
	for _, d := range got {
		if want[d.Prefix] != d.WgPeer {
			t.Errorf("prefix %s -> %s, want %s", d.Prefix, d.WgPeer, want[d.Prefix])
		}
	}
}

func TestParseFRRBestPathsObjectShape(t *testing.T) {
	raw := []byte(`{"routes": {
		"10.20.0.10/32": {"paths": [{"peerId": "10.200.0.12", "bestPath": true}]}
	}}`)
	got, err := ParseFRRBestPaths(testCfg(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].WgPeer != "site-b" {
		t.Fatalf("decisions = %v", got)
	}
}

func mustPath(t *testing.T, prefix string, plen uint32, source string, withdraw bool) *gobgpapi.Path {
	t.Helper()
	nlri, err := anypb.New(&gobgpapi.IPAddressPrefix{Prefix: prefix, PrefixLen: plen})
	if err != nil {
		t.Fatal(err)
	}
	return &gobgpapi.Path{Nlri: nlri, SourceId: source, IsWithdraw: withdraw}
}

func TestDecisionsFromWatch(t *testing.T) {
	r := &gobgpapi.WatchEventResponse{
		Event: &gobgpapi.WatchEventResponse_Table{
			Table: &gobgpapi.WatchEventResponse_TableEvent{
				Paths: []*gobgpapi.Path{
					mustPath(t, "10.20.0.10", 32, "10.200.0.12", false),
					mustPath(t, "10.20.0.20", 32, "10.200.0.99", false), // unmapped neighbor
					mustPath(t, "10.20.0.30", 32, "10.200.0.11", true),  // withdrawal
				},
			},
		},
	}
	got := decisionsFromWatch(testCfg(), r)
	if len(got) != 1 || got[0].Prefix != "10.20.0.10/32" || got[0].WgPeer != "site-b" {
		t.Fatalf("decisions = %v", got)
	}
}
