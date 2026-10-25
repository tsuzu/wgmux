package bgp

import (
	"context"
	"fmt"
	"net"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/tsuzu/wgmux/internal/config"
)

// GoBGPSource embeds a GoBGP server in the control-plane process and
// translates its best-path table events into Decisions.
type GoBGPSource struct {
	cfg    *config.Config
	server *server.BgpServer
}

// Server exposes the embedded GoBGP server (for origination helpers
// and tests); valid after Run has started it.
func (s *GoBGPSource) Server() *server.BgpServer { return s.server }

func (s *GoBGPSource) Run(ctx context.Context, out chan<- Decision) error {
	s.server = server.NewBgpServer()
	go s.server.Serve()
	port := s.cfg.BGP.ListenPort
	if port == 0 {
		port = 179
	}
	if err := s.server.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{
			Asn:        s.cfg.BGP.LocalAS,
			RouterId:   s.cfg.BGP.RouterID,
			ListenPort: port,
		},
	}); err != nil {
		return fmt.Errorf("gobgp start: %w", err)
	}
	defer s.server.StopBgp(ctx, &gobgpapi.StopBgpRequest{})
	for _, n := range s.cfg.BGP.Neighbors {
		err := s.server.AddPeer(ctx, &gobgpapi.AddPeerRequest{
			Peer: &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: n.Address,
					PeerAsn:         n.RemoteAS,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("gobgp add neighbor %s: %w", n.Address, err)
		}
	}
	return s.server.WatchEvent(ctx, &gobgpapi.WatchEventRequest{
		Table: &gobgpapi.WatchEventRequest_Table{
			Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
				{Type: gobgpapi.WatchEventRequest_Table_Filter_BEST, Init: true},
			},
		},
	}, func(r *gobgpapi.WatchEventResponse) {
		for _, d := range decisionsFromWatch(s.cfg, r) {
			select {
			case out <- d:
			case <-ctx.Done():
			}
		}
	})
}

// decisionsFromWatch extracts (prefix, peer) pairs from a best-path
// watch response: the table event carries best paths directly, each
// with its NLRI and the neighbor it came from (SourceId). Pure, so it
// can be unit-tested with fabricated responses.
func decisionsFromWatch(cfg *config.Config, r *gobgpapi.WatchEventResponse) []Decision {
	table := r.GetTable()
	if table == nil {
		return nil
	}
	var out []Decision
	for _, path := range table.Paths {
		if path == nil || path.IsWithdraw {
			continue
		}
		peer, ok := NeighborPeer(cfg, path.GetSourceId())
		if !ok {
			continue
		}
		// Decode the NLRI directly instead of via apiutil: the native
		// conversion insists on path.Family being set, which watch
		// events do not guarantee on every path.
		var ipp gobgpapi.IPAddressPrefix
		if path.Nlri == nil || path.Nlri.UnmarshalTo(&ipp) != nil {
			continue
		}
		prefix := fmt.Sprintf("%s/%d", ipp.Prefix, ipp.PrefixLen)
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			continue
		}
		out = append(out, Decision{Prefix: prefix, WgPeer: peer})
	}
	return out
}

// Announce originates a prefix toward all configured neighbors with
// the local router as next hop. Callers are expected to announce a
// muxed prefix only while the corresponding selection is active in
// the datapath (anycast-style failover), and Withdraw otherwise.
func (s *GoBGPSource) Announce(ctx context.Context, cidr string) error {
	return s.setPath(ctx, cidr, false)
}

// Withdraw removes a prefix previously added with Announce.
func (s *GoBGPSource) Withdraw(ctx context.Context, cidr string) error {
	return s.setPath(ctx, cidr, true)
}

func (s *GoBGPSource) setPath(ctx context.Context, cidr string, withdraw bool) error {
	if s.server == nil {
		return fmt.Errorf("gobgp server not started")
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipnet.Mask.Size()
	nlri := bgp.NewIPAddrPrefix(uint8(ones), ipnet.IP.String())
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), // IGP
		bgp.NewPathAttributeNextHop("0.0.0.0"),
	}
	path, err := apiutil.NewPath(nlri, withdraw, attrs, time.Now())
	if err != nil {
		return err
	}
	if withdraw {
		return s.server.DeletePath(ctx, &gobgpapi.DeletePathRequest{Path: path})
	}
	_, err = s.server.AddPath(ctx, &gobgpapi.AddPathRequest{Path: path})
	return err
}
