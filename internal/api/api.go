// Package api is the contract between wgmux's control plane and data
// plane. The data-plane daemon (wgmuxd) owns everything that touches
// the kernel: network namespaces, WireGuard engines (kernel or
// wireguard-go), the eBPF steering programs and their maps. Control
// plane processes (wgmuxctl, the failover monitor, BGP sources) never
// touch netlink or BPF directly; they send the requests defined here
// over a unix socket (JSON, one request per line).
//
// The split is deliberate: replacing a decision maker (static config,
// failover logic, GoBGP, FRR) never requires datapath changes, and the
// datapath does not care where a SetActive call came from.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// PeerSpec is one multiplexed peer as the control plane wants it.
// PrivateKey travels over the (root-only, filesystem-permissioned)
// unix socket only.
type PeerSpec struct {
	Name                string   `json:"name"`
	ID                  uint32   `json:"id"`
	PrivateKey          string   `json:"private_key"` // base64
	PublicKey           string   `json:"public_key"`  // base64
	ListenPort          int      `json:"listen_port"`
	Endpoint            string   `json:"endpoint,omitempty"`   // resolved IP:port
	PersistentKeepalive int      `json:"persistent_keepalive"` // seconds
	AllowedIPs          []string `json:"allowed_ips"`          // CIDRs, duplicates across peers expected
}

// PrefixSpec is one steered prefix with resolved candidate peer IDs.
type PrefixSpec struct {
	CIDR         string   `json:"cidr"`
	CandidateIDs []uint32 `json:"candidate_ids"`
	ActiveID     uint32   `json:"active_id"`
	Policy       string   `json:"policy"` // active | hash (datapath form; failover/bgp arrive as active + SetActive)
}

// ApplySpec is the full desired datapath state.
type ApplySpec struct {
	Engine       string `json:"engine"` // kernel | userspace
	BackendNS    string `json:"backend_ns"`
	Interconnect string `json:"interconnect"` // veth | netkit
	Attach       string `json:"attach"`       // tcx | tc
	PinDir       string `json:"pin_dir"`
	ManageRoutes bool   `json:"manage_routes"`

	FrontName      string `json:"front_name"`
	FrontAddress   string `json:"front_address"`
	BackendAddress string `json:"backend_address"`
	MTU            int    `json:"mtu"`

	Peers    []PeerSpec   `json:"peers"`
	Prefixes []PrefixSpec `json:"prefixes"`
}

// PeerState is the datapath's view of one peer.
type PeerState struct {
	Name          string    `json:"name"`
	ID            uint32    `json:"id"`
	Device        string    `json:"device"`
	Ifindex       int       `json:"ifindex"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	BytesReceived uint64    `json:"bytes_received"`
	BytesSent     uint64    `json:"bytes_sent"`
}

// PrefixState is the datapath's current selection for one prefix.
type PrefixState struct {
	CIDR         string   `json:"cidr"`
	CandidateIDs []uint32 `json:"candidate_ids"`
	ActiveID     uint32   `json:"active_id"`
	Policy       string   `json:"policy"`
}

// State is the full datapath snapshot returned by the state method.
type State struct {
	Engine   string        `json:"engine"`
	Peers    []PeerState   `json:"peers"`
	Prefixes []PrefixState `json:"prefixes"`
}

// SetActiveRequest retargets one prefix to a different candidate peer.
// This is the single decision point every control-plane policy
// (manual, failover, BGP) funnels through.
type SetActiveRequest struct {
	CIDR   string `json:"cidr"`
	PeerID uint32 `json:"peer_id"`
}

type request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler is implemented by the data-plane daemon.
type Handler interface {
	Apply(spec ApplySpec) error
	Destroy() error
	SetActive(req SetActiveRequest) error
	State() (State, error)
}

// Serve accepts connections on l and dispatches to h until l is closed.
func Serve(l net.Listener, h Handler) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go serveConn(conn, h)
	}
}

func serveConn(conn net.Conn, h Handler) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			enc.Encode(response{Error: "bad request: " + err.Error()})
			continue
		}
		resp := dispatch(h, req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func dispatch(h Handler, req request) response {
	wrap := func(v interface{}, err error) response {
		if err != nil {
			return response{Error: err.Error()}
		}
		raw, merr := json.Marshal(v)
		if merr != nil {
			return response{Error: merr.Error()}
		}
		return response{Result: raw}
	}
	switch req.Method {
	case "apply":
		var spec ApplySpec
		if err := json.Unmarshal(req.Params, &spec); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.Apply(spec))
	case "destroy":
		return wrap(struct{}{}, h.Destroy())
	case "set_active":
		var sa SetActiveRequest
		if err := json.Unmarshal(req.Params, &sa); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.SetActive(sa))
	case "state":
		return wrap(h.State())
	default:
		return response{Error: fmt.Sprintf("unknown method %q", req.Method)}
	}
}

// Client is the control plane's handle to the data plane.
type Client struct {
	SocketPath string
}

func (c *Client) call(ctx context.Context, method string, params, out interface{}) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("dial wgmuxd at %s (is it running?): %w", c.SocketPath, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(mustJSON(request{Method: method, Params: raw}), '\n')); err != nil {
		return err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("wgmuxd: %s", resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

func mustJSON(v interface{}) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func (c *Client) Apply(ctx context.Context, spec ApplySpec) error {
	return c.call(ctx, "apply", spec, nil)
}

func (c *Client) Destroy(ctx context.Context) error {
	return c.call(ctx, "destroy", struct{}{}, nil)
}

func (c *Client) SetActive(ctx context.Context, req SetActiveRequest) error {
	return c.call(ctx, "set_active", req, nil)
}

func (c *Client) State(ctx context.Context) (State, error) {
	var st State
	err := c.call(ctx, "state", struct{}{}, &st)
	return st, err
}
