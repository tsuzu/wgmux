// Package api is the contract between wgmux's control plane and data
// plane. The data-plane daemon (wgmuxd) hosts any number of mux
// instances, all of ONE engine kind — the kind is a daemon-startup
// choice (wgmuxd -engine), not a per-instance parameter. Every
// request addresses one instance by name. An instance is created
// once (Create; the only creation parameter is an optional
// backend-address override) and afterwards the control plane pushes
// desired state (Apply), single selection changes (SetActive) and
// reads snapshots (State).
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

// Engine kinds an instance can be created with.
const (
	EngineKernel    = "kernel"
	EngineUserspace = "userspace"
)

// CreateParams are the instance-construction parameters, fixed for
// the instance's lifetime. Deliberately minimal: the engine kind is
// the daemon's (a startup flag), and everything kernel-shaped
// (backend namespace, interconnect, attach mode, pin dir) is either
// a daemon-startup setting or derived from the instance name.
type CreateParams struct {
	Mux string `json:"mux"`
	// BackendAddress optionally overrides the kernel engine's
	// interconnect backend-end address (CIDR). Empty means: derive
	// once from the first applied front address, then keep it for
	// the instance's lifetime. Ignored by the userspace engine.
	BackendAddress string `json:"backend_address,omitempty"`
}

// Instance lifecycle states reported by List and State.
const (
	// StatusActive: created/applied by this daemon process.
	StatusActive = "active"
	// StatusAdopted: at startup, the kernel objects were still
	// there and were adopted without touching the datapath.
	StatusAdopted = "adopted"
	// StatusRestored: rebuilt from the spec store at startup.
	StatusRestored = "restored"
	// StatusStored: present in the spec store but not activated
	// (restore disabled, or nothing applied yet).
	StatusStored = "stored"
	// StatusFailed: restore tried and failed; Error says why.
	StatusFailed = "failed"
	// StatusOrphaned: the store entry belongs to a daemon of the
	// other engine kind; this daemon leaves it untouched.
	StatusOrphaned = "orphaned"
)

// InstanceInfo describes one mux instance known to the daemon.
type InstanceInfo struct {
	Mux            string    `json:"mux"`
	Engine         string    `json:"engine"` // the daemon's engine kind
	Status         string    `json:"status"`
	Error          string    `json:"error,omitempty"`
	BackendAddress string    `json:"backend_address,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// DaemonInfo describes the daemon itself: the startup configuration
// every instance shares. Control-plane tools use it to reject
// applies that assume a different engine kind or kernel datapath
// shape than the daemon was started with.
type DaemonInfo struct {
	Engine       string `json:"engine"`
	Interconnect string `json:"interconnect,omitempty"` // kernel daemons
	Attach       string `json:"attach,omitempty"`       // kernel daemons
	PinRoot      string `json:"pin_root,omitempty"`
	StateDir     string `json:"state_dir,omitempty"`
	Restore      bool   `json:"restore"`
}

// PeerSpec is one multiplexed peer as the control plane wants it.
// PrivateKey travels over the (root-only, filesystem-permissioned)
// unix socket only.
type PeerSpec struct {
	Name                string   `json:"name"`
	ID                  uint32   `json:"id"`
	PrivateKey          string   `json:"private_key"`             // base64
	PublicKey           string   `json:"public_key"`              // base64
	PresharedKey        string   `json:"preshared_key,omitempty"` // base64, optional
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

// FrontSpec is the one interface visible in the main namespace.
// Its name is the mux instance's name (like wg-quick, where the
// config name is the interface name); engines fall back to the
// instance name when Name is empty.
type FrontSpec struct {
	Name    string `json:"name"`
	Address string `json:"address"` // CIDR
	MTU     int    `json:"mtu"`
}

// ApplySpec is the full desired state of one mux instance. It
// carries only engine-neutral state: which engine an instance runs
// is the daemon's startup choice, not desired state.
type ApplySpec struct {
	Front        FrontSpec    `json:"front"`
	ManageRoutes bool         `json:"manage_routes"`
	Peers        []PeerSpec   `json:"peers"`
	Prefixes     []PrefixSpec `json:"prefixes"`
}

// PeerState is the engine's view of one peer.
type PeerState struct {
	Name          string    `json:"name"`
	ID            uint32    `json:"id"`
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

// State is the full snapshot of one mux instance. Counters are the
// engine's datapath observability counters by name (e.g.
// front_entries, front_redirects, wg_entries, wg_redirects): the
// kernel engine fills them from its BPF debug map, the userspace
// engine from its packet pump, using the same names where they
// correspond.
type State struct {
	Mux      string            `json:"mux"`
	Engine   string            `json:"engine"` // the daemon's kind, reported by the engine side
	Status   string            `json:"status"`
	Error    string            `json:"error,omitempty"`
	Peers    []PeerState       `json:"peers"`
	Prefixes []PrefixState     `json:"prefixes"`
	Counters map[string]uint64 `json:"counters,omitempty"`
}

// SetActiveRequest retargets one prefix of one mux to a different
// candidate peer. This is the single decision point every
// control-plane policy (manual, failover, BGP) funnels through.
type SetActiveRequest struct {
	Mux    string `json:"mux"`
	CIDR   string `json:"cidr"`
	PeerID uint32 `json:"peer_id"`
}

// ApplyRequest wraps an ApplySpec with its target instance.
type ApplyRequest struct {
	Mux  string    `json:"mux"`
	Spec ApplySpec `json:"spec"`
}

// MuxRequest addresses one instance (destroy/state).
type MuxRequest struct {
	Mux string `json:"mux"`
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
	Create(params CreateParams) error
	Apply(req ApplyRequest) error
	Destroy(req MuxRequest) error
	SetActive(req SetActiveRequest) error
	State(req MuxRequest) (State, error)
	List() ([]InstanceInfo, error)
	Info() (DaemonInfo, error)
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
	case "create":
		var p CreateParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.Create(p))
	case "apply":
		var ar ApplyRequest
		if err := json.Unmarshal(req.Params, &ar); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.Apply(ar))
	case "destroy":
		var mr MuxRequest
		if err := json.Unmarshal(req.Params, &mr); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.Destroy(mr))
	case "set_active":
		var sa SetActiveRequest
		if err := json.Unmarshal(req.Params, &sa); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.SetActive(sa))
	case "state":
		var mr MuxRequest
		if err := json.Unmarshal(req.Params, &mr); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(h.State(mr))
	case "list":
		return wrap(h.List())
	case "info":
		return wrap(h.Info())
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

func (c *Client) Create(ctx context.Context, params CreateParams) error {
	return c.call(ctx, "create", params, nil)
}

func (c *Client) Apply(ctx context.Context, mux string, spec ApplySpec) error {
	return c.call(ctx, "apply", ApplyRequest{Mux: mux, Spec: spec}, nil)
}

func (c *Client) Destroy(ctx context.Context, mux string) error {
	return c.call(ctx, "destroy", MuxRequest{Mux: mux}, nil)
}

func (c *Client) SetActive(ctx context.Context, req SetActiveRequest) error {
	return c.call(ctx, "set_active", req, nil)
}

func (c *Client) State(ctx context.Context, mux string) (State, error) {
	var st State
	err := c.call(ctx, "state", MuxRequest{Mux: mux}, &st)
	return st, err
}

func (c *Client) List(ctx context.Context) ([]InstanceInfo, error) {
	var out []InstanceInfo
	err := c.call(ctx, "list", struct{}{}, &out)
	return out, err
}

func (c *Client) Info(ctx context.Context) (DaemonInfo, error) {
	var out DaemonInfo
	err := c.call(ctx, "info", struct{}{}, &out)
	return out, err
}
