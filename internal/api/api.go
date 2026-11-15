// Package api is the contract between wgmux's control plane and data
// plane. The data-plane daemon (wgmuxd) hosts any number of mux
// instances, all of ONE engine kind — the kind is a daemon-startup
// choice (wgmuxd -engine), not a per-instance parameter. Every
// request addresses one instance by name. An instance is created
// once (Create; the only creation parameter is an optional
// backend-address override) and afterwards the control plane pushes
// desired state (Apply), single selection changes (SetSelection / FlushPeer)
// and reads snapshots (State).
//
// The split is deliberate: replacing a decision maker (static config,
// failover logic, GoBGP, FRR) never requires datapath changes, and the
// datapath does not care where a SetSelection call came from.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Version is the API contract version. Control-plane tools refuse
// to drive a daemon reporting a different one (DaemonInfo).
const Version = 2

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
	APIVersion   int    `json:"api_version"` // must equal api.Version
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

// Steering modes: how many candidates carry a prefix's traffic at
// once. The datapath realizes both as a hash-slot table (see
// steer.Slots); a mode only constrains the selection's shape.
const (
	// ModeSingle: exactly one selected peer carries all new flows.
	ModeSingle = "single"
	// ModeECMP: one or more selected peers, new flows spread over
	// them by flow hash in proportion to their weights.
	ModeECMP = "ecmp"
)

// Decision policies: WHO changes a prefix's selection at runtime.
// The data plane never acts on these; they are carried only so the
// daemon can report them (observability) and policy runners can find
// the prefixes they own.
const (
	PolicyStatic   = "static"   // only operator decisions (apply / select)
	PolicyFailover = "failover" // handshake-age health monitor
	PolicyBGP      = "bgp"      // BGP best path(s)
)

// PeerWeight is one member of a selection. Weight 0 means 1.
type PeerWeight struct {
	Peer   string `json:"peer"`
	Weight uint32 `json:"weight,omitempty"`
}

// EffectiveWeight returns the weight with the 0-means-1 default.
func (w PeerWeight) EffectiveWeight() uint32 {
	if w.Weight == 0 {
		return 1
	}
	return w.Weight
}

// PrefixSpec is one steered prefix. Peers are always addressed by
// NAME in the API (names are the stable identity; datapath peer IDs
// are an implementation detail of the engines).
type PrefixSpec struct {
	CIDR       string   `json:"cidr"`
	Candidates []string `json:"candidates"` // peer names allowed to carry this prefix
	Mode       string   `json:"mode"`       // ModeSingle | ModeECMP ("" = single)
	Policy     string   `json:"policy"`     // PolicyStatic | PolicyFailover | PolicyBGP (informational)
	// Selection is the configured (initial) selection. Empty means
	// DefaultSelection. Engines always receive it resolved and
	// validated (see EffectiveSelection / ValidateSelection).
	Selection []PeerWeight `json:"selection,omitempty"`
}

// EffectiveMode returns the mode with the "" = single default.
func (p PrefixSpec) EffectiveMode() string {
	if p.Mode == "" {
		return ModeSingle
	}
	return p.Mode
}

// DefaultSelection is the selection a prefix gets when none is
// configured: single → the first candidate; ecmp → every candidate
// with weight 1.
func (p PrefixSpec) DefaultSelection() []PeerWeight {
	if len(p.Candidates) == 0 {
		return nil
	}
	if p.EffectiveMode() == ModeSingle {
		return []PeerWeight{{Peer: p.Candidates[0], Weight: 1}}
	}
	out := make([]PeerWeight, 0, len(p.Candidates))
	for _, c := range p.Candidates {
		out = append(out, PeerWeight{Peer: c, Weight: 1})
	}
	return out
}

// EffectiveSelection returns Selection, or DefaultSelection if empty.
func (p PrefixSpec) EffectiveSelection() []PeerWeight {
	if len(p.Selection) > 0 {
		return p.Selection
	}
	return p.DefaultSelection()
}

// ValidateSelection checks sel against the prefix: non-empty, no
// duplicates, every peer a candidate, and exactly one peer in
// single mode.
func (p PrefixSpec) ValidateSelection(sel []PeerWeight) error {
	if len(sel) == 0 {
		return fmt.Errorf("prefix %s: empty selection", p.CIDR)
	}
	if p.EffectiveMode() == ModeSingle && len(sel) != 1 {
		return fmt.Errorf("prefix %s: mode single takes exactly one peer, got %d", p.CIDR, len(sel))
	}
	cand := map[string]bool{}
	for _, c := range p.Candidates {
		cand[c] = true
	}
	seen := map[string]bool{}
	for _, w := range sel {
		if !cand[w.Peer] {
			return fmt.Errorf("prefix %s: peer %q is not a candidate", p.CIDR, w.Peer)
		}
		if seen[w.Peer] {
			return fmt.Errorf("prefix %s: peer %q selected twice", p.CIDR, w.Peer)
		}
		seen[w.Peer] = true
	}
	return nil
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

// PrefixState is the current selection for one prefix.
type PrefixState struct {
	CIDR       string       `json:"cidr"`
	Candidates []string     `json:"candidates"`
	Mode       string       `json:"mode"`
	Policy     string       `json:"policy"`
	Selection  []PeerWeight `json:"selection"`
	// Slots is the datapath's ground truth: how many of the
	// steer.Slots hash slots each peer currently owns.
	Slots map[string]int `json:"slots,omitempty"`
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

// SetSelectionRequest replaces one prefix's selection. This is the
// single decision point every control-plane policy (manual, failover,
// BGP) funnels through. Established flows stay pinned to the peer
// they use (graceful); use FlushPeer to move them off a peer.
type SetSelectionRequest struct {
	Mux       string       `json:"mux"`
	CIDR      string       `json:"cidr"`
	Selection []PeerWeight `json:"selection"`
}

// FlushPeerRequest invalidates every flow pin to one peer (all
// prefixes of the instance), so its established flows re-steer by
// the current selections on their next packet. Failover calls it
// for a peer it declares dead.
type FlushPeerRequest struct {
	Mux  string `json:"mux"`
	Peer string `json:"peer"`
}

// ApplyRequest wraps an ApplySpec with its target instance.
// Runtime selections (SetSelection) survive a re-apply for every
// prefix whose candidates, mode and configured Selection are
// unchanged, unless ResetSelections is set.
type ApplyRequest struct {
	Mux             string    `json:"mux"`
	Spec            ApplySpec `json:"spec"`
	ResetSelections bool      `json:"reset_selections,omitempty"`
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
	SetSelection(req SetSelectionRequest) error
	FlushPeer(req FlushPeerRequest) error
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
	case "set_selection":
		var sr SetSelectionRequest
		if err := json.Unmarshal(req.Params, &sr); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.SetSelection(sr))
	case "flush_peer":
		var fr FlushPeerRequest
		if err := json.Unmarshal(req.Params, &fr); err != nil {
			return response{Error: err.Error()}
		}
		return wrap(struct{}{}, h.FlushPeer(fr))
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

func (c *Client) Apply(ctx context.Context, req ApplyRequest) error {
	return c.call(ctx, "apply", req, nil)
}

func (c *Client) Destroy(ctx context.Context, mux string) error {
	return c.call(ctx, "destroy", MuxRequest{Mux: mux}, nil)
}

func (c *Client) SetSelection(ctx context.Context, req SetSelectionRequest) error {
	return c.call(ctx, "set_selection", req, nil)
}

func (c *Client) FlushPeer(ctx context.Context, req FlushPeerRequest) error {
	return c.call(ctx, "flush_peer", req, nil)
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
