package steer

// Binary layouts of the BPF map keys/values. These must match bpf/mux.c
// exactly (see bpf/NOTES.md, "Map contract"); the size assertions in
// maps_test.go guard them.

// SteeringKey is the LPM key of the steering map.
type SteeringKey struct {
	PrefixLen uint32
	Addr      uint32 // wire representation, see WireAddr
}

// SteeringVal is the steering map value: the prefix's slot table.
type SteeringVal struct {
	Slots SlotTable
}

// PeerVal is the peer_dev map value. Gen is the peer's pin
// generation: a flow pin is valid only while its Gen equals this.
type PeerVal struct {
	Ifindex uint32
	Gen     uint32
}

// FlowKeyT is the flow_peer map key.
type FlowKeyT struct {
	SAddr uint32 // wire representation, see WireAddr
	DAddr uint32
	SPort uint16 // wire representation
	DPort uint16
	Proto uint8
	Pad   [3]uint8
}

// FlowVal is the flow_peer map value.
type FlowVal struct {
	PeerID uint32
	Gen    uint32
}

// RuntimeCfg is runtime_cfg[0]. SpecHash is the kernel engine's
// completed-apply marker (0 = an apply is in progress / never
// completed); Adopt compares it with the stored spec's hash.
type RuntimeCfg struct {
	BackIfindex uint32
	FrontMAC    [6]uint8
	BackMAC     [6]uint8
	SpecHash    uint64
}

// MapVal converts an Entry into map form.
func (e Entry) MapVal() SteeringVal { return SteeringVal{Slots: e.Slots} }
