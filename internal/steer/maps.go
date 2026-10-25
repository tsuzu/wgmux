package steer

// Binary layouts of the BPF map keys/values. These must match bpf/mux.c
// exactly; the static assertions in datapath_test.go guard the sizes.

type SteeringKey struct {
	PrefixLen uint32
	Addr      uint32 // network byte order
}

type SteeringVal struct {
	PeerIDs [MaxCandidates]uint32
	Count   uint8
	Active  uint8
	Policy  uint8
	Pad     uint8
}

type FlowKeyT struct {
	SAddr uint32 // network byte order
	DAddr uint32
	SPort uint16 // network byte order
	DPort uint16
	Proto uint8
	Pad   [3]uint8
}

type RuntimeCfg struct {
	BackIfindex uint32
	FrontMAC    [6]uint8
	BackMAC     [6]uint8
}

// MapKey/MapVal convert a resolved Entry into map form.
func (e Entry) MapKey() SteeringKey {
	return SteeringKey{PrefixLen: e.PrefixLen, Addr: e.Addr}
}

func (e Entry) MapVal() SteeringVal {
	return SteeringVal{
		PeerIDs: e.PeerIDs,
		Count:   e.Count,
		Active:  e.Active,
		Policy:  e.Policy,
	}
}
