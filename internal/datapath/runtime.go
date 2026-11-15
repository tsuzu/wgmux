package datapath

// Runtime API on the pinned maps. Each call opens the pinned map it
// needs and closes it again; the daemon serializes calls per instance,
// so read-modify-write sequences here are not racy.

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/tsuzu/wgmux/internal/steer"
)

func openPinned(pinDir, name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned %s map: %w", name, err)
	}
	return m, nil
}

// ReplaceSteering makes the pinned steering map hold exactly
// entries: puts every entry, then deletes keys not in entries. Used
// by the kernel engine's in-place re-apply (no program reload).
func ReplaceSteering(pinDir string, entries []steer.Entry) error {
	m, err := openPinned(pinDir, MapSteering)
	if err != nil {
		return err
	}
	defer m.Close()

	want := make(map[steer.SteeringKey]struct{}, len(entries))
	for _, e := range entries {
		want[e.Key()] = struct{}{}
		if err := m.Put(e.Key(), e.MapVal()); err != nil {
			return fmt.Errorf("put steering entry: %w", err)
		}
	}
	// Collect first, delete after: do not mutate the trie while iterating.
	var stale []steer.SteeringKey
	var k steer.SteeringKey
	var v steer.SteeringVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		if _, ok := want[k]; !ok {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate steering: %w", err)
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete steering entry: %w", err)
		}
	}
	return nil
}

// SetSlots overwrites one existing prefix's slot table; error if the
// key is not in the map.
func SetSlots(pinDir string, key steer.SteeringKey, slots steer.SlotTable) error {
	m, err := openPinned(pinDir, MapSteering)
	if err != nil {
		return err
	}
	defer m.Close()
	var cur steer.SteeringVal
	if err := m.Lookup(key, &cur); err != nil {
		return fmt.Errorf("steering key %+v: %w", key, err)
	}
	return m.Put(key, steer.SteeringVal{Slots: slots})
}

// BumpPeerGen increments peer_dev[peerID].Gen, invalidating every
// flow pin to that peer (FlushPeer).
func BumpPeerGen(pinDir string, peerID uint32) error {
	m, err := openPinned(pinDir, MapPeerDev)
	if err != nil {
		return err
	}
	defer m.Close()
	var pv steer.PeerVal
	if err := m.Lookup(peerID, &pv); err != nil {
		return fmt.Errorf("read peer_dev %d: %w", peerID, err)
	}
	pv.Gen++
	if err := m.Put(peerID, pv); err != nil {
		return fmt.Errorf("write peer_dev %d: %w", peerID, err)
	}
	return nil
}

// SteeringSnapshot reads all steering entries.
func SteeringSnapshot(pinDir string) (map[steer.SteeringKey]steer.SlotTable, error) {
	m, err := openPinned(pinDir, MapSteering)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	out := map[steer.SteeringKey]steer.SlotTable{}
	var k steer.SteeringKey
	var v steer.SteeringVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		out[k] = v.Slots
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate steering: %w", err)
	}
	return out, nil
}

// SetSpecHash writes runtime_cfg[0].SpecHash (0 = apply in progress).
func SetSpecHash(pinDir string, h uint64) error {
	m, err := openPinned(pinDir, MapRuntimeCfg)
	if err != nil {
		return err
	}
	defer m.Close()
	var rc steer.RuntimeCfg
	if err := m.Lookup(uint32(0), &rc); err != nil {
		return fmt.Errorf("read runtime_cfg: %w", err)
	}
	rc.SpecHash = h
	if err := m.Put(uint32(0), rc); err != nil {
		return fmt.Errorf("write runtime_cfg: %w", err)
	}
	return nil
}

// SpecHash reads runtime_cfg[0].SpecHash.
func SpecHash(pinDir string) (uint64, error) {
	m, err := openPinned(pinDir, MapRuntimeCfg)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	var rc steer.RuntimeCfg
	if err := m.Lookup(uint32(0), &rc); err != nil {
		return 0, fmt.Errorf("read runtime_cfg: %w", err)
	}
	return rc.SpecHash, nil
}
