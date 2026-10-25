package datapath

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadCollection asks the real kernel verifier to check both
// programs and all maps. It needs privileges, so it only runs when
// WGMUX_TEST_LOAD=1 is set in the environment.
func TestLoadCollection(t *testing.T) {
	if os.Getenv("WGMUX_TEST_LOAD") != "1" {
		t.Skip("set WGMUX_TEST_LOAD=1 to run against the kernel")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	for _, l2 := range []bool{false, true} {
		spec, err := loadSpec(l2, nil)
		if err != nil {
			t.Fatal(err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Fatalf("l2=%v: verifier rejected collection: %v", l2, err)
		}
		for name, prog := range coll.Programs {
			if prog == nil {
				t.Errorf("l2=%v: program %s missing", l2, name)
			}
		}
		for _, name := range []string{MapSteering, MapFlowPeer, MapPeerDev, MapRuntimeCfg} {
			if coll.Maps[name] == nil {
				t.Errorf("l2=%v: map %s missing", l2, name)
			}
		}
		coll.Close()
	}
	// Per-peer instance: own_peer_id constant rewrite must also load.
	id := uint32(7)
	spec, err := loadSpec(true, &id)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("from_wg instance: %v", err)
	}
	coll.Close()
}
