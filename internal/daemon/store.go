package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tsuzu/wgmux/internal/api"
)

// Record is one instance's persisted state: its creation
// parameters and last applied spec. The store is the record of
// what SHOULD exist; kernel objects are the record of what does.
type Record struct {
	Name           string         `json:"name"`
	Engine         string         `json:"engine"` // kind of the daemon that wrote it
	BackendAddress string         `json:"backend_address,omitempty"`
	Spec           *api.ApplySpec `json:"spec,omitempty"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Store persists Records as one JSON file per instance under
// <state dir>/instances/, written atomically (tmp + fsync +
// rename) so a crash mid-write never leaves a torn record.
type Store struct {
	dir string
}

func NewStore(stateDir string) *Store {
	return &Store{dir: filepath.Join(stateDir, "instances")}
}

// Names lists the stored instance names.
func (s *Store) Names() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name()[:len(e.Name())-len(".json")])
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name+".json")
}

// Load reads one instance's record.
func (s *Store) Load(name string) (Record, error) {
	var rec Record
	raw, err := os.ReadFile(s.path(name))
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("parse stored instance %q: %w", name, err)
	}
	return rec, nil
}

// Put atomically writes one instance's record.
func (s *Store) Put(rec Record) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path(rec.Name))
}

// Delete removes one instance's record (destroy). Missing is fine.
func (s *Store) Delete(name string) error {
	err := os.Remove(s.path(name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
