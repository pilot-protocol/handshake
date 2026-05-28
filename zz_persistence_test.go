// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveTrust_NoPathIsNoop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "") // empty storePath
	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now()}
	hm.mu.Unlock()
	hm.saveTrust() // must not panic
}

func TestSaveTrust_WritesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	hm := newTestHM(t, path)

	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now(), Mutual: true}
	hm.pending[2] = &PendingHandshake{NodeID: 2, ReceivedAt: time.Now()}
	hm.mu.Unlock()

	hm.saveTrust()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(body) == 0 {
		t.Error("trust file empty")
	}
}

func TestSaveTrust_MkdirError(t *testing.T) {
	t.Parallel()
	// Path under /dev/null can't have its parent dir created.
	hm := newTestHM(t, "/dev/null/cannot/trust.json")
	hm.saveTrust() // must not panic; logs error and returns
}

func TestLoadTrust_NoPathIsNoop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.loadTrust() // must not panic
	if len(hm.trusted) != 0 {
		t.Errorf("trusted len = %d, want 0", len(hm.trusted))
	}
}

func TestLoadTrust_MissingFileIsNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hm := newTestHM(t, filepath.Join(dir, "no-such.json"))
	hm.loadTrust()
	if len(hm.trusted) != 0 {
		t.Errorf("trusted len = %d, want 0", len(hm.trusted))
	}
}

func TestSaveLoadTrust_Roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	hm := newTestHM(t, path)

	approvedAt := time.Now()
	hm.mu.Lock()
	hm.trusted[42] = &TrustRecord{
		NodeID:     42,
		PublicKey:  "pk",
		ApprovedAt: approvedAt,
		Mutual:     true,
		Network:    7,
	}
	hm.mu.Unlock()
	hm.saveTrust()

	// Fresh manager loads the same file.
	hm2 := newTestHM(t, path)
	hm2.loadTrust()
	hm2.mu.RLock()
	defer hm2.mu.RUnlock()
	rec, ok := hm2.trusted[42]
	if !ok {
		t.Fatal("trust record missing after roundtrip")
	}
	if rec.PublicKey != "pk" || rec.Network != 7 || !rec.Mutual {
		t.Errorf("loaded = %+v", rec)
	}
}
