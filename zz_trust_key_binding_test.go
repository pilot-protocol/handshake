// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	bindKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	bindKeyB = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
)

func seedTrusted(hm *Manager, nodeID uint32, key string) {
	hm.mu.Lock()
	hm.trusted[nodeID] = &TrustRecord{
		NodeID:     nodeID,
		PublicKey:  key,
		ApprovedAt: time.Now().Add(-time.Hour),
	}
	hm.mu.Unlock()
}

func trustRecordOf(hm *Manager, nodeID uint32) *TrustRecord {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.trusted[nodeID]
}

// Trust granted against key A stays valid for key A.
func TestIsTrustedWithKeySameKeyStaysTrusted(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)

	if !hm.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("peer presenting the bound key should stay trusted")
	}
	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("record mutated on a matching check: %+v", rec)
	}
}

// The same node ID presenting a different key is not trusted, and the
// stale record is dropped rather than left to match again later.
func TestIsTrustedWithKeyDifferentKeyNotTrusted(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)

	if hm.IsTrustedWithKey(42, bindKeyB) {
		t.Fatal("peer presenting a different key must not be trusted")
	}
	if rec := trustRecordOf(hm, 42); rec != nil {
		t.Fatal("stale trust record should have been dropped")
	}
	// And it stays dropped for the original key holder too.
	if hm.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("dropped record should not resurrect for the original key")
	}
}

// Legacy records — persisted before keys were bound — keep working, so
// an upgrade does not untrust anyone.
func TestIsTrustedWithKeyLegacyUnboundRecordStaysTrusted(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, "")

	if !hm.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("legacy unbound record must remain trusted")
	}
	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("legacy record should have adopted the presented key: %+v", rec)
	}
	// Having adopted key A, it now rejects a different key.
	if hm.IsTrustedWithKey(42, bindKeyB) {
		t.Fatal("record should be bound after adoption")
	}
}

// A call site with no key in scope degrades to the node-ID-only answer
// rather than denying.
func TestIsTrustedWithKeyEmptyKeyFallsBackToNodeID(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)

	if !hm.IsTrustedWithKey(42, "") {
		t.Fatal("empty presented key should fall back to node-ID-only trust")
	}
	if hm.IsTrustedWithKey(43, "") {
		t.Fatal("untrusted node must stay untrusted regardless of key")
	}
	if rec := trustRecordOf(hm, 42); rec.PublicKey != bindKeyA {
		t.Fatalf("binding must not be cleared by a keyless check, got %q", rec.PublicKey)
	}
}

// IsTrusted keeps its node-ID-only contract for callers with no key.
func TestIsTrustedUnchangedForNodeIDOnlyCallers(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)

	if !hm.IsTrusted(42) {
		t.Fatal("IsTrusted should still answer on node ID alone")
	}
	if hm.IsTrusted(43) {
		t.Fatal("IsTrusted should be false for an unknown node")
	}
}

// A node ID reaped from the registry and re-claimed by a different
// identity does not inherit the previous holder's trust: backfill sees
// the registry key diverge from the bound key and drops the record.
func TestBackfillPeerKeyReclaimedNodeIDLosesTrust(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyB})

	seedTrusted(hm, 42, bindKeyA)
	hm.backfillPeerKey(42)

	if rec := trustRecordOf(hm, 42); rec != nil {
		t.Fatalf("trust must not survive the node ID being re-claimed by another key: %+v", rec)
	}
}

// The same path binds a relay-established record once the registry
// answers, and leaves a matching one alone.
func TestBackfillPeerKeyBindsThenValidates(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyA})

	seedTrusted(hm, 42, "")
	hm.backfillPeerKey(42)

	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("relay record should have been bound to the registry key: %+v", rec)
	}

	hm.backfillPeerKey(42)
	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("a matching backfill must be a no-op: %+v", rec)
	}
}

// An accept carrying a different key than the record we hold does not
// silently rebind it.
func TestHandleAcceptDifferentKeyDropsRecord(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)
	hm.mu.Lock()
	hm.outgoing[42] = time.Now()
	hm.mu.Unlock()

	hm.handleAccept(&HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    42,
		PublicKey: bindKeyB,
		Timestamp: time.Now().Unix(),
	})

	if rec := trustRecordOf(hm, 42); rec != nil {
		t.Fatalf("accept from a different key holder must not keep or rebind the record: %+v", rec)
	}
}

// An accept that omits the key leaves an existing binding intact rather
// than clearing it.
func TestHandleAcceptWithoutKeyPreservesBinding(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	seedTrusted(hm, 42, bindKeyA)

	hm.handleAccept(&HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    42,
		Timestamp: time.Now().Unix(),
	})

	rec := trustRecordOf(hm, 42)
	if rec == nil {
		t.Fatal("keyless accept should not drop the record")
	}
	if rec.PublicKey != bindKeyA {
		t.Fatalf("binding cleared by a keyless accept, got %q", rec.PublicKey)
	}
}

// Snapshots written before public keys were recorded load as unbound
// records, and unbound records still count as trusted.
func TestLoadTrustSnapshotWithoutPublicKeyStaysTrusted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	legacy := `{"trusted":[{"node_id":42,"approved_at":"` +
		time.Now().Add(-time.Hour).Format(time.RFC3339) + `","mutual":true}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy snapshot: %v", err)
	}

	// NewManager derives storePath from the identity path's directory
	// and loads the snapshot during construction.
	hm := newTestHM(t, path)
	t.Cleanup(hm.Stop)

	rec := trustRecordOf(hm, 42)
	if rec == nil {
		t.Fatal("legacy snapshot entry did not load")
	}
	if rec.PublicKey != "" {
		t.Fatalf("expected an unbound record, got key %q", rec.PublicKey)
	}
	// Checked with no key in scope, so nothing is adopted and no
	// background save is triggered into the temp dir.
	if !hm.IsTrusted(42) || !hm.IsTrustedWithKey(42, "") {
		t.Fatal("legacy snapshot entry must remain trusted after upgrade")
	}
}

// A bound key survives a save/load round trip, so the binding is not
// re-learned from scratch on every restart.
func TestSaveLoadTrustPreservesBoundKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	hm := newTestHM(t, path)
	t.Cleanup(hm.Stop)
	seedTrusted(hm, 42, bindKeyA)
	hm.saveTrust() // synchronous; no drain goroutine involved

	hm2 := newTestHM(t, path)
	t.Cleanup(hm2.Stop)

	rec := trustRecordOf(hm2, 42)
	if rec == nil {
		t.Fatal("record missing after round trip")
	}
	if rec.PublicKey != bindKeyA {
		t.Fatalf("bound key not persisted: got %q, want %q", rec.PublicKey, bindKeyA)
	}
	if !hm2.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("reloaded record should still accept the bound key")
	}
}
