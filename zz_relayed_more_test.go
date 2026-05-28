// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"
)

// TestProcessRelayedRequest_AlreadyTrustedIsAccept exercises the
// already-trusted fast path.
func TestProcessRelayedRequest_AlreadyTrustedIsAccept(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	// Seed: peer 42 is already trusted.
	hm.mu.Lock()
	hm.trusted[42] = &TrustRecord{NodeID: 42, ApprovedAt: time.Now()}
	hm.mu.Unlock()

	// No registry → the "respond" branch quietly bails.
	hm.ProcessRelayedRequest(42, "any justification")
	// Just verify no panic + trust map unchanged.
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[42]; !ok {
		t.Error("trust record should remain")
	}
}

// TestProcessRelayedRequest_MutualHandshakeAutoApproves drives the
// outgoing → mutual path.
func TestProcessRelayedRequest_MutualHandshakeAutoApproves(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	// Seed an outgoing request to peer 99.
	hm.mu.Lock()
	hm.outgoing[99] = time.Now()
	hm.mu.Unlock()

	hm.ProcessRelayedRequest(99, "mutual please")

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[99]; !ok {
		t.Error("peer 99 should be trusted after mutual handshake")
	}
	if _, ok := hm.outgoing[99]; ok {
		t.Error("outgoing entry should be cleared")
	}
}

// TestProcessRelayedRequest_NewRequestPending stages a pending request.
func TestProcessRelayedRequest_NewRequestPending(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.ProcessRelayedRequest(0x1234, "test justification")
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.pending[0x1234]; !ok {
		t.Error("expected pending entry for 0x1234")
	}
	if _, ok := hm.trusted[0x1234]; ok {
		t.Error("should not auto-trust without mutual/network")
	}
}

// TestProcessRelayedApproval_KnownOutgoingTrusts drives the
// outgoing → trusted approval path.
func TestProcessRelayedApproval_KnownOutgoingTrusts(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.outgoing[55] = time.Now()
	hm.mu.Unlock()

	hm.ProcessRelayedApproval(55)
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[55]; !ok {
		t.Error("peer 55 should be trusted after approval")
	}
}

// TestProcessRelayedApproval_UnknownPeerNoPanic — auto-approve may
// create a trust record without an outgoing entry; the test only
// verifies no panic.
func TestProcessRelayedApproval_UnknownPeerNoPanic(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.ProcessRelayedApproval(0x9999) // no panic = pass
}

// TestProcessRelayedRejection_RemovesOutgoing covers the rejection path.
func TestProcessRelayedRejection_RemovesOutgoing(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.outgoing[77] = time.Now()
	hm.mu.Unlock()

	hm.ProcessRelayedRejection(77)
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.outgoing[77]; ok {
		t.Error("outgoing entry should be removed on rejection")
	}
}

// TestProcessRelayedRejection_UnknownPeerIsNoop covers the no-op branch.
func TestProcessRelayedRejection_UnknownPeerIsNoop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.ProcessRelayedRejection(0x9999) // no panic
}

// TestRejectHandshake_RemovesPending drives the local-reject path.
func TestRejectHandshake_RemovesPending(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.pending[0xABCD] = &PendingHandshake{NodeID: 0xABCD}
	hm.mu.Unlock()

	// Without registry, sendMessage will fail — that returns the
	// pending-not-removed error path. So we set up testRuntime without
	// a registry. Just verify the local rejection completes.
	_ = hm.RejectHandshake(0xABCD, "no thanks")
	// The pending entry should be cleared regardless of registry success.
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.pending[0xABCD]; ok {
		t.Error("pending entry should be cleared after RejectHandshake")
	}
}

// TestRejectHandshake_UnknownPeerSafeNoop verifies the unknown-peer
// path doesn't panic (implementation tolerates the missing entry).
func TestRejectHandshake_UnknownPeerSafeNoop(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	_ = hm.RejectHandshake(0x9999, "n/a") // no panic = pass
}

// TestRevokeTrust_RemovesTrustedPeer drives the trust-removal path.
func TestRevokeTrust_RemovesTrustedPeer(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	hm.trusted[0x1111] = &TrustRecord{NodeID: 0x1111}
	hm.mu.Unlock()

	if err := hm.RevokeTrust(0x1111); err != nil {
		t.Errorf("RevokeTrust: %v", err)
	}
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[0x1111]; ok {
		t.Error("trust entry should be removed")
	}
}

// TestRevokeTrust_UnknownPeerErrors covers the not-found branch.
func TestRevokeTrust_UnknownPeerErrors(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if err := hm.RevokeTrust(0x9999); err == nil {
		t.Error("expected error for unknown peer")
	}
}

// TestReapOutgoingAndRevoked_PrunesExpired drives the cleanup loop.
func TestReapOutgoingAndRevoked_PrunesExpired(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	hm.mu.Lock()
	// Old outgoing — should be reaped.
	hm.outgoing[10] = time.Now().Add(-2 * time.Hour)
	// Fresh outgoing — should remain.
	hm.outgoing[20] = time.Now()
	hm.mu.Unlock()

	hm.reapOutgoingAndRevoked()

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.outgoing[10]; ok {
		t.Error("old outgoing should be reaped")
	}
	if _, ok := hm.outgoing[20]; !ok {
		t.Error("fresh outgoing should remain")
	}
}
