// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import "testing"

// TestPreChecksHandleAlreadyTrustedAndOverCap pins SECURITY_REVIEW_v1.14
// finding M1 on the plain path: handshakes that need no new trust decision —
// an already-trusted peer or over-cap spam — are settled by the pre-checks.
// The trusted peer keeps its record and is not queued; over-cap spam, direct
// or relayed, is neither queued nor trusted.
func TestPreChecksHandleAlreadyTrustedAndOverCap(t *testing.T) {
	runtime := newTestRuntime()
	manager := NewManager(runtime)
	t.Cleanup(manager.Stop)

	// Already-trusted peer (matching key): accepted on the fast path.
	manager.mu.Lock()
	manager.trusted[71] = &TrustRecord{NodeID: 71, PublicKey: "peer-key"}
	manager.mu.Unlock()
	manager.handleRequest(nil, &HandshakeMsg{NodeID: 71, PublicKey: "peer-key", Justification: "join"}, false)
	manager.mu.RLock()
	rec, trusted := manager.trusted[71]
	_, queued := manager.pending[71]
	manager.mu.RUnlock()
	if !trusted || rec.PublicKey != "peer-key" {
		t.Fatalf("already-trusted peer lost or changed its record: trusted=%v rec=%+v", trusted, rec)
	}
	if queued {
		t.Fatal("already-trusted peer was queued for approval")
	}

	// Over-cap spam: fill the pending queue, then an untrusted, unqueued peer
	// is rejected.
	manager.mu.Lock()
	for i := uint32(1000); i < 1000+uint32(maxPendingHandshakes); i++ {
		manager.pending[i] = &PendingHandshake{NodeID: i}
	}
	manager.mu.Unlock()
	manager.handleRequest(nil, &HandshakeMsg{NodeID: 5000, PublicKey: "spam-key"}, false)

	// Relayed over-cap spam is likewise rejected.
	manager.processRelayedRequest(6000, "join")

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if n := len(manager.pending); n != maxPendingHandshakes {
		t.Fatalf("pending len = %d after over-cap spam, want %d", n, maxPendingHandshakes)
	}
	for _, id := range []uint32{5000, 6000} {
		if _, ok := manager.pending[id]; ok {
			t.Fatalf("over-cap peer %d was queued", id)
		}
		if _, ok := manager.trusted[id]; ok {
			t.Fatalf("over-cap peer %d was trusted", id)
		}
	}
}
