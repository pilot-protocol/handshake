// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"
)

func fillPending(m *Manager) {
	m.mu.Lock()
	for i := uint32(1000); i < 1000+uint32(maxPendingHandshakes); i++ {
		m.pending[i] = &PendingHandshake{NodeID: i}
	}
	m.mu.Unlock()
}

// A full pending queue used to drop every new peer before the auto-accept
// rules ran, so a node with trust-auto-approve on (or a mutual request
// outstanding) refused peers it would have trusted without queueing them.
// The caps only apply to a request that actually has to be queued.
func TestFullPendingQueueDoesNotBlockAutoAccept(t *testing.T) {
	t.Run("trust-auto-approve, direct", func(t *testing.T) {
		m, _ := hsTestManager(t, true)
		fillPending(m)
		m.handleRequest(nil, &HandshakeMsg{NodeID: 5000, PublicKey: "k"}, false)
		m.mu.RLock()
		defer m.mu.RUnlock()
		if _, ok := m.trusted[5000]; !ok {
			t.Fatal("auto-approve node dropped a new peer because its pending queue was full")
		}
		if n := len(m.pending); n != maxPendingHandshakes {
			t.Fatalf("pending len = %d, want it unchanged at %d", n, maxPendingHandshakes)
		}
	})

	t.Run("trust-auto-approve, relayed", func(t *testing.T) {
		m, _ := hsTestManager(t, true)
		fillPending(m)
		m.processRelayedRequest(6000, "join")
		m.mu.RLock()
		defer m.mu.RUnlock()
		if _, ok := m.trusted[6000]; !ok {
			t.Fatal("auto-approve node dropped a relayed request because its pending queue was full")
		}
	})

	t.Run("mutual request, relayed", func(t *testing.T) {
		m, _ := hsTestManager(t, false)
		fillPending(m)
		m.mu.Lock()
		m.outgoing[7000] = time.Now()
		m.mu.Unlock()
		m.processRelayedRequest(7000, "join")
		m.mu.RLock()
		defer m.mu.RUnlock()
		if _, ok := m.trusted[7000]; !ok {
			t.Fatal("a mutual request was dropped because the pending queue was full")
		}
	})

	t.Run("nothing to auto-accept: still not queued", func(t *testing.T) {
		m, _ := hsTestManager(t, false)
		fillPending(m)
		m.handleRequest(nil, &HandshakeMsg{NodeID: 8000, PublicKey: "k"}, false)
		m.processRelayedRequest(8001, "join")
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, id := range []uint32{8000, 8001} {
			if _, ok := m.pending[id]; ok {
				t.Fatalf("over-cap peer %d was queued", id)
			}
			if _, ok := m.trusted[id]; ok {
				t.Fatalf("over-cap peer %d was trusted", id)
			}
		}
		if n := len(m.pending); n != maxPendingHandshakes {
			t.Fatalf("pending len = %d, want %d", n, maxPendingHandshakes)
		}
	})
}
