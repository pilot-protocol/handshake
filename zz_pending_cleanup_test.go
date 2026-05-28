// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

// Regression for the stale pending/outgoing entries observed on
// 2026-05-26: processRelayedRequest's sameNetwork / trustedAgent /
// autoApprove branches (and symmetric paths in handleRequest) call
// markTrustedLocked without clearing hm.pending or hm.outgoing, so a
// peer who sent a direct request (recorded in pending) and then arrives
// via a relayed auto-approve path stays in pending forever — pilotctl
// surfaces it, the policy fill_trust loop could re-target it.
//
// markTrustedLocked now centralizes the cleanup. These tests pin the
// invariant: after any trust grant, the peer's pending + outgoing
// entries are gone.

import (
	"testing"
	"time"
)

func TestMarkTrustedClearsPending(t *testing.T) {
	t.Parallel()

	hm := &Manager{
		trusted:      make(map[uint32]*TrustRecord),
		pending:      make(map[uint32]*PendingHandshake),
		outgoing:     make(map[uint32]time.Time),
		revoked:      make(map[uint32]time.Time),
		replaySet:    make(map[[32]byte]time.Time),
		trustWaiters: make(map[uint32][]chan struct{}),
	}

	const peer = uint32(7777)
	hm.pending[peer] = &PendingHandshake{NodeID: peer, ReceivedAt: time.Now()}

	hm.mu.Lock()
	hm.markTrustedLocked(peer, &TrustRecord{NodeID: peer, ApprovedAt: time.Now()})
	hm.mu.Unlock()

	if _, ok := hm.pending[peer]; ok {
		t.Fatal("markTrustedLocked left a stale entry in hm.pending — " +
			"would show in pilotctl pending forever")
	}
	if _, ok := hm.trusted[peer]; !ok {
		t.Fatal("markTrustedLocked did not record trust")
	}
}

func TestMarkTrustedClearsOutgoing(t *testing.T) {
	t.Parallel()

	hm := &Manager{
		trusted:      make(map[uint32]*TrustRecord),
		pending:      make(map[uint32]*PendingHandshake),
		outgoing:     make(map[uint32]time.Time),
		revoked:      make(map[uint32]time.Time),
		replaySet:    make(map[[32]byte]time.Time),
		trustWaiters: make(map[uint32][]chan struct{}),
	}

	const peer = uint32(8888)
	hm.outgoing[peer] = time.Now()

	hm.mu.Lock()
	hm.markTrustedLocked(peer, &TrustRecord{NodeID: peer, ApprovedAt: time.Now()})
	hm.mu.Unlock()

	if _, ok := hm.outgoing[peer]; ok {
		t.Fatal("markTrustedLocked left a stale entry in hm.outgoing — " +
			"policy fill_trust could re-target this peer")
	}
}

func TestMarkTrustedClearsBothMaps(t *testing.T) {
	t.Parallel()

	hm := &Manager{
		trusted:      make(map[uint32]*TrustRecord),
		pending:      make(map[uint32]*PendingHandshake),
		outgoing:     make(map[uint32]time.Time),
		revoked:      make(map[uint32]time.Time),
		replaySet:    make(map[[32]byte]time.Time),
		trustWaiters: make(map[uint32][]chan struct{}),
	}

	const peer = uint32(9999)
	hm.pending[peer] = &PendingHandshake{NodeID: peer, ReceivedAt: time.Now()}
	hm.outgoing[peer] = time.Now()

	hm.mu.Lock()
	hm.markTrustedLocked(peer, &TrustRecord{NodeID: peer, ApprovedAt: time.Now()})
	hm.mu.Unlock()

	if _, ok := hm.pending[peer]; ok {
		t.Error("pending not cleared")
	}
	if _, ok := hm.outgoing[peer]; ok {
		t.Error("outgoing not cleared")
	}
	if _, ok := hm.trusted[peer]; !ok {
		t.Error("trusted not recorded")
	}
}

func TestMarkTrustedNoEntryIsIdempotent(t *testing.T) {
	t.Parallel()
	// delete() on a missing key must be a no-op so that callers which
	// pre-delete (handleRequest mutual path, handleAccept) stay correct.

	hm := &Manager{
		trusted:      make(map[uint32]*TrustRecord),
		pending:      make(map[uint32]*PendingHandshake),
		outgoing:     make(map[uint32]time.Time),
		revoked:      make(map[uint32]time.Time),
		replaySet:    make(map[[32]byte]time.Time),
		trustWaiters: make(map[uint32][]chan struct{}),
	}

	hm.mu.Lock()
	hm.markTrustedLocked(1, &TrustRecord{NodeID: 1, ApprovedAt: time.Now()})
	hm.mu.Unlock()

	if _, ok := hm.trusted[1]; !ok {
		t.Fatal("trust grant should not depend on pre-existing pending/outgoing")
	}
}
