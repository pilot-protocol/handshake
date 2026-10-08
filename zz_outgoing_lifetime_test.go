// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"path/filepath"
	"testing"
	"time"
)

// A person accepts a friend request when they see it, often hours later.
// The acceptance must still complete trust on the requester's side; it used
// to be dropped as unsolicited once the outgoing entry passed 10 minutes.
func TestOutgoing_AcceptanceHoursLaterIsHonoured(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.mu.Lock()
	hm.addOutgoingLocked(77, time.Now().Add(-3*time.Hour))
	hm.mu.Unlock()
	hm.reapOutgoingAndRevoked() // the reaper must not drop it

	hm.handleAccept(&HandshakeMsg{Type: HandshakeAccept, NodeID: 77, PublicKey: "k", Timestamp: time.Now().Unix()})

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[77]; !ok {
		t.Fatal("an acceptance three hours after the request was dropped")
	}
}

// The same, relayed through the registry, which is how most private nodes
// learn of an acceptance.
func TestOutgoing_RelayedApprovalHoursLaterIsHonoured(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.mu.Lock()
	hm.addOutgoingLocked(78, time.Now().Add(-5*time.Hour))
	hm.mu.Unlock()
	hm.reapOutgoingAndRevoked()

	hm.ProcessRelayedApproval(78)

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[78]; !ok {
		t.Fatal("a relayed approval five hours after the request was dropped")
	}
}

// A request survives a restart: it is saved with the trust state, and an
// acceptance that arrives after the restart completes trust.
func TestOutgoing_SurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trust.json")
	before := newTestHM(t, path)
	before.mu.Lock()
	before.addOutgoingLocked(90, time.Now().Add(-time.Hour))
	before.addOutgoingLocked(91, time.Now().Add(-outgoingRequestTTL-time.Hour)) // too old to keep
	before.mu.Unlock()
	before.saveTrust()

	after := newTestHM(t, path)
	t.Cleanup(after.Stop)
	after.loadTrust()
	after.mu.RLock()
	_, kept := after.outgoing[90]
	_, stale := after.outgoing[91]
	after.mu.RUnlock()
	if !kept || stale {
		t.Fatalf("after a restart: request 90 kept=%v (want true), expired 91 kept=%v (want false)", kept, stale)
	}

	after.ProcessRelayedApproval(90)
	after.mu.RLock()
	defer after.mu.RUnlock()
	if _, ok := after.trusted[90]; !ok {
		t.Fatal("an acceptance after a restart was dropped")
	}
}

// Cancelling a request (revoking) forgets it for good, also across a restart,
// so a late acceptance of a cancelled request is not honoured.
func TestOutgoing_CancelledRequestIsForgottenAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trust.json")
	before := newTestHM(t, path)
	before.mu.Lock()
	before.addOutgoingLocked(95, time.Now())
	before.mu.Unlock()
	before.saveTrust()
	before.RevokeTrust(95)
	before.saveTrust()

	after := newTestHM(t, path)
	t.Cleanup(after.Stop)
	after.loadTrust()
	after.mu.RLock()
	defer after.mu.RUnlock()
	if _, ok := after.outgoing[95]; ok {
		t.Fatal("a cancelled request came back after a restart")
	}
}

// The outgoing set is bounded: past maxOutgoingRequests the oldest goes.
func TestOutgoing_Bounded(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	start := time.Now().Add(-time.Hour)
	hm.mu.Lock()
	defer hm.mu.Unlock()
	for i := 0; i <= maxOutgoingRequests; i++ {
		hm.addOutgoingLocked(uint32(1000+i), start.Add(time.Duration(i)*time.Millisecond))
	}
	if len(hm.outgoing) != maxOutgoingRequests {
		t.Fatalf("outgoing holds %d, want %d", len(hm.outgoing), maxOutgoingRequests)
	}
	if _, ok := hm.outgoing[1000]; ok {
		t.Fatal("the oldest request should have been forgotten first")
	}
	if _, ok := hm.outgoing[uint32(1000+maxOutgoingRequests)]; !ok {
		t.Fatal("the newest request is missing")
	}
}
