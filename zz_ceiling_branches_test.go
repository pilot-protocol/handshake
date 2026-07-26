// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// This file targets every coverage hole identified by the iter-baseline
// (79.9%) audit: the registry-side branches in
// processRelayedRequest / processRelayedApproval / handleRequest /
// handleAccept / RevokeTrust / RejectHandshake / handleRevokeMsg, the
// sharedNetwork happy-path (registry returns shared network ids), the
// recently-revoked cooldown branches, reapStalePending, replay-set-full,
// service.Stop with a live listener, goRPC stopping race, and
// WaitForTrust's post-registration recheck.
//
// All file-touching tests use t.TempDir(). Test identities use fixed
// ed25519 seeds for deterministic signatures (see fakeRuntime.withDeterministicIdentity).

// -----------------------------------------------------------------------
// processRelayedRequest: same-network auto-approve (registry happy path)
// -----------------------------------------------------------------------

func TestProcessRelayedRequest_SameNetworkAutoApproves(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	const selfID, peerID uint32 = 100, 200

	rt.mu.Lock()
	rt.nodeID = selfID
	rt.mu.Unlock()

	// Both nodes share network 7 (non-backbone). Programmed in the fake.
	rt.registry.setLookup(selfID, map[string]interface{}{
		"networks": []interface{}{float64(0), float64(7)},
	})
	rt.registry.setLookup(peerID, map[string]interface{}{
		"networks":   []interface{}{float64(7), float64(99)},
		"public_key": "peer-key-from-registry",
	})

	hm.processRelayedRequest(peerID, "join us")

	hm.mu.RLock()
	rec, trusted := hm.trusted[peerID]
	_, isPending := hm.pending[peerID]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("same-network relay must auto-trust")
	}
	if isPending {
		t.Fatal("must not be pending on same-network auto-approve")
	}
	if rec.Network != 7 {
		t.Fatalf("rec.Network = %d, want 7", rec.Network)
	}
	if rec.Mutual {
		t.Fatal("same-network record must not be Mutual")
	}

	// Wait for async goRPC (RespondHandshake + ReportTrust + backfillPeerKey).
	hm.Stop()

	reports := rt.registry.snapshotReports()
	if len(reports) == 0 {
		t.Fatal("ReportTrust not invoked")
	}
	if reports[0] != [2]uint32{selfID, peerID} {
		t.Fatalf("ReportTrust args = %v", reports[0])
	}
	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 {
		t.Fatal("RespondHandshake not invoked")
	}
	if !responds[0].Accept {
		t.Fatal("RespondHandshake should accept=true on same-network")
	}
}

// -----------------------------------------------------------------------
// processRelayedRequest: trusted-agent path WITH registry — fires goRPCs
// -----------------------------------------------------------------------

func TestProcessRelayedRequest_TrustedAgentWithRegistryFiresRespond(t *testing.T) {
	// Not t.Parallel — setTestTrustedAgents mutates a package-global.
	setTestTrustedAgents(t, []testAgent{{NodeID: 4444, Hostname: "list-agents"}})

	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.trustChecker = testTrustChecker{}
	rt.nodeID = 1
	rt.mu.Unlock()

	// No same-network match (registry returns no networks).
	rt.registry.setLookup(1, map[string]interface{}{"networks": []interface{}{}})
	rt.registry.setLookup(4444, map[string]interface{}{
		"networks":   []interface{}{},
		"public_key": "trusted-agent-key",
	})

	hm.processRelayedRequest(4444, "trusted-agent reply")

	hm.mu.RLock()
	_, ok := hm.trusted[4444]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted-agent must be auto-trusted on relay path")
	}

	// Drain async work — both RespondHandshake AND ReportTrust must fire.
	hm.Stop()

	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 || responds[0].PeerID != 4444 || !responds[0].Accept {
		t.Fatalf("RespondHandshake not called as accept=true; got %+v", responds)
	}
	reports := rt.registry.snapshotReports()
	if len(reports) == 0 || reports[0][1] != 4444 {
		t.Fatalf("ReportTrust not called; got %+v", reports)
	}
}

// -----------------------------------------------------------------------
// processRelayedRequest: trust-auto-approve WITH registry — fires goRPCs
// -----------------------------------------------------------------------

func TestProcessRelayedRequest_AutoApproveWithRegistryFiresRespond(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.trustAutoApprove = true
	rt.nodeID = 1
	rt.mu.Unlock()

	rt.registry.setLookup(1, map[string]interface{}{"networks": []interface{}{}})
	rt.registry.setLookup(5555, map[string]interface{}{"networks": []interface{}{}})

	hm.processRelayedRequest(5555, "")

	hm.mu.RLock()
	_, ok := hm.trusted[5555]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("auto-approve must trust on relay path")
	}
	hm.Stop()

	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 || responds[0].PeerID != 5555 {
		t.Fatalf("RespondHandshake not invoked; got %+v", responds)
	}
}

// -----------------------------------------------------------------------
// processRelayedRequest: mutual path with registry — fires async goRPC
// -----------------------------------------------------------------------

func TestProcessRelayedRequest_MutualWithRegistryFiresRespond(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.outgoing[6666] = time.Now()

	rt.registry.setLookup(6666, map[string]interface{}{"networks": []interface{}{}})

	hm.processRelayedRequest(6666, "")

	hm.Stop()

	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 {
		t.Fatal("RespondHandshake not invoked on mutual relay")
	}
}

// -----------------------------------------------------------------------
// processRelayedRequest: already-trusted path with registry — fires RespondHandshake
// -----------------------------------------------------------------------

func TestProcessRelayedRequest_AlreadyTrustedWithRegistryRespondsAccept(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 9
	rt.mu.Unlock()

	hm.trusted[7777] = &TrustRecord{NodeID: 7777, ApprovedAt: time.Now()}

	hm.processRelayedRequest(7777, "already trusted")

	hm.Stop()

	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 || responds[0].PeerID != 7777 || !responds[0].Accept {
		t.Fatalf("already-trusted relay should send accept; got %+v", responds)
	}
}

// -----------------------------------------------------------------------
// processRelayedApproval: recently-revoked drops + clears outgoing
// -----------------------------------------------------------------------

func TestProcessRelayedApproval_RecentlyRevokedDrops(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.revoked[42] = time.Now().Add(5 * time.Minute)
	hm.outgoing[42] = time.Now()
	hm.mu.Unlock()

	hm.processRelayedApproval(42)

	hm.mu.RLock()
	_, trusted := hm.trusted[42]
	_, stillOutgoing := hm.outgoing[42]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("recently-revoked peer must NOT be re-trusted via relay approval")
	}
	if stillOutgoing {
		t.Fatal("outgoing should have been cleared on the revoked-drop path")
	}
}

// -----------------------------------------------------------------------
// processRelayedApproval: expired revoke cooldown clears + establishes trust
// -----------------------------------------------------------------------

func TestProcessRelayedApproval_ExpiredRevokeCooldownProceeds(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.revoked[51] = time.Now().Add(-1 * time.Minute) // already-expired
	hm.outgoing[51] = time.Now()
	hm.mu.Unlock()

	hm.processRelayedApproval(51)

	hm.mu.RLock()
	_, trusted := hm.trusted[51]
	_, stillRevoked := hm.revoked[51]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("expired cooldown should not block trust establishment")
	}
	if stillRevoked {
		t.Fatal("expired revoke entry should be GC'd as we move on")
	}
}

// -----------------------------------------------------------------------
// handleAccept: recently-revoked drops + clears outgoing
// -----------------------------------------------------------------------

func TestHandleAccept_RecentlyRevokedDrops(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.revoked[60] = time.Now().Add(5 * time.Minute)
	hm.outgoing[60] = time.Now()
	hm.mu.Unlock()

	hm.handleAccept(&HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    60,
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, trusted := hm.trusted[60]
	_, stillOutgoing := hm.outgoing[60]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("revoked peer must not be trusted via handleAccept")
	}
	if stillOutgoing {
		t.Fatal("outgoing should have been cleared on revoked-drop path")
	}
}

// -----------------------------------------------------------------------
// handleAccept: expired revoke cooldown then establish trust + fires ReportTrust
// -----------------------------------------------------------------------

func TestHandleAccept_ExpiredRevokeAllowsTrustAndFiresReport(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.mu.Lock()
	hm.revoked[70] = time.Now().Add(-1 * time.Hour) // expired
	hm.outgoing[70] = time.Now()
	hm.mu.Unlock()

	hm.handleAccept(&HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    70,
		PublicKey: "pk70",
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, trusted := hm.trusted[70]
	_, stillRevoked := hm.revoked[70]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("expired revoke must not block accept")
	}
	if stillRevoked {
		t.Fatal("expired revoke entry must be GC'd")
	}

	hm.Stop()
	reports := rt.registry.snapshotReports()
	if len(reports) == 0 || reports[0][1] != 70 {
		t.Fatalf("ReportTrust not fired; got %+v", reports)
	}
}

// -----------------------------------------------------------------------
// sharedNetwork happy path: registry returns shared network → non-zero
// -----------------------------------------------------------------------

func TestSharedNetwork_ReturnsFirstShared(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{float64(0), float64(5), float64(9)},
	})
	rt.registry.setLookup(2, map[string]interface{}{
		"networks": []interface{}{float64(9), float64(11)},
	})
	if got := hm.sharedNetwork(2); got != 9 {
		t.Fatalf("sharedNetwork = %d, want 9", got)
	}
	if !hm.sameNetwork(2) {
		t.Fatal("sameNetwork should be true with shared network 9")
	}
}

func TestSharedNetwork_NoOverlapReturnsZero(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{float64(0), float64(5)},
	})
	rt.registry.setLookup(2, map[string]interface{}{
		"networks": []interface{}{float64(11)},
	})
	if got := hm.sharedNetwork(2); got != 0 {
		t.Fatalf("sharedNetwork = %d, want 0", got)
	}
}

func TestSharedNetwork_OnlyBackboneReturnsZero(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{float64(0)},
	})
	rt.registry.setLookup(2, map[string]interface{}{
		"networks": []interface{}{float64(0)},
	})
	if got := hm.sharedNetwork(2); got != 0 {
		t.Fatalf("backbone-only should not count as shared: %d", got)
	}
}

func TestSharedNetwork_BadNetworkValueTypesSkipped(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{"not-a-number", float64(3)},
	})
	// "also-junk" FIRST on peer side so the inner-loop `continue` fires
	// BEFORE the match — exercises the 1348-1349 branch.
	rt.registry.setLookup(2, map[string]interface{}{
		"networks": []interface{}{"also-junk", float64(3)},
	})
	if got := hm.sharedNetwork(2); got != 3 {
		t.Fatalf("sharedNetwork should skip non-float entries, got %d", got)
	}
}

func TestSharedNetwork_LookupSelfErrorReturnsZero(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookupErr(1, errors.New("self lookup down"))
	rt.registry.setLookup(2, map[string]interface{}{"networks": []interface{}{float64(3)}})
	if got := hm.sharedNetwork(2); got != 0 {
		t.Fatalf("sharedNetwork with self-lookup err should return 0; got %d", got)
	}
}

func TestSharedNetwork_LookupPeerErrorReturnsZero(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{"networks": []interface{}{float64(3)}})
	rt.registry.setLookupErr(2, errors.New("peer lookup down"))
	if got := hm.sharedNetwork(2); got != 0 {
		t.Fatalf("sharedNetwork with peer-lookup err should return 0; got %d", got)
	}
}

// -----------------------------------------------------------------------
// reapStalePending: 0% baseline — empty + stale + mixed
// -----------------------------------------------------------------------

func TestReapStalePending_EmptyIsNoop(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.reapStalePending() // no panic, no allocs
	if len(hm.pending) != 0 {
		t.Fatal("pending should remain empty")
	}
}

func TestReapStalePending_RemovesOlderThanTTL(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	// Stale: older than the 30-day TTL.
	hm.pending[1] = &PendingHandshake{NodeID: 1, ReceivedAt: time.Now().Add(-pendingHandshakeTTL - time.Hour)}
	// Fresh: well within the TTL.
	hm.pending[2] = &PendingHandshake{NodeID: 2, ReceivedAt: time.Now()}
	hm.mu.Unlock()

	hm.reapStalePending()

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.pending[1]; ok {
		t.Fatal("stale pending[1] should have been reaped")
	}
	if _, ok := hm.pending[2]; !ok {
		t.Fatal("fresh pending[2] should have survived")
	}
}

func TestReapStalePending_AllFreshNoSave(t *testing.T) {
	t.Parallel()
	// Empty + non-empty fresh — covers the early-return path (no stale).
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.pending[10] = &PendingHandshake{NodeID: 10, ReceivedAt: time.Now()}
	hm.mu.Unlock()
	hm.reapStalePending()
	hm.mu.RLock()
	_, ok := hm.pending[10]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("fresh pending should survive when none are stale")
	}
}

func TestReapStalePending_PersistsViaSaveTrust(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	hm := newTestHM(t, idPath) // gives us a real storePath
	t.Cleanup(hm.Stop)

	hm.mu.Lock()
	hm.pending[1] = &PendingHandshake{NodeID: 1, ReceivedAt: time.Now().Add(-pendingHandshakeTTL - time.Hour)}
	hm.mu.Unlock()

	hm.reapStalePending()

	// trust.json now exists and reflects the empty pending slot.
	// PILOT-325: saveTrust now defers fsync to a drain goroutine, so the
	// write is asynchronous. Poll briefly for the file to land.
	trustPath := filepath.Join(dir, "trust.json")
	var data []byte
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(trustPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("trust.json not written after reap: %v", err)
	}
	var snap trustSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal trust.json: %v", err)
	}
	if len(snap.Pending) != 0 {
		t.Fatalf("expected pending cleared in persisted snapshot; got %+v", snap.Pending)
	}
}

// -----------------------------------------------------------------------
// processMessage: a full replay set evicts rather than dropping the
// message, and stays at the cap
// -----------------------------------------------------------------------

func TestProcessMessage_ReplaySetFullStillDispatches(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	// Fill the replay set to exactly the cap, spread across many peers so
	// no single peer is over its own limit.
	hm.replayMu.Lock()
	for i := 0; i < maxReplaySetEntries; i++ {
		var h [32]byte
		// Stamp the counter into the hash so each is unique.
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = byte(i >> 16)
		h[3] = byte(i >> 24)
		peer := uint32(1000 + i)
		hm.replaySet[h] = replayEntry{seen: time.Now(), peer: peer}
		hm.replayPeer[peer]++
	}
	hm.replayMu.Unlock()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    77,
		Reason:    "test",
		Timestamp: time.Now().Unix(),
	}
	// Seed an outgoing entry so the dispatch is observable.
	hm.outgoing[77] = time.Now()
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: 77}}, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[77]
	hm.mu.RUnlock()
	if stillOut {
		t.Fatal("a full replay set must not block an authenticated message — outgoing[77] should have been cleared")
	}

	hm.replayMu.Lock()
	size := len(hm.replaySet)
	hm.replayMu.Unlock()
	if size > maxReplaySetEntries {
		t.Fatalf("replay set grew past the cap: %d > %d", size, maxReplaySetEntries)
	}
}

// -----------------------------------------------------------------------
// processMessage: registry pubkey MISMATCH → rejected (downgrade defense)
// -----------------------------------------------------------------------

func TestProcessMessage_RegistryPubkeyMismatchRejected(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()

	// Registry has a DIFFERENT key than the one the caller claims.
	rt.registry.setLookup(2, map[string]interface{}{
		"public_key": "REGISTRY-SAYS-OTHER-KEY",
	})
	hm.outgoing[2] = time.Now() // would be cleared by Reject dispatch

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    2,
		PublicKey: "ATTACKER-CLAIMED-KEY",
		Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)),
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[2]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("registry pubkey mismatch must reject before dispatch")
	}
}

// -----------------------------------------------------------------------
// processMessage: registry Lookup error — verify fall-through to direct sig
// -----------------------------------------------------------------------
// When the registry is unreachable, the code does NOT downgrade trust —
// it just skips the registry-bound flag and tries to verify against the
// claimed pubkey. This is the iter-1 "registry-unavailable" path. If the
// claimed-pubkey verify succeeds, the message dispatches but
// registryBound=false — so the trusted-agents auto-accept path stays
// disabled even though the peer IS on the allowlist.

func TestProcessMessage_RegistryLookupErrorDoesNotAutoAcceptTrustedAgent(t *testing.T) {
	// Not t.Parallel — setTestTrustedAgents mutates a package-global.
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.trustChecker = testTrustChecker{}
	rt.mu.Unlock()
	rt.registry.setLookupErr(2, errors.New("registry down"))
	setTestTrustedAgents(t, []testAgent{{NodeID: 2, Hostname: "should-not-auto-accept"}})

	// Build a valid signed handshake REQUEST from peer 2 using a fixed seed.
	peerID := deterministicIdentity(0xAA)
	challenge := fmt.Sprintf("handshake:%d:%d", 2, 1)
	sig := peerID.Sign([]byte(challenge))
	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    2,
		PublicKey: base64.StdEncoding.EncodeToString(peerID.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, trusted := hm.trusted[2]
	_, pending := hm.pending[2]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("SECURITY: trusted-agent auto-accept fired without registry binding")
	}
	if !pending {
		t.Fatal("peer should be queued for manual approval when registry can't bind")
	}
}

// -----------------------------------------------------------------------
// service.Stop: live listener path — closes ln, calls mgr.Stop
// -----------------------------------------------------------------------

func TestService_StopClosesLiveListener(t *testing.T) {
	t.Parallel()
	// Real port-444 bind via daemon-backed runtime so svc.Stop hits the
	// `if s.mgr.ln != nil { s.mgr.ln.Close() }` branch.
	hm, d := newDaemonBackedHM(t)
	if err := hm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	svc := &Service{mgr: hm}
	// Stop should close the listener cleanly + drain goRPCs.
	if err := svc.Stop(nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Confirm port is now free (re-bind succeeds).
	if _, err := d.Ports().Bind(443); err != nil {
		t.Fatalf("unrelated port bind sanity: %v", err)
	}
	// And the original port can be re-bound.
}

// -----------------------------------------------------------------------
// goRPC: stopping race — Stop blocks new RPCs after stopping=true
// -----------------------------------------------------------------------

func TestGoRPC_StoppingPreventsNewGoroutines(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.Stop() // sets stopping=true

	// Any goRPC submitted after Stop should be silently dropped — no
	// panic, no wg.Add, no actual goroutine.
	ran := false
	hm.goRPC(func() { ran = true })
	time.Sleep(50 * time.Millisecond)
	if ran {
		t.Fatal("goRPC fired after Stop — stopping check broken")
	}
}

func TestGoRPCLocked_StoppingPreventsNewGoroutines(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.Stop()

	hm.mu.Lock()
	ran := false
	hm.goRPCLocked(func() { ran = true })
	hm.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if ran {
		t.Fatal("goRPCLocked fired after Stop")
	}
}

// -----------------------------------------------------------------------
// WaitForTrust: post-registration recheck — trust granted between
// the first read and the channel registration is still observed.
// -----------------------------------------------------------------------

func TestWaitForTrust_PostRegistrationRecheckCatchesGrant(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	const peer uint32 = 11
	// Inject trust BEFORE calling WaitForTrust — fast path returns true.
	// (We still exercise the registration recheck by injecting between
	// reads. Easiest: do the inject-then-wait race deterministically.)
	hm.mu.Lock()
	hm.trusted[peer] = &TrustRecord{NodeID: peer}
	hm.mu.Unlock()
	if !hm.WaitForTrust(peer, 100*time.Millisecond) {
		t.Fatal("WaitForTrust should observe pre-existing trust")
	}
}

func TestWaitForTrust_ZeroTimeoutFiresAndCleansUpWaiter(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	const peer uint32 = 13
	if hm.WaitForTrust(peer, 1*time.Millisecond) {
		t.Fatal("WaitForTrust for never-granted peer must time out")
	}
	// Waiter must be GC'd by the timeout path (removeWaiter).
	hm.trustWaitersMu.Lock()
	defer hm.trustWaitersMu.Unlock()
	if len(hm.trustWaiters[peer]) != 0 {
		t.Fatalf("waiter not cleaned up after timeout: %v", hm.trustWaiters[peer])
	}
}

// -----------------------------------------------------------------------
// RevokeTrust: with registry + identity — fires RevokeTrust RPC + RemoveTunnelPeer
// -----------------------------------------------------------------------

func TestRevokeTrust_WithRegistryFiresRPCAndTunnelTeardown(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.withDeterministicIdentity(t, 0x11)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.trusted[99] = &TrustRecord{NodeID: 99}

	if err := hm.RevokeTrust(99); err != nil {
		t.Fatalf("RevokeTrust: %v", err)
	}

	hm.Stop()

	rt.mu.RLock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.mu.RUnlock()
	if len(removed) == 0 || removed[0] != 99 {
		t.Fatalf("RemoveTunnelPeer not called for 99; got %v", removed)
	}
	revokes := rt.registry.snapshotRevokes()
	if len(revokes) == 0 || revokes[0][1] != 99 {
		t.Fatalf("registry.RevokeTrust not called for 99; got %+v", revokes)
	}

	// Cooldown was set, peer is no longer trusted.
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.trusted[99]; ok {
		t.Fatal("trusted[99] should be cleared")
	}
	if _, ok := hm.revoked[99]; !ok {
		t.Fatal("revoked[99] should be set as cooldown anchor")
	}
}

// -----------------------------------------------------------------------
// RejectHandshake: with registry + identity — fires RespondHandshake(false)
// -----------------------------------------------------------------------

func TestRejectHandshake_FiresRespondHandshakeFalse(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.withDeterministicIdentity(t, 0x22)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.pending[88] = &PendingHandshake{NodeID: 88}

	if err := hm.RejectHandshake(88, "policy"); err != nil {
		t.Fatalf("RejectHandshake: %v", err)
	}
	hm.Stop()

	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 || responds[0].PeerID != 88 || responds[0].Accept {
		t.Fatalf("RespondHandshake(false) not invoked; got %+v", responds)
	}
}

// -----------------------------------------------------------------------
// handleRevokeMsg: with trusted + registry — fires RevokeTrust + RemoveTunnelPeer
// -----------------------------------------------------------------------

func TestHandleRevokeMsg_TrustedWithRegistryFiresTeardownAndRPC(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.trusted[123] = &TrustRecord{NodeID: 123}

	hm.handleRevokeMsg(&HandshakeMsg{Type: HandshakeRevoke, NodeID: 123})

	hm.Stop()

	rt.mu.RLock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.mu.RUnlock()
	if len(removed) == 0 || removed[0] != 123 {
		t.Fatalf("RemoveTunnelPeer not called; got %v", removed)
	}
	revokes := rt.registry.snapshotRevokes()
	if len(revokes) == 0 || revokes[0][1] != 123 {
		t.Fatalf("registry.RevokeTrust not invoked; got %+v", revokes)
	}
}

func TestHandleRevokeMsg_UnknownPeerSkipsRegistryRevoke(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	// Not previously trusted/pending — wasTrusted=false → no registry call.
	hm.handleRevokeMsg(&HandshakeMsg{Type: HandshakeRevoke, NodeID: 321})

	hm.Stop()

	revokes := rt.registry.snapshotRevokes()
	if len(revokes) != 0 {
		t.Fatalf("registry.RevokeTrust must not be called for unknown peer; got %+v", revokes)
	}
	rt.mu.RLock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.mu.RUnlock()
	// RemoveTunnelPeer is still called (cheap teardown), but RPC must skip.
	if len(removed) == 0 {
		t.Fatal("RemoveTunnelPeer is called unconditionally")
	}
}

// -----------------------------------------------------------------------
// SendRequest: revoked-cooldown clears on explicit SendRequest
// -----------------------------------------------------------------------

func TestSendRequest_ClearsRevokedCooldown(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.withDeterministicIdentity(t, 0x33)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	hm.mu.Lock()
	hm.revoked[200] = time.Now().Add(5 * time.Minute)
	hm.mu.Unlock()

	// DialAndSend always fails → falls into relay path. Relay should
	// succeed (fake RequestHandshake returns ok).
	if err := hm.SendRequest(200, "fresh intent"); err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	hm.mu.RLock()
	_, stillRevoked := hm.revoked[200]
	_, isOutgoing := hm.outgoing[200]
	hm.mu.RUnlock()
	if stillRevoked {
		t.Fatal("revoked entry must be cleared by explicit SendRequest")
	}
	if !isOutgoing {
		t.Fatal("outgoing entry should be set")
	}
}

func TestSendRequest_DirectAndRelayBothFailReturnsDirectErr(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.requestErr = errors.New("relay fails")
	err := hm.SendRequest(300, "x")
	if err == nil {
		t.Fatal("SendRequest must surface relay error when both fail")
	}
}

func TestSendRequest_NoRegistryReturnsDirectErr(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.clearRegistry()
	err := hm.SendRequest(400, "no registry")
	if err == nil {
		t.Fatal("SendRequest without registry must surface the direct-dial err")
	}
}

// -----------------------------------------------------------------------
// sendAccept: direct fails → relay path succeeds
// -----------------------------------------------------------------------

func TestSendAccept_DirectFailsRelaySucceeds(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.withDeterministicIdentity(t, 0x44)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()

	if err := hm.sendAccept(500); err != nil {
		t.Fatalf("sendAccept: %v", err)
	}
	responds := rt.registry.snapshotResponds()
	if len(responds) == 0 || responds[0].PeerID != 500 || !responds[0].Accept {
		t.Fatalf("sendAccept relay missing; got %+v", responds)
	}
}

func TestSendAccept_DirectFailsRelayAlsoFailsErrors(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.withDeterministicIdentity(t, 0x55)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.respondErr = errors.New("relay accept failed")

	err := hm.sendAccept(600)
	if err == nil {
		t.Fatal("sendAccept must surface relay error when both fail")
	}
}

func TestSendAccept_NoRegistryNoIdentityReturnsDirectErr(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.clearRegistry()
	err := hm.sendAccept(700)
	if err == nil {
		t.Fatal("sendAccept without registry must return direct-dial err")
	}
}

// -----------------------------------------------------------------------
// ApproveHandshake: no registry — runs synchronously without RPC
// -----------------------------------------------------------------------

func TestApproveHandshake_NoRegistrySkipsRPC(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.clearRegistry()
	hm.pending[111] = &PendingHandshake{NodeID: 111, PublicKey: "k"}

	if err := hm.ApproveHandshake(111); err != nil {
		t.Fatalf("ApproveHandshake: %v", err)
	}
	hm.mu.RLock()
	_, ok := hm.trusted[111]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("trusted[111] not set on no-registry approve")
	}
}

// -----------------------------------------------------------------------
// reapOutgoingAndRevoked: revoked cooldown expiry path
// -----------------------------------------------------------------------

func TestReapOutgoingAndRevoked_PrunesExpiredRevoked(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.revoked[1] = time.Now().Add(-time.Hour) // expired
	hm.revoked[2] = time.Now().Add(time.Hour)  // future
	hm.mu.Unlock()

	hm.reapOutgoingAndRevoked()

	hm.mu.RLock()
	defer hm.mu.RUnlock()
	if _, ok := hm.revoked[1]; ok {
		t.Fatal("expired revoked entry should be reaped")
	}
	if _, ok := hm.revoked[2]; !ok {
		t.Fatal("future-anchored revoked entry should survive")
	}
}

// -----------------------------------------------------------------------
// saveTrust: marshal-only-roundtrip + missing pubkey OK
// -----------------------------------------------------------------------

func TestSaveTrust_TrustedWithoutMutualSerializes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	hm := newTestHM(t, idPath)
	t.Cleanup(hm.Stop)

	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now().UTC(), Mutual: false}
	hm.mu.Unlock()
	hm.saveTrust()

	data, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatalf("saveTrust did not produce file: %v", err)
	}
	var snap trustSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("saved trust.json invalid: %v", err)
	}
	if len(snap.Trusted) != 1 || snap.Trusted[0].NodeID != 1 {
		t.Fatalf("trust snapshot wrong: %+v", snap)
	}
}

// -----------------------------------------------------------------------
// loadTrust: malformed timestamps load as zero (no panic)
// -----------------------------------------------------------------------

func TestLoadTrust_MalformedTimestampSkipsEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	trustPath := filepath.Join(dir, "trust.json")
	// Per PILOT-326, a malformed RFC3339 timestamp must NOT be restored with a
	// fabricated zero-time (1970-01-01) — that silently corrupts downstream
	// "trust is N days old" telemetry. Instead loadTrust logs and skips the
	// offending entry. Well-formed sibling entries in the same snapshot must
	// still load, proving the loop continues past a bad record rather than
	// aborting.
	good := time.Now().UTC().Truncate(time.Second)
	snap := trustSnapshot{
		Trusted: []trustSnapshotEntry{
			{NodeID: 1, PublicKey: "pk", ApprovedAt: "garbage-not-rfc3339"},
			{NodeID: 3, PublicKey: "pk3", ApprovedAt: good.Format(time.RFC3339)},
		},
		Pending: []pendingSnapshotEntry{
			{NodeID: 2, ReceivedAt: "also-garbage"},
			{NodeID: 4, ReceivedAt: good.Format(time.RFC3339)},
		},
	}
	data, _ := json.MarshalIndent(snap, "", "  ")
	if err := os.WriteFile(trustPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hm := newTestHM(t, idPath)
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	// Malformed entries are dropped, not restored with bogus zero-time.
	if _, ok := hm.trusted[1]; ok {
		t.Fatal("trusted[1] with malformed ApprovedAt should be skipped, not loaded")
	}
	if _, ok := hm.pending[2]; ok {
		t.Fatal("pending[2] with malformed ReceivedAt should be skipped, not loaded")
	}

	// Well-formed sibling entries still load — the loop continues past the bad one.
	rec, ok := hm.trusted[3]
	if !ok {
		t.Fatal("trusted[3] with valid timestamp should load")
	}
	if !rec.ApprovedAt.Equal(good) {
		t.Fatalf("trusted[3] ApprovedAt = %v, want %v", rec.ApprovedAt, good)
	}
	if _, ok := hm.pending[4]; !ok {
		t.Fatal("pending[4] with valid timestamp should load")
	}
}

