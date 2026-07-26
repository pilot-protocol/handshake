// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// -----------------------------------------------------------------------
// handleAccept consumes a matching outgoing request
// -----------------------------------------------------------------------

func TestHandleAccept_WithoutOutgoingRequestDropped(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	// No hm.outgoing entry: this node never asked to handshake with 4242.
	hm.handleAccept(&HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    4242,
		PublicKey: "pk4242",
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, trusted := hm.trusted[4242]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("an acceptance with no matching outgoing request must not establish trust")
	}
}

func TestProcessMessage_UnsolicitedAcceptOverAuthenticatedStreamDropped(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const peer = uint32(4343)
	// The stream is authenticated as the claimed sender — the only
	// remaining precondition is a pending outgoing request, and there is
	// none.
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: peer}}, &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    peer,
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("unsolicited accept must not establish trust even over an authenticated stream")
	}
}

func TestHandleAccept_ConsumesOutgoingEntryOnce(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const peer = uint32(4444)
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()

	msg := &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    peer,
		PublicKey: "pk4444",
		Timestamp: time.Now().Unix(),
	}
	hm.handleAccept(msg)

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	_, stillOutgoing := hm.outgoing[peer]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("a solicited accept must still establish trust")
	}
	if stillOutgoing {
		t.Fatal("the outgoing entry must be consumed by the accept")
	}

	// Second delivery of the same acceptance has nothing left to consume.
	hm.mu.Lock()
	delete(hm.trusted, peer)
	hm.mu.Unlock()
	hm.handleAccept(msg)

	hm.mu.RLock()
	_, reTrusted := hm.trusted[peer]
	hm.mu.RUnlock()
	if reTrusted {
		t.Fatal("a replayed accept must not re-establish trust after the outgoing entry is consumed")
	}
}

// -----------------------------------------------------------------------
// reject is bound to the authenticated sender
// -----------------------------------------------------------------------

func TestProcessMessage_RejectFromMismatchedStreamIgnored(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const victim = uint32(700)
	const other = uint32(666)
	hm.mu.Lock()
	hm.outgoing[victim] = time.Now()
	hm.mu.Unlock()

	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: other}}, &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    victim,
		Reason:    "not from the victim",
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[victim]
	hm.mu.RUnlock()
	if !stillOutgoing {
		t.Fatal("a reject claiming another node's ID must not cancel that node's outgoing request")
	}
}

func TestProcessMessage_RejectWithNoTransportIgnored(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const peer = uint32(701)
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()

	hm.processMessage(nil, &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    peer,
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[peer]
	hm.mu.RUnlock()
	if !stillOutgoing {
		t.Fatal("a reject with no authenticated transport must not cancel an outgoing request")
	}
}

func TestProcessMessage_RejectOverMatchingStreamCancels(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const peer = uint32(702)
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()

	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: peer}}, &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    peer,
		Timestamp: time.Now().Unix(),
	})

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[peer]
	hm.mu.RUnlock()
	if stillOutgoing {
		t.Fatal("an honest reject over a matching authenticated stream must cancel the outgoing request")
	}
}

// -----------------------------------------------------------------------
// replay-set entries are only recorded for authenticated messages
// -----------------------------------------------------------------------

func TestProcessMessage_UnverifiedMessageDoesNotConsumeReplayCapacity(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	// Well-formed encodings, but the signature does not verify against
	// the claimed key.
	for i := 0; i < 32; i++ {
		hm.processMessage(&addrStream{addr: coreapi.Addr{Node: 900}}, &HandshakeMsg{
			Type:      HandshakeReject,
			NodeID:    900,
			Reason:    string(rune('a' + i)),
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			Signature: base64.StdEncoding.EncodeToString(append(make([]byte, 63), byte(i))),
			Timestamp: time.Now().Unix(),
		})
	}

	hm.replayMu.Lock()
	size := len(hm.replaySet)
	hm.replayMu.Unlock()
	if size != 0 {
		t.Fatalf("messages that fail signature verification must not be recorded; replaySet has %d entries", size)
	}

	// An authenticated message is still recorded.
	hm.mu.Lock()
	hm.outgoing[901] = time.Now()
	hm.mu.Unlock()
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: 901}}, &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    901,
		Timestamp: time.Now().Unix(),
	})

	hm.replayMu.Lock()
	size = len(hm.replaySet)
	hm.replayMu.Unlock()
	if size != 1 {
		t.Fatalf("an authenticated message must be recorded exactly once; replaySet has %d entries", size)
	}
}

func TestRecordReplay_PerPeerCapEvictsOnlyThatPeersEntries(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	base := time.Now().Add(-time.Minute)

	// A quiet peer's entries must survive a loud peer's flood.
	var quiet [][32]byte
	for i := 0; i < 4; i++ {
		var h [32]byte
		h[0] = 0xAA
		h[1] = byte(i)
		quiet = append(quiet, h)
		if !hm.recordReplay(1, h, base.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("recordReplay(quiet, %d) returned false", i)
		}
	}

	for i := 0; i < maxReplayPerPeer+64; i++ {
		var h [32]byte
		h[0] = 0xBB
		h[1] = byte(i)
		h[2] = byte(i >> 8)
		if !hm.recordReplay(2, h, base.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("recordReplay(loud, %d) returned false", i)
		}
	}

	hm.replayMu.Lock()
	defer hm.replayMu.Unlock()
	if got := hm.replayPeer[2]; got > maxReplayPerPeer {
		t.Fatalf("loud peer holds %d entries, cap is %d", got, maxReplayPerPeer)
	}
	if got := hm.replayPeer[1]; got != len(quiet) {
		t.Fatalf("quiet peer holds %d entries, want %d", got, len(quiet))
	}
	for i, h := range quiet {
		if _, ok := hm.replaySet[h]; !ok {
			t.Fatalf("quiet peer entry %d was evicted by another peer's traffic", i)
		}
	}
}

func TestRecordReplay_RejectsDuplicateHash(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	h := [32]byte{9, 9, 9}
	now := time.Now()
	if !hm.recordReplay(5, h, now) {
		t.Fatal("first record should succeed")
	}
	if hm.recordReplay(5, h, now) {
		t.Fatal("a duplicate hash must be reported as already seen")
	}
	hm.replayMu.Lock()
	defer hm.replayMu.Unlock()
	if hm.replayPeer[5] != 1 {
		t.Fatalf("duplicate must not double-count; replayPeer[5] = %d", hm.replayPeer[5])
	}
}

// -----------------------------------------------------------------------
// key-bound allowlist gate
// -----------------------------------------------------------------------

// keyedTestRuntime adds the optional KeyedTrustChecker behavior to
// testRuntime: nodeID must be in pinned AND present the pinned key.
type keyedTestRuntime struct {
	*testRuntime
	pinned map[uint32]string
}

func (r *keyedTestRuntime) IsTrustedWithKey(nodeID uint32, pubKeyB64 string) (string, bool) {
	want, ok := r.pinned[nodeID]
	if !ok {
		return "", false
	}
	if want != pubKeyB64 {
		return "", false
	}
	return "pinned-agent", true
}

func newKeyedHM(t *testing.T, pinned map[uint32]string) *Manager {
	t.Helper()
	rt := &keyedTestRuntime{testRuntime: newTestRuntime(), pinned: pinned}
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)
	return hm
}

func TestHandleRequest_KeyedGateRejectsMismatchedKey(t *testing.T) {
	t.Parallel()
	const peer = uint32(3131)
	hm := newKeyedHM(t, map[uint32]string{peer: "PINNED-KEY"})

	hm.handleRequest(nil, &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    peer,
		PublicKey: "OTHER-KEY",
		Timestamp: time.Now().Unix(),
	}, true)

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	_, pending := hm.pending[peer]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("auto-accept must not fire when the presented key differs from the pinned one")
	}
	if !pending {
		t.Fatal("the request should fall through to pending approval")
	}
}

func TestHandleRequest_KeyedGateAcceptsMatchingKey(t *testing.T) {
	t.Parallel()
	const peer = uint32(3232)
	hm := newKeyedHM(t, map[uint32]string{peer: "PINNED-KEY"})

	hm.handleRequest(nil, &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    peer,
		PublicKey: "PINNED-KEY",
		Timestamp: time.Now().Unix(),
	}, true)

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("auto-accept must fire when the presented key matches the pinned one")
	}
}

func TestProcessRelayedRequest_KeyedGateHasNoPeerKey(t *testing.T) {
	t.Parallel()
	const peer = uint32(3333)
	hm := newKeyedHM(t, map[uint32]string{peer: "PINNED-KEY"})

	hm.processRelayedRequest(peer, "relayed")

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	_, pending := hm.pending[peer]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("the relay carries no peer key, so a pinned entry must not auto-accept")
	}
	if !pending {
		t.Fatal("the relayed request should fall through to pending approval")
	}
}

// -----------------------------------------------------------------------
// Manager.IsTrustedWithKey
// -----------------------------------------------------------------------

// keyBoundTrustService mirrors the method set the daemon type-asserts
// for when it wants the key-bound answer from the handshake service.
// The guard below keeps the Manager's signatures aligned with it.
type keyBoundTrustService interface {
	IsTrusted(nodeID uint32) bool
	IsTrustedWithKey(nodeID uint32, pubKeyB64 string) bool
}

var _ keyBoundTrustService = (*Manager)(nil)

func TestManagerIsTrustedWithKey(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, PublicKey: "KEY-ONE", ApprovedAt: time.Now()}
	hm.trusted[2] = &TrustRecord{NodeID: 2, ApprovedAt: time.Now()} // relay-established, key not yet backfilled
	hm.mu.Unlock()

	if hm.IsTrustedWithKey(99, "KEY-ONE") {
		t.Fatal("an unknown node must not be trusted")
	}
	if !hm.IsTrustedWithKey(1, "KEY-ONE") {
		t.Fatal("a matching key must be trusted")
	}
	if hm.IsTrustedWithKey(1, "KEY-TWO") {
		t.Fatal("a differing key must not be trusted")
	}
	if hm.IsTrustedWithKey(1, "") {
		t.Fatal("an empty key must not match a recorded one")
	}
	if !hm.IsTrustedWithKey(2, "ANY-KEY") {
		t.Fatal("a record with no key recorded answers on node ID alone")
	}
}
