// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"io"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// Additional ceiling tests for the small uncovered branches that fell out
// of the iter-1 sweep. Each test targets a specific 1-2 line gap in the
// coverage profile.

// -----------------------------------------------------------------------
// handleRequest: same-network direct path (lines 630-651)
// -----------------------------------------------------------------------

func TestHandleRequest_SameNetworkDirectPathAutoApproves(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{float64(7)},
	})
	rt.registry.setLookup(99, map[string]interface{}{
		"networks": []interface{}{float64(7)},
	})

	hm.handleRequest(nil, &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    99,
		PublicKey: "peer-99-key",
		Timestamp: time.Now().Unix(),
	}, false)

	hm.mu.RLock()
	rec, trusted := hm.trusted[99]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("same-network direct request must auto-approve")
	}
	if rec.Network != 7 {
		t.Fatalf("rec.Network = %d, want 7", rec.Network)
	}

	hm.Stop()

	reports := rt.registry.snapshotReports()
	if len(reports) == 0 || reports[0][1] != 99 {
		t.Fatalf("ReportTrust not fired for same-network direct: %+v", reports)
	}
}

// -----------------------------------------------------------------------
// markTrustedLocked: explicit waiters loop fires close() — covers the
// for-range loop body (lines 199-201).
// -----------------------------------------------------------------------

func TestMarkTrustedLocked_FiresChannelClose(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	const peer uint32 = 555
	ch := make(chan struct{})

	hm.trustWaitersMu.Lock()
	hm.trustWaiters[peer] = []chan struct{}{ch}
	hm.trustWaitersMu.Unlock()

	hm.mu.Lock()
	hm.markTrustedLocked(peer, &TrustRecord{NodeID: peer, ApprovedAt: time.Now()})
	hm.mu.Unlock()

	select {
	case <-ch:
		// success — channel closed
	case <-time.After(time.Second):
		t.Fatal("waiter channel not closed by markTrustedLocked")
	}
}

// -----------------------------------------------------------------------
// WaitForTrust: post-registration recheck observes a race-window grant
// (lines 233-236).
// -----------------------------------------------------------------------

func TestWaitForTrust_PostRegistrationRecheckHit(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	const peer uint32 = 41

	// We need to grant trust AFTER the first hm.mu.RLock() check but
	// BEFORE the second one. Simulate by hooking into the lock path:
	// grant trust on a goroutine that fires immediately after we start.
	//
	// In practice the easiest way to hit the recheck branch deterministically
	// is to grant trust just before calling WaitForTrust but withhold the
	// waiter close — that is, race the trust grant with the registration.
	// Below we accept that the test is probabilistic; if the test is run
	// a few times the recheck branch fires. We make it deterministic by
	// taking the trustWaitersMu lock to stall the registration step
	// until we've granted trust.

	// Pre-take trustWaitersMu so WaitForTrust's append blocks momentarily.
	hm.trustWaitersMu.Lock()
	go func() {
		// Wait a bit so WaitForTrust enters its first lookup, finds nothing,
		// then attempts to append to trustWaiters (blocked on our lock).
		time.Sleep(10 * time.Millisecond)
		hm.mu.Lock()
		hm.trusted[peer] = &TrustRecord{NodeID: peer}
		hm.mu.Unlock()
		hm.trustWaitersMu.Unlock()
	}()

	if !hm.WaitForTrust(peer, 500*time.Millisecond) {
		t.Fatal("post-registration recheck must see the trust grant")
	}
}

// -----------------------------------------------------------------------
// SendRequest: direct dial SUCCEEDS — covers the err==nil early return
// (lines 806-808).
// -----------------------------------------------------------------------

func TestSendRequest_DirectDialSucceeds(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.dialErr = nil // success path
	rt.nodeID = 1
	rt.mu.Unlock()

	if err := hm.SendRequest(700, "direct dial works"); err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	// outgoing should be set, registry RequestHandshake should NOT be called
	// (direct succeeded → relay branch skipped).
	hm.mu.RLock()
	_, isOut := hm.outgoing[700]
	hm.mu.RUnlock()
	if !isOut {
		t.Fatal("outgoing[700] should be set")
	}
	if reqs := rt.registry.requestCalls; len(reqs) != 0 {
		t.Fatalf("RequestHandshake should not fire on direct success; got %+v", reqs)
	}

	rt.mu.RLock()
	dials := append([]fakeDialCall(nil), rt.dialCalls...)
	rt.mu.RUnlock()
	if len(dials) == 0 || dials[0].NodeID != 700 {
		t.Fatalf("DialAndSend not invoked; got %+v", dials)
	}
}

// -----------------------------------------------------------------------
// TrustedPeers: loop populates result (lines 1227-1229)
// -----------------------------------------------------------------------

func TestTrustedPeers_ReturnsAllEntries(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	hm.mu.Lock()
	hm.trusted[10] = &TrustRecord{NodeID: 10, PublicKey: "a"}
	hm.trusted[20] = &TrustRecord{NodeID: 20, PublicKey: "b"}
	hm.mu.Unlock()

	got := hm.TrustedPeers()
	if len(got) != 2 {
		t.Fatalf("TrustedPeers len = %d, want 2", len(got))
	}
	seen := map[uint32]string{}
	for _, r := range got {
		seen[r.NodeID] = r.PublicKey
	}
	if seen[10] != "a" || seen[20] != "b" {
		t.Fatalf("TrustedPeers contents = %+v", seen)
	}
}

// -----------------------------------------------------------------------
// handleConnection: read timeout (line 441-442) — Read blocks past
// handshakeRecvTimeout (10s default). To hit the branch deterministically
// without waiting 10s, we use a Read that blocks until the test ends.
// Use a short timeout test by exposing — actually we can't override the
// const, so we just verify the timeout branch by using a stream that
// blocks indefinitely and bounding the test to 11s.
// -----------------------------------------------------------------------

type slowStream struct {
	done chan struct{}
}

func newSlowStream() *slowStream { return &slowStream{done: make(chan struct{})} }

func (s *slowStream) Read(p []byte) (int, error) {
	<-s.done
	return 0, io.EOF
}
func (s *slowStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *slowStream) Close() error                     { close(s.done); return nil }
func (s *slowStream) LocalAddr() coreapi.Addr           { return coreapi.Addr{} }
func (s *slowStream) LocalPort() uint16                { return 0 }
func (s *slowStream) RemoteAddr() coreapi.Addr          { return coreapi.Addr{} }
func (s *slowStream) RemotePort() uint16               { return 0 }
func (s *slowStream) SetDeadline(time.Time) error      { return nil }
func (s *slowStream) SetReadDeadline(time.Time) error  { return nil }
func (s *slowStream) SetWriteDeadline(time.Time) error { return nil }

// We avoid the 10s wall-clock penalty by skipping this in -short mode.
// Plain `go test ./...` (no -short) hits it once and credits coverage.
func TestHandleConnection_TimeoutBranch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10s timeout coverage in -short mode")
	}
	t.Parallel()
	hm, _ := newFakeHM(t)
	stream := newSlowStream()
	defer stream.Close()

	done := make(chan struct{})
	go func() {
		hm.handleConnection(stream)
		close(done)
	}()
	select {
	case <-done:
		// covered timeout branch
	case <-time.After(15 * time.Second):
		t.Fatal("handleConnection did not return — timeout path not firing")
	}
}

// -----------------------------------------------------------------------
// saveTrust: AtomicWrite error path (line 324-327) — write fails when
// the storePath is a directory rather than a file. We can't trigger
// json.MarshalIndent failure (HandshakeMsg always marshals).
// -----------------------------------------------------------------------

func TestSaveTrust_AtomicWriteErrorIsNonFatal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Point storePath at a directory — AtomicWrite will fail.
	hm := newTestHM(t, dir+"/identity.json")
	// Now replace storePath with the directory itself so the write target
	// is invalid (can't write a file with the same name as an existing dir).
	hm.storePath = dir

	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now()}
	hm.mu.Unlock()
	// Should NOT panic; logs slog.Error and returns.
	hm.saveTrust()
}

// -----------------------------------------------------------------------
// sharedNetwork: 1348-1349 branch — peerNetID==0 (backbone) is skipped
// when present on peer side. Already partially covered, but make explicit.
// -----------------------------------------------------------------------

func TestSharedNetwork_PeerBackboneSkipped(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.mu.Lock()
	rt.nodeID = 1
	rt.mu.Unlock()
	rt.registry.setLookup(1, map[string]interface{}{
		"networks": []interface{}{float64(5)},
	})
	rt.registry.setLookup(2, map[string]interface{}{
		"networks": []interface{}{float64(0), float64(5)}, // backbone first
	})
	if got := hm.sharedNetwork(2); got != 5 {
		t.Fatalf("sharedNetwork should find 5 past peer backbone; got %d", got)
	}
}

// -----------------------------------------------------------------------
// sendMessage: marshal error path (1305-1307) is hit only when the
// HandshakeMsg has an unmarshalable value — but HandshakeMsg only holds
// strings/ints, so marshal always succeeds. This branch is effectively
// dead code. We acknowledge it explicitly so reviewers know it isn't
// missed by accident.
// -----------------------------------------------------------------------

// (intentional no-op — branch is unreachable in current type)

// -----------------------------------------------------------------------
// Start: tick the reaper at least once before Stop (lines 394-397).
// We cannot wait 5 minutes for handshakeReapInterval to fire, so we
// instead probe the same code path via reapReplay+reapOutgoing+reapStale
// directly — they're individually 100% covered above. This documents the
// gap: the periodic ticker tick is exercised in integration but not
// directly observed.
// -----------------------------------------------------------------------

// (no test — exercised by the daemon-backed bootstrap tests, which Start
// the manager; the ticker branch fires the first time the ticker rolls,
// well after our tests have exited.)

// -----------------------------------------------------------------------
// saveTrust: MkdirAll error path (line 313-316). Triggered by a path
// where Mkdir cannot create the directory tree. /dev/null/x is portable.
// -----------------------------------------------------------------------

func TestSaveTrust_MkdirAllErrorIsNonFatal(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "/dev/null/nope/identity.json")
	hm.mu.Lock()
	hm.trusted[1] = &TrustRecord{NodeID: 1, ApprovedAt: time.Now()}
	hm.mu.Unlock()
	hm.saveTrust() // logs error, must not panic
}

