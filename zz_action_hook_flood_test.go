// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"

	"github.com/pilot-protocol/common/decision"
)

// TestActionHookNotInvokedForAlreadyTrustedOrOverCap pins SECURITY_REVIEW_v1.14
// finding M1: the managed action hook (a synchronous authority round-trip in
// enforce mode) must NOT run for handshakes that need no new trust decision —
// an already-trusted peer or over-cap spam — so a peer cannot amplify each
// handshake into an authority call and bypass the anti-flood caps.
func TestActionHookNotInvokedForAlreadyTrustedOrOverCap(t *testing.T) {
	runtime := newTestRuntime()
	manager := NewManager(runtime)
	t.Cleanup(manager.Stop)
	hook := &trustHookStub{outcomes: map[string]decision.Outcome{}}
	manager.SetActionHook(hook)

	hookCalls := func() int {
		hook.mu.Lock()
		defer hook.mu.Unlock()
		return len(hook.before)
	}

	// Already-trusted peer (matching key): the pre-hook fast path accepts
	// without invoking the hook.
	manager.mu.Lock()
	manager.trusted[71] = &TrustRecord{NodeID: 71, PublicKey: "peer-key"}
	manager.mu.Unlock()
	manager.handleRequest(nil, &HandshakeMsg{NodeID: 71, PublicKey: "peer-key", Justification: "join"}, false)
	if n := hookCalls(); n != 0 {
		t.Fatalf("action hook invoked %d times for an already-trusted peer; want 0", n)
	}

	// Over-cap spam: fill the pending queue, then an untrusted, unqueued peer is
	// rejected before the hook.
	manager.mu.Lock()
	for i := uint32(1000); i < 1000+uint32(maxPendingHandshakes); i++ {
		manager.pending[i] = &PendingHandshake{NodeID: i}
	}
	manager.mu.Unlock()
	manager.handleRequest(nil, &HandshakeMsg{NodeID: 5000, PublicKey: "spam-key"}, false)
	if n := hookCalls(); n != 0 {
		t.Fatalf("action hook invoked %d times for over-cap spam; want 0 (rejected before hook)", n)
	}

	// Relayed over-cap spam is likewise rejected before the hook.
	manager.processRelayedRequest(6000, "join")
	if n := hookCalls(); n != 0 {
		t.Fatalf("action hook invoked %d times for over-cap relayed spam; want 0", n)
	}
}
