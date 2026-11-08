// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// Regression tests for trust that is granted or bound only against a key
// the registry confirmed, and for IsTrustedWithKey with no key.

var errRegistryDown = errors.New("registry down")

// waitFor polls cond until it holds or two seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// boundKeyOf reads a record's key under the lock: background binds
// write it in place.
func boundKeyOf(hm *Manager, nodeID uint32) (key string, ok bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	rec, ok := hm.trusted[nodeID]
	if !ok {
		return "", false
	}
	return rec.PublicKey, true
}

func pendingOf(hm *Manager, nodeID uint32) *PendingHandshake {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.pending[nodeID]
}

func dialsTo(rt *fakeRuntime, nodeID uint32) int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	n := 0
	for _, c := range rt.dialCalls {
		if c.NodeID == nodeID {
			n++
		}
	}
	return n
}

func lookupsOf(rt *fakeRuntime, nodeID uint32) int {
	rt.registry.mu.Lock()
	defer rt.registry.mu.Unlock()
	n := 0
	for _, id := range rt.registry.lookupCalls {
		if id == nodeID {
			n++
		}
	}
	return n
}

// keyedFakeRuntime is a fakeRuntime whose allowlist pins keys
// (KeyedTrustChecker), recording the key it was asked about.
type keyedFakeRuntime struct {
	*fakeRuntime
	pinned map[uint32]string
	asked  chan string
}

func (r *keyedFakeRuntime) IsTrustedWithKey(nodeID uint32, pubKeyB64 string) (string, bool) {
	select {
	case r.asked <- pubKeyB64:
	default:
	}
	if want, ok := r.pinned[nodeID]; ok && want == pubKeyB64 {
		return "pinned-agent", true
	}
	return "", false
}

// --- item 1: IsTrustedWithKey ---

// An unbound record does not take the key a caller presents; a registry
// lookup binds it to the registry's key, which then decides.
func TestIsTrustedWithKey_UnboundRecordBindsToRegistryKeyNotPresentedKey(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyB})
	seedTrusted(hm, 42, "")

	if !hm.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("an unbound record is node-ID trust until the registry binds it")
	}
	waitFor(t, "the registry bind", func() bool {
		key, _ := boundKeyOf(hm, 42)
		return key != ""
	})
	if key, _ := boundKeyOf(hm, 42); key != bindKeyB {
		t.Fatalf("record bound to %q, want the registry's key, not the presented one", key)
	}
	if hm.IsTrustedWithKey(42, bindKeyA) {
		t.Fatal("once bound to the registry's key, another key is not trusted")
	}
}

// Trust checks run per packet: an unbound record starts at most one
// registry lookup per bindRetryInterval, also while the lookup fails.
func TestIsTrustedWithKey_RegistryBindIsRateLimited(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.registry.setLookupErr(42, errRegistryDown)
	seedTrusted(hm, 42, "")

	for i := 0; i < 50; i++ {
		hm.IsTrustedWithKey(42, bindKeyA)
	}
	waitFor(t, "the first lookup", func() bool { return lookupsOf(rt, 42) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if n := lookupsOf(rt, 42); n != 1 {
		t.Fatalf("%d registry lookups for one unbound record, want 1 per retry interval", n)
	}
	if key, ok := boundKeyOf(hm, 42); !ok || key != "" {
		t.Fatalf("a failed lookup must leave the record as it was: key %q, present %v", key, ok)
	}
}

// --- item 2: direct requests ---

// The TrustAutoApprove rule needs the registry to confirm the requester's
// key, like the other rules. A request whose lookup fails waits for the
// operator instead of being trusted under whatever node ID it claims.
func TestProcessMessage_AutoApproveWithoutRegistryConfirmationIsPending(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.trustAutoApprove = true
	rt.registry.setLookupErr(500, errRegistryDown)

	attacker := deterministicIdentity(66)
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: 666}},
		signedMsg(attacker, HandshakeRequest, 500, 1))

	if trustRecordOf(hm, 500) != nil {
		t.Fatal("auto-approve trusted a node ID whose key the registry did not confirm")
	}
	p := pendingOf(hm, 500)
	if p == nil {
		t.Fatal("the unconfirmed request should wait for the operator")
	}
	if p.KeyConfirmed {
		t.Fatal("pending entry marked confirmed although the registry did not answer")
	}
}

// The same request, confirmed by the registry, is auto-approved and bound
// to the confirmed key.
func TestProcessMessage_AutoApproveWithRegistryConfirmationTrusts(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.trustAutoApprove = true
	peer := deterministicIdentity(67)
	rt.registry.setLookup(500, map[string]interface{}{"public_key": keyOf(peer)})

	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: 500}},
		signedMsg(peer, HandshakeRequest, 500, 1))

	rec := trustRecordOf(hm, 500)
	if rec == nil {
		t.Fatal("a confirmed request must be auto-approved")
	}
	if rec.PublicKey != keyOf(peer) {
		t.Fatalf("record bound to %q, want the confirmed key", rec.PublicKey)
	}
}

// A request under another key the registry could not confirm neither
// drops a bound record nor rebinds it, and is not answered.
func TestHandleRequest_UnconfirmedKeyKeepsBoundRecord(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	seedTrusted(hm, 42, bindKeyA)

	hm.handleRequest(nil, &HandshakeMsg{Type: HandshakeRequest, NodeID: 42, PublicKey: bindKeyB}, false)
	hm.Stop() // drain any accept it started

	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("an unconfirmed key changed the bound record: %+v", rec)
	}
	if pendingOf(hm, 42) != nil {
		t.Fatal("an unconfirmed request for a trusted node must not be queued")
	}
	if n := dialsTo(rt, 42); n != 0 {
		t.Fatalf("an unconfirmed request under another key was answered (%d dials)", n)
	}
}

// An unbound record does not take the key of an unconfirmed request; the
// registry binds it.
func TestHandleRequest_UnconfirmedKeyDoesNotBindUnboundRecord(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyB})
	seedTrusted(hm, 42, "")

	hm.handleRequest(nil, &HandshakeMsg{Type: HandshakeRequest, NodeID: 42, PublicKey: bindKeyA}, false)
	waitFor(t, "the registry bind", func() bool {
		key, _ := boundKeyOf(hm, 42)
		return key != ""
	})
	if key, _ := boundKeyOf(hm, 42); key != bindKeyB {
		t.Fatalf("record bound to %q, want the registry's key", key)
	}
}

// An unconfirmed request does not replace a confirmed pending one under
// another key, so the operator approves what the registry confirmed.
func TestHandleRequest_UnconfirmedRequestDoesNotReplaceConfirmedPending(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)

	hm.handleRequest(nil, &HandshakeMsg{Type: HandshakeRequest, NodeID: 42, PublicKey: bindKeyA, Justification: "real"}, true)
	hm.handleRequest(nil, &HandshakeMsg{Type: HandshakeRequest, NodeID: 42, PublicKey: bindKeyB, Justification: "forged"}, false)

	p := pendingOf(hm, 42)
	if p == nil || p.PublicKey != bindKeyA || !p.KeyConfirmed || p.Justification != "real" {
		t.Fatalf("confirmed pending request was replaced: %+v", p)
	}
}

// Approving a request the registry did not confirm binds the record to
// the registry's key, never to the key the request carried.
func TestApproveHandshake_UnconfirmedPendingBindsRegistryKey(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.registry.setLookup(77, map[string]interface{}{"public_key": bindKeyB})
	hm.mu.Lock()
	hm.pending[77] = &PendingHandshake{NodeID: 77, PublicKey: bindKeyA, ReceivedAt: time.Now()}
	hm.mu.Unlock()

	if err := hm.ApproveHandshake(77); err != nil {
		t.Fatalf("ApproveHandshake: %v", err)
	}
	if key, ok := boundKeyOf(hm, 77); !ok || key == bindKeyA {
		t.Fatalf("the unconfirmed key bound the record at approval: key %q, present %v", key, ok)
	}
	hm.Stop() // waits for the backfill
	if rec := trustRecordOf(hm, 77); rec == nil || rec.PublicKey != bindKeyB {
		t.Fatalf("record bound to %+v, want the registry's key", rec)
	}
}

// Whether a pending request's key was confirmed survives a restart.
func TestPendingKeyConfirmedPersists(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "identity.json")
	hm := newTestHM(t, path)
	t.Cleanup(hm.Stop)
	hm.mu.Lock()
	hm.pending[1] = &PendingHandshake{NodeID: 1, PublicKey: bindKeyA, KeyConfirmed: true, ReceivedAt: time.Now()}
	hm.pending[2] = &PendingHandshake{NodeID: 2, PublicKey: bindKeyB, ReceivedAt: time.Now()}
	hm.mu.Unlock()
	hm.saveTrust()

	hm2 := newTestHM(t, path)
	t.Cleanup(hm2.Stop)
	if p := pendingOf(hm2, 1); p == nil || !p.KeyConfirmed {
		t.Fatalf("confirmed flag lost: %+v", p)
	}
	if p := pendingOf(hm2, 2); p == nil || p.KeyConfirmed {
		t.Fatalf("unconfirmed entry loaded as confirmed: %+v", p)
	}
}

// An accept the registry did not confirm completes the request but does
// not bind its key; the registry's key is bound instead.
func TestHandleAccept_UnconfirmedKeyBindsRegistryKey(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyB})
	hm.mu.Lock()
	hm.outgoing[42] = time.Now()
	hm.mu.Unlock()

	hm.handleAccept(&HandshakeMsg{Type: HandshakeAccept, NodeID: 42, PublicKey: bindKeyA}, false)

	if trustRecordOf(hm, 42) == nil {
		t.Fatal("a solicited accept must still complete the handshake")
	}
	waitFor(t, "the registry bind", func() bool {
		key, _ := boundKeyOf(hm, 42)
		return key != ""
	})
	if key, _ := boundKeyOf(hm, 42); key != bindKeyB {
		t.Fatalf("record bound to %q, want the registry's key", key)
	}
}

// An unconfirmed accept under another key leaves a bound record and the
// outgoing request alone.
func TestHandleAccept_UnconfirmedDifferentKeyIgnored(t *testing.T) {
	t.Parallel()
	hm, _ := newFakeHM(t)
	seedTrusted(hm, 42, bindKeyA)
	hm.mu.Lock()
	hm.outgoing[42] = time.Now()
	hm.mu.Unlock()

	hm.handleAccept(&HandshakeMsg{Type: HandshakeAccept, NodeID: 42, PublicKey: bindKeyB}, false)

	if rec := trustRecordOf(hm, 42); rec == nil || rec.PublicKey != bindKeyA {
		t.Fatalf("an unconfirmed accept changed the bound record: %+v", rec)
	}
	hm.mu.RLock()
	_, out := hm.outgoing[42]
	hm.mu.RUnlock()
	if !out {
		t.Fatal("an ignored accept must not consume the outgoing request")
	}
}

// --- item 2: relayed requests ---

// No automatic rule trusts a relayed request when the registry cannot
// confirm the sender's key; each waits for the operator.
func TestProcessRelayedRequest_NoRegistryKeyMeansNoAutoTrust(t *testing.T) {
	setTestTrustedAgents(t, []testAgent{{NodeID: 303, Hostname: "agent"}})

	cases := []struct {
		name  string
		setup func(hm *Manager, rt *fakeRuntime, peer uint32)
	}{
		{"auto-approve", func(hm *Manager, rt *fakeRuntime, peer uint32) { rt.trustAutoApprove = true }},
		{"mutual", func(hm *Manager, rt *fakeRuntime, peer uint32) {
			hm.mu.Lock()
			hm.outgoing[peer] = time.Now()
			hm.mu.Unlock()
		}},
		{"same network", func(hm *Manager, rt *fakeRuntime, peer uint32) {
			rt.registry.setLookup(1, map[string]interface{}{"networks": []interface{}{float64(9)}})
		}},
		{"trusted agent", func(hm *Manager, rt *fakeRuntime, peer uint32) { rt.trustChecker = testTrustChecker{} }},
	}
	for _, tc := range cases {
		for _, lookup := range []struct {
			name string
			resp map[string]interface{}
			err  error
		}{
			{"lookup fails", nil, errRegistryDown},
			{"no key listed", map[string]interface{}{"networks": []interface{}{float64(9)}, "public_key": ""}, nil},
		} {
			t.Run(tc.name+", "+lookup.name, func(t *testing.T) {
				const peer = uint32(303)
				hm, rt := newFakeHM(t)
				rt.nodeID = 1
				if lookup.err != nil {
					rt.registry.setLookupErr(peer, lookup.err)
				} else {
					rt.registry.setLookup(peer, lookup.resp)
				}
				tc.setup(hm, rt, peer)

				hm.processRelayedRequest(peer, "relayed")

				if rec := trustRecordOf(hm, peer); rec != nil {
					t.Fatalf("trusted without a registry-confirmed key: %+v", rec)
				}
				if pendingOf(hm, peer) == nil {
					t.Fatal("the request should wait for the operator")
				}
			})
		}
	}
}

// With the registry's key, each rule trusts the relayed sender, bound to
// that key from the start.
func TestProcessRelayedRequest_RulesBindRegistryKey(t *testing.T) {
	setTestTrustedAgents(t, []testAgent{{NodeID: 304, Hostname: "agent"}})

	cases := []struct {
		name  string
		setup func(hm *Manager, rt *fakeRuntime, peer uint32)
	}{
		{"auto-approve", func(hm *Manager, rt *fakeRuntime, peer uint32) { rt.trustAutoApprove = true }},
		{"mutual", func(hm *Manager, rt *fakeRuntime, peer uint32) {
			hm.mu.Lock()
			hm.outgoing[peer] = time.Now()
			hm.mu.Unlock()
		}},
		{"same network", func(hm *Manager, rt *fakeRuntime, peer uint32) {
			rt.registry.setLookup(1, map[string]interface{}{"networks": []interface{}{float64(9)}})
		}},
		{"trusted agent", func(hm *Manager, rt *fakeRuntime, peer uint32) { rt.trustChecker = testTrustChecker{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const peer = uint32(304)
			hm, rt := newFakeHM(t)
			rt.nodeID = 1
			rt.registry.setLookup(peer, map[string]interface{}{"networks": []interface{}{float64(9)}, "public_key": bindKeyA})
			tc.setup(hm, rt, peer)

			hm.processRelayedRequest(peer, "relayed")

			rec := trustRecordOf(hm, peer)
			if rec == nil {
				t.Fatal("a relayed request the registry confirmed should be trusted by this rule")
			}
			if rec.PublicKey != bindKeyA {
				t.Fatalf("record bound to %q, want the registry's key", rec.PublicKey)
			}
		})
	}
}

// The registry's key also reaches a pinned allowlist entry on the relay
// path, which used to be asked with no key and could never match.
func TestProcessRelayedRequest_PinnedAgentCheckedAgainstRegistryKey(t *testing.T) {
	t.Parallel()
	const peer = uint32(305)
	for _, tc := range []struct {
		name    string
		regKey  string
		trusted bool
	}{
		{"registry lists the pinned key", bindKeyA, true},
		{"registry lists another key", bindKeyB, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &keyedFakeRuntime{fakeRuntime: newFakeRuntime(), pinned: map[uint32]string{peer: bindKeyA}, asked: make(chan string, 1)}
			rt.registry.setLookup(peer, map[string]interface{}{"public_key": tc.regKey})
			hm := NewManager(rt)
			t.Cleanup(hm.Stop)

			hm.processRelayedRequest(peer, "relayed")

			select {
			case got := <-rt.asked:
				if got != tc.regKey {
					t.Fatalf("allowlist asked with %q, want the registry's key", got)
				}
			default:
				t.Fatal("the allowlist was not asked")
			}
			if (trustRecordOf(hm, peer) != nil) != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trustRecordOf(hm, peer) != nil, tc.trusted)
			}
		})
	}
}

// A relayed request for a trusted node ID whose registry key is no longer
// the bound one drops the stale record and is handled as a new request.
func TestProcessRelayedRequest_RebindingDropsStaleRecord(t *testing.T) {
	t.Parallel()
	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.registry.setLookup(42, map[string]interface{}{"public_key": bindKeyB})
	seedTrusted(hm, 42, bindKeyA)

	hm.processRelayedRequest(42, "new holder")

	if rec := trustRecordOf(hm, 42); rec != nil {
		t.Fatalf("stale record survived: %+v", rec)
	}
	if pendingOf(hm, 42) == nil {
		t.Fatal("the new key holder's request should wait for the operator")
	}
}
