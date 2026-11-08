// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// Regression tests: accept, reject and revoke must carry a key and a
// valid signature, and without the registry, the key a trusted peer's
// record is bound to.

// A message with no key and no signature is refused for every type,
// including over a stream from the claimed sender.
func TestProcessMessage_UnsignedAcceptRejectRevokeRefused(t *testing.T) {
	t.Parallel()
	const peer = uint32(810)
	stream := &addrStream{addr: coreapi.Addr{Node: peer}}

	t.Run("accept", func(t *testing.T) {
		hm := newTestHM(t, "")
		t.Cleanup(hm.Stop)
		hm.mu.Lock()
		hm.outgoing[peer] = time.Now()
		hm.mu.Unlock()
		hm.processMessage(stream, &HandshakeMsg{Type: HandshakeAccept, NodeID: peer, Timestamp: time.Now().Unix()})
		if trustRecordOf(hm, peer) != nil {
			t.Fatal("an unsigned accept established trust")
		}
	})
	t.Run("reject", func(t *testing.T) {
		hm := newTestHM(t, "")
		t.Cleanup(hm.Stop)
		hm.mu.Lock()
		hm.outgoing[peer] = time.Now()
		hm.mu.Unlock()
		hm.processMessage(stream, &HandshakeMsg{Type: HandshakeReject, NodeID: peer, Timestamp: time.Now().Unix()})
		hm.mu.RLock()
		_, out := hm.outgoing[peer]
		hm.mu.RUnlock()
		if !out {
			t.Fatal("an unsigned reject cancelled the outgoing request")
		}
	})
	t.Run("revoke", func(t *testing.T) {
		hm := newTestHM(t, "")
		t.Cleanup(hm.Stop)
		seedTrusted(hm, peer, "")
		hm.processMessage(stream, &HandshakeMsg{Type: HandshakeRevoke, NodeID: peer, Timestamp: time.Now().Unix()})
		if trustRecordOf(hm, peer) == nil {
			t.Fatal("an unsigned revoke dropped trust")
		}
	})
	t.Run("key without signature", func(t *testing.T) {
		hm := newTestHM(t, "")
		t.Cleanup(hm.Stop)
		seedTrusted(hm, peer, "")
		msg := signedMsg(deterministicIdentity(81), HandshakeRevoke, peer, hm.rt.NodeID())
		msg.Signature = ""
		hm.processMessage(stream, msg)
		if trustRecordOf(hm, peer) == nil {
			t.Fatal("a revoke without a signature dropped trust")
		}
	})
}

// With the registry unreachable, a revoke for a key-bound record must be
// signed by the bound key: a signature by whatever key the message brings
// proves nothing.
func TestProcessMessage_RevokeWithoutRegistryNeedsBoundKey(t *testing.T) {
	t.Parallel()
	const peer = uint32(820)
	trustedID := deterministicIdentity(82)
	otherID := deterministicIdentity(83)
	stream := &addrStream{addr: coreapi.Addr{Node: peer}}

	hm, rt := newFakeHM(t)
	rt.nodeID = 1
	rt.registry.setLookupErr(peer, errRegistryDown)
	seedTrusted(hm, peer, keyOf(trustedID))

	hm.processMessage(stream, signedMsg(otherID, HandshakeRevoke, peer, 1))
	if trustRecordOf(hm, peer) == nil {
		t.Fatal("a revoke signed by a key other than the bound one dropped trust")
	}

	hm.processMessage(stream, signedMsg(trustedID, HandshakeRevoke, peer, 1))
	if trustRecordOf(hm, peer) != nil {
		t.Fatal("a revoke signed by the bound key must still revoke")
	}
}
