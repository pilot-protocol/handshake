// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

func newBoundHM(t *testing.T, selfNodeID uint32) (*Manager, *testRuntime) {
	t.Helper()
	rt := newTestRuntime()
	rt.nodeID = selfNodeID
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)
	return hm, rt
}

func TestPPA001_ForgedUnsignedAcceptForVictimRejected(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1)

	const victim = uint32(700)
	const attacker = uint32(666)

	msg := &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    victim,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: attacker}}, msg)

	hm.mu.RLock()
	_, trusted := hm.trusted[victim]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("forged unsigned accept from a non-matching authenticated node must not inject trust")
	}
}

func TestPPA001_UnsignedAcceptWithNoStreamRejected(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1)

	msg := &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    44,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, trusted := hm.trusted[44]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("accept with no authenticated transport must not inject trust")
	}
}

func TestPPA001_HonestAcceptOverMatchingStreamTrusts(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1)

	const peer = uint32(500)
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()

	msg := &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    peer,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: peer}}, msg)

	hm.mu.RLock()
	_, trusted := hm.trusted[peer]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("honest accept over a matching authenticated stream must still establish trust")
	}
}

func TestPPA001_ForgedUnsignedRevokeForVictimRejected(t *testing.T) {
	t.Parallel()
	hm, rt := newBoundHM(t, 1)

	const victim = uint32(700)
	const attacker = uint32(666)

	hm.mu.Lock()
	hm.trusted[victim] = &TrustRecord{NodeID: victim, ApprovedAt: time.Now()}
	hm.mu.Unlock()

	msg := &HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    victim,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: attacker}}, msg)

	hm.mu.RLock()
	_, stillTrusted := hm.trusted[victim]
	hm.mu.RUnlock()
	if !stillTrusted {
		t.Fatal("forged unsigned revoke from a non-matching authenticated node must not revoke trust")
	}

	rt.removedPeersMu.Lock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.removedPeersMu.Unlock()
	for _, id := range removed {
		if id == victim {
			t.Fatal("forged revoke must not tear down the victim's tunnel")
		}
	}
}

func TestPPA001_HonestRevokeOverMatchingStreamRevokes(t *testing.T) {
	t.Parallel()
	hm, rt := newBoundHM(t, 1)

	const peer = uint32(800)
	hm.mu.Lock()
	hm.trusted[peer] = &TrustRecord{NodeID: peer, ApprovedAt: time.Now()}
	hm.mu.Unlock()

	msg := &HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    peer,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(&addrStream{addr: coreapi.Addr{Node: peer}}, msg)

	hm.mu.RLock()
	_, stillTrusted := hm.trusted[peer]
	hm.mu.RUnlock()
	if stillTrusted {
		t.Fatal("honest revoke over a matching authenticated stream must revoke trust")
	}

	rt.removedPeersMu.Lock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.removedPeersMu.Unlock()
	var tornDown bool
	for _, id := range removed {
		if id == peer {
			tornDown = true
		}
	}
	if !tornDown {
		t.Fatal("honest revoke must tear down the peer's tunnel")
	}
}
