// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/crypto"
)

// Adversarial replay harness for the pentest findings against the
// handshake trust surface (PPA-001 / PPA-002 family). These tests drive
// the real production paths — handleConnection parses attacker-supplied
// JSON bytes off a stream exactly as the listener does — so they fail
// loudly if the accept/revoke identity binding at processMessage is ever
// relaxed again.
//
// Threat model: the attacker owns a node on the overlay and can open a
// handshake stream to the victim. The stream's authenticated identity is
// the attacker's node ID (that is what the tunnel proved). Everything
// inside the JSON body is attacker-chosen.

// wireStream is a coreapi.Stream that replays a fixed attacker payload
// and reports an attacker-controlled authenticated remote node ID. It is
// the closest fake to what handleConnection sees in production: a real
// stream whose RemoteAddr().Node was established by the transport, not
// by the message body.
type wireStream struct {
	data     []byte
	pos      int
	addr     coreapi.Addr
	writes   [][]byte
	closed   bool
	readDone bool
}

func newWireStream(payload []byte, remoteNode uint32) *wireStream {
	return &wireStream{data: payload, addr: coreapi.Addr{Node: remoteNode}}
}

func (s *wireStream) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		s.readDone = true
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}

func (s *wireStream) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	s.writes = append(s.writes, cp)
	return len(p), nil
}

func (s *wireStream) Close() error                     { s.closed = true; return nil }
func (s *wireStream) LocalAddr() coreapi.Addr          { return coreapi.Addr{} }
func (s *wireStream) LocalPort() uint16                { return 0 }
func (s *wireStream) RemoteAddr() coreapi.Addr         { return s.addr }
func (s *wireStream) RemotePort() uint16               { return 0 }
func (s *wireStream) SetDeadline(time.Time) error      { return nil }
func (s *wireStream) SetReadDeadline(time.Time) error  { return nil }
func (s *wireStream) SetWriteDeadline(time.Time) error { return nil }

// attackPayload marshals a handshake message to the exact bytes an
// attacker would put on the wire.
func attackPayload(t *testing.T, msg *HandshakeMsg) []byte {
	t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal attack payload: %v", err)
	}
	return b
}

func assertNotTrusted(t *testing.T, hm *Manager, nodeID uint32, what string) {
	t.Helper()
	hm.mu.RLock()
	rec, trusted := hm.trusted[nodeID]
	hm.mu.RUnlock()
	if trusted {
		t.Fatalf("ATTACK SUCCEEDED (%s): node %d is trusted, record=%+v", what, nodeID, rec)
	}
}

func assertTrusted(t *testing.T, hm *Manager, nodeID uint32, what string) {
	t.Helper()
	hm.mu.RLock()
	_, trusted := hm.trusted[nodeID]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatalf("ATTACK SUCCEEDED (%s): node %d lost its trust record", what, nodeID)
	}
}

// TestAttackReplay_BareAcceptOverWire replays the original pentest
// payload byte-for-byte through handleConnection: a handshake_accept
// naming the victim node ID, with no public key and no signature, sent
// from an attacker-authenticated stream. This is the exact message that
// used to inject trust for an arbitrary node ID.
func TestAttackReplay_BareAcceptOverWire(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1000)

	const victim = uint32(31337)
	const attacker = uint32(66613)

	payload := attackPayload(t, &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    victim,
		PublicKey: "",
		Signature: "",
		Timestamp: time.Now().Unix(),
	})

	hm.handleConnection(newWireStream(payload, attacker))

	assertNotTrusted(t, hm, victim, "bare empty-pubkey accept over the wire")
	assertNotTrusted(t, hm, attacker, "bare empty-pubkey accept over the wire (attacker self-trust)")
}

// TestAttackReplay_BareAcceptSprayOverWire replays the same bare accept
// against a whole range of victim node IDs from one attacker stream —
// the "harvest the network" form of the attack. Distinct node IDs each
// produce a distinct replay-set hash, so every message reaches the
// identity check rather than being swallowed by replay suppression.
func TestAttackReplay_BareAcceptSprayOverWire(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1001)

	const attacker = uint32(66614)
	for victim := uint32(20000); victim < 20064; victim++ {
		payload := attackPayload(t, &HandshakeMsg{
			Type:      HandshakeAccept,
			NodeID:    victim,
			Timestamp: time.Now().Unix(),
		})
		hm.handleConnection(newWireStream(payload, attacker))
	}

	hm.mu.RLock()
	n := len(hm.trusted)
	hm.mu.RUnlock()
	if n != 0 {
		t.Fatalf("ATTACK SUCCEEDED (bare accept spray): %d trust records injected", n)
	}
}

// TestAttackReplay_BareRevokeOverWire is the destructive half of
// PPA-001: an unauthenticated handshake_revoke naming a victim must not
// strip an existing trust record (a trust-teardown DoS against any peer
// pair on the network).
func TestAttackReplay_BareRevokeOverWire(t *testing.T) {
	t.Parallel()
	hm, rt := newBoundHM(t, 1002)

	const victim = uint32(4242)
	const attacker = uint32(66615)

	hm.mu.Lock()
	hm.trusted[victim] = &TrustRecord{NodeID: victim, ApprovedAt: time.Now()}
	hm.mu.Unlock()

	payload := attackPayload(t, &HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    victim,
		Reason:    "trust revoked",
		Timestamp: time.Now().Unix(),
	})

	hm.handleConnection(newWireStream(payload, attacker))

	assertTrusted(t, hm, victim, "bare revoke over the wire")

	// The revoke handler also tears the tunnel down; a rejected revoke
	// must not have reached that side effect either.
	rt.removedPeersMu.Lock()
	removed := append([]uint32(nil), rt.removedPeers...)
	rt.removedPeersMu.Unlock()
	for _, id := range removed {
		if id == victim {
			t.Fatalf("ATTACK SUCCEEDED (bare revoke): tunnel to victim %d was torn down", victim)
		}
	}
}

// TestAttackReplay_SignedAcceptWithAttackerKey is the upgraded form of
// the attack: rather than a bare message, the attacker mints their own
// ed25519 identity and produces a *cryptographically valid* signature
// over the challenge for the victim's node ID. With no registry record
// to contradict it, signature verification passes — so the only thing
// standing between the attacker and injected trust is the
// accept/revoke-to-transport-identity binding.
func TestAttackReplay_SignedAcceptWithAttackerKey(t *testing.T) {
	t.Parallel()
	const self = uint32(1003)
	hm, _ := newBoundHM(t, self)

	const victim = uint32(777)
	const attacker = uint32(66616)

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate attacker identity: %v", err)
	}
	challenge := fmt.Sprintf("handshake:%d:%d", victim, self)
	sig := ed25519.Sign(id.PrivateKey, []byte(challenge))

	payload := attackPayload(t, &HandshakeMsg{
		Type:      HandshakeAccept,
		NodeID:    victim,
		PublicKey: crypto.EncodePublicKey(id.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().Unix(),
	})

	hm.handleConnection(newWireStream(payload, attacker))

	assertNotTrusted(t, hm, victim, "self-signed accept impersonating a victim node ID")
}

// TestAttackReplay_SignedRevokeWithAttackerKey is the same escalation
// applied to revoke: a valid signature over an attacker-owned key must
// not let them tear down someone else's trust record.
func TestAttackReplay_SignedRevokeWithAttackerKey(t *testing.T) {
	t.Parallel()
	const self = uint32(1004)
	hm, _ := newBoundHM(t, self)

	const victim = uint32(778)
	const attacker = uint32(66617)

	hm.mu.Lock()
	hm.trusted[victim] = &TrustRecord{NodeID: victim, ApprovedAt: time.Now()}
	hm.mu.Unlock()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate attacker identity: %v", err)
	}
	challenge := fmt.Sprintf("handshake:%d:%d", victim, self)
	sig := ed25519.Sign(id.PrivateKey, []byte(challenge))

	payload := attackPayload(t, &HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    victim,
		PublicKey: crypto.EncodePublicKey(id.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().Unix(),
	})

	hm.handleConnection(newWireStream(payload, attacker))

	assertTrusted(t, hm, victim, "self-signed revoke impersonating a victim node ID")
}

// TestAttackReplay_AcceptWithNoAuthenticatedTransport covers the
// registry-relay / no-stream shape: an accept that arrives with no
// authenticated transport underneath it has nothing to bind the claimed
// node ID to, so it must be dropped rather than defaulting to trust.
func TestAttackReplay_AcceptWithNoAuthenticatedTransport(t *testing.T) {
	t.Parallel()
	hm, _ := newBoundHM(t, 1005)

	for _, typ := range []string{HandshakeAccept, HandshakeRevoke} {
		hm.processMessage(nil, &HandshakeMsg{
			Type:      typ,
			NodeID:    999,
			Timestamp: time.Now().Unix(),
		})
	}
	assertNotTrusted(t, hm, 999, "accept with nil stream")
}

// TestAttackReplay_RelayedApprovalWithoutOutgoing is the second pentest
// path: rather than a direct stream, the attacker gets the registry to
// relay an approval for a peer the victim never handshaked with. Without
// a matching outgoing request the approval has no precondition to
// satisfy and must be dropped (PPA-002).
func TestAttackReplay_RelayedApprovalWithoutOutgoing(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	for peer := uint32(50000); peer < 50032; peer++ {
		hm.ProcessRelayedApproval(peer)
	}

	hm.mu.RLock()
	n := len(hm.trusted)
	hm.mu.RUnlock()
	if n != 0 {
		t.Fatalf("ATTACK SUCCEEDED (relayed approval without outgoing): %d trust records injected", n)
	}
}

// TestAttackReplay_RelayedApprovalDuringRevokeCooldown checks the
// stale-approval replay: after a local revoke, an approval still sitting
// in the registry inbox (or replayed by an attacker) must not resurrect
// the trust record during the cooldown window, even when an outgoing
// request exists.
func TestAttackReplay_RelayedApprovalDuringRevokeCooldown(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	const peer = uint32(8181)
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.revoked[peer] = time.Now().Add(5 * time.Minute)
	hm.mu.Unlock()

	hm.ProcessRelayedApproval(peer)

	assertNotTrusted(t, hm, peer, "relayed approval replayed inside the revoke cooldown")
}
