// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/crypto"
)

type addrStream struct {
	addr coreapi.Addr
}

func (s *addrStream) Read(p []byte) (int, error)       { return 0, errStub("addrStream: not implemented") }
func (s *addrStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *addrStream) Close() error                     { return nil }
func (s *addrStream) LocalAddr() coreapi.Addr          { return coreapi.Addr{} }
func (s *addrStream) LocalPort() uint16                { return 0 }
func (s *addrStream) RemoteAddr() coreapi.Addr         { return s.addr }
func (s *addrStream) RemotePort() uint16               { return 0 }
func (s *addrStream) SetDeadline(time.Time) error      { return nil }
func (s *addrStream) SetReadDeadline(time.Time) error  { return nil }
func (s *addrStream) SetWriteDeadline(time.Time) error { return nil }

func signedHandshakeRequest(t *testing.T, id *crypto.Identity, claimedNodeID, selfNodeID uint32, justification string) *HandshakeMsg {
	t.Helper()
	challenge := fmt.Sprintf("handshake:%d:%d", claimedNodeID, selfNodeID)
	sig := id.Sign([]byte(challenge))
	return &HandshakeMsg{
		Type:          HandshakeRequest,
		NodeID:        claimedNodeID,
		PublicKey:     base64.StdEncoding.EncodeToString(id.PublicKey),
		Signature:     base64.StdEncoding.EncodeToString(sig),
		Justification: justification,
		Timestamp:     time.Now().Unix(),
	}
}

func TestProcessMessageEmptyPublicKeyRequestRejected(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	rt.trustAutoApprove = true
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    424242,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, pending := hm.pending[424242]
	_, trusted := hm.trusted[424242]
	hm.mu.RUnlock()
	if pending {
		t.Fatal("empty-pubkey handshake_request must never be enqueued in pending")
	}
	if trusted {
		t.Fatal("empty-pubkey handshake_request must never be auto-approved, even with trust-auto-approve on")
	}
}

func TestProcessMessageEmptyPublicKeyWithSignaturePresentStillRejected(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	rt.trustAutoApprove = true
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    555555,
		Signature: "not-empty-but-meaningless-without-a-pubkey",
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, pending := hm.pending[555555]
	_, trusted := hm.trusted[555555]
	hm.mu.RUnlock()
	if pending || trusted {
		t.Fatal("handshake_request with empty PublicKey must be rejected regardless of Signature content")
	}
}

func TestProcessMessageEmptySignatureWithPublicKeyRejected(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	rt.trustAutoApprove = true
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	msg := &HandshakeMsg{
		Type:      HandshakeRequest,
		NodeID:    666666,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, pending := hm.pending[666666]
	_, trusted := hm.trusted[666666]
	hm.mu.RUnlock()
	if pending || trusted {
		t.Fatal("handshake_request with non-empty PublicKey but empty Signature must be rejected")
	}
}

func TestPendingQueuePerSourceCapPreventsSingleSourceExhaustion(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	attacker, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	streamA := &addrStream{addr: coreapi.Addr{Network: 0, Node: 111}}

	for i := 0; i < maxPendingPerSource; i++ {
		nodeID := uint32(5000 + i)
		msg := signedHandshakeRequest(t, attacker, nodeID, rt.nodeID, "spam")
		hm.processMessage(streamA, msg)
		hm.mu.RLock()
		_, ok := hm.pending[nodeID]
		hm.mu.RUnlock()
		if !ok {
			t.Fatalf("request %d from source A should have been accepted (under per-source cap)", i)
		}
	}

	hm.mu.RLock()
	countAfterFill := len(hm.pending)
	hm.mu.RUnlock()
	if countAfterFill != maxPendingPerSource {
		t.Fatalf("pending count = %d, want %d", countAfterFill, maxPendingPerSource)
	}

	overCapMsg := signedHandshakeRequest(t, attacker, 6000, rt.nodeID, "spam-overflow")
	hm.processMessage(streamA, overCapMsg)
	hm.mu.RLock()
	_, overCapAccepted := hm.pending[6000]
	hm.mu.RUnlock()
	if overCapAccepted {
		t.Fatal("source A should not be able to exceed its per-source pending cap")
	}

	victim, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	streamB := &addrStream{addr: coreapi.Addr{Network: 0, Node: 222}}
	legitMsg := signedHandshakeRequest(t, victim, 7000, rt.nodeID, "legitimate request")
	hm.processMessage(streamB, legitMsg)

	hm.mu.RLock()
	_, legitAccepted := hm.pending[7000]
	hm.mu.RUnlock()
	if !legitAccepted {
		t.Fatal("a request from a different source must still get a pending slot after source A is capped")
	}
}

func TestJustificationSanitizedStripsControlCharsAndNewlines(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	attacker, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	dirty := "line-one\nline-two\r\ttab\x00null\x1bescape"
	msg := signedHandshakeRequest(t, attacker, 8000, rt.nodeID, dirty)
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	p, ok := hm.pending[8000]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("pending[8000] missing")
	}
	if p.Justification == dirty {
		t.Fatalf("justification was not sanitized: %q", p.Justification)
	}
	for _, r := range p.Justification {
		if r == '\n' || r == '\r' || r == '\t' || r == 0x00 || r == 0x1b {
			t.Fatalf("sanitized justification still contains control char %q: %q", r, p.Justification)
		}
	}
	if p.Justification != "line-oneline-twotabnullescape" {
		t.Fatalf("unexpected sanitized justification: %q", p.Justification)
	}
}

func TestJustificationSanitizationAppliedOnRelayedPath(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	dirty := "hello\nworld\x00"
	hm.processRelayedRequest(9000, dirty)

	hm.mu.RLock()
	p, ok := hm.pending[9000]
	hm.mu.RUnlock()
	if !ok {
		t.Fatal("pending[9000] missing")
	}
	if p.Justification != "helloworld" {
		t.Fatalf("relayed justification not sanitized: %q", p.Justification)
	}
}
