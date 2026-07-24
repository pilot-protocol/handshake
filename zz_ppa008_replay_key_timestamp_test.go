// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

func TestPPA008_SignedMessageReStampedIsDeduped(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	rt.nodeID = 1
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	const peer = uint32(909)
	challenge := fmt.Sprintf("handshake:%d:%d", peer, rt.nodeID)
	sig := base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge)))
	pub := base64.StdEncoding.EncodeToString(id.PublicKey)

	first := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    peer,
		PublicKey: pub,
		Signature: sig,
		Timestamp: time.Now().Unix(),
	}

	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()
	hm.processMessage(nil, first)

	hm.mu.RLock()
	_, clearedByFirst := hm.outgoing[peer]
	hm.mu.RUnlock()
	if clearedByFirst {
		t.Fatal("first signed reject should have dispatched and cleared outgoing")
	}

	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()

	reStamped := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    peer,
		PublicKey: pub,
		Signature: sig,
		Timestamp: first.Timestamp + 7,
	}
	hm.processMessage(nil, reStamped)

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[peer]
	hm.mu.RUnlock()
	if !stillOutgoing {
		t.Fatal("re-stamped copy of a captured signed message must hit the replay set (timestamp must not be part of the key)")
	}
}

func TestPPA008_DistinctSendersGetDistinctReplayKeys(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.mu.Lock()
	hm.outgoing[11] = time.Now()
	hm.outgoing[22] = time.Now()
	hm.mu.Unlock()

	ts := time.Now().Unix()
	hm.processMessage(nil, &HandshakeMsg{Type: HandshakeReject, NodeID: 11, Timestamp: ts})
	hm.processMessage(nil, &HandshakeMsg{Type: HandshakeReject, NodeID: 22, Timestamp: ts})

	hm.mu.RLock()
	_, out11 := hm.outgoing[11]
	_, out22 := hm.outgoing[22]
	hm.mu.RUnlock()
	if out11 || out22 {
		t.Fatal("distinct senders must get distinct replay keys and both dispatch — no false dedup")
	}
}
