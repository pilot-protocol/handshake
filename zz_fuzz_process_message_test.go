// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// Port 444 accepts one JSON message per connection from any node that can
// reach it — no prior trust required, which is the whole point of a
// handshake. Everything in HandshakeMsg is attacker-chosen, including the
// base64 public_key and signature that feed the Ed25519 verify.

// fuzzHM builds a Manager over a fake runtime with a registry whose Lookup
// returns three deliberately different shapes, so a fuzzed node_id can land
// on each branch of the registry-binding check:
//
//	node 1 — a well-formed registered key (pubkey-match branch)
//	node 2 — a registered key that is valid base64 but the wrong length
//	node 3 — a registered key that is not valid base64 at all
//
// Nodes 2 and 3 are the interesting ones: verifyKey is taken from the
// registry response and handed to the base64 decoder and then to the
// signature verify.
func fuzzHM(tb testing.TB) (*Manager, ed25519.PublicKey) {
	tb.Helper()
	rt := newFakeRuntime()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		tb.Fatalf("identity: %v", err)
	}
	rt.identity = id
	rt.nodeID = 4242

	good := crypto.EncodePublicKey(id.PublicKey)
	rt.registry.setLookup(1, map[string]interface{}{"public_key": good})
	rt.registry.setLookup(2, map[string]interface{}{
		"public_key": base64.StdEncoding.EncodeToString(make([]byte, 7)),
	})
	rt.registry.setLookup(3, map[string]interface{}{"public_key": "!!!not-base64!!!"})

	hm := NewManager(rt)
	tb.Cleanup(hm.Stop)
	return hm, id.PublicKey
}

// FuzzHandshakeConnection drives raw connection bytes through the exact path
// a remote peer reaches: bounded read, json.Unmarshal into HandshakeMsg, then
// processMessage. Seeds cover each message type plus the malformed-base64 and
// wrong-length key shapes explicitly.
func FuzzHandshakeConnection(f *testing.F) {
	hm, pub := fuzzHM(f)

	add := func(v map[string]interface{}) {
		b, err := json.Marshal(v)
		if err == nil {
			f.Add(b)
		}
	}

	now := time.Now().Unix()
	goodKey := crypto.EncodePublicKey(pub)

	for _, msgType := range []string{
		HandshakeRequest, HandshakeAccept, HandshakeReject, HandshakeRevoke, "", "bogus",
	} {
		add(map[string]interface{}{
			"type": msgType, "node_id": 1, "public_key": goodKey,
			"signature": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
			"timestamp": now,
		})
	}

	// Wrong-length key material on both the key and the signature — the
	// exact shape that panics an unguarded ed25519.Verify.
	for _, n := range []int{0, 1, 7, 31, 33, 63, 64, 65, 128} {
		add(map[string]interface{}{
			"type": HandshakeRequest, "node_id": 9,
			"public_key": base64.StdEncoding.EncodeToString(make([]byte, n)),
			"signature":  base64.StdEncoding.EncodeToString(make([]byte, n)),
			"timestamp":  now,
		})
	}

	// Registry-supplied keys that are malformed (nodes 2 and 3).
	for _, nodeID := range []int{1, 2, 3} {
		add(map[string]interface{}{
			"type": HandshakeRequest, "node_id": nodeID, "public_key": goodKey,
			"signature": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
			"timestamp": now,
		})
	}

	// Non-base64 key/signature, missing fields, extreme timestamps.
	add(map[string]interface{}{"type": HandshakeRequest, "node_id": 1, "public_key": "@@@@", "signature": "@@@@", "timestamp": now})
	add(map[string]interface{}{"type": HandshakeRequest, "node_id": 1, "timestamp": now})
	add(map[string]interface{}{"type": HandshakeAccept, "node_id": 1, "public_key": goodKey, "signature": "", "timestamp": now})
	add(map[string]interface{}{"type": HandshakeRequest, "node_id": 1, "public_key": goodKey, "timestamp": int64(1) << 62})
	add(map[string]interface{}{"type": HandshakeRequest, "node_id": 1, "public_key": goodKey, "timestamp": -(int64(1) << 62)})
	add(map[string]interface{}{
		"type": HandshakeRequest, "node_id": 1, "public_key": goodKey,
		"justification": string(make([]byte, 4096)), "timestamp": now,
	})

	// Structural junk the JSON decoder must reject rather than crash on.
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte(`{"node_id":99999999999999999999}`))
	f.Add([]byte(`{"type":123}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		// handleConnection has its own recover; call it so the bounded-read
		// and decode framing are covered, then assert no panic escaped by
		// re-running the decoded message through processMessage directly.
		hm.handleConnection(newMockStreamData(data))

		var msg HandshakeMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		// Fresh timestamp on half the iterations so the age gate does not
		// short-circuit every input before the signature path runs.
		msg.Timestamp = time.Now().Unix()
		hm.processMessage(newMockStreamData(nil), &msg)
	})
}

// FuzzHandshakeProcessMessage builds the message struct from fuzzer-chosen
// fields instead of going through JSON, so the fuzzer spends its budget on
// the crypto/validation branches rather than on rediscovering JSON syntax.
func FuzzHandshakeProcessMessage(f *testing.F) {
	hm, pub := fuzzHM(f)
	goodKey := crypto.EncodePublicKey(pub)

	f.Add(HandshakeRequest, uint32(1), goodKey, "")
	f.Add(HandshakeRequest, uint32(2), goodKey, "AAAA")
	f.Add(HandshakeRequest, uint32(3), goodKey, "AAAA")
	f.Add(HandshakeAccept, uint32(1), "", "")
	f.Add(HandshakeRevoke, uint32(1), goodKey, "@@")
	f.Add("", uint32(0), "", "")
	f.Add(HandshakeReject, uint32(0xFFFFFFFF), base64.StdEncoding.EncodeToString(make([]byte, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 63)))

	f.Fuzz(func(t *testing.T, msgType string, nodeID uint32, pubKeyB64, sigB64 string) {
		if len(pubKeyB64) > 8192 || len(sigB64) > 8192 || len(msgType) > 1024 {
			return
		}
		msg := &HandshakeMsg{
			Type:      msgType,
			NodeID:    nodeID,
			PublicKey: pubKeyB64,
			Signature: sigB64,
			Timestamp: time.Now().Unix(),
			// Vary the justification so the replay-set hash differs per
			// iteration; otherwise every input after the first is dropped
			// by the replay guard.
			Justification: fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		hm.processMessage(newMockStreamData(nil), msg)
	})
}
