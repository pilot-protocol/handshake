// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// Adversarial replay for the remote-panic finding: a handshake message
// whose public_key is well-formed base64 but decodes to something other
// than 32 bytes used to reach ed25519.Verify, which panics on a
// wrong-size key. A panic inside the handshake listener is a remote DoS
// against any node reachable on the handshake port.
//
// The fix is two-layer: crypto.Verify (common) length-guards before
// calling into ed25519, and handleConnection carries a recover() so any
// future panic inside the dispatch drops one connection rather than the
// process. Both layers are exercised here.

// malformedKeySizes covers every interesting wrong length: empty-ish,
// truncated, off-by-one either side of the real key size, signature-
// sized (a plausible copy/paste confusion), and oversized.
var malformedKeySizes = []int{1, 2, 15, 16, 31, 33, 63, 64, 65, 128, 1024, 4096}

func randomB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestAttackReplay_CryptoVerifyRejectsWrongLengthKeys pins the common
// v0.5.9 guard directly: crypto.Verify must return false — never panic —
// for any key length other than ed25519.PublicKeySize.
func TestAttackReplay_CryptoVerifyRejectsWrongLengthKeys(t *testing.T) {
	t.Parallel()

	real, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	msg := []byte("handshake:1:2")
	sig := ed25519.Sign(real.PrivateKey, msg)

	for _, n := range append([]int{0}, malformedKeySizes...) {
		t.Run(fmt.Sprintf("keylen=%d", n), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ATTACK SUCCEEDED: crypto.Verify panicked on a %d-byte key: %v", n, r)
				}
			}()
			key := make([]byte, n)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand: %v", err)
			}
			if crypto.Verify(key, msg, sig) {
				t.Fatalf("ATTACK SUCCEEDED: crypto.Verify accepted a %d-byte key", n)
			}
		})
	}
}

// TestAttackReplay_MalformedPubKeyOverWire drives the full production
// path — attacker JSON bytes into handleConnection — for every handshake
// message type and every wrong key length. The assertion is twofold: the
// process must survive (no panic escapes), and nothing may end up
// trusted.
func TestAttackReplay_MalformedPubKeyOverWire(t *testing.T) {
	t.Parallel()

	types := []string{HandshakeRequest, HandshakeAccept, HandshakeReject, HandshakeRevoke}

	nodeID := uint32(60000)
	for _, typ := range types {
		for _, n := range malformedKeySizes {
			typ, n := typ, n
			nodeID++
			victim := nodeID
			t.Run(fmt.Sprintf("%s/keylen=%d", typ, n), func(t *testing.T) {
				hm, _ := newBoundHM(t, 2000)
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("ATTACK SUCCEEDED: handshake panicked on %s with a %d-byte public_key: %v", typ, n, r)
					}
				}()

				payload := attackPayload(t, &HandshakeMsg{
					Type:      typ,
					NodeID:    victim,
					PublicKey: randomB64(t, n),
					Signature: randomB64(t, ed25519.SignatureSize),
					Timestamp: time.Now().Unix(),
				})
				hm.handleConnection(newWireStream(payload, victim))

				assertNotTrusted(t, hm, victim, fmt.Sprintf("%s with a %d-byte public_key", typ, n))
			})
		}
	}
}

// TestAttackReplay_MalformedSignatureOverWire is the sibling case: a
// correctly-sized key paired with a wrong-length signature. ed25519
// tolerates this without panicking, but the message must still be
// rejected rather than sliding into trust.
func TestAttackReplay_MalformedSignatureOverWire(t *testing.T) {
	t.Parallel()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	nodeID := uint32(61000)
	for _, n := range []int{0, 1, 32, 63, 65, 128, 4096} {
		n := n
		nodeID++
		victim := nodeID
		t.Run(fmt.Sprintf("siglen=%d", n), func(t *testing.T) {
			hm, _ := newBoundHM(t, 2001)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ATTACK SUCCEEDED: handshake panicked on a %d-byte signature: %v", n, r)
				}
			}()

			payload := attackPayload(t, &HandshakeMsg{
				Type:      HandshakeAccept,
				NodeID:    victim,
				PublicKey: crypto.EncodePublicKey(id.PublicKey),
				Signature: randomB64(t, n),
				Timestamp: time.Now().Unix(),
			})
			hm.handleConnection(newWireStream(payload, victim))

			assertNotTrusted(t, hm, victim, fmt.Sprintf("accept with a %d-byte signature", n))
		})
	}
}

// TestAttackReplay_HostilePubKeyEncodings covers the parser layer under
// the length guard: non-base64 bytes, padding abuse, embedded NULs, and
// an oversized field. None of these may panic or trust anything.
func TestAttackReplay_HostilePubKeyEncodings(t *testing.T) {
	t.Parallel()

	keys := map[string]string{
		"not-base64":     "!!!!not base64 at all!!!!",
		"bad-padding":    "AAAA=AAA",
		"embedded-nul":   "AAAA\x00AAAA",
		"whitespace":     "   \n\t  ",
		"huge":           strings.Repeat("A", 60000),
		"unicode":        "🔑🔑🔑🔑",
		"only-padding":   "====",
		"valid-b64-odd":  base64.StdEncoding.EncodeToString([]byte("short")),
		"url-safe-alpha": "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-A",
	}

	nodeID := uint32(62000)
	for name, key := range keys {
		name, key := name, key
		nodeID++
		victim := nodeID
		t.Run(name, func(t *testing.T) {
			hm, _ := newBoundHM(t, 2002)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ATTACK SUCCEEDED: handshake panicked on public_key %q: %v", name, r)
				}
			}()

			payload := attackPayload(t, &HandshakeMsg{
				Type:      HandshakeRequest,
				NodeID:    victim,
				PublicKey: key,
				Signature: randomB64(t, ed25519.SignatureSize),
				Timestamp: time.Now().Unix(),
			})
			hm.handleConnection(newWireStream(payload, victim))

			assertNotTrusted(t, hm, victim, "hostile public_key encoding "+name)
		})
	}
}

// TestAttackReplay_TruncatedAndGarbageWire feeds bytes that are not a
// handshake message at all straight into the connection handler — the
// outermost layer an unauthenticated remote can reach.
func TestAttackReplay_TruncatedAndGarbageWire(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{
		nil,
		{},
		[]byte("{"),
		[]byte(`{"type":`),
		[]byte(`{"type":"handshake_accept","node_id":`),
		[]byte(`{"type":"handshake_accept","node_id":99999999999999999999}`),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`"handshake_accept"`),
		[]byte{0x00, 0xff, 0xfe, 0x01, 0x02},
	}

	for i, p := range payloads {
		i, p := i, p
		t.Run(fmt.Sprintf("payload=%d", i), func(t *testing.T) {
			hm, _ := newBoundHM(t, 2003)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ATTACK SUCCEEDED: handshake panicked on payload %d: %v", i, r)
				}
			}()
			hm.handleConnection(newWireStream(p, 66666))

			hm.mu.RLock()
			n := len(hm.trusted)
			hm.mu.RUnlock()
			if n != 0 {
				t.Fatalf("ATTACK SUCCEEDED: garbage payload %d injected %d trust records", i, n)
			}
		})
	}
}
