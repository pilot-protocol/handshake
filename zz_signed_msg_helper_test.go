// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// signedMsg builds a handshake message of any type the way sendMessage
// does: from's key in PublicKey, and the signature over
// "handshake:<from>:<to>" made with id.
func signedMsg(id *crypto.Identity, typ string, from, to uint32) *HandshakeMsg {
	challenge := fmt.Sprintf("handshake:%d:%d", from, to)
	return &HandshakeMsg{
		Type:      typ,
		NodeID:    from,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge))),
		Timestamp: time.Now().Unix(),
	}
}

// keyOf returns id's public key as TrustRecord.PublicKey encodes it.
func keyOf(id *crypto.Identity) string {
	return base64.StdEncoding.EncodeToString(id.PublicKey)
}
