// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"testing"
	"time"
)

func TestPPA002_RelayedApprovalWithoutOutgoingDropped(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.ProcessRelayedApproval(4242)

	hm.mu.RLock()
	_, trusted := hm.trusted[4242]
	hm.mu.RUnlock()
	if trusted {
		t.Fatal("relayed approval for a peer we never sent a request to must be dropped")
	}
}

func TestPPA002_RelayedApprovalWithOutgoingTrusts(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	hm.mu.Lock()
	hm.outgoing[4242] = time.Now()
	hm.mu.Unlock()

	hm.ProcessRelayedApproval(4242)

	hm.mu.RLock()
	rec, trusted := hm.trusted[4242]
	_, stillOutgoing := hm.outgoing[4242]
	hm.mu.RUnlock()
	if !trusted {
		t.Fatal("relayed approval matching an outgoing request must establish trust")
	}
	if !rec.Mutual {
		t.Fatal("relayed approval must record mutual trust")
	}
	if stillOutgoing {
		t.Fatal("outgoing entry must be cleared once trust is established")
	}
}
