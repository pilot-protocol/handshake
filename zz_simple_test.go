// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"context"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

func TestNewService_DefaultsAndAccessors(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	svc := NewService(rt)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.Name() != "handshake" {
		t.Errorf("Name = %q, want handshake", svc.Name())
	}
	if svc.Order() != 60 {
		t.Errorf("Order = %d, want 60", svc.Order())
	}
	if svc.Manager() == nil {
		t.Error("Manager() returned nil")
	}
}

func TestService_StartFailsWithoutPortListener(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	svc := NewService(rt)
	// testRuntime.PortListener returns an error stub → Manager.Start should
	// surface the error.
	err := svc.Start(context.Background(), coreapi.Deps{})
	if err == nil {
		t.Error("expected error from Start (PortListener stub)")
	}
}

func TestService_StopIdempotentAfterFailedStart(t *testing.T) {
	t.Parallel()
	rt := newTestRuntime()
	svc := NewService(rt)
	_ = svc.Start(context.Background(), coreapi.Deps{}) // fails
	if err := svc.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	// Second Stop is safe.
	if err := svc.Stop(context.Background()); err != nil {
		t.Errorf("Stop 2: %v", err)
	}
}

func TestManager_IsTrustedTrustedPeersPendingCount(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	if hm.IsTrusted(0xCAFE) {
		t.Error("fresh manager: IsTrusted should be false")
	}
	if got := hm.TrustedPeers(); len(got) != 0 {
		t.Errorf("TrustedPeers fresh = %v", got)
	}
	if got := hm.PendingCount(); got != 0 {
		t.Errorf("PendingCount fresh = %d, want 0", got)
	}
}

func TestManager_WaitForTrust_SelfReturnsTrue(t *testing.T) {
	t.Parallel()
	// Manager whose runtime has NodeID=0 — and we ask about 0 → self.
	hm := newTestHM(t, "")
	if !hm.WaitForTrust(0, 10*time.Millisecond) {
		t.Error("WaitForTrust(self): want true")
	}
}

func TestManager_WaitForTrust_AlreadyTrusted(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	// Inject a trust record under the lock.
	hm.mu.Lock()
	hm.trusted[0xCAFE] = &TrustRecord{NodeID: 0xCAFE}
	hm.mu.Unlock()

	if !hm.WaitForTrust(0xCAFE, 10*time.Millisecond) {
		t.Error("WaitForTrust(trusted): want true")
	}
}

func TestManager_WaitForTrust_Timeout(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	start := time.Now()
	if hm.WaitForTrust(0xCAFE, 50*time.Millisecond) {
		t.Error("WaitForTrust(unknown): want false on timeout")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("returned too fast: %v", elapsed)
	}
}

func TestManager_WaitForTrust_TrustGrantedAfterRegister(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	const peer uint32 = 0x1234

	go func() {
		// Give the WaitForTrust call time to register its channel.
		time.Sleep(20 * time.Millisecond)
		hm.mu.Lock()
		hm.trusted[peer] = &TrustRecord{NodeID: peer}
		hm.mu.Unlock()
		// Notify waiters.
		hm.trustWaitersMu.Lock()
		for _, ch := range hm.trustWaiters[peer] {
			close(ch)
		}
		delete(hm.trustWaiters, peer)
		hm.trustWaitersMu.Unlock()
	}()

	if !hm.WaitForTrust(peer, time.Second) {
		t.Error("WaitForTrust should observe the post-registration trust")
	}
}

func TestRemoveWaiter_NoMatchIsNoOp(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	ch := make(chan struct{})
	other := make(chan struct{})
	// Pre-seed a waiter for 7 with the wrong channel.
	hm.trustWaitersMu.Lock()
	hm.trustWaiters[7] = []chan struct{}{other}
	hm.trustWaitersMu.Unlock()

	hm.removeWaiter(7, ch) // ch not in slice → no-op

	hm.trustWaitersMu.Lock()
	defer hm.trustWaitersMu.Unlock()
	if len(hm.trustWaiters[7]) != 1 || hm.trustWaiters[7][0] != other {
		t.Errorf("waiter slice mutated: %v", hm.trustWaiters[7])
	}
}

func TestRemoveWaiter_RemovesAndCleansEmptySlot(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	ch := make(chan struct{})
	hm.trustWaitersMu.Lock()
	hm.trustWaiters[7] = []chan struct{}{ch}
	hm.trustWaitersMu.Unlock()

	hm.removeWaiter(7, ch)
	hm.trustWaitersMu.Lock()
	defer hm.trustWaitersMu.Unlock()
	if _, ok := hm.trustWaiters[7]; ok {
		t.Error("empty waiter slot should be deleted")
	}
}
