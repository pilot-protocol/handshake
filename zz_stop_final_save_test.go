// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Stop used to lose trust changes: it closed done before waiting for the
// background RPCs, never waited for the drain goroutine, and never saved
// on its own. drainSaves picked between a pending dirty signal and done
// at random, so a queued save was dropped about half the time, and a
// change made by an RPC that finished while Stop waited (backfillPeerKey,
// say) was never saved at all. These tests pin the fixed behaviour: every
// change made before Stop returns is in trust.json, a hung RPC holds Stop
// up for stopRPCWait only, and a later Stop still saves what it changed.

// hangingLookupRegistry is a RegistryClient whose Lookup blocks until
// release is closed, then answers with pubKey. It reports each call on
// entered, so a test knows the RPC is in flight before it calls Stop.
type hangingLookupRegistry struct {
	*fakeRegistry
	pubKey      string
	entered     chan uint32
	release     chan struct{}
	releaseOnce sync.Once
}

func newHangingLookupRegistry(pubKey string) *hangingLookupRegistry {
	return &hangingLookupRegistry{
		fakeRegistry: newFakeRegistry(),
		pubKey:       pubKey,
		entered:      make(chan uint32, 16),
		release:      make(chan struct{}),
	}
}

func (r *hangingLookupRegistry) Lookup(nodeID uint32) (map[string]interface{}, error) {
	r.entered <- nodeID
	<-r.release
	return map[string]interface{}{"public_key": r.pubKey}, nil
}

func (r *hangingLookupRegistry) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

// registryOverrideRuntime is a fakeRuntime whose Registry() returns reg,
// so a test can supply a RegistryClient other than *fakeRegistry.
type registryOverrideRuntime struct {
	*fakeRuntime
	reg RegistryClient
}

func (r *registryOverrideRuntime) Registry() RegistryClient { return r.reg }

// newPersistentHM builds a Manager that persists to dir/trust.json and
// talks to reg (nil keeps the default fakeRegistry, whose Lookup fails).
func newPersistentHM(t *testing.T, dir string, reg RegistryClient) *Manager {
	t.Helper()
	frt := newFakeRuntime()
	frt.identityPath = filepath.Join(dir, "identity.json")
	if reg == nil {
		return NewManager(frt)
	}
	return NewManager(&registryOverrideRuntime{fakeRuntime: frt, reg: reg})
}

// relayApproval establishes trust in peer the way a relayed approval of
// our outgoing request does. With a registry present it also starts the
// backfillPeerKey RPC.
func relayApproval(hm *Manager, peer uint32) {
	hm.mu.Lock()
	hm.outgoing[peer] = time.Now()
	hm.mu.Unlock()
	hm.processRelayedApproval(peer)
}

// loadTrustFile parses dir/trust.json into node ID → entry.
func loadTrustFile(dir string) (map[uint32]trustSnapshotEntry, error) {
	data, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil {
		return nil, err
	}
	var snap trustSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	out := make(map[uint32]trustSnapshotEntry, len(snap.Trusted))
	for _, e := range snap.Trusted {
		out[e.NodeID] = e
	}
	return out, nil
}

func readTrustFile(t *testing.T, dir string) map[uint32]trustSnapshotEntry {
	t.Helper()
	got, err := loadTrustFile(dir)
	if err != nil {
		t.Fatalf("load trust.json: %v", err)
	}
	return got
}

// waitStopping waits until Stop has marked the manager stopping.
func waitStopping(t *testing.T, hm *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hm.mu.RLock()
		stopping := hm.stopping
		hm.mu.RUnlock()
		if stopping {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Stop never marked the manager stopping")
}

// stopAsync runs hm.Stop in a goroutine and returns a channel closed
// when it returns.
func stopAsync(hm *Manager) <-chan struct{} {
	stopped := make(chan struct{})
	go func() {
		hm.Stop()
		close(stopped)
	}()
	return stopped
}

// Eight relayed approvals, then Stop: every one is in trust.json once
// Stop returns. Before the fix the last save was dropped whenever
// drainSaves picked done over the pending dirty signal.
func TestStop_PersistsEveryRelayedChange(t *testing.T) {
	t.Parallel()
	const iterations, changes = 200, 8
	lost := 0
	for i := 0; i < iterations; i++ {
		dir := t.TempDir()
		hm := newPersistentHM(t, dir, nil)
		for p := uint32(1); p <= changes; p++ {
			relayApproval(hm, 100+p)
		}
		hm.Stop()

		got, err := loadTrustFile(dir)
		if err != nil {
			lost++
			continue
		}
		for p := uint32(1); p <= changes; p++ {
			if _, ok := got[100+p]; !ok {
				lost++
				break
			}
		}
	}
	if lost > 0 {
		t.Fatalf("trust.json was missing entries after Stop in %d of %d runs", lost, iterations)
	}
}

// A registry RPC that changes trust while Stop waits for it (here
// backfillPeerKey binding the peer's key) has its change saved.
func TestStop_SavesTrustChangedByInFlightRPC(t *testing.T) {
	t.Parallel()
	const peer = uint32(300)
	reg := newHangingLookupRegistry("cGVlci1rZXk=")
	t.Cleanup(reg.unblock)
	dir := t.TempDir()
	hm := newPersistentHM(t, dir, reg)

	relayApproval(hm, peer)
	<-reg.entered // backfillPeerKey is in flight

	stopped := stopAsync(hm)
	waitStopping(t, hm)
	// The RPC is slow: give the drain goroutine time to act on whatever
	// Stop has signalled it so far, as it would in production.
	time.Sleep(50 * time.Millisecond)
	reg.unblock()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}

	got := readTrustFile(t, dir)
	rec, ok := got[peer]
	if !ok {
		t.Fatalf("peer %d missing from trust.json", peer)
	}
	if rec.PublicKey != reg.pubKey {
		t.Fatalf("persisted public key = %q, want %q (the backfill made during Stop was lost)", rec.PublicKey, reg.pubKey)
	}
}

// An RPC that never returns holds Stop up for stopRPCWait only, and Stop
// still saves what changed before it. A second Stop does not wait again,
// and its save picks up the change the RPC made after the first returned.
func TestStop_HungRPCIsBoundedAndStillSaves(t *testing.T) {
	t.Parallel()
	const peer = uint32(400)
	reg := newHangingLookupRegistry("bGF0ZS1rZXk=")
	t.Cleanup(reg.unblock)
	dir := t.TempDir()
	hm := newPersistentHM(t, dir, reg)

	relayApproval(hm, peer)
	<-reg.entered

	start := time.Now()
	stopped := stopAsync(hm)
	select {
	case <-stopped:
	case <-time.After(stopRPCWait + 2*time.Second):
		t.Fatal("Stop is still blocked on the hung RPC")
	}
	if elapsed := time.Since(start); elapsed < stopRPCWait {
		t.Fatalf("Stop returned after %v, before the %v RPC wait", elapsed, stopRPCWait)
	}
	rec, ok := readTrustFile(t, dir)[peer]
	if !ok {
		t.Fatalf("peer %d missing from trust.json after a Stop that timed out", peer)
	}
	if rec.PublicKey != "" {
		t.Fatalf("public key %q persisted before the backfill ran", rec.PublicKey)
	}

	// The RPC finishes late and binds the key.
	reg.unblock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hm.mu.RLock()
		key := hm.trusted[peer].PublicKey
		hm.mu.RUnlock()
		if key != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late backfill never bound the key")
		}
		time.Sleep(time.Millisecond)
	}

	start = time.Now()
	hm.Stop()
	if elapsed := time.Since(start); elapsed > stopRPCWait/2 {
		t.Fatalf("second Stop took %v; it should not wait for RPCs again", elapsed)
	}
	if got := readTrustFile(t, dir)[peer].PublicKey; got != reg.pubKey {
		t.Fatalf("persisted public key after second Stop = %q, want %q", got, reg.pubKey)
	}
}

// Concurrent Stop calls all return, none races (run under -race), their
// saves do not collide on trust.json.tmp, and the file is complete.
func TestStop_ConcurrentCalls(t *testing.T) {
	t.Parallel()
	const peer = uint32(500)
	reg := newHangingLookupRegistry("Y29uY3VycmVudA==")
	t.Cleanup(reg.unblock)
	dir := t.TempDir()
	hm := newPersistentHM(t, dir, reg)

	relayApproval(hm, peer)
	<-reg.entered
	for p := uint32(1); p <= 8; p++ {
		hm.mu.Lock()
		hm.markTrustedLocked(600+p, &TrustRecord{NodeID: 600 + p, ApprovedAt: time.Now()})
		hm.markDirty()
		hm.mu.Unlock()
	}

	const callers = 4
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hm.Stop()
		}()
	}
	waitStopping(t, hm)
	reg.unblock()

	allStopped := make(chan struct{})
	go func() {
		wg.Wait()
		close(allStopped)
	}()
	select {
	case <-allStopped:
	case <-time.After(stopRPCWait + 3*time.Second):
		t.Fatal("concurrent Stop calls did not all return")
	}

	got := readTrustFile(t, dir)
	if len(got) != 9 {
		t.Fatalf("trust.json has %d entries, want 9: %+v", len(got), got)
	}
	if got[peer].PublicKey != reg.pubKey {
		t.Fatalf("persisted public key = %q, want %q", got[peer].PublicKey, reg.pubKey)
	}
	if _, err := os.Stat(filepath.Join(dir, "trust.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("trust.json.tmp left behind (stat err = %v)", err)
	}
}
