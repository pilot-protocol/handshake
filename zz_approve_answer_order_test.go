// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// orderedRegistry records the order of the calls an approval makes, and
// fails the first RespondHandshake the way a dropped connection does.
type orderedRegistry struct {
	*fakeRegistry
	mu       sync.Mutex
	order    []string
	failOnce bool
}

func (o *orderedRegistry) note(s string) {
	o.mu.Lock()
	o.order = append(o.order, s)
	o.mu.Unlock()
}
func (o *orderedRegistry) ReportTrust(n, p uint32) (map[string]interface{}, error) {
	o.note("report")
	return o.fakeRegistry.ReportTrust(n, p)
}
func (o *orderedRegistry) Lookup(n uint32) (map[string]interface{}, error) {
	o.note("lookup")
	return o.fakeRegistry.Lookup(n)
}
func (o *orderedRegistry) RespondHandshake(n, p uint32, accept bool, sig string) (map[string]interface{}, error) {
	o.mu.Lock()
	fail := o.failOnce
	o.failOnce = false
	o.mu.Unlock()
	if fail {
		o.note("respond-failed")
		return nil, errors.New("connection reset by peer")
	}
	o.note("respond")
	return o.fakeRegistry.RespondHandshake(n, p, accept, sig)
}

// Approving a relayed request (which carries no key): the registry learns the
// trust pair before anything is answered, the requester's key comes from the
// registry, a dropped relay answer is tried again, and the direct accept is
// still attempted. A lost answer once left the two sides disagreeing for weeks.
func TestApproveRegistersThePairBeforeAnsweringAndRetries(t *testing.T) {
	reg := &orderedRegistry{fakeRegistry: newFakeRegistry(), failOnce: true}
	reg.setLookup(252515, map[string]interface{}{"public_key": "cmVxdWVzdGVyLWtleQ=="})
	frt := newFakeRuntime()
	hm := NewManager(&registryOverrideRuntime{fakeRuntime: frt, reg: reg})
	t.Cleanup(hm.Stop)
	hm.mu.Lock()
	hm.pending[252515] = &PendingHandshake{NodeID: 252515} // relayed: no key
	hm.mu.Unlock()

	if err := hm.ApproveHandshake(252515); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		reg.mu.Lock()
		order := append([]string(nil), reg.order...)
		reg.mu.Unlock()
		frt.mu.RLock()
		dialed := len(frt.dialCalls)
		frt.mu.RUnlock()
		if len(order) >= 4 && dialed > 0 {
			if order[0] != "report" || order[1] != "lookup" || order[2] != "respond-failed" || order[3] != "respond" {
				t.Fatalf("order: %v", order)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("order so far: %v, direct accepts tried: %d", order, dialed)
		}
		time.Sleep(20 * time.Millisecond)
	}
	hm.mu.RLock()
	rec := hm.trusted[252515]
	hm.mu.RUnlock()
	if rec == nil || rec.PublicKey != "cmVxdWVzdGVyLWtleQ==" {
		t.Fatalf("trust record: %+v", rec)
	}
}
