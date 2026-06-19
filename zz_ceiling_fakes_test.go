// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/common/crypto"
)

// fakeRegistry is an in-memory RegistryClient that lets tests pre-program
// Lookup / ReportTrust / RespondHandshake / RequestHandshake / RevokeTrust /
// PollHandshakes return values + record what calls were made.
//
// Using a fake (rather than the real test-registry fixture) is the only way
// to exercise the sharedNetwork happy-path and the registry-side branches
// where we want deterministic responses without spinning up server state.
type fakeRegistry struct {
	mu sync.Mutex

	// Per-node Lookup canned responses. Keyed by nodeID.
	lookups map[uint32]map[string]interface{}
	// If lookupErr[id] is set, Lookup(id) returns the error instead.
	lookupErr map[uint32]error

	// Pre-canned generic returns.
	requestErr     error
	respondErr     error
	reportErr      error
	revokeErr      error
	pollErr        error
	requestResp    map[string]interface{}
	respondResp    map[string]interface{}
	reportResp     map[string]interface{}
	revokeResp     map[string]interface{}
	pollResp       map[string]interface{}
	resolveResp    map[string]interface{}
	resolveErr     error

	// Call traces.
	lookupCalls   []uint32
	requestCalls  []fakeReqCall
	respondCalls  []fakeRespCall
	reportCalls   [][2]uint32
	revokeCalls   [][2]uint32
	pollCalls     []uint32
}

type fakeReqCall struct {
	From, To      uint32
	Justification string
	SignatureB64  string
}
type fakeRespCall struct {
	NodeID, PeerID uint32
	Accept         bool
	SignatureB64   string
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		lookups:   map[uint32]map[string]interface{}{},
		lookupErr: map[uint32]error{},
	}
}

func (f *fakeRegistry) setLookup(id uint32, resp map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups[id] = resp
}
func (f *fakeRegistry) setLookupErr(id uint32, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupErr[id] = err
}

func (f *fakeRegistry) Lookup(nodeID uint32) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupCalls = append(f.lookupCalls, nodeID)
	if err, ok := f.lookupErr[nodeID]; ok {
		return nil, err
	}
	if r, ok := f.lookups[nodeID]; ok {
		return r, nil
	}
	return nil, errors.New("not found")
}
func (f *fakeRegistry) ReportTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reportCalls = append(f.reportCalls, [2]uint32{nodeID, peerID})
	if f.reportErr != nil {
		return nil, f.reportErr
	}
	if f.reportResp != nil {
		return f.reportResp, nil
	}
	return map[string]interface{}{"type": "report_trust_ok"}, nil
}
func (f *fakeRegistry) RevokeTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, [2]uint32{nodeID, peerID})
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	if f.revokeResp != nil {
		return f.revokeResp, nil
	}
	return map[string]interface{}{"type": "revoke_trust_ok"}, nil
}
func (f *fakeRegistry) RequestHandshake(fromNodeID, toNodeID uint32, justification, signatureB64 string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestCalls = append(f.requestCalls, fakeReqCall{
		From: fromNodeID, To: toNodeID, Justification: justification, SignatureB64: signatureB64,
	})
	if f.requestErr != nil {
		return nil, f.requestErr
	}
	if f.requestResp != nil {
		return f.requestResp, nil
	}
	return map[string]interface{}{"type": "request_handshake_ok"}, nil
}
func (f *fakeRegistry) RespondHandshake(nodeID, peerID uint32, accept bool, signatureB64 string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respondCalls = append(f.respondCalls, fakeRespCall{
		NodeID: nodeID, PeerID: peerID, Accept: accept, SignatureB64: signatureB64,
	})
	if f.respondErr != nil {
		return nil, f.respondErr
	}
	if f.respondResp != nil {
		return f.respondResp, nil
	}
	return map[string]interface{}{"type": "respond_handshake_ok"}, nil
}
func (f *fakeRegistry) PollHandshakes(nodeID uint32) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollCalls = append(f.pollCalls, nodeID)
	if f.pollErr != nil {
		return nil, f.pollErr
	}
	if f.pollResp != nil {
		return f.pollResp, nil
	}
	return map[string]interface{}{"type": "poll_handshakes_ok"}, nil
}

func (f *fakeRegistry) snapshotReports() [][2]uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][2]uint32, len(f.reportCalls))
	copy(out, f.reportCalls)
	return out
}
func (f *fakeRegistry) snapshotRevokes() [][2]uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][2]uint32, len(f.revokeCalls))
	copy(out, f.revokeCalls)
	return out
}
func (f *fakeRegistry) snapshotResponds() []fakeRespCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeRespCall, len(f.respondCalls))
	copy(out, f.respondCalls)
	return out
}

// fakeRuntime is a Runtime impl that returns a fakeRegistry from
// Registry(). It also captures DialAndSend / RemoveTunnelPeer calls so
// tests can assert side effects deterministically.
type fakeRuntime struct {
	mu sync.RWMutex

	nodeID           uint32
	identity         *crypto.Identity
	identityPath     string
	trustAutoApprove bool
	registry         *fakeRegistry
	trustChecker     daemon.TrustChecker

	dialErr      error
	publishedMu  sync.Mutex
	published    []publishedEvent
	dialCalls    []fakeDialCall
	removedPeers []uint32
}

type fakeDialCall struct {
	NodeID uint32
	Port   uint16
	Data   []byte
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		registry: newFakeRegistry(),
		dialErr:  errors.New("DialAndSend: no peer reachable"),
	}
}

func (r *fakeRuntime) NodeID() uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nodeID
}
func (r *fakeRuntime) HasIdentity() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identity != nil
}
func (r *fakeRuntime) PublicKey() ed25519.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.identity == nil {
		return nil
	}
	return r.identity.PublicKey
}
func (r *fakeRuntime) Sign(msg []byte) []byte {
	r.mu.RLock()
	id := r.identity
	r.mu.RUnlock()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}
func (r *fakeRuntime) IdentityPath() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identityPath
}
func (r *fakeRuntime) TrustAutoApprove() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.trustAutoApprove
}
func (r *fakeRuntime) IsTrusted(nodeID uint32) (string, bool) {
	r.mu.RLock()
	tc := r.trustChecker
	r.mu.RUnlock()
	if tc == nil {
		return "", false
	}
	return tc.IsTrusted(nodeID)
}
func (r *fakeRuntime) PublishEvent(topic string, payload map[string]any) {
	r.publishedMu.Lock()
	r.published = append(r.published, publishedEvent{Topic: topic, Payload: payload})
	r.publishedMu.Unlock()
}
func (r *fakeRuntime) PortListener(port uint16) (coreapi.Listener, error) {
	return nil, errStub("PortListener stub")
}
func (r *fakeRuntime) DialAndSend(peerNodeID uint32, port uint16, data []byte) error {
	r.mu.Lock()
	r.dialCalls = append(r.dialCalls, fakeDialCall{NodeID: peerNodeID, Port: port, Data: append([]byte(nil), data...)})
	err := r.dialErr
	r.mu.Unlock()
	return err
}
func (r *fakeRuntime) RemoveTunnelPeer(nodeID uint32) {
	r.mu.Lock()
	r.removedPeers = append(r.removedPeers, nodeID)
	r.mu.Unlock()
}
func (r *fakeRuntime) Registry() RegistryClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.registry == nil {
		return nil
	}
	return r.registry
}

// Used to suppress the registry-dependent path in some tests.
func (r *fakeRuntime) clearRegistry() {
	r.mu.Lock()
	r.registry = nil
	r.mu.Unlock()
}

// newFakeHM is the common builder.
func newFakeHM(t *testing.T) (*Manager, *fakeRuntime) {
	t.Helper()
	rt := newFakeRuntime()
	hm := NewManager(rt)
	t.Cleanup(hm.Stop)
	return hm, rt
}

// withDeterministicIdentity wires a fixed test-vector identity so signatures
// are reproducible across runs. Uses an ed25519 seed of N repeated bytes for
// deterministic key derivation.
//
// The base64 of the resulting pubkey is intentionally not hardcoded — its
// value depends on the ed25519 KDF and is computed once at startup.
func (r *fakeRuntime) withDeterministicIdentity(t *testing.T, seedByte byte) {
	t.Helper()
	id := deterministicIdentity(seedByte)
	r.mu.Lock()
	r.identity = id
	r.mu.Unlock()
}

// deterministicIdentity returns a reproducible *crypto.Identity derived from
// a single-byte seed expanded to 32 bytes. The same byte produces the same
// keypair every run, so tests can assert on signatures across runs.
func deterministicIdentity(seedByte byte) *crypto.Identity {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &crypto.Identity{
		PrivateKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
	}
}
