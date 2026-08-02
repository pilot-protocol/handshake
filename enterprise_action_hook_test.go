// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/decision"
)

type trustHookCall struct {
	envelope actionhook.Envelope
	result   actionhook.ObservedResult
}

type trustHookStub struct {
	mu       sync.Mutex
	outcomes map[string]decision.Outcome
	before   []actionhook.Envelope
	after    []trustHookCall
	afterErr error
}

func (hook *trustHookStub) BeforeAction(_ context.Context, envelope actionhook.Envelope) (actionhook.Preflight, error) {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	hook.before = append(hook.before, envelope)
	outcome := decision.Allow
	if configured, exists := hook.outcomes[envelope.Action]; exists {
		outcome = configured
	}
	return actionhook.Preflight{Outcome: outcome, Reference: actionhook.DecisionReference{DecisionID: "test-decision"}}, nil
}

func (hook *trustHookStub) AfterAction(_ context.Context, envelope actionhook.Envelope, _ actionhook.Preflight, result actionhook.ObservedResult) error {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	hook.after = append(hook.after, trustHookCall{envelope: envelope, result: result})
	return hook.afterErr
}

func (hook *trustHookStub) observed(action string, status actionhook.ObservedStatus) bool {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	for _, call := range hook.after {
		if call.envelope.Action == action && call.result.Status == status {
			return true
		}
	}
	return false
}

func TestActionHookDenyTurnsEveryAutomaticTrustPathIntoPending(t *testing.T) {
	for _, relayed := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "relayed"}[relayed], func(t *testing.T) {
			runtime := newTestRuntime()
			runtime.trustAutoApprove = true
			manager := NewManager(runtime)
			t.Cleanup(manager.Stop)
			hook := &trustHookStub{outcomes: map[string]decision.Outcome{"trust.auto_accept": decision.Deny}}
			manager.SetActionHook(hook)

			if relayed {
				manager.processRelayedRequest(71, "join")
			} else {
				manager.handleRequest(nil, &HandshakeMsg{NodeID: 71, PublicKey: "peer-key", Justification: "join"}, false)
			}
			manager.mu.RLock()
			_, trusted := manager.trusted[71]
			_, pending := manager.pending[71]
			manager.mu.RUnlock()
			if trusted || !pending {
				t.Fatalf("denied auto-accept trusted=%v pending=%v", trusted, pending)
			}
			if !hook.observed("trust.auto_accept", actionhook.StatusDenied) {
				t.Fatal("denied automatic action was not sent to the post-hook")
			}
		})
	}
}

func TestActionHookDenyCoversManualAndOutgoingTrustGrantPaths(t *testing.T) {
	hook := &trustHookStub{outcomes: map[string]decision.Outcome{"trust.accept": decision.Deny}}
	manager := newTestHM(t, "")
	t.Cleanup(manager.Stop)
	manager.SetActionHook(hook)

	manager.pending[80] = &PendingHandshake{NodeID: 80, Justification: "manual"}
	if err := manager.ApproveHandshake(80); err == nil {
		t.Fatal("manual approval bypassed trust.accept deny")
	}
	manager.outgoing[81] = time.Now()
	manager.handleAccept(&HandshakeMsg{NodeID: 81, PublicKey: "peer-key"})
	manager.outgoing[82] = time.Now()
	manager.processRelayedApproval(82)

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, peer := range []uint32{80, 81, 82} {
		if _, trusted := manager.trusted[peer]; trusted {
			t.Fatalf("peer %d became trusted despite trust.accept deny", peer)
		}
	}
	if _, pending := manager.pending[80]; !pending {
		t.Fatal("manual request must remain pending after denial")
	}
	if _, outgoing := manager.outgoing[81]; !outgoing {
		t.Fatal("direct outgoing request must remain available after denial")
	}
	if _, outgoing := manager.outgoing[82]; !outgoing {
		t.Fatal("relayed outgoing request must remain available after denial")
	}
}

func TestActionHookApprovalRequiredSuspendsBeforeMutation(t *testing.T) {
	hook := &trustHookStub{outcomes: map[string]decision.Outcome{"trust.accept": decision.ApprovalRequired}}
	manager := newTestHM(t, "")
	t.Cleanup(manager.Stop)
	manager.SetActionHook(hook)
	manager.pending[90] = &PendingHandshake{NodeID: 90}

	err := manager.ApproveHandshake(90)
	var blocked *actionhook.BlockedError
	if !errors.As(err, &blocked) || blocked.Outcome != decision.ApprovalRequired {
		t.Fatalf("expected approval-required block, got %v", err)
	}
	if _, trusted := manager.trusted[90]; trusted {
		t.Fatal("approval-required action mutated trust")
	}
	if !hook.observed("trust.accept", actionhook.StatusApprovalPending) {
		t.Fatal("approval suspension was not evidenced")
	}
}

func TestActionHookDenyBlocksTrustRequestBeforeOutgoingState(t *testing.T) {
	hook := &trustHookStub{outcomes: map[string]decision.Outcome{"trust.request": decision.Deny}}
	manager := newTestHM(t, "")
	t.Cleanup(manager.Stop)
	manager.SetActionHook(hook)
	if err := manager.SendRequest(101, "connect"); err == nil {
		t.Fatal("denied trust request returned success")
	}
	if _, exists := manager.outgoing[101]; exists {
		t.Fatal("denied trust request created outgoing state")
	}
}

func TestPostHookFailureCannotUndoGrantedTrust(t *testing.T) {
	hook := &trustHookStub{outcomes: map[string]decision.Outcome{"trust.accept": decision.Allow}, afterErr: errors.New("journal unavailable")}
	manager := newTestHM(t, "")
	t.Cleanup(manager.Stop)
	manager.SetActionHook(hook)
	manager.pending[111] = &PendingHandshake{NodeID: 111}
	if err := manager.ApproveHandshake(111); err != nil {
		t.Fatalf("post-hook failure changed action result: %v", err)
	}
	if _, trusted := manager.trusted[111]; !trusted {
		t.Fatal("post-hook failure rolled back trust")
	}
}
