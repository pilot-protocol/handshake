// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/decision"
)

const handshakeActionAdapterID = "pilot.handshake"

// ActionHook is the common optional before/after action boundary. Keeping the
// alias here gives embedders one stable handshake-facing type without a
// handshake-specific policy language.
type ActionHook = actionhook.Hook

type trustActionAttempt struct {
	hook      actionhook.Hook
	envelope  actionhook.Envelope
	preflight actionhook.Preflight
	once      sync.Once
}

// SetActionHook attaches an explicitly configured hook. Passing nil restores
// unmanaged behavior. Composition roots should call this before Start.
func (hm *Manager) SetActionHook(hook ActionHook) {
	hm.mu.Lock()
	hm.actionHook = hook
	hm.mu.Unlock()
}

// prepareTrustAction must be called without hm.mu held because a managed hook
// may perform bounded network I/O. It returns (nil, nil) when no hook is
// attached, which is the exact legacy path.
func (hm *Manager) prepareTrustAction(action string, peerNodeID uint32, direction, reason string, automatic bool, hasJustification bool) (*trustActionAttempt, error) {
	hm.mu.RLock()
	hook := hm.actionHook
	hm.mu.RUnlock()
	if hook == nil {
		return nil, nil
	}
	attributes := map[string]string{
		"peer_node_id":      strconv.FormatUint(uint64(peerNodeID), 10),
		"direction":         direction,
		"reason":            reason,
		"automatic":         strconv.FormatBool(automatic),
		"has_justification": strconv.FormatBool(hasJustification),
	}
	envelope, err := actionhook.NewEnvelope(
		action, fmt.Sprintf("agent:%d", peerNodeID), actionhook.HashMetadata(attributes),
		handshakeActionAdapterID, attributes, time.Now(),
	)
	if err != nil {
		return nil, err
	}
	envelope.ResumeToken = fmt.Sprintf("%s:%s:%d", action, direction, peerNodeID)
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	preflight, err := hook.BeforeAction(context.Background(), envelope)
	if err != nil {
		return nil, fmt.Errorf("handshake: %s preflight for node %d: %w", action, peerNodeID, err)
	}
	attempt := &trustActionAttempt{hook: hook, envelope: envelope, preflight: preflight}
	if err := preflight.RequireUnconstrained(); err != nil {
		status := actionhook.StatusFailed
		var blocked *actionhook.BlockedError
		if errors.As(err, &blocked) {
			switch blocked.Outcome {
			case decision.Deny:
				status = actionhook.StatusDenied
			case decision.ApprovalRequired:
				status = actionhook.StatusApprovalPending
			}
		}
		attempt.complete(status, "preflight_blocked", nil)
		return nil, fmt.Errorf("handshake: %s for node %d: %w", action, peerNodeID, err)
	}
	return attempt, nil
}

func (attempt *trustActionAttempt) complete(status actionhook.ObservedStatus, errorCode string, attributes map[string]string) {
	if attempt == nil {
		return
	}
	attempt.once.Do(func() {
		result := actionhook.ObservedResult{
			Status: status, ObservedAt: time.Now().Unix(), ErrorCode: errorCode, Attributes: attributes,
		}
		if err := attempt.hook.AfterAction(context.Background(), attempt.envelope, attempt.preflight, result); err != nil {
			// Post-hooks are evidence-only. Never repeat or roll back a trust
			// transition because evidence export failed.
			slog.Error("handshake action post-hook failed", "action", attempt.envelope.Action, "action_id", attempt.envelope.ID, "error", err)
		}
	})
}
