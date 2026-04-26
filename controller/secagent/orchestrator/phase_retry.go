package orchestrator

import (
	"context"
	"errors"
)

// PhaseRecover describes the one-shot recovery path for a stalled phase.
// Compact runs between the failed initial attempt and the retry; it
// typically interrupts the agent and re-queues the last instruction / last
// prompt so the retry starts from a clean state. OnExhausted runs when the
// retry also fails and performs the phase-specific graceful degrade
// (auto-dismiss in-flight candidates, force direction_done, etc). Both are
// optional; a nil hook is a no-op.
type PhaseRecover struct {
	Compact     func()
	OnExhausted func(err error)
}

// RunPhaseAttempt runs attempt once. On a non-Deadline error it invokes
// policy.Compact, runs attempt a second time, and on further failure
// invokes policy.OnExhausted with the final error. Context errors
// propagate immediately — they are not retried.
//
// The helper is generic so verify/direct (single TurnSummary) and
// autonomous (a slice of turn summaries) share one retry shape. Each
// phase's caller owns its own graceful-degrade semantics via OnExhausted.
func RunPhaseAttempt[T any](
	ctx context.Context,
	attempt func(context.Context) (T, error),
	policy PhaseRecover,
	log *Logger, phase string,
) (T, error) {
	out, err := attempt(ctx)
	if err == nil {
		return out, nil
	}
	if isCtxErr(err) {
		return out, err
	}
	if log != nil {
		log.Log(phase, "recover", map[string]any{"attempt": 1, "err": err.Error()})
	}
	if policy.Compact != nil {
		policy.Compact()
	}
	out, err = attempt(ctx)
	if err == nil {
		return out, nil
	}
	if isCtxErr(err) {
		return out, err
	}
	if log != nil {
		log.Log(phase, "retry exhausted", map[string]any{"err": err.Error()})
	}
	if policy.OnExhausted != nil {
		policy.OnExhausted(err)
	}
	return out, err
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
