package orchestrator

import (
	"context"
	"errors"
)

// PhaseRecover holds optional hooks for one-shot phase recovery.
// Compact runs between the failed first attempt and the retry; OnExhausted
// runs when the retry also fails. Both are optional.
type PhaseRecover struct {
	Compact     func()
	OnExhausted func(err error)
}

// RunPhaseAttempt runs attempt once; on non-context error it invokes
// policy.Compact, retries once, and on further failure invokes
// policy.OnExhausted. Context errors propagate immediately.
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
