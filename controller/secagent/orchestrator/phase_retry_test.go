package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunPhaseAttempt_SuccessFirstTry(t *testing.T) {
	t.Parallel()
	calls := 0
	var compacted, exhausted bool
	out, err := RunPhaseAttempt(t.Context(),
		func(ctx context.Context) (int, error) { calls++; return 42, nil },
		PhaseRecover{
			Compact:     func() { compacted = true },
			OnExhausted: func(err error) { exhausted = true },
		}, nil, "test")
	require.NoError(t, err)
	assert.Equal(t, 42, out)
	assert.Equal(t, 1, calls)
	assert.False(t, compacted)
	assert.False(t, exhausted)
}

func TestRunPhaseAttempt_RecoverySucceeds(t *testing.T) {
	t.Parallel()
	calls := 0
	var compacted, exhausted bool
	out, err := RunPhaseAttempt(t.Context(),
		func(ctx context.Context) (int, error) {
			calls++
			if calls == 1 {
				return 0, errors.New("flake")
			}
			return 7, nil
		},
		PhaseRecover{
			Compact:     func() { compacted = true },
			OnExhausted: func(err error) { exhausted = true },
		}, nil, "test")
	require.NoError(t, err)
	assert.Equal(t, 7, out)
	assert.Equal(t, 2, calls)
	assert.True(t, compacted, "Compact must run between failure and retry")
	assert.False(t, exhausted)
}

func TestRunPhaseAttempt_ExhaustedInvokesDegrade(t *testing.T) {
	t.Parallel()
	calls := 0
	var gotErr error
	_, err := RunPhaseAttempt(t.Context(),
		func(ctx context.Context) (int, error) {
			calls++
			return 0, errors.New("persistent")
		},
		PhaseRecover{
			Compact:     func() {},
			OnExhausted: func(err error) { gotErr = err },
		}, nil, "test")
	require.Error(t, err)
	assert.Equal(t, 2, calls, "one initial + one retry")
	assert.Equal(t, "persistent", gotErr.Error())
}

func TestRunPhaseAttempt_CtxErrorPropagatesNoRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	var compacted, exhausted bool
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel before invocation so the first call returns ctx.Err()
	_, err := RunPhaseAttempt(ctx,
		func(ctx context.Context) (int, error) {
			calls++
			return 0, ctx.Err()
		},
		PhaseRecover{
			Compact:     func() { compacted = true },
			OnExhausted: func(err error) { exhausted = true },
		}, nil, "test")
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls, "ctx errors must not retry")
	assert.False(t, compacted)
	assert.False(t, exhausted)
}

func TestRunPhaseAttempt_NilHooksAreOK(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RunPhaseAttempt(t.Context(),
		func(ctx context.Context) (int, error) {
			calls++
			return 0, errors.New("x")
		},
		PhaseRecover{}, // both nil
		nil, "test")
	require.Error(t, err)
	assert.Equal(t, 2, calls)
}
