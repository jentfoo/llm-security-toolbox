package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShutdownPhaseTransitions(t *testing.T) {
	t.Parallel()
	t.Run("running_to_verify_only", func(t *testing.T) {
		sd := NewShutdown(context.Background(), nil)
		assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
		assert.NoError(t, sd.WorkersCtx.Err())
		assert.NoError(t, sd.VerifierCtx.Err())

		sd.RequestVerifyOnly()
		assert.Equal(t, ShutdownPhaseVerifyOnly, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.NoError(t, sd.VerifierCtx.Err(), "verifier still alive at stage 1")
	})

	t.Run("verify_then_dump", func(t *testing.T) {
		sd := NewShutdown(context.Background(), nil)
		sd.RequestVerifyOnly()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.ErrorIs(t, sd.VerifierCtx.Err(), context.Canceled)
	})

	t.Run("dump_without_verify_first", func(t *testing.T) {
		// Skipping straight to phase 2 still cancels both ctxs.
		sd := NewShutdown(context.Background(), nil)
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.ErrorIs(t, sd.VerifierCtx.Err(), context.Canceled)
	})

	t.Run("kill_is_terminal", func(t *testing.T) {
		sd := NewShutdown(context.Background(), nil)
		sd.RequestKill()
		assert.Equal(t, ShutdownPhaseKill, sd.Phase())
		// Once kill, lower-priority requests are ignored.
		sd.RequestVerifyOnly()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseKill, sd.Phase())
	})

	t.Run("idempotent", func(t *testing.T) {
		sd := NewShutdown(context.Background(), nil)
		sd.RequestVerifyOnly()
		sd.RequestVerifyOnly()
		sd.RequestVerifyOnly()
		assert.Equal(t, ShutdownPhaseVerifyOnly, sd.Phase())
		sd.RequestDumpUnvalidated()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
	})
}

func TestShutdownNilSafe(t *testing.T) {
	t.Parallel()
	var sd *Shutdown
	assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
	require.NotPanics(t, func() {
		sd.RequestVerifyOnly()
		sd.RequestDumpUnvalidated()
		sd.RequestKill()
	})
}

func TestShutdownParentCancellation(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	sd := NewShutdown(parent, nil)

	cancel()
	// Both child ctxs propagate parent cancellation even without a stage transition.
	<-sd.WorkersCtx.Done()
	<-sd.VerifierCtx.Done()
	// Phase remains 0 — we only flipped the parent ctx, not the shutdown state.
	assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
}
