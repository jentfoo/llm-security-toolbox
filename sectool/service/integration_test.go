package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInteractshBackend_EnsureClientForRedirectTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	backend := NewInteractshBackend("")
	t.Cleanup(func() { _ = backend.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	t.Run("creates_default_client", func(t *testing.T) {
		c, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		assert.NotEmpty(t, c.CorrelationID())
		assert.NotEmpty(t, c.ServerHost())
		assert.True(t, c.IsPolling())
	})

	t.Run("returns_same_client", func(t *testing.T) {
		c1, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		c2, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		assert.Same(t, c1, c2)
	})

	t.Run("different_target_different_client", func(t *testing.T) {
		defaultClient, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)

		redirectClient, err := backend.ensureClientForRedirectTarget(ctx, "https://example.com")
		require.NoError(t, err)

		assert.NotSame(t, defaultClient, redirectClient)
		assert.NotEqual(t, defaultClient.CorrelationID(), redirectClient.CorrelationID())
		assert.True(t, redirectClient.IsPolling())
	})

	t.Run("closed_backend_returns_error", func(t *testing.T) {
		b := NewInteractshBackend("")
		require.NoError(t, b.Close())

		_, err := b.ensureClientForRedirectTarget(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed")
	})
}

func TestInteractshBackend_ProbeRedirectSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	t.Run("oast_pro_unsupported", func(t *testing.T) {
		backend := NewInteractshBackend("https://oast.pro")
		t.Cleanup(func() { _ = backend.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		backend.ProbeRedirectSupport(ctx)
		assert.False(t, backend.SupportsRedirect())
	})

	t.Run("oastsrv_supported", func(t *testing.T) {
		backend := NewInteractshBackend("https://alpha.oastsrv.net")
		t.Cleanup(func() { _ = backend.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		backend.ProbeRedirectSupport(ctx)
		assert.True(t, backend.SupportsRedirect())
	})
}
