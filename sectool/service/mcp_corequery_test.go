package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreQuery(t *testing.T) {
	t.Parallel()

	srv, _, mockHTTP, _, _ := setupMockMCPServer(t, nil)
	flowID := mockHTTP.AddProxyEntry(
		"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\n",
		"",
	)

	t.Run("dispatches_read_tool", func(t *testing.T) {
		params, _ := json.Marshal(map[string]any{"output_mode": "flows", "limit": 10})
		content, isErr, err := srv.CoreQuery(t.Context(), "proxy_poll", params)
		require.NoError(t, err)
		assert.False(t, isErr)
		assert.Contains(t, content, flowID)
	})

	t.Run("rejects_write_tool", func(t *testing.T) {
		_, _, err := srv.CoreQuery(t.Context(), "proxy_rule_add", json.RawMessage(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
	})

	t.Run("rejects_unknown_tool", func(t *testing.T) {
		_, _, err := srv.CoreQuery(t.Context(), "definitely_not_a_tool", nil)
		require.Error(t, err)
	})

	t.Run("flow_get_returns_flow", func(t *testing.T) {
		params, _ := json.Marshal(map[string]any{"flow_id": flowID})
		content, _, err := srv.CoreQuery(t.Context(), "flow_get", params)
		require.NoError(t, err)
		assert.Contains(t, content, "example.com")
	})
}
