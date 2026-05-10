package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestMCP_HistoryDelete(t *testing.T) {
	t.Parallel()

	t.Run("no_args", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		res := CallMCPTool(t, mcpClient, "_internal_history_delete", map[string]interface{}{})
		require.True(t, res.IsError)
		assert.Contains(t, ExtractMCPText(t, res), "flow_ids is required")
	})

	t.Run("skips_note_referenced", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		pid := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{pid}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)
		assert.Equal(t, []string{pid}, resp.Skipped)

		// Proxy entry and note both untouched
		got, _ := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.Len(t, got, 1)
		assert.Equal(t, pid, got[0].FlowID)
		n1, ok := srv.noteStore.Get("n1")
		require.True(t, ok)
		assert.Equal(t, []string{pid}, n1.FlowIDs)
	})

	t.Run("partial_skip", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		pid1 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		pid2 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: b\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")

		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{pid1}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid1, pid2},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, []string{pid1}, resp.Skipped)

		// pid1 (note-protected) survives; pid2 is gone
		got, _ := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.Len(t, got, 1)
		assert.Equal(t, pid1, got[0].FlowID)
	})

	t.Run("no_replay_cascade", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		pid := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{FlowID: "r1", SourceFlowID: pid, CreatedAt: time.Now()})

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)

		// Replay survives
		r1, ok := srv.replayHistoryStore.Get("r1")
		require.True(t, ok)
		assert.Equal(t, pid, r1.SourceFlowID)
	})

	t.Run("unknown_ids_noop", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{"missing1", "missing2"},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)
	})

	t.Run("mixed_proxy_and_replay", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		pid1 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		pid2 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: b\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")

		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{FlowID: "r1", CreatedAt: time.Now()})
		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{FlowID: "r2", CreatedAt: time.Now()})

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid1, "r1", "missing"},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, 1, resp.DeletedReplay)

		// Survivors remain
		_, ok := srv.replayHistoryStore.Get("r2")
		assert.True(t, ok)
		got, _ := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.Len(t, got, 1)
		assert.Equal(t, pid2, got[0].FlowID)
	})
}
