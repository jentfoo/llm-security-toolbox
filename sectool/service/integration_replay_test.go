package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for replay functionality against a real Burp Suite instance.
// These tests validate end-to-end functionality through both HTTP handlers and MCP tools.

func TestReplay_Integration(t *testing.T) {
	srv, mcpClient, cleanup := setupIntegrationServer(t)
	defer cleanup()

	t.Run("send_and_get", func(t *testing.T) {
		// Get a flow to replay
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET", Limit: 1})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var list ProxyListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))

		if len(list.Flows) == 0 {
			t.Skip("no proxy history entries available")
		}

		flowID := list.Flows[0].FlowID

		// Send via MCP
		result := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		require.False(t, result.IsError, "replay_send should succeed: %s", testutil.ExtractMCPText(t, result))

		text := testutil.ExtractMCPText(t, result)
		var sendResp ReplaySendResponse
		require.NoError(t, json.Unmarshal([]byte(text), &sendResp))
		assert.NotEmpty(t, sendResp.ReplayID)

		// Get via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/get", ReplayGetRequest{ReplayID: sendResp.ReplayID})
		require.Equal(t, 200, w.Code)

		var getResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &getResp))
		var replay ReplayGetResponse
		require.NoError(t, json.Unmarshal(getResp.Data, &replay))

		assert.Equal(t, sendResp.ReplayID, replay.ReplayID)
		assert.NotEmpty(t, replay.RespHeaders)
	})

	t.Run("send_via_http", func(t *testing.T) {
		// Get a flow to replay
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET", Limit: 1})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var list ProxyListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))

		if len(list.Flows) == 0 {
			t.Skip("no proxy history entries available")
		}

		flowID := list.Flows[0].FlowID

		// Send via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			FlowID: flowID,
		})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var sendResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &sendResp))

		assert.NotEmpty(t, sendResp.ReplayID)
		assert.NotEmpty(t, sendResp.Duration)
		t.Logf("Replay via HTTP: status=%d duration=%s", sendResp.Status, sendResp.Duration)
	})

	t.Run("with_header_modifications", func(t *testing.T) {
		// Get a flow to replay
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET", Limit: 1})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var list ProxyListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))

		if len(list.Flows) == 0 {
			t.Skip("no proxy history entries available")
		}

		flowID := list.Flows[0].FlowID

		// Replay with header modifications via MCP
		result := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":        flowID,
			"add_headers":    []string{"X-Integration-Test: modified"},
			"remove_headers": []string{"Accept-Encoding"},
		})
		require.False(t, result.IsError, "replay with mods should succeed: %s", testutil.ExtractMCPText(t, result))

		text := testutil.ExtractMCPText(t, result)
		var sendResp ReplaySendResponse
		require.NoError(t, json.Unmarshal([]byte(text), &sendResp))
		assert.NotEmpty(t, sendResp.ReplayID)

		// Replay with header modifications via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			FlowID:        flowID,
			AddHeaders:    []string{"X-HTTP-Test: modified"},
			RemoveHeaders: []string{"Accept-Language"},
		})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpSendResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpSendResp))
		assert.NotEmpty(t, httpSendResp.ReplayID)
	})

	t.Run("send_validation", func(t *testing.T) {
		// Missing flow_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Missing flow_id via HTTP (also missing bundle_id)
		w := doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{})
		assert.Equal(t, 400, w.Code)

		// Invalid flow_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)

		// Invalid flow_id via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			FlowID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)
	})

	t.Run("get_validation", func(t *testing.T) {
		// Missing replay_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Missing replay_id via HTTP
		w := doTestRequest(t, srv, "POST", "/replay/get", ReplayGetRequest{})
		assert.Equal(t, 400, w.Code)

		// Invalid replay_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{
			"replay_id": "nonexistent",
		})
		assert.True(t, result.IsError)

		// Invalid replay_id via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/get", ReplayGetRequest{
			ReplayID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)
	})
}

func TestFlowExport_Integration(t *testing.T) {
	srv, _, cleanup := setupIntegrationServer(t)
	defer cleanup()

	t.Run("export_and_replay_from_bundle", func(t *testing.T) {
		// Get a flow ID
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET", Limit: 1})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var list ProxyListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))

		if len(list.Flows) == 0 {
			t.Skip("no proxy history entries available")
		}

		flowID := list.Flows[0].FlowID

		// Export via HTTP
		w = doTestRequest(t, srv, "POST", "/flow/export", FlowExportRequest{FlowID: flowID})
		require.Equal(t, 200, w.Code)

		var exportResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &exportResp))
		require.True(t, exportResp.OK, "export failed: %v", exportResp.Error)

		var export FlowExportResponse
		require.NoError(t, json.Unmarshal(exportResp.Data, &export))

		assert.NotEmpty(t, export.BundleID)
		assert.NotEmpty(t, export.BundlePath)
		t.Logf("Exported to bundle: %s at %s", export.BundleID, export.BundlePath)

		// Verify bundle files exist
		assert.FileExists(t, filepath.Join(export.BundlePath, "request.http"))
		assert.FileExists(t, filepath.Join(export.BundlePath, "body"))
		assert.FileExists(t, filepath.Join(export.BundlePath, "request.meta.json"))

		// Read request content
		reqContent, err := os.ReadFile(filepath.Join(export.BundlePath, "request.http"))
		require.NoError(t, err)
		assert.Contains(t, string(reqContent), "HTTP/")

		// Replay from bundle_id via HTTP
		w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			BundleID: export.BundleID,
		})
		require.Equal(t, 200, w.Code)

		var replayResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &replayResp))
		require.True(t, replayResp.OK, "replay from bundle failed: %v", replayResp.Error)

		var replay ReplaySendResponse
		require.NoError(t, json.Unmarshal(replayResp.Data, &replay))

		assert.NotEmpty(t, replay.ReplayID)
		assert.NotEmpty(t, replay.Duration)
		t.Logf("Replay from bundle: status=%d duration=%s", replay.Status, replay.Duration)
	})

	t.Run("export_validation", func(t *testing.T) {
		// Missing flow_id via HTTP
		w := doTestRequest(t, srv, "POST", "/flow/export", FlowExportRequest{})
		assert.Equal(t, 400, w.Code)

		// Invalid flow_id via HTTP
		w = doTestRequest(t, srv, "POST", "/flow/export", FlowExportRequest{
			FlowID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)
	})
}
