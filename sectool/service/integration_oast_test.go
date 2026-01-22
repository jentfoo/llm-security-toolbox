package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for OAST functionality against a real Burp Suite instance.
// These tests validate end-to-end functionality through both HTTP handlers and MCP tools.

func TestOast_Integration(t *testing.T) {
	srv, mcpClient, cleanup := setupIntegrationServer(t)
	defer cleanup()

	var oastID string

	t.Run("create_via_mcp", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "integration-test",
		})
		require.False(t, result.IsError, "oast_create should succeed: %s", testutil.ExtractMCPText(t, result))

		text := testutil.ExtractMCPText(t, result)
		var resp OastCreateResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		oastID = resp.OastID
		t.Logf("Created OAST: id=%s domain=%s", oastID, resp.Domain)
	})

	t.Run("create_via_http", func(t *testing.T) {
		w := doTestRequest(t, srv, "POST", "/oast/create", OastCreateRequest{
			Label: "integration-http-test",
		})
		require.Equal(t, 200, w.Code)

		var apiResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &apiResp))
		require.True(t, apiResp.OK)

		var resp OastCreateResponse
		require.NoError(t, json.Unmarshal(apiResp.Data, &resp))

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, "integration-http-test", resp.Label)
		t.Logf("Created OAST via HTTP: id=%s domain=%s", resp.OastID, resp.Domain)

		// Clean up
		_ = testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": resp.OastID,
		})
	})

	t.Run("list_via_http", func(t *testing.T) {
		w := doTestRequest(t, srv, "POST", "/oast/list", OastListRequest{})
		require.Equal(t, 200, w.Code)

		var apiResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &apiResp))
		var list OastListResponse
		require.NoError(t, json.Unmarshal(apiResp.Data, &list))

		var found bool
		for _, s := range list.Sessions {
			if s.OastID == oastID {
				found = true
				break
			}
		}
		assert.True(t, found, "OAST created via MCP should be visible via HTTP")
	})

	t.Run("list_via_mcp", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var list OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &list))

		var found bool
		for _, s := range list.Sessions {
			if s.OastID == oastID {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("poll_via_http", func(t *testing.T) {
		w := doTestRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: oastID,
		})
		require.Equal(t, 200, w.Code)

		var apiResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &apiResp))
		var poll OastPollResponse
		require.NoError(t, json.Unmarshal(apiResp.Data, &poll))
		// Events may be empty
	})

	t.Run("poll_via_mcp", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var poll OastPollResponse
		require.NoError(t, json.Unmarshal([]byte(text), &poll))
		// Events may be empty
	})

	t.Run("delete_via_mcp", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError)

		// Verify via HTTP
		w := doTestRequest(t, srv, "POST", "/oast/list", OastListRequest{})
		require.Equal(t, 200, w.Code)

		var apiResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &apiResp))
		var list OastListResponse
		require.NoError(t, json.Unmarshal(apiResp.Data, &list))

		for _, s := range list.Sessions {
			assert.NotEqual(t, oastID, s.OastID)
		}
	})

	t.Run("delete_via_http", func(t *testing.T) {
		// Create a new session to delete via HTTP
		result := testutil.CallMCPTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "delete-http-test",
		})
		require.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var createResp OastCreateResponse
		require.NoError(t, json.Unmarshal([]byte(text), &createResp))

		// Delete via HTTP
		w := doTestRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{
			OastID: createResp.OastID,
		})
		require.Equal(t, 200, w.Code)

		// Verify via MCP
		listResult := testutil.CallMCPTool(t, mcpClient, "oast_list", nil)
		text = testutil.ExtractMCPText(t, listResult)
		var list OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &list))

		for _, s := range list.Sessions {
			assert.NotEqual(t, createResp.OastID, s.OastID)
		}
	})

	t.Run("poll_validation", func(t *testing.T) {
		// Missing oast_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Missing oast_id via HTTP
		w := doTestRequest(t, srv, "POST", "/oast/poll", OastPollRequest{})
		assert.Equal(t, 400, w.Code)

		// Invalid oast_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)

		// Invalid oast_id via HTTP
		w = doTestRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)
	})

	t.Run("get_validation", func(t *testing.T) {
		// Missing oast_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Missing event_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{
			"oast_id": "test",
		})
		assert.True(t, result.IsError)

		// Missing oast_id via HTTP
		w := doTestRequest(t, srv, "POST", "/oast/get", OastGetRequest{})
		assert.Equal(t, 400, w.Code)

		// Missing event_id via HTTP
		w = doTestRequest(t, srv, "POST", "/oast/get", OastGetRequest{
			OastID: "test",
		})
		assert.Equal(t, 400, w.Code)
	})

	t.Run("delete_validation", func(t *testing.T) {
		// Missing oast_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Missing oast_id via HTTP
		w := doTestRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{})
		assert.Equal(t, 400, w.Code)

		// Invalid oast_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)

		// Invalid oast_id via HTTP
		w = doTestRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{
			OastID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)
	})
}
