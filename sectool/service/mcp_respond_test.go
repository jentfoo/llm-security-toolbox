package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleProxyRespondAdd(t *testing.T) {
	t.Parallel()

	t.Run("full_fields", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host":        "example.com",
			"path":        "/set-cookies",
			"status_code": 200,
			"headers":     map[string]interface{}{"Set-Cookie": "session=abc123"},
			"body":        "<html>ok</html>",
			"label":       "set-cookies",
		})

		assert.NotEmpty(t, resp.ResponderID)
		assert.Equal(t, "example.com", resp.Host)
		assert.Equal(t, "/set-cookies", resp.Path)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "set-cookies", resp.Label)
		assert.Equal(t, "<html>ok</html>", resp.Body)
	})

	t.Run("scalar_headers", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host": "example.com",
			"path": "/scalars",
			"headers": map[string]interface{}{
				"Content-Length": 0,
				"X-Flag":         true,
				"X-Name":         "value",
				"X-Empty":        nil,
			},
		})

		assert.Equal(t, "0", resp.Headers["Content-Length"])
		assert.Equal(t, "true", resp.Headers["X-Flag"])
		assert.Equal(t, "value", resp.Headers["X-Name"])
		assert.Empty(t, resp.Headers["X-Empty"])
	})

	t.Run("missing_host", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"path": "/page",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "host is required")
	})

	t.Run("missing_path", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host": "example.com",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "path is required")
	})

	t.Run("duplicate_label", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host":  "example.com",
			"path":  "/a",
			"label": "dup",
		})

		result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host":  "example.com",
			"path":  "/b",
			"label": "dup",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "label already exists")
	})
}

func TestHandleProxyRespondDelete(t *testing.T) {
	t.Parallel()

	t.Run("by_id", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host": "example.com",
			"path": "/page",
		})

		CallMCPToolTextOK(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
			"id": resp.ResponderID,
		})

		result := CallMCPTool(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
			"id": resp.ResponderID,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("by_label", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"host":  "example.com",
			"path":  "/page",
			"label": "my-page",
		})

		CallMCPToolTextOK(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
			"id": "my-page",
		})

		listResp := CallMCPToolJSONOK[protocol.ResponderListResponse](t, mcpClient, "proxy_respond_list", nil)
		assert.Empty(t, listResp.Responders)
	})
}

func TestHandleProxyRespondList(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	// Empty list
	listResp := CallMCPToolJSONOK[protocol.ResponderListResponse](t, mcpClient, "proxy_respond_list", nil)
	require.Empty(t, listResp.Responders)

	// Add two
	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"host": "example.com",
		"path": "/a",
	})
	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"host": "example.com",
		"path": "/b",
	})

	listResp = CallMCPToolJSONOK[protocol.ResponderListResponse](t, mcpClient, "proxy_respond_list", nil)
	assert.Len(t, listResp.Responders, 2)
}
