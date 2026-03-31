package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestMCP_ProxyRespondAdd(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin":      "https://example.com",
		"path":        "/set-cookies",
		"status_code": 200,
		"headers":     map[string]interface{}{"Set-Cookie": "session=abc123"},
		"body":        "<html>ok</html>",
		"label":       "set-cookies",
	})

	assert.NotEmpty(t, resp.ResponderID)
	assert.Equal(t, "https://example.com", resp.Origin)
	assert.Equal(t, "/set-cookies", resp.Path)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "set-cookies", resp.Label)
	assert.Equal(t, "<html>ok</html>", resp.Body)
}

func TestMCP_ProxyRespondAdd_Validation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	t.Run("missing_origin", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"path": "/page",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "origin is required")
	})

	t.Run("missing_path", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
			"origin": "https://example.com",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "path is required")
	})
}

func TestMCP_ProxyRespondAdd_DuplicateLabel(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/a",
		"label":  "dup",
	})

	result := CallMCPTool(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/b",
		"label":  "dup",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, ExtractMCPText(t, result), "label already exists")
}

func TestMCP_ProxyRespondDelete(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/page",
	})

	// Delete by ID
	CallMCPToolTextOK(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
		"id": resp.ResponderID,
	})

	// Delete again fails
	result := CallMCPTool(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
		"id": resp.ResponderID,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, ExtractMCPText(t, result), "not found")
}

func TestMCP_ProxyRespondDelete_ByLabel(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/page",
		"label":  "my-page",
	})

	CallMCPToolTextOK(t, mcpClient, "proxy_respond_delete", map[string]interface{}{
		"id": "my-page",
	})
}

func TestMCP_ProxyRespondList(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

	// Empty list
	listResp := CallMCPToolJSONOK[protocol.ResponderListResponse](t, mcpClient, "proxy_respond_list", nil)
	require.Empty(t, listResp.Responders)

	// Add two
	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/a",
	})
	CallMCPToolTextOK(t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/b",
	})

	listResp = CallMCPToolJSONOK[protocol.ResponderListResponse](t, mcpClient, "proxy_respond_list", nil)
	assert.Len(t, listResp.Responders, 2)
}
