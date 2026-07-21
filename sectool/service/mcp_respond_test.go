package service

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestMCP_ProxyRespondAdd(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

func TestMCP_ProxyRespondAdd_ScalarHeaders(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	resp := CallMCPToolJSONOK[protocol.ResponderEntry](t, mcpClient, "proxy_respond_add", map[string]interface{}{
		"origin": "https://example.com",
		"path":   "/scalars",
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
}

func TestGetStringMapArg(t *testing.T) {
	t.Parallel()

	newReq := func(args map[string]interface{}) mcp.CallToolRequest {
		return mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}}
	}

	t.Run("missing_key", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(newReq(map[string]interface{}{}), "headers"))
	})

	t.Run("nil_value", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(newReq(map[string]interface{}{"headers": nil}), "headers"))
	})

	t.Run("wrong_type", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(newReq(map[string]interface{}{"headers": "oops"}), "headers"))
	})

	t.Run("string_encoded_object", func(t *testing.T) {
		got := getStringMapArg(newReq(map[string]interface{}{
			"headers": `{"X-Test": "v", "X-Num": 2}`,
		}), "headers")

		assert.Equal(t, map[string]string{"X-Test": "v", "X-Num": "2"}, got)
	})

	t.Run("coerce_scalars", func(t *testing.T) {
		got := getStringMapArg(newReq(map[string]interface{}{"headers": map[string]interface{}{
			"str":    "v",
			"num":    float64(0),
			"flag":   true,
			"null":   nil,
			"nested": map[string]interface{}{"a": "b"},
			"list":   []interface{}{"a"},
		}}), "headers")

		assert.Equal(t, map[string]string{
			"str":  "v",
			"num":  "0",
			"flag": "true",
			"null": "",
		}, got)
	})
}

func TestMCP_ProxyRespondAdd_Validation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
