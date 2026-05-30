package service

import (
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleJSEndpoint(t *testing.T) {
	t.Parallel()

	jsBody := `
fetch('/api/users', {method: 'POST', body: JSON.stringify({name, email}), headers: {'X-API-Key': 'abc'}});
fetch('/api/items', {method: 'POST'});
var bare = '/just/a/literal/path';
`

	setup := func(t *testing.T) (*mcpclient.Client, string) {
		t.Helper()
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)
		flowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
			"",
		)
		return mcpClient, flowID
	}

	t.Run("expands_body_and_headers", func(t *testing.T) {
		client, flowID := setup(t)

		surface := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, client, "js_surface",
			map[string]interface{}{"flow_id": flowID})
		var id string
		for _, e := range surface.Endpoints {
			if e.URL == "/api/users" {
				id = e.EndpointID
			}
		}
		require.NotEmpty(t, id, "expected endpoint_id on /api/users")

		resp := CallMCPToolJSONOK[protocol.JSEndpointResponse](t, client, "js_endpoint",
			map[string]interface{}{"endpoint": flowID + "." + id})

		assert.Equal(t, "POST", resp.Method)
		assert.Equal(t, "/api/users", resp.URL)
		require.Len(t, resp.CallSites, 1)
		cs := resp.CallSites[0]
		require.NotNil(t, cs.Body)
		assert.Equal(t, "json", cs.Body.ContentType)
		require.Len(t, cs.Body.Fields, 2)
		require.Len(t, cs.Headers, 1)
		assert.Equal(t, "X-API-Key", cs.Headers[0].Name)
		assert.Equal(t, "abc", cs.Headers[0].Value)
	})

	t.Run("method_only_endpoint_has_no_id", func(t *testing.T) {
		client, flowID := setup(t)
		surface := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, client, "js_surface",
			map[string]interface{}{"flow_id": flowID})
		for _, e := range surface.Endpoints {
			if e.URL == "/api/items" || e.URL == "/just/a/literal/path" {
				assert.Empty(t, e.EndpointID, e.URL)
			}
		}
	})

	t.Run("invalid_handle", func(t *testing.T) {
		client, _ := setup(t)
		res := CallMCPTool(t, client, "js_endpoint", map[string]interface{}{"endpoint": "no-dot"})
		assert.True(t, res.IsError)
	})

	t.Run("unknown_endpoint_id", func(t *testing.T) {
		client, flowID := setup(t)
		res := CallMCPTool(t, client, "js_endpoint", map[string]interface{}{"endpoint": flowID + ".zzzzzz"})
		assert.True(t, res.IsError)
	})
}
