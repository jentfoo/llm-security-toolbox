package service

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	burpmcp "github.com/go-harden/llm-security-toolbox/sectool/service/mcp"
	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for proxy functionality against a real Burp Suite instance.
// These tests validate end-to-end functionality through both HTTP handlers and MCP tools.
//
// Skip automatically if Burp is not available or if running with -short flag.
// Run with: go test -v ./sectool/service -run Integration
// Run all (including integration): make test-all

func TestBurpClient_Integration(t *testing.T) {
	client := connectBurpOrSkip(t)

	t.Run("parse_response", func(t *testing.T) {
		params := burpmcp.SendRequestParams{
			Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
			TargetHostname: "httpbin.org",
			TargetPort:     443,
			UsesHTTPS:      true,
		}
		response, err := client.SendHTTP1Request(t.Context(), params)
		require.NoError(t, err)

		t.Logf("Raw Burp response length: %d bytes", len(response))

		headers, body, err := parseBurpResponse(response)
		require.NoError(t, err, "parseBurpResponse should succeed")

		assert.True(t, bytes.HasPrefix(headers, []byte("HTTP/")))
		assert.True(t, bytes.HasSuffix(headers, []byte("\r\n\r\n")))

		resp, err := readResponseBytes(headers)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)

		assert.NotEmpty(t, body)
		assert.True(t, bytes.Contains(body, []byte("httpbin.org")))
	})
}

func TestProxyHistory_Integration(t *testing.T) {
	srv, mcpClient, cleanup := setupIntegrationServer(t)
	defer cleanup()

	t.Run("summary_via_http", func(t *testing.T) {
		w := doTestRequest(t, srv, "POST", "/proxy/summary", ProxyListRequest{})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var summaryResp ProxySummaryResponse
		require.NoError(t, json.Unmarshal(resp.Data, &summaryResp))
		t.Logf("HTTP summary: %d aggregates", len(summaryResp.Aggregates))
	})

	t.Run("summary_via_mcp", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_summary", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var resp ProxySummaryResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		t.Logf("MCP summary: %d aggregates", len(resp.Aggregates))
	})

	t.Run("list_requires_filters", func(t *testing.T) {
		// HTTP handler requires filters
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{})
		require.Equal(t, 400, w.Code)

		// MCP tool requires filters
		result := testutil.CallMCPTool(t, mcpClient, "proxy_list", nil)
		assert.True(t, result.IsError)
	})

	t.Run("list_with_filters", func(t *testing.T) {
		// Via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET", Limit: 5})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpList ProxyListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpList))

		// Via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_list", map[string]interface{}{
			"method": "GET",
			"limit":  5,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var mcpList ProxyListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))

		t.Logf("HTTP list: %d flows, MCP list: %d flows", len(httpList.Flows), len(mcpList.Flows))
	})

	t.Run("get_flow", func(t *testing.T) {
		// Get a flow ID first
		w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Limit: 1})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var list ProxyListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))

		if len(list.Flows) == 0 {
			t.Skip("no proxy history entries available")
		}

		flowID := list.Flows[0].FlowID

		// Get via HTTP
		w = doTestRequest(t, srv, "POST", "/flow/get", FlowGetRequest{FlowID: flowID})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpFlow FlowGetResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpFlow))

		// Get via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
			"flow_id": flowID,
		})
		require.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var mcpFlow ProxyGetResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpFlow))

		// Both should return same data
		assert.Equal(t, httpFlow.Method, mcpFlow.Method)
		assert.Equal(t, httpFlow.URL, mcpFlow.URL)
		assert.Equal(t, httpFlow.Status, mcpFlow.Status)
	})

	t.Run("get_flow_validation", func(t *testing.T) {
		// Missing flow_id via HTTP
		w := doTestRequest(t, srv, "POST", "/flow/get", FlowGetRequest{})
		assert.Equal(t, 400, w.Code)

		// Missing flow_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Invalid flow_id via HTTP
		w = doTestRequest(t, srv, "POST", "/flow/get", FlowGetRequest{FlowID: "nonexistent"})
		assert.Equal(t, 404, w.Code)

		// Invalid flow_id via MCP
		result = testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
	})
}

func TestProxyRules_Integration(t *testing.T) {
	t.Skip("tests only work if burp allows config edits")

	srv, mcpClient, cleanup := setupIntegrationServer(t)
	defer cleanup()

	backend := srv.httpBackend
	cleanupAllRules(t, backend)
	t.Cleanup(func() { cleanupAllRules(t, backend) })

	var createdRuleID string

	t.Run("list_empty_via_both", func(t *testing.T) {
		// Via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpList))
		assert.Empty(t, httpList.Rules)

		// Via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var mcpList RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))
		assert.Empty(t, mcpList.Rules)
	})

	t.Run("add_via_http_read_via_mcp", func(t *testing.T) {
		// Add via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "integration-http-add",
			Type:    RuleTypeRequestHeader,
			Replace: "X-Integration-Test: http-added",
		})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var rule RuleEntry
		require.NoError(t, json.Unmarshal(httpResp.Data, &rule))
		createdRuleID = rule.RuleID

		// Verify via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var mcpList RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))

		var found bool
		for _, r := range mcpList.Rules {
			if r.RuleID == createdRuleID {
				found = true
				assert.Equal(t, "integration-http-add", r.Label)
				break
			}
		}
		assert.True(t, found, "rule added via HTTP should be visible via MCP")
	})

	t.Run("update_via_mcp_read_via_http", func(t *testing.T) {
		// Update via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": createdRuleID,
			"type":    RuleTypeRequestBody,
			"label":   "integration-mcp-updated",
			"match":   "old",
			"replace": "new",
		})
		assert.False(t, result.IsError)

		// Verify via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpList))

		var found bool
		for _, r := range httpList.Rules {
			if r.RuleID == createdRuleID {
				found = true
				assert.Equal(t, "integration-mcp-updated", r.Label)
				assert.Equal(t, RuleTypeRequestBody, r.Type)
				break
			}
		}
		assert.True(t, found, "rule updated via MCP should be visible via HTTP")
	})

	t.Run("delete_via_http", func(t *testing.T) {
		w := doTestRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{
			RuleID: createdRuleID,
		})
		require.Equal(t, 200, w.Code)

		// Verify via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var mcpList RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))

		for _, r := range mcpList.Rules {
			assert.NotEqual(t, createdRuleID, r.RuleID)
		}
	})

	t.Run("websocket_rules", func(t *testing.T) {
		// Add WS rule via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    "ws:to-server",
			"label":   "integration-ws-rule",
			"match":   "client-msg",
			"replace": "modified-msg",
		})
		require.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var wsRule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &wsRule))

		// Verify WS rule appears in WS list via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var wsList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &wsList))

		var found bool
		for _, r := range wsList.Rules {
			if r.RuleID == wsRule.RuleID {
				found = true
				assert.Equal(t, "ws:to-server", r.Type)
				break
			}
		}
		assert.True(t, found)

		// Verify WS rule does NOT appear in HTTP list
		w = doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: false})
		require.Equal(t, 200, w.Code)

		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpList))

		for _, r := range httpList.Rules {
			assert.NotEqual(t, wsRule.RuleID, r.RuleID)
		}
	})

	t.Run("add_validation", func(t *testing.T) {
		// Missing type via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Replace: "X-Test: value",
		})
		assert.Equal(t, 400, w.Code)

		// Missing type via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError)

		// Invalid type via HTTP
		w = doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Type: "invalid_type",
		})
		assert.Equal(t, 400, w.Code)

		// Invalid type via MCP
		result = testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type": "invalid_type",
		})
		assert.True(t, result.IsError)
	})

	t.Run("update_validation", func(t *testing.T) {
		// Missing rule_id via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			Type:    RuleTypeRequestHeader,
			Replace: "X-Test: value",
		})
		assert.Equal(t, 400, w.Code)

		// Missing rule_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"type":    RuleTypeRequestHeader,
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError)

		// Missing type via HTTP
		w = doTestRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID: "some-id",
		})
		assert.Equal(t, 400, w.Code)

		// Missing type via MCP
		result = testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
		})
		assert.True(t, result.IsError)

		// Not found via HTTP
		w = doTestRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID:  "nonexistent",
			Type:    RuleTypeRequestHeader,
			Replace: "X-Test: value",
		})
		assert.Equal(t, 404, w.Code)

		// Not found via MCP
		result = testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "nonexistent",
			"type":    RuleTypeRequestHeader,
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError)
	})

	t.Run("delete_validation", func(t *testing.T) {
		// Missing rule_id via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{})
		assert.Equal(t, 400, w.Code)

		// Missing rule_id via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{})
		assert.True(t, result.IsError)

		// Not found via HTTP
		w = doTestRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{
			RuleID: "nonexistent",
		})
		assert.Equal(t, 404, w.Code)

		// Not found via MCP
		result = testutil.CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
			"rule_id": "nonexistent",
		})
		assert.True(t, result.IsError)
	})

	t.Run("regex_rule", func(t *testing.T) {
		// Add regex rule via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "integration-regex",
			Type:    RuleTypeResponseHeader,
			IsRegex: true,
			Match:   "^X-Server:.*$",
			Replace: "",
		})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var rule RuleEntry
		require.NoError(t, json.Unmarshal(httpResp.Data, &rule))

		assert.True(t, rule.IsRegex)
		assert.Equal(t, "^X-Server:.*$", rule.Match)
		assert.Equal(t, RuleTypeResponseHeader, rule.Type)

		// Verify via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		text := testutil.ExtractMCPText(t, result)
		var mcpList RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))

		var found bool
		for _, r := range mcpList.Rules {
			if r.RuleID == rule.RuleID {
				found = true
				assert.True(t, r.IsRegex)
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("duplicate_label_rejected", func(t *testing.T) {
		// Add first rule
		w := doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "integration-dup-label",
			Type:    RuleTypeRequestHeader,
			Replace: "X-Dup: first",
		})
		require.Equal(t, 200, w.Code)

		// Try to add duplicate label via HTTP
		w = doTestRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "integration-dup-label",
			Type:    RuleTypeRequestHeader,
			Replace: "X-Dup: second",
		})
		assert.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp.Error.Hint, "already exists")

		// Try to add duplicate label via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"label":   "integration-dup-label",
			"type":    RuleTypeRequestHeader,
			"replace": "X-Dup: third",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "already exists")
	})

	t.Run("list_with_limit", func(t *testing.T) {
		// List with limit=1 via HTTP
		w := doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{Limit: 1})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpList))
		assert.LessOrEqual(t, len(httpList.Rules), 1)

		// List with limit=1 via MCP
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", map[string]interface{}{
			"limit": 1,
		})
		assert.False(t, result.IsError)
		text := testutil.ExtractMCPText(t, result)
		var mcpList RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &mcpList))
		assert.LessOrEqual(t, len(mcpList.Rules), 1)
	})

	t.Run("ws_all_rule_types", func(t *testing.T) {
		// Test ws:to-client
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    "ws:to-client",
			"label":   "integration-ws-to-client",
			"match":   "server-msg",
			"replace": "modified-server-msg",
		})
		require.False(t, result.IsError)
		text := testutil.ExtractMCPText(t, result)
		var toClientRule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &toClientRule))
		assert.Equal(t, "ws:to-client", toClientRule.Type)

		// Test ws:both
		result = testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    "ws:both",
			"label":   "integration-ws-both",
			"match":   "secret",
			"replace": "REDACTED",
		})
		require.False(t, result.IsError)
		text = testutil.ExtractMCPText(t, result)
		var bothRule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &bothRule))
		assert.Equal(t, "ws:both", bothRule.Type)

		// Verify both appear in WS list
		w := doTestRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)

		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var wsList RuleListResponse
		require.NoError(t, json.Unmarshal(httpResp.Data, &wsList))

		foundTypes := make(map[string]bool)
		for _, r := range wsList.Rules {
			foundTypes[r.Type] = true
		}
		assert.True(t, foundTypes["ws:to-client"])
		assert.True(t, foundTypes["ws:both"])
	})
}

func TestMCPToolList_Integration(t *testing.T) {
	_, mcpClient, cleanup := setupIntegrationServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)

	expectedTools := []string{
		"proxy_summary",
		"proxy_list",
		"proxy_get",
		"proxy_rule_list",
		"proxy_rule_add",
		"proxy_rule_update",
		"proxy_rule_delete",
		"replay_send",
		"replay_get",
		"oast_create",
		"oast_poll",
		"oast_get",
		"oast_list",
		"oast_delete",
		"encode_url",
		"encode_base64",
		"encode_html",
	}

	toolNames := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		toolNames[i] = tool.Name
	}

	for _, expected := range expectedTools {
		assert.Contains(t, toolNames, expected, "tool %s should be registered", expected)
	}
}
