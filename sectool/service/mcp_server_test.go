package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// Unit tests for MCP server functionality using mock backends.
// Integration tests that require Burp Suite are in integration_test.go.

// setupMCPServerWithMock creates an MCP server with mock backends for unit testing.
func setupMCPServerWithMock(t *testing.T) (*Server, *client.Client, *TestMCPServer) {
	t.Helper()

	mockMCP := NewTestMCPServer(t)
	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:      workDir,
		BurpMCPURL:   mockMCP.URL(),
		MCP:          true,
		MCPPort:      0, // Let OS pick a port
		WorkflowMode: WorkflowModeNone,
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	require.NotNil(t, srv.mcpServer, "MCP server should be started")

	// Use in-process client for reliable testing
	mcpClient, err := client.NewInProcessClient(srv.mcpServer.server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = mcpClient.Close()
		srv.RequestShutdown()
		<-serverErr
	})

	return srv, mcpClient, mockMCP
}

// =============================================================================
// Tool List Tests
// =============================================================================

func TestMCP_ListTools(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

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

// =============================================================================
// Mock-Based Happy Path Tests
// =============================================================================

func TestMCP_ProxySummaryWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP := setupMCPServerWithMock(t)

	// Add mock proxy history
	mockMCP.AddProxyEntry(
		"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[]}",
		"",
	)
	mockMCP.AddProxyEntry(
		"POST /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n{\"name\":\"test\"}",
		"HTTP/1.1 201 Created\r\n\r\n",
		"",
	)

	result := testutil.CallMCPTool(t, mcpClient, "proxy_summary", nil)
	assert.False(t, result.IsError, "proxy_summary should succeed")

	text := testutil.ExtractMCPText(t, result)
	var resp ProxySummaryResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))
	assert.NotEmpty(t, resp.Aggregates)
}

func TestMCP_ProxyListWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP := setupMCPServerWithMock(t)

	// Add mock entries
	mockMCP.AddProxyEntry(
		"GET /api/data HTTP/1.1\r\nHost: test.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)

	result := testutil.CallMCPTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	assert.False(t, result.IsError, "proxy_list with filter should succeed")

	text := testutil.ExtractMCPText(t, result)
	var resp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))
	assert.NotEmpty(t, resp.Flows)
	assert.Equal(t, "GET", resp.Flows[0].Method)
}

func TestMCP_ProxyListWithLimit(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP := setupMCPServerWithMock(t)

	// Add multiple entries
	for i := 0; i < 5; i++ {
		mockMCP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n",
			"",
		)
	}

	result := testutil.CallMCPTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
		"limit":  2,
	})
	assert.False(t, result.IsError)

	text := testutil.ExtractMCPText(t, result)
	var resp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))
	assert.LessOrEqual(t, len(resp.Flows), 2)
}

func TestMCP_ProxyGetWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP := setupMCPServerWithMock(t)

	mockMCP.AddProxyEntry(
		"GET /api/test HTTP/1.1\r\nHost: mock.example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ntest response body",
		"",
	)

	// First get a flow ID
	listResult := testutil.CallMCPTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := testutil.ExtractMCPText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))
	require.NotEmpty(t, listResp.Flows)

	flowID := listResp.Flows[0].FlowID

	// Get full flow data
	getResult := testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
		"flow_id": flowID,
	})
	assert.False(t, getResult.IsError)

	text = testutil.ExtractMCPText(t, getResult)
	var getResp ProxyGetResponse
	require.NoError(t, json.Unmarshal([]byte(text), &getResp))

	assert.Equal(t, flowID, getResp.FlowID)
	assert.Equal(t, "GET", getResp.Method)
	assert.NotEmpty(t, getResp.ReqHeaders)
	assert.NotEmpty(t, getResp.RespHeaders)
}

func TestMCP_ProxyRulesCRUDWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	var ruleID string

	t.Run("add_rule", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    RuleTypeRequestHeader,
			"label":   "mock-test-rule",
			"replace": "X-Mock-Test: value",
		})
		require.False(t, result.IsError, "add should succeed: %s", testutil.ExtractMCPText(t, result))

		text := testutil.ExtractMCPText(t, result)
		var rule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &rule))
		assert.NotEmpty(t, rule.RuleID)
		assert.Equal(t, "mock-test-rule", rule.Label)
		ruleID = rule.RuleID
	})

	t.Run("list_rules", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var resp RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		var found bool
		for _, r := range resp.Rules {
			if r.RuleID == ruleID {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("update_rule", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": ruleID,
			"type":    RuleTypeRequestBody,
			"label":   "mock-test-updated",
			"match":   "old",
			"replace": "new",
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var rule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &rule))
		assert.Equal(t, "mock-test-updated", rule.Label)
		assert.Equal(t, RuleTypeRequestBody, rule.Type)
	})

	t.Run("delete_rule", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
			"rule_id": ruleID,
		})
		assert.False(t, result.IsError)

		// Verify deleted
		listResult := testutil.CallMCPTool(t, mcpClient, "proxy_rule_list", nil)
		text := testutil.ExtractMCPText(t, listResult)
		var resp RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		for _, r := range resp.Rules {
			assert.NotEqual(t, ruleID, r.RuleID)
		}
	})
}

func TestMCP_ReplayWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP := setupMCPServerWithMock(t)

	// Add mock entry and set response
	mockMCP.AddProxyEntry(
		"GET /replay-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\noriginal",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=GET /replay-test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nreplayed response}",
	)

	// Get flow ID
	listResult := testutil.CallMCPTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := testutil.ExtractMCPText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))
	require.NotEmpty(t, listResp.Flows)

	flowID := listResp.Flows[0].FlowID

	// Send replay
	sendResult := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	require.False(t, sendResult.IsError, "replay_send should succeed: %s", testutil.ExtractMCPText(t, sendResult))

	text = testutil.ExtractMCPText(t, sendResult)
	var sendResp ReplaySendResponse
	require.NoError(t, json.Unmarshal([]byte(text), &sendResp))
	assert.NotEmpty(t, sendResp.ReplayID)

	// Get replay result
	getResult := testutil.CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{
		"replay_id": sendResp.ReplayID,
	})
	assert.False(t, getResult.IsError)

	text = testutil.ExtractMCPText(t, getResult)
	var getResp ReplayGetResponse
	require.NoError(t, json.Unmarshal([]byte(text), &getResp))
	assert.Equal(t, sendResp.ReplayID, getResp.ReplayID)
	assert.NotEmpty(t, getResp.RespHeaders)
}

func TestMCP_OastLifecycleWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	var oastID string

	t.Run("create", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "mock-oast-test",
		})
		require.False(t, result.IsError, "oast_create should succeed: %s", testutil.ExtractMCPText(t, result))

		text := testutil.ExtractMCPText(t, result)
		var resp OastCreateResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, "mock-oast-test", resp.Label)
		oastID = resp.OastID
	})

	t.Run("list", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_list", nil)
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var resp OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		var found bool
		for _, s := range resp.Sessions {
			if s.OastID == oastID {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("poll", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		var resp OastPollResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		// Events may be empty
	})

	t.Run("delete", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError)

		// Verify deleted
		listResult := testutil.CallMCPTool(t, mcpClient, "oast_list", nil)
		text := testutil.ExtractMCPText(t, listResult)
		var resp OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		for _, s := range resp.Sessions {
			assert.NotEqual(t, oastID, s.OastID)
		}
	})
}

func TestMCP_ProxyListRequiresFilters(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	result := testutil.CallMCPTool(t, mcpClient, "proxy_list", nil)
	assert.True(t, result.IsError, "proxy_list without filters should fail")
}

func TestMCP_ProxyGetValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("missing_flow_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without flow_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "flow_id is required")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid flow_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})
}

func TestMCP_ProxyRuleValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("add_missing_type", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError, "should fail without type")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "type is required")
	})

	t.Run("add_invalid_type", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type": "invalid_type",
		})
		assert.True(t, result.IsError, "should fail with invalid type")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "invalid rule type")
	})

	t.Run("update_missing_rule_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"type": RuleTypeRequestHeader,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "rule_id is required")
	})

	t.Run("update_missing_type", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "type is required")
	})

	t.Run("update_invalid_type", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
			"type":    "invalid_type",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "invalid rule type")
	})

	t.Run("update_invalid_rule_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "nonexistent",
			"type":    RuleTypeRequestHeader,
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})

	t.Run("delete_missing_rule_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without rule_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "rule_id is required")
	})

	t.Run("delete_invalid_rule_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
			"rule_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})
}

func TestMCP_ReplayValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("missing_flow_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without flow_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "flow_id")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid flow_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})

	t.Run("missing_replay_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without replay_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "replay_id is required")
	})

	t.Run("invalid_replay_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{
			"replay_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid replay_id")
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})
}

func TestMCP_OastValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("poll_missing_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "oast_id is required")
	})

	t.Run("poll_invalid_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})

	t.Run("get_missing_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "oast_id is required")
	})

	t.Run("get_missing_event_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{
			"oast_id": "test",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "event_id is required")
	})

	t.Run("delete_missing_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "oast_id is required")
	})

	t.Run("delete_invalid_id", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "not found")
	})
}

// =============================================================================
// Encode Tests
// =============================================================================

func TestMCP_EncodeURL(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("encode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_url", map[string]interface{}{
			"input": "hello world&test=<value>",
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "hello+world%26test%3D%3Cvalue%3E", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_url", map[string]interface{}{
			"input":  "hello+world%26test%3D%3Cvalue%3E",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "hello world&test=<value>", text)
	})

	t.Run("missing_input", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_url", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "input is required")
	})
}

func TestMCP_EncodeBase64(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("encode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input": "hello world",
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "aGVsbG8gd29ybGQ=", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "aGVsbG8gd29ybGQ=",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "hello world", text)
	})

	t.Run("invalid_base64", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "not valid base64!!!",
			"decode": true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, testutil.ExtractMCPText(t, result), "base64 decode error")
	})
}

func TestMCP_EncodeHTML(t *testing.T) {
	t.Parallel()

	_, mcpClient, _ := setupMCPServerWithMock(t)

	t.Run("encode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_html", map[string]interface{}{
			"input": "<script>alert('xss')</script>",
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := testutil.CallMCPTool(t, mcpClient, "encode_html", map[string]interface{}{
			"input":  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := testutil.ExtractMCPText(t, result)
		assert.Equal(t, "<script>alert('xss')</script>", text)
	})
}
