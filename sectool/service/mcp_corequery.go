package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// coreToolHandler is a read-side MCP tool handler invocable via core_query.
type coreToolHandler func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)

// coreQueryHandlers builds the read-only core tools a sidecar may invoke. Write
// tools are intentionally excluded; the host enforces the same allowlist. Called
// once at construction; CoreQuery dispatches via the stored coreQueryDispatch.
func (m *mcpServer) coreQueryHandlers() map[string]coreToolHandler {
	return map[string]coreToolHandler{
		"proxy_poll":      m.handleProxyPoll,
		"flow_get":        m.handleFlowGet,
		"proxy_rule_list": m.handleProxyRuleList,
		"cookie_jar":      m.handleCookieJar,
		"diff_flow":       m.handleDiffFlow,
		"find_reflected":  m.handleFindReflected,
		"notes_list":      m.handleNotesList,
		"oast_poll":       m.handleOastPoll,
	}
}

// CoreQuery dispatches a read-side core tool by name with the supplied params,
// returning its result text and whether it reported an error. It reuses the
// exact handlers agents call, so results match.
func (m *mcpServer) CoreQuery(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	handler, ok := m.coreQueryDispatch[tool]
	if !ok {
		return "", false, fmt.Errorf("tool not permitted: %s", tool)
	}
	args := map[string]any{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return "", false, fmt.Errorf("invalid params: %w", err)
		}
	}
	var req mcp.CallToolRequest
	req.Params.Name = tool
	req.Params.Arguments = args
	res, err := handler(ctx, req)
	if err != nil {
		return "", false, err
	}
	return resultText(res), res.IsError, nil
}

// resultText flattens a tool result's text content blocks.
func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
