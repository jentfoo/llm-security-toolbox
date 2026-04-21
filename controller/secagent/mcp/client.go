// Package mcp wraps the mark3labs/mcp-go streamable HTTP client and
// exposes a sectool-tool-to-ToolDef bridge.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/secagent/agent"
)

// Client wraps an mcp-go streamable-HTTP client.
type Client struct {
	c   *mcpclient.Client
	url string
}

// Connect initializes and returns an MCP client.
func Connect(ctx context.Context, url string) (*Client, error) {
	httpClient := &http.Client{Timeout: 25 * time.Minute}
	cl, err := mcpclient.NewStreamableHttpClient(url, transport.WithHTTPBasicClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("mcp: new client: %w", err)
	}
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "secagent", Version: "0.1.0"}
	initReq.Params.Capabilities = mcp.ClientCapabilities{}
	if _, err := cl.Initialize(ctx, initReq); err != nil {
		_ = cl.Close()
		return nil, fmt.Errorf("mcp: initialize: %w", err)
	}
	return &Client{c: cl, url: url}, nil
}

// Close closes the underlying MCP client.
func (c *Client) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	return c.c.Close()
}

// ListTools fetches the current tool list.
func (c *Client) ListTools(ctx context.Context) ([]mcp.Tool, error) {
	res, err := c.c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// CallTool invokes a tool, returns the concatenated text and error flag.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (string, bool, error) {
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}}
	res, err := c.c.CallTool(ctx, req)
	if err != nil {
		return "", true, err
	}
	text := extractTextContent(res.Content)
	return text, res.IsError, nil
}

func extractTextContent(content []mcp.Content) string {
	var sb strings.Builder
	for i, ci := range content {
		if tc, ok := ci.(mcp.TextContent); ok {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// BuildToolDefs lists sectool tools and wraps each as an agent.ToolDef whose
// handler dispatches through this client with per-result truncation. Tool
// names are prefixed with `prefix`.
func (c *Client) BuildToolDefs(ctx context.Context, prefix string, maxResultBytes int) ([]agent.ToolDef, error) {
	tools, err := c.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	defs := make([]agent.ToolDef, 0, len(tools))
	for _, t := range tools {
		name := t.Name
		prefixed := prefix + name
		schema, err := toolSchemaAsMap(t)
		if err != nil {
			return nil, fmt.Errorf("mcp: schema for %s: %w", name, err)
		}
		defs = append(defs, agent.ToolDef{
			Name:        prefixed,
			Description: t.Description,
			Schema:      schema,
			Handler:     c.dispatchHandler(name, maxResultBytes),
		})
	}
	return defs, nil
}

func (c *Client) dispatchHandler(realName string, maxResultBytes int) agent.ToolHandler {
	return func(ctx context.Context, args json.RawMessage) agent.ToolResult {
		var m map[string]any
		if len(args) > 0 {
			if err := json.Unmarshal(args, &m); err != nil {
				return agent.ToolResult{
					Text:    fmt.Sprintf("ERROR: MCP tool %q received invalid JSON: %v", realName, err),
					IsError: true,
				}
			}
		}
		text, isErr, err := c.CallTool(ctx, realName, m)
		if err != nil {
			return agent.ToolResult{
				Text:    fmt.Sprintf("ERROR: MCP tool %q failed: %v", realName, err),
				IsError: true,
			}
		}
		text = TruncateResult(text, maxResultBytes)
		return agent.ToolResult{Text: text, IsError: isErr}
	}
}

// toolSchemaAsMap converts mcp.ToolInputSchema to a JSON-schema-compatible map.
func toolSchemaAsMap(t mcp.Tool) (map[string]any, error) {
	raw, err := json.Marshal(t.InputSchema)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
