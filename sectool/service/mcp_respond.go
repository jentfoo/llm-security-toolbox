package service

import (
	"context"
	"errors"
	"log"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func (m *mcpServer) addRespondTools(rb ResponderBackend) {
	m.server.AddTool(m.proxyRespondAddTool(), m.handleProxyRespondAdd(rb))
	m.server.AddTool(m.proxyRespondDeleteTool(), m.handleProxyRespondDelete(rb))
	m.server.AddTool(m.proxyRespondListTool(), m.handleProxyRespondList(rb))
}

func (m *mcpServer) proxyRespondAddTool() mcp.Tool {
	return mcp.NewTool("proxy_respond_add",
		mcp.WithDescription(`Register a custom HTTP response for a specific origin and path.

When the browser requests the matching URL through the proxy, the registered response is served directly without forwarding to upstream. Use this to set browser state (cookies, localStorage via JS, etc.) under the target site's origin.

The response is stored in proxy history like a normal request.
Responders persist until explicitly deleted with proxy_respond_delete.`),
		mcp.WithString("origin", mcp.Required(), mcp.Description("Full origin: scheme://host[:port] (e.g., 'https://example.com', 'http://example.com:8080')")),
		mcp.WithString("path", mcp.Required(), mcp.Description("Exact URL path to intercept (e.g., '/set-cookies'). Query strings are ignored during matching.")),
		mcp.WithString("method", mcp.Description("HTTP method to match (e.g., 'GET'). Empty matches all methods.")),
		mcp.WithNumber("status_code", mcp.Description("Response status code (default: 200)")),
		mcp.WithObject("headers", mcp.Description("Response headers as key-value pairs (e.g., {\"Set-Cookie\": \"session=abc123; Path=/\", \"Content-Type\": \"text/html\"})")),
		mcp.WithString("body", mcp.Description("Response body text")),
		mcp.WithString("label", mcp.Description("Optional unique human-readable label (can be used as id in delete)")),
	)
}

func (m *mcpServer) proxyRespondDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_respond_delete",
		mcp.WithDescription("Delete a registered proxy responder by responder_id or label."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Responder ID or label to delete")),
	)
}

func (m *mcpServer) proxyRespondListTool() mcp.Tool {
	return mcp.NewTool("proxy_respond_list",
		mcp.WithDescription("List all registered proxy responders."),
	)
}

func (m *mcpServer) handleProxyRespondAdd(rb ResponderBackend) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := m.requireWorkflow(); err != nil {
			return err, nil
		}

		origin := req.GetString("origin", "")
		if origin == "" {
			return errorResult("origin is required"), nil
		}
		path := req.GetString("path", "")
		if path == "" {
			return errorResult("path is required"), nil
		}

		input := protocol.ResponderEntry{
			Origin:     origin,
			Path:       path,
			Method:     req.GetString("method", ""),
			StatusCode: req.GetInt("status_code", 0),
			Body:       req.GetString("body", ""),
			Label:      req.GetString("label", ""),
			Headers:    getStringMapArg(req, "headers"),
		}

		responder, err := rb.AddResponder(ctx, input)
		if err != nil {
			if errors.Is(err, ErrLabelExists) {
				return errorResult("label already exists: delete the existing responder first, or use a different label"), nil
			}
			return errorResultFromErr("failed to add responder: ", err), nil
		}

		log.Printf("proxy/respond_add: created %s origin=%s path=%s label=%q", responder.ResponderID, origin, path, input.Label)
		return jsonResult(responder)
	}
}

func (m *mcpServer) handleProxyRespondDelete(rb ResponderBackend) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := m.requireWorkflow(); err != nil {
			return err, nil
		}

		id := req.GetString("id", "")
		if id == "" {
			return errorResult("id is required"), nil
		}

		if err := rb.DeleteResponder(ctx, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("responder not found"), nil
			}
			return errorResultFromErr("failed to delete responder: ", err), nil
		}

		log.Printf("proxy/respond_delete: deleted responder %s", id)
		return jsonResult(protocol.ResponderDeleteResponse{})
	}
}

func (m *mcpServer) handleProxyRespondList(rb ResponderBackend) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := m.requireWorkflow(); err != nil {
			return err, nil
		}

		responders, err := rb.ListResponders(ctx)
		if err != nil {
			return errorResultFromErr("failed to list responders: ", err), nil
		}

		log.Printf("proxy/respond_list: %d responders", len(responders))
		return jsonResult(protocol.ResponderListResponse{Responders: responders})
	}
}

// getStringMapArg extracts a map[string]string from an MCP request parameter.
func getStringMapArg(req mcp.CallToolRequest, key string) map[string]string {
	args := req.GetArguments()
	if args == nil {
		return nil
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}
