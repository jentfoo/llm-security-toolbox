package service

import (
	"context"
	"errors"
	"log"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func (m *mcpServer) addRespondTools(rb ResponderBackend) {
	m.server.AddTool(m.proxyRespondAddTool(), m.requireWorkflow(m.handleProxyRespondAdd(rb)))
	m.server.AddTool(m.proxyRespondDeleteTool(), m.requireWorkflow(m.handleProxyRespondDelete(rb)))
	m.server.AddTool(m.proxyRespondListTool(), m.requireWorkflow(m.handleProxyRespondList(rb)))
}

func (m *mcpServer) proxyRespondAddTool() mcp.Tool {
	return mcp.NewTool("proxy_respond_add",
		mcp.WithDescription(`Register a custom HTTP response for a specific host and path.

When the browser requests the matching URL through the proxy, the registered response is served directly without forwarding to upstream. Use this to set browser state (cookies, localStorage via JS, etc.) under the target site's origin. A responder answers over both HTTP and HTTPS and does not require the host to resolve.

The response is stored in proxy history like a normal request.
Responders persist until explicitly deleted with proxy_respond_delete.`),
		mcp.WithString("host", mcp.Required(), mcp.Description("Target hostname to intercept (e.g., 'example.com'). Matches over both HTTP and HTTPS; scheme and port are ignored.")),
		mcp.WithString("path", mcp.Required(), mcp.Description("Exact URL path to intercept (e.g., '/set-cookies'). Query strings are ignored during matching.")),
		mcp.WithString("method", mcp.Description("HTTP method to match (e.g., 'GET'). Empty matches all methods.")),
		mcp.WithNumber("status_code", mcp.Description("Response status code (default: 200)")),
		withFlexKV("headers", "Response headers as an array of \"Name: Value\" strings."),
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
		host := req.GetString("host", "")
		if host == "" {
			return errorResult("host is required"), nil
		}
		path := req.GetString("path", "")
		if path == "" {
			return errorResult("path is required"), nil
		}

		headers := getStringMapArg(req, "headers", ":")
		if bad := unparsedArg(req, "headers", len(headers), `an object {"Name":"Value"} or an array of "Name: Value" strings`); bad != nil {
			return bad, nil
		}

		input := protocol.ResponderEntry{
			Host:       host,
			Path:       path,
			Method:     req.GetString("method", ""),
			StatusCode: req.GetInt("status_code", 0),
			Body:       req.GetString("body", ""),
			Label:      req.GetString("label", ""),
			Headers:    headers,
		}

		responder, err := rb.AddResponder(ctx, input)
		if err != nil {
			if errors.Is(err, ErrLabelExists) {
				return errorResult("label already exists: delete the existing responder first, or use a different label"), nil
			}
			return errorResultFromErr("failed to add responder: ", err), nil
		}

		log.Printf("proxy/respond_add: created %s host=%s path=%s label=%q", responder.ResponderID, responder.Host, path, input.Label)
		return jsonResult(responder)
	}
}

func (m *mcpServer) handleProxyRespondDelete(rb ResponderBackend) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		responders, err := rb.ListResponders(ctx)
		if err != nil {
			return errorResultFromErr("failed to list responders: ", err), nil
		}

		log.Printf("proxy/respond_list: %d responders", len(responders))
		return jsonResult(protocol.ResponderListResponse{Responders: responders})
	}
}
