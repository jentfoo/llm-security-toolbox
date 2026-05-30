package service

import (
	"context"
	"log"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/js"
)

func (m *mcpServer) addJSEndpointTools() {
	m.server.AddTool(m.jsEndpointTool(), m.handleJSEndpoint)
}

func (m *mcpServer) jsEndpointTool() mcp.Tool {
	return mcp.NewTool("js_endpoint",
		mcp.WithDescription(`Expand a single endpoint from js_surface into its full request shape.

The endpoint is returned with:
- body: request body field names and values (static literals, or the source expression when dynamic)
- headers: request header names and values
- query: query-string parameters
- path_params: the variable names behind ${...} placeholders in the URL
- call: the rendered call expression

Use this to construct a request for an endpoint when no example flow exists yet.`),
		mcp.WithString("endpoint", mcp.Required(), mcp.Description(`Endpoint handle "<flow_id>.<endpoint_id>" (endpoint_id from js_surface)`)),
	)
}

func (m *mcpServer) handleJSEndpoint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID, endpointID, ok := splitEndpointHandle(req.GetString("endpoint", ""))
	if !ok {
		return errorResult(`endpoint must be "<flow_id>.<endpoint_id>" (endpoint_id from js_surface)`), nil
	}

	body, _, isHTML, flow, errResult := m.decodeJSFlowBody(ctx, flowID)
	if errResult != nil {
		return errResult, nil
	}

	var resp *protocol.JSEndpointResponse
	var found bool
	if isHTML {
		resp, found = js.AnalyzeHTMLEndpoint(body, endpointID)
	} else {
		resp, found = js.AnalyzeJSEndpoint(body, endpointID)
	}
	if !found {
		return errorResult("no endpoint with id " + endpointID + " found in flow " + flowID), nil
	}

	_, bundleHost, bundlePath := extractRequestMeta(string(flow.DisplayRequest()))
	resp.LastFlow = m.lookupLastFlow(ctx, resp.URL, bundleHost, bundleBaseURL(bundleHost, bundlePath))

	log.Printf("js_endpoint: flow=%s endpoint=%s call_sites=%d", flowID, endpointID, len(resp.CallSites))
	return jsonResult(resp)
}

// splitEndpointHandle parses "<flow_id>.<endpoint_id>" into its parts. Both halves must be
// valid base62 ids; ok is false otherwise (rejecting malformed or traversal input).
func splitEndpointHandle(handle string) (flowID, endpointID string, ok bool) {
	i := strings.LastIndexByte(handle, '.')
	if i <= 0 || i == len(handle)-1 {
		return "", "", false
	}
	flowID, endpointID = handle[:i], handle[i+1:]
	if !ids.IsValid(flowID) || !ids.IsValid(endpointID) {
		return "", "", false
	}
	return flowID, endpointID, true
}

// lookupLastFlow returns the most recent proxy flow_id matching url, or "" when none.
func (m *mcpServer) lookupLastFlow(ctx context.Context, endpointURL, bundleHost string, base *url.URL) string {
	entries, err := drainProxyHistory(ctx, m.service.httpBackend, false)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return buildLastFlowIndex(entries).lookup(endpointURL, bundleHost, base)
}
