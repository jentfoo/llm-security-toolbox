package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// sidecarManager returns the connected sidecar registry, or nil when the active
// backend hosts no sidecars (Burp, or sidecars disabled).
func (m *mcpServer) sidecarManager() *sidecar.Manager {
	type sidecarHost interface {
		SidecarManager() *sidecar.Manager
	}
	if h, ok := m.service.httpBackend.(sidecarHost); ok {
		return h.SidecarManager()
	}
	return nil
}

// coreToolNames returns the static core tool names captured at construction, used
// to reject a colliding sidecar tool name at registration. Connected sidecars'
// tool names are checked separately against the live registry, so this stays the
// genuine core set even after sidecar tools are registered.
func (m *mcpServer) coreToolNames() []string {
	return m.coreTools
}

// syncSidecarTools recomposes the advertised tool list to match the connected
// adapter set: every connected sidecar's tools are registered, disconnected ones
// removed, and the core tools gain sidecar-conditional params (proxy_poll
// adapter/protocol_tag, proxy_rule_add adapter) while any sidecar is connected.
// With none connected the surface returns to the core baseline. It is invoked
// whenever the registry changes; serialized so concurrent changes converge.
func (m *mcpServer) syncSidecarTools() {
	mgr := m.sidecarManager()
	if mgr == nil {
		return
	}
	m.sidecarMu.Lock()
	defer m.sidecarMu.Unlock()

	defs := mgr.ToolDefs()
	names := mgr.AdapterNames()

	desired := make(map[string]struct{}, len(defs))
	var add []server.ServerTool
	for _, d := range defs {
		desired[d.Tool.Name] = struct{}{}
		schemaRaw := d.Tool.InputSchema
		if len(schemaRaw) == 0 {
			schemaRaw = json.RawMessage(`{"type":"object"}`)
		}
		schema, err := compileToolSchema(schemaRaw)
		if err != nil {
			// Expose the tool but skip validation when its schema does not compile.
			log.Printf("sidecar tool %q (%s): input_schema does not compile: %v", d.Tool.Name, d.Adapter, err)
		}
		add = append(add, server.ServerTool{
			Tool:    sidecarToolDef(d.Tool, schemaRaw),
			Handler: m.delegateSidecarTool(mgr, d.Tool.Name, schema),
		})
	}
	if len(add) > 0 {
		m.server.AddTools(add...)
	}
	for name := range m.sidecarToolNames {
		if _, ok := desired[name]; !ok {
			m.server.DeleteTools(name)
		}
	}
	m.sidecarToolNames = desired

	switch {
	case len(names) > 0:
		m.server.AddTool(m.proxyPollTool(sidecarPollParams()...), m.handleProxyPoll)
		m.server.AddTool(m.proxyRuleAddTool(ruleAdapterParam(names)), m.handleProxyRuleAdd)
		m.sidecarCoreParams = true
	case m.sidecarCoreParams:
		// last sidecar disconnected: restore the byte-identical core schema
		m.server.AddTool(m.proxyPollTool(), m.handleProxyPoll)
		m.server.AddTool(m.proxyRuleAddTool(), m.handleProxyRuleAdd)
		m.sidecarCoreParams = false
	}
}

// delegateSidecarTool returns a handler that validates the client arguments
// against the tool's schema and delegates the call to the owning sidecar.
func (m *mcpServer) delegateSidecarTool(mgr *sidecar.Manager, name string, schema *jsonschema.Schema) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if r := m.requireWorkflow(); r != nil {
			return r, nil
		}
		args, err := json.Marshal(req.GetArguments())
		if err != nil {
			return errorResultFromErr("invalid arguments", err), nil
		}
		if schema != nil {
			inst, ierr := jsonschema.UnmarshalJSON(bytes.NewReader(args))
			if ierr != nil {
				return errorResultFromErr("invalid arguments", ierr), nil
			}
			if verr := schema.Validate(inst); verr != nil {
				return errorResultFromErr("invalid arguments", verr), nil
			}
		}
		res, rpcErr := mgr.InvokeTool(ctx, name, args)
		if rpcErr != nil {
			return errorResult(rpcErr.Error()), nil
		}
		return sidecarToolResult(res), nil
	}
}

// sidecarToolDef builds an MCP tool definition from a sidecar's declaration,
// carrying its raw input_schema and optional annotations verbatim.
func sidecarToolDef(t wire.MCPTool, schemaRaw json.RawMessage) mcp.Tool {
	out := mcp.Tool{
		Name:           t.Name,
		Description:    t.Description,
		RawInputSchema: schemaRaw,
	}
	if len(t.Annotations) > 0 {
		_ = json.Unmarshal(t.Annotations, &out.Annotations)
	}
	return out
}

// sidecarToolResult converts a sidecar tool result into an MCP result, returning
// its text and optional structured content to the client verbatim.
func sidecarToolResult(res wire.InvokeToolResult) *mcp.CallToolResult {
	out := mcp.NewToolResultText(res.Content)
	if len(res.StructuredContent) > 0 {
		var sc any
		if err := json.Unmarshal(res.StructuredContent, &sc); err == nil {
			out.StructuredContent = sc
		}
	}
	out.IsError = res.IsError
	return out
}

// compileToolSchema compiles a JSON Schema for argument validation.
func compileToolSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("tool.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("tool.json")
}

// sidecarPollParams are the proxy_poll filters exposed only when a sidecar is connected.
func sidecarPollParams() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("adapter", mcp.Description("Filter by emitting adapter name glob (*, ?), e.g. 'sectool' or a sidecar name")),
		mcp.WithString("protocol_tag", mcp.Description("Filter by protocol tag glob (*, ?), e.g. 'http/1.1' or 'mqtt/3.publish'")),
	}
}

// ruleAdapterParam is the proxy_rule_add adapter scope, exposed only when a sidecar
// is connected. Empty applies to all adapters.
func ruleAdapterParam(names []string) mcp.ToolOption {
	return mcp.WithString("adapter", mcp.Description(fmt.Sprintf(
		"Adapter scope: empty applies to all adapters; %q targets the in-process proxy and Burp; or a sidecar name (%s)",
		types.AdapterScopeCore, strings.Join(names, ", "))))
}

// sidecarToolsSection lists connected sidecars' tools for the workflow
// instructions, or empty when none are registered.
func (m *mcpServer) sidecarToolsSection() string {
	mgr := m.sidecarManager()
	if mgr == nil {
		return ""
	}
	defs := mgr.ToolDefs()
	if len(defs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n## Sidecar Tools\n\nProtocol adapters contribute these tools:\n")
	for _, d := range defs {
		fmt.Fprintf(&b, "- %s (%s): %s\n", d.Tool.Name, d.Adapter, d.Tool.Description)
	}
	return b.String()
}
