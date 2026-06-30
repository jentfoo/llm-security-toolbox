package sidecar

import (
	"context"
	"encoding/json"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// AdapterTool pairs an MCP tool definition with the adapter that provides it.
type AdapterTool struct {
	Adapter string
	Tool    wire.MCPTool
}

// ToolDefs returns the MCP tools contributed by all healthy connected adapters.
func (m *Manager) ToolDefs() []AdapterTool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AdapterTool
	for _, r := range m.records {
		if !r.Healthy() {
			continue
		}
		for _, t := range r.MCPTools {
			out = append(out, AdapterTool{Adapter: r.Name, Tool: t})
		}
	}
	return out
}

// AdapterNames returns the names of all healthy connected adapters.
func (m *Manager) AdapterNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.records {
		if r.Healthy() {
			out = append(out, r.Name)
		}
	}
	return out
}

// InvokeTool delegates a sidecar-registered tool call to its owning adapter and
// returns the tool's result. The tool name is resolved to the adapter that
// declared it; arguments are validated by the caller before delegation.
func (m *Manager) InvokeTool(ctx context.Context, name string, args json.RawMessage) (wire.InvokeToolResult, *wire.Error) {
	rec := m.toolOwner(name)
	if rec == nil {
		return wire.InvokeToolResult{}, wire.NewError(wire.CodeUnknownDestAdapter, "invoke_tool: unknown tool: "+name)
	}
	var res wire.InvokeToolResult
	if rpcErr := rec.peer.Call(ctx, wire.MethodInvokeTool, wire.InvokeToolParams{Name: name, Arguments: args}, &res); rpcErr != nil {
		return wire.InvokeToolResult{}, rpcErr
	}
	return res, nil
}

// toolOwner returns the healthy adapter that declared a tool by name, or nil.
func (m *Manager) toolOwner(name string) *Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if !r.Healthy() {
			continue
		}
		for _, t := range r.MCPTools {
			if t.Name == name {
				return r
			}
		}
	}
	return nil
}
