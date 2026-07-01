package sidecar

import (
	"context"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// SidecarSend routes a replay or origination to the named adapter. For replay
// (FlowID set) it fetches the source flow and passes it inline so the adapter has
// body/body_raw/body_codec without a round-trip. Egress scope is enforced inside
// dial_upstream when the adapter sends.
func (m *Manager) SidecarSend(ctx context.Context, adapter string, p wire.SidecarSendParams) (wire.SidecarSendResult, *wire.Error) {
	rec, ok := m.Get(adapter)
	if !ok {
		return wire.SidecarSendResult{}, wire.NewError(wire.CodeUnknownDestAdapter, "sidecar_send: unknown adapter: "+adapter)
	}
	if !rec.Healthy() {
		return wire.SidecarSendResult{}, wire.NewError(wire.CodeUnknownDestAdapter, "sidecar_send: adapter unhealthy: "+adapter).
			WithData(&wire.ErrorData{Adapter: adapter})
	}
	if p.FlowID != "" && p.Flow == nil {
		if f, ok := m.flows.Get(p.FlowID); ok {
			p.Flow = flowToWireFlow(f)
		}
	}
	var res wire.SidecarSendResult
	if rpcErr := rec.peer.Call(ctx, wire.MethodSidecarSend, p, &res); rpcErr != nil {
		return wire.SidecarSendResult{}, rpcErr
	}
	return res, nil
}

// HasAdapter reports whether a healthy adapter is registered under name.
func (m *Manager) HasAdapter(name string) bool {
	rec, ok := m.Get(name)
	return ok && rec.Healthy()
}

// handleInvokeAdapter routes an outbound message through another adapter's
// injection_target, attributes the origination to the caller via
// annotations.invoked_by, and returns the produced flows.
func (s *session) handleInvokeAdapter(ctx context.Context, p *wire.InvokeAdapterParams) (any, *wire.Error) {
	caller := s.record()
	if caller == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "invoke_adapter: register first")
	}
	dest, ok := s.m.Get(p.Adapter)
	if !ok {
		return nil, wire.NewError(wire.CodeUnknownDestAdapter, "invoke_adapter: unknown adapter: "+p.Adapter).
			WithData(&wire.ErrorData{Adapter: caller.Name})
	}
	if dest.Capabilities.InjectionTarget == nil {
		return nil, wire.NewError(wire.CodeNoInjectionTarget, "invoke_adapter: adapter has no injection_target: "+p.Adapter).
			WithData(&wire.ErrorData{Adapter: caller.Name})
	}

	res, rpcErr := s.m.SidecarSend(ctx, p.Adapter, wire.SidecarSendParams{
		Target:          p.Target,
		Payload:         p.Payload,
		Mutations:       p.Mutations,
		WaitForResponse: p.WaitForResponse,
	})
	if rpcErr != nil {
		return nil, rpcErr
	}

	for _, id := range res.NewFlowIDs {
		s.m.flows.Complete(id, nil, time.Time{}, map[string]any{"invoked_by": caller.Name})
	}
	return wire.InvokeAdapterResult{NewFlowIDs: res.NewFlowIDs, Response: res.Response}, nil
}
