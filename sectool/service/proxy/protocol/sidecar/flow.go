package sidecar

import (
	"context"
	"encoding/json"
	"log"
	"maps"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// FlowSink persists sidecar-emitted flows into sectool's unified history.
// Satisfied by *proxy.HistoryStore.
type FlowSink interface {
	Store(*types.Flow) string
	Complete(flowID string, resp *types.Message, completedAt time.Time, annotations map[string]any) bool
	Get(flowID string) (*types.Flow, bool)
	ShouldCapture(*types.Flow) bool
}

// CoreQuerier dispatches a read-side core tool by name, backing core_query. It
// is the authority on which tools are permitted: a tool outside its read-only
// set returns an error rather than dispatching.
type CoreQuerier interface {
	CoreQuery(ctx context.Context, tool string, params json.RawMessage) (content string, isErr bool, err error)
}

// RuleSource returns the current rule snapshot for a named adapter: the monotonic
// version and the rules whose scope is empty or equals the adapter name. It backs the
// register-time snapshot and sync_rules pushes.
type RuleSource interface {
	RuleSnapshot(adapter string) (version uint64, rules []wire.Rule)
}

func (s *session) handlePushFlow(p *wire.Flow) (any, *wire.Error) {
	rec := s.record()
	if rec == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "push_flow: register first")
	}
	if s.m.flows == nil {
		return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: flow store unavailable").
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}

	// Re-targeting an existing flow: two-phase completion or session/stream teardown
	if p.FlowID != "" {
		if !rec.owns(p.FlowID) {
			return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: flow not owned by adapter").
				WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.FlowID})
		}
		if !s.m.flows.Complete(p.FlowID, flowMessageToMessage(p.Response), p.CompletedAt, p.Annotations) {
			return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: unknown flow_id").
				WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.FlowID})
		}
		rec.markComplete(p.FlowID)
		return wire.PushFlowResult{FlowID: p.FlowID}, nil
	}

	flow := wireFlowToFlow(rec, p, s.m.now())
	if !s.m.flows.ShouldCapture(flow) {
		// Excluded by the operator's capture filter: not stored, so no flow_id is
		// minted. An empty flow_id (with no error) signals "not captured"; the
		// sidecar must not attempt two-phase completion against it.
		return wire.PushFlowResult{}, nil
	}
	flowID := s.m.flows.Store(flow)
	rec.trackOwned(flowID, flow.Response == nil && flow.CompletedAt.IsZero())
	return wire.PushFlowResult{FlowID: flowID}, nil
}

func (s *session) handleCoreQuery(ctx context.Context, p *wire.CoreQueryParams) (any, *wire.Error) {
	rec := s.record()
	if rec == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "core_query: register first")
	}
	if s.m.coreQuery == nil {
		return nil, wire.NewError(wire.CodeCoreQueryRejected, "core_query: unavailable").
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}
	// The querier enforces the read-only tool allowlist and rejects anything else
	content, isErr, err := s.m.coreQuery.CoreQuery(ctx, p.Tool, p.Params)
	if err != nil {
		return nil, wire.NewError(wire.CodeCoreQueryRejected, "core_query: "+err.Error()).
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}
	return wire.CoreQueryResult{Content: content, IsError: isErr}, nil
}

func (s *session) handleLog(p *wire.LogParams) {
	level := p.Level
	if level == "" {
		level = "info"
	}
	if len(p.Fields) > 0 {
		log.Printf("sidecar[%s] %s: %s %v", s.adapterName(), level, p.Message, p.Fields)
	} else {
		log.Printf("sidecar[%s] %s: %s", s.adapterName(), level, p.Message)
	}
}

func (s *session) handleReportMetrics(p *wire.ReportMetricsParams) {
	log.Printf("sidecar[%s] metrics: counters=%v gauges=%v", s.adapterName(), p.Counters, p.Gauges)
}

func (s *session) adapterName() string {
	if rec := s.record(); rec != nil {
		return rec.Name
	}
	return "?"
}

// wireFlowToFlow converts a pushed wire flow into a store Flow, forcing the
// emitting adapter's name and stamping its identity into annotations.
func wireFlowToFlow(rec *Record, p *wire.Flow, now time.Time) *types.Flow {
	f := &types.Flow{
		Adapter:      rec.Name,
		ProtocolTag:  p.ProtocolTag,
		Direction:    p.Direction,
		ParentFlowID: p.ParentFlowID,
		Scheme:       p.Scheme,
		Port:         p.Port,
		Request:      flowMessageToMessage(p.Request),
		Response:     flowMessageToMessage(p.Response),
		StartedAt:    p.StartedAt,
		CompletedAt:  p.CompletedAt,
		Annotations:  sidecarAnnotations(rec, p.Annotations),
	}
	if f.StartedAt.IsZero() {
		f.StartedAt = now
	}
	return f
}

// sidecarAnnotations merges the sidecar's version and instance_id into the
// flow's annotations for per-flow attribution.
func sidecarAnnotations(rec *Record, extra map[string]any) map[string]any {
	if len(extra) == 0 && rec.Version == "" && rec.InstanceID == "" {
		return nil
	}
	ann := make(map[string]any, len(extra)+2)
	maps.Copy(ann, extra)
	if rec.Version != "" {
		ann["sidecar_version"] = rec.Version
	}
	if rec.InstanceID != "" {
		ann["sidecar_instance_id"] = rec.InstanceID
	}
	return ann
}

func flowMessageToMessage(m *wire.FlowMessage) *types.Message {
	if m == nil {
		return nil
	}
	// Default the HTTP version so the HTTP-shaped envelope serializes into a
	// parseable request/status line for the read-side tools.
	msg := &types.Message{
		Method:     m.Method,
		Path:       m.Path,
		Query:      m.Query,
		Version:    "HTTP/1.1",
		StatusCode: m.StatusCode,
		StatusText: m.StatusText,
		Body:       m.Body,
		BodyRaw:    m.BodyRaw,
	}
	if len(m.Headers) > 0 {
		msg.Headers = make(types.Headers, len(m.Headers))
		for i, h := range m.Headers {
			msg.Headers[i] = types.Header{Name: h.Name, Value: h.Value}
		}
	}
	if m.BodyCodec != nil {
		msg.BodyCodec = &types.BodyCodec{Transforms: m.BodyCodec.Transforms, ContentType: m.BodyCodec.ContentType}
	}
	return msg
}
