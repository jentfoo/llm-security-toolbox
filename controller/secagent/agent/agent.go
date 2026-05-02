// Package agent implements the OpenAI-compatible agent runtime: Agent
// interface, tool dispatch loop, client pool, history, and compaction.
package agent

import (
	"context"
	"encoding/json"
)

// OpenAI chat message roles.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// EscalationReason values surfaced to the orchestrator.
const (
	escalationCandidate        = "candidate"
	escalationSilent           = "silent"
	escalationError            = "error"
	escalationContextExhausted = "context_exhausted"
)

// Phase identifies which orchestrator phase an in-process tool is gated for.
type Phase int

const (
	PhaseIdle Phase = iota
	PhaseVerification
	PhaseDirection
)

func (p Phase) String() string {
	switch p {
	case PhaseVerification:
		return "verification"
	case PhaseDirection:
		return "direction"
	default:
		return "idle"
	}
}

// ToolHandler runs an in-process tool call and returns its result.
type ToolHandler func(ctx context.Context, args json.RawMessage) ToolResult

// ToolResult is an in-process tool's response.
type ToolResult struct {
	Text    string
	IsError bool
}

// ToolDef declares a tool available to an agent. A nil Handler routes the
// call through MCP; a non-nil Handler runs in process.
type ToolDef struct {
	Name        string
	Description string
	Schema      map[string]any
	Handler     ToolHandler
}

// ToolCallRecord captures one tool call from an assistant turn.
type ToolCallRecord struct {
	Name          string
	InputSummary  string
	ResultSummary string
	IsError       bool
	RawInput      json.RawMessage
}

// TurnSummary is the result of a single Drain: one assistant-final response
// plus all intermediate tool calls.
type TurnSummary struct {
	AssistantText    string
	ToolCalls        []ToolCallRecord
	FlowIDs          []string
	TokensIn         int
	TokensOut        int
	EscalationReason string // "" | "candidate" | "silent" | "budget" | "error" | "context_exhausted"
	TimedOut         bool
}

// Agent is the sole interface used by the orchestrator.
type Agent interface {
	Query(content string)
	Drain(ctx context.Context) (TurnSummary, error)
	// DrainBounded is like Drain but caps tool-dispatch rounds at maxRounds
	// for this single call.
	DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error)
	Interrupt()
	SetTools(defs []ToolDef)
	ContextUsage() (tokens, max int)
	// ReplaceHistory installs msgs as the agent's working memory. The system
	// prompt is preserved (re-prepended if msgs[0] is not a system message).
	// Cancels any in-flight Drain and resets iteration-boundary state.
	ReplaceHistory(msgs []Message)
	// MarkIterationBoundary records the current HistoryID watermark as the
	// start of the active iter's content. Safe to call multiple times per
	// iter; each call updates the watermark.
	MarkIterationBoundary()
	Close() error
}
