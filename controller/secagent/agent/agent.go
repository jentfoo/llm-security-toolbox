// Package agent implements the OpenAI-compatible agent runtime: Agent
// interface, tool dispatch loop, client pool, history, and compaction.
package agent

import (
	"context"
	"encoding/json"
)

// OpenAI chat message roles.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
)

// EscalationReason values surfaced to the orchestrator.
const (
	escalationCandidate = "candidate"
	escalationSilent    = "silent"
	escalationError     = "error"
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

// ToolHandler runs an in-process tool call. Returning IsError=true signals
// the orchestrator that the tool rejected the call; the text still goes
// back to the model as a tool result.
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
	EscalationReason string // "" | "candidate" | "silent" | "budget" | "error"
	TimedOut         bool
}

// Agent is the sole interface used by the orchestrator.
type Agent interface {
	Query(content string)
	Drain(ctx context.Context) (TurnSummary, error)
	// DrainBounded is like Drain but caps the number of tool-dispatch rounds
	// in this single Drain call. Used for the director self-review substep
	// where the spec allows only 2 more rounds.
	DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error)
	Interrupt()
	SetTools(defs []ToolDef)
	ContextUsage() (tokens, max int)
	Close() error
}
