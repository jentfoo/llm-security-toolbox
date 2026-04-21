package orchestrator

import (
	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/mcp"
)

// WorkerState tracks one worker across iterations.
type WorkerState struct {
	ID                 int
	Agent              agent.Agent
	MCP                *mcp.Client
	LastInstruction    string
	Alive              bool
	Assignment         string
	ProgressNoneStreak int
	StallWarned        bool
	AutonomousBudget   int
	EscalationReason   string
	AutonomousTurns    []agent.TurnSummary
}

// Close releases agent and MCP resources held by the worker.
func (w *WorkerState) Close() {
	if w == nil {
		return
	}
	if w.Agent != nil {
		_ = w.Agent.Close()
	}
	if w.MCP != nil {
		_ = w.MCP.Close()
	}
}
