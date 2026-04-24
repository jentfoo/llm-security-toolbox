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
	// RecentToolErrors is a rolling window of recent tool-error signatures
	// (first 80 chars of error_text). Used to detect workers stuck on the
	// same error across multiple turns.
	RecentToolErrors []string
	// CoachedErrorSig tracks the last signature for which a coaching
	// message was injected, preventing the same nudge from firing every
	// iteration while the error persists.
	CoachedErrorSig string
}

// MaxRecentToolErrors caps the rolling error signature window on WorkerState.
const MaxRecentToolErrors = 5

// RepeatedErrorThreshold is how many identical signatures in RecentToolErrors
// trigger the silent-stall + coaching path.
const RepeatedErrorThreshold = 3

// ErrorSignatureMaxLen caps the prefix of error_text recorded on WorkerState.
const ErrorSignatureMaxLen = 80

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
