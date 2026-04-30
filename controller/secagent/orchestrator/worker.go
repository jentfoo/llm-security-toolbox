package orchestrator

import (
	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/mcp"
)

// IterationOutcome classifies a worker's result for a single iteration.
type IterationOutcome string

const (
	OutcomeFinding         IterationOutcome = "finding"          // candidate explicitly linked to a filed finding via SupersedesCandidateIDs
	OutcomePossibleFinding IterationOutcome = "possible-finding" // filed finding heuristically matched the candidate but verifier did not link it; director should probe further
	OutcomeDismissed       IterationOutcome = "dismissed"        // a candidate from this worker dismissed
	OutcomeCandidate       IterationOutcome = "candidate"        // reported, still pending at iter end
	OutcomeSilent          IterationOutcome = "silent"
	OutcomeError           IterationOutcome = "error"
	OutcomeBudget          IterationOutcome = "budget"
	OutcomeStopped         IterationOutcome = "stopped"
)

// IterationEntry is one row of per-worker history surfaced to the director.
type IterationEntry struct {
	Iteration    int
	Angle        string // short summary of the worker's instruction
	Outcome      IterationOutcome
	ToolCalls    int
	FlowsTouched int
}

// WorkerHistoryRing caps the per-worker iteration history.
const WorkerHistoryRing = 6

// WorkerState tracks one worker across iterations.
type WorkerState struct {
	ID                 int
	Agent              agent.Agent
	MCP                *mcp.Client
	LastInstruction    string
	Alive              bool
	ProgressNoneStreak int
	StallWarned        bool
	AutonomousBudget   int
	EscalationReason   string
	AutonomousTurns    []agent.TurnSummary
	// Chronicle is the worker's accumulated chat messages across iterations,
	// installed onto the agent at each iter start.
	Chronicle []agent.Message
	// ChronicleIter is parallel to Chronicle: ChronicleIter[i] is the
	// iteration in which Chronicle[i] was appended.
	ChronicleIter []int
	// RecentToolErrors is a rolling window of recent tool-error signatures.
	RecentToolErrors []string
	// CoachedErrorSig is the last error signature for which coaching was
	// injected; prevents repeating the same nudge.
	CoachedErrorSig string
	// History is a ring buffer of per-iteration outcomes surfaced to the
	// director.
	History     [WorkerHistoryRing]IterationEntry
	HistoryLen  int // 0..WorkerHistoryRing
	HistoryHead int // next write index (mod WorkerHistoryRing)
}

// AppendHistory records e in the ring buffer, overwriting the oldest entry
// once WorkerHistoryRing entries are stored.
func (w *WorkerState) AppendHistory(e IterationEntry) {
	w.History[w.HistoryHead] = e
	w.HistoryHead = (w.HistoryHead + 1) % WorkerHistoryRing
	if w.HistoryLen < WorkerHistoryRing {
		w.HistoryLen++
	}
}

// RecentHistory returns history entries oldest to newest, or nil when
// none have been recorded.
func (w *WorkerState) RecentHistory() []IterationEntry {
	if w.HistoryLen == 0 {
		return nil
	}
	out := make([]IterationEntry, 0, w.HistoryLen)
	start := (w.HistoryHead - w.HistoryLen + WorkerHistoryRing) % WorkerHistoryRing
	for i := 0; i < w.HistoryLen; i++ {
		out = append(out, w.History[(start+i)%WorkerHistoryRing])
	}
	return out
}

// MaxRecentToolErrors caps the rolling error signature window.
const MaxRecentToolErrors = 5

// RepeatedErrorThreshold is the count of identical signatures in
// RecentToolErrors that triggers the silent-stall + coaching path.
const RepeatedErrorThreshold = 3

// ErrorSignatureMaxLen caps the recorded prefix of each error_text.
const ErrorSignatureMaxLen = 80

// Close releases agent and MCP resources.
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
