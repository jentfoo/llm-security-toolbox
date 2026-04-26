package orchestrator

import (
	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/mcp"
)

// IterationOutcome classifies a worker's result for a single iteration.
// Used by the director's iteration-history block to spot repetition without
// progress ("same angle, 3 iters, nothing filed").
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
	Angle        string // short summary of the instruction the worker operated on
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
	Assignment         string
	ProgressNoneStreak int
	StallWarned        bool
	AutonomousBudget   int
	EscalationReason   string
	AutonomousTurns    []agent.TurnSummary
	// Chronicle is the canonical investigative record for this worker —
	// raw messages (directive, assistant turns, tool calls, tool results)
	// accumulated across every iteration. Lives at the controller and is
	// NEVER loaded directly into the worker agent's chat history.
	//
	// At iter start the chronicle is summarized fresh by the Summarizer
	// (one-shot from this raw record, never from a prior summary) and the
	// resulting summary is installed as the worker's pre-iter context.
	// Computing every install from canonical raw bytes avoids the
	// summary-of-summary dilution that would otherwise pull workers back
	// to their original angle each iteration.
	//
	// At iter end, extractAndAppend reads everything from the iteration
	// boundary through the end of the agent's history and appends it
	// here, preserving full byte-level texture for the next install.
	Chronicle []agent.Message
	// SummaryCache holds the last successfully-produced chronicle summary
	// for this worker. installChronicle reuses it when the directive AND
	// chronicle length both match what was current when the summary was
	// generated — avoiding redundant LLM calls on no-op iters (e.g. dead
	// iters) while preserving the "always derived from raw chronicle"
	// invariant: every cached summary IS a fresh-from-raw output, just one
	// we already paid for. Also serves as the fallback when a fresh
	// summarize call fails.
	SummaryCache          string
	SummaryCacheChronLen  int
	SummaryCacheDirective string
	// RecentToolErrors is a rolling window of recent tool-error signatures
	// (first 80 chars of error_text). Used to detect workers stuck on the
	// same error across multiple turns.
	RecentToolErrors []string
	// CoachedErrorSig tracks the last signature for which a coaching
	// message was injected, preventing the same nudge from firing every
	// iteration while the error persists.
	CoachedErrorSig string
	// History is a capped ring buffer of per-iteration outcomes surfaced to
	// the director so it can detect angle repetition. Entries are appended
	// at iteration tail (after decisions land). Never shrinks; overflows
	// wrap via HistoryHead.
	History     [WorkerHistoryRing]IterationEntry
	HistoryLen  int // 0..WorkerHistoryRing
	HistoryHead int // next write index (mod WorkerHistoryRing)
}

// AppendHistory records one iteration's result. Ring-buffer semantics:
// once WorkerHistoryRing entries are stored, the oldest is overwritten.
func (w *WorkerState) AppendHistory(e IterationEntry) {
	w.History[w.HistoryHead] = e
	w.HistoryHead = (w.HistoryHead + 1) % WorkerHistoryRing
	if w.HistoryLen < WorkerHistoryRing {
		w.HistoryLen++
	}
}

// RecentHistory returns history entries oldest → newest. Suitable for
// direct rendering in prompts without callers having to know about the ring
// layout. Returns nil when no entries have been recorded.
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
