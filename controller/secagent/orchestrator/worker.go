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
	ProgressNoneStreak int
	StallWarned        bool
	AutonomousBudget   int
	EscalationReason   string
	AutonomousTurns    []agent.TurnSummary
	// Chronicle is the canonical investigative record for this worker —
	// the raw chat messages (directive, assistant turns with thinking,
	// tool calls, tool results) accumulated across every iteration. The
	// controller installs the chronicle on the worker agent at iter start
	// (no LLM call) and at iter end appends the iter's new content via
	// extractAndAppend.
	//
	// To bound growth, compactChronicle runs at iter end after extract: it
	// applies StripAssistantThink + StubToolResult in place to messages
	// older than the keep-recent window (parallel ChronicleIter tracks
	// per-message iter so the window is iteration-based). Recent iters
	// stay raw so the worker keeps short-term context intact; older iters
	// remain present (preserving structural memory + flow IDs in tool-call
	// args) but stripped of bulk so token growth stays sublinear.
	//
	// We never summarize a live worker's chronicle — only at retire time
	// (SummarizeCompletedWorker) does it collapse into a single CompletedWorker.Summary entry that lives in the director chat.
	Chronicle []agent.Message
	// ChronicleIter is parallel to Chronicle: ChronicleIter[i] is the
	// iteration number under which Chronicle[i] was appended. Used by
	// compactChronicle to decide which messages are "old" enough to
	// think-strip + tool-stub vs which are recent enough to keep raw.
	ChronicleIter []int
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
