package orchestrator

import (
	"sync"

	"github.com/go-appsec/secagent/agent"
)

// WorkerDecision captures a director directive for one worker.
type WorkerDecision struct {
	Kind             string // continue | expand | stop
	WorkerID         int
	Instruction      string
	Progress         string // none | incremental | new
	Reason           string
	AutonomousBudget int
}

// PlanEntry is one element of a plan_workers call.
type PlanEntry struct {
	WorkerID   int
	Assignment string
}

// ForkEntry is one fork_worker call: spawn a new worker that inherits the
// parent's investigative summary, plus a steering instruction. Parent
// continues unchanged unless the director also issues a separate decision
// for it in the same direction phase.
type ForkEntry struct {
	ParentWorkerID int
	NewWorkerID    int
	Instruction    string
}

// CompletedWorker is the durable record of a worker retired during the run.
// The director reads these from BuildDirectorPrompt as historical reference
// — the IDs are gone and not eligible for planning, forking, or narration.
// Summary is generated synchronously at retire time via
// Summarizer.SummarizeCompletedWorker (one-shot from the worker's
// canonical raw chronicle, never from a prior summary).
type CompletedWorker struct {
	ID        int
	StoppedAt int    // iteration when the worker was retired
	Reason    string // explicit director reason, "stall-force-stop", or empty
	Summary   string // detailed third-person recap of the worker's full investigation
}

// FindingFiled is a verifier-filed finding.
type FindingFiled struct {
	Title                  string
	Severity               string
	Endpoint               string
	Description            string
	ReproductionSteps      string
	Evidence               string
	Impact                 string
	VerificationNotes      string
	SupersedesCandidateIDs []string
	FollowUpHint           string
}

// CandidateDismissal records a dismissal.
type CandidateDismissal struct {
	CandidateID  string
	Reason       string
	FollowUpHint string
}

// DecisionQueue holds cross-phase orchestrator tool-call state.
type DecisionQueue struct {
	mu                      sync.Mutex
	Plan                    []PlanEntry
	HasPlan                 bool
	Forks                   []ForkEntry
	HasForks                bool
	WorkerDecisions         []WorkerDecision
	Findings                []FindingFiled
	Dismissals              []CandidateDismissal
	EndRunSummary           string
	HasEndRun               bool
	VerificationDoneSummary string
	HasVerificationDone     bool
	DirectionDoneSummary    string
	HasDirectionDone        bool
	phase                   agent.Phase
}

// NewDecisionQueue creates an idle queue.
func NewDecisionQueue() *DecisionQueue {
	return &DecisionQueue{phase: agent.PhaseIdle}
}

// Reset clears all iteration-scoped state.
func (q *DecisionQueue) Reset() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Plan, q.HasPlan = nil, false
	q.Forks, q.HasForks = nil, false
	q.WorkerDecisions = nil
	q.Findings = nil
	q.Dismissals = nil
	q.EndRunSummary, q.HasEndRun = "", false
	q.VerificationDoneSummary, q.HasVerificationDone = "", false
	q.DirectionDoneSummary, q.HasDirectionDone = "", false
	q.phase = agent.PhaseIdle
}

// BeginPhase transitions into a phase and clears only that phase's done flag.
func (q *DecisionQueue) BeginPhase(p agent.Phase) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.phase = p
	switch p {
	case agent.PhaseVerification:
		q.VerificationDoneSummary = ""
		q.HasVerificationDone = false
	case agent.PhaseDirection:
		q.DirectionDoneSummary = ""
		q.HasDirectionDone = false
	}
}

// Phase returns the current phase.
func (q *DecisionQueue) Phase() agent.Phase {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.phase
}

// SetPlan overwrites the current plan.
func (q *DecisionQueue) SetPlan(entries []PlanEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Plan = append(q.Plan[:0], entries...)
	q.HasPlan = true
}

// AddFork appends a fork entry to the queue.
func (q *DecisionQueue) AddFork(f ForkEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Forks = append(q.Forks, f)
	q.HasForks = true
}

// AddDecision records a per-worker decision.
func (q *DecisionQueue) AddDecision(d WorkerDecision) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.WorkerDecisions = append(q.WorkerDecisions, d)
}

// AddFinding records a filed finding.
func (q *DecisionQueue) AddFinding(f FindingFiled) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Findings = append(q.Findings, f)
}

// AddDismissal records a dismissal.
func (q *DecisionQueue) AddDismissal(d CandidateDismissal) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Dismissals = append(q.Dismissals, d)
}

// SetEndRun signals run end.
func (q *DecisionQueue) SetEndRun(summary string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.EndRunSummary = summary
	q.HasEndRun = true
}

// SetVerificationDone marks the verification phase complete.
func (q *DecisionQueue) SetVerificationDone(summary string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.VerificationDoneSummary = summary
	q.HasVerificationDone = true
}

// SetDirectionDone marks the direction phase complete.
func (q *DecisionQueue) SetDirectionDone(summary string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.DirectionDoneSummary = summary
	q.HasDirectionDone = true
}

// coalesceDecisions reduces per-worker duplicates from the director's tool calls.
//
// The director often re-invokes continue_worker/expand_worker/stop_worker on
// the same worker across substeps (and even multiple times within a single
// turn), which would otherwise queue duplicate instruction messages into the
// worker's history. Rules:
//   - Last decision per worker_id wins (pure last-writer-wins). A later
//     continue after stop resurrects the worker intent; a later stop after
//     continue kills it.
//   - A worker already covered by a Plan entry gets its continue/expand
//     dropped entirely — the plan's spawn/retarget carries the instruction.
//     A stop still survives (contradictory, but explicit).
//
// Order is preserved based on the final position of each worker's surviving
// decision.
func coalesceDecisions(decisions []WorkerDecision, plan []PlanEntry) []WorkerDecision {
	if len(decisions) == 0 {
		return nil
	}
	inPlan := map[int]bool{}
	for _, p := range plan {
		inPlan[p.WorkerID] = true
	}
	lastIdx := map[int]int{}
	for i, d := range decisions {
		if inPlan[d.WorkerID] && d.Kind != "stop" {
			continue
		}
		lastIdx[d.WorkerID] = i
	}
	if len(lastIdx) == 0 {
		return nil
	}
	keep := make([]bool, len(decisions))
	for _, i := range lastIdx {
		keep[i] = true
	}
	out := make([]WorkerDecision, 0, len(lastIdx))
	for i, d := range decisions {
		if keep[i] {
			out = append(out, d)
		}
	}
	return out
}
