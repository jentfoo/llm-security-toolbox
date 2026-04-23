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
