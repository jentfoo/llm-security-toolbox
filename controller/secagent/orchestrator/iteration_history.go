package orchestrator

import (
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// appendIterationHistory derives and appends one IterationEntry per worker
// that was alive at iteration start. Called at end-of-iteration once
// decisions/candidates have settled so outcome classification is accurate.
func appendIterationHistory(
	workers []*WorkerState,
	aliveAtStart map[int]bool,
	angleAt map[int]string,
	workerRuns map[int][]agent.TurnSummary,
	decisions *DecisionQueue,
	candidates *CandidatePool,
	candidatesBefore, iteration int,
) {
	for _, w := range workers {
		if !aliveAtStart[w.ID] {
			continue
		}
		runs := workerRuns[w.ID]
		mine := candidates.IDsSinceForWorker(candidatesBefore, w.ID)
		outcome := DeriveIterationOutcome(w, runs, decisions, candidates, mine)
		toolCalls, flows := countToolCallsAndFlows(runs)
		w.AppendHistory(IterationEntry{
			Iteration:    iteration,
			Angle:        truncateAngle(angleAt[w.ID]),
			Outcome:      outcome,
			ToolCalls:    toolCalls,
			FlowsTouched: flows,
		})
	}
}

// angleMaxLen caps the Angle field so the rendered history stays compact.
const angleMaxLen = 100

// truncateAngle normalizes whitespace and truncates the result so the
// output is no more than angleMaxLen bytes (including the trailing ellipsis).
func truncateAngle(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= angleMaxLen {
		return s
	}
	const ellipsis = "…"
	return s[:angleMaxLen-len(ellipsis)] + ellipsis
}

// countToolCallsAndFlows sums across a worker's turns for the iteration.
func countToolCallsAndFlows(runs []agent.TurnSummary) (toolCalls, flows int) {
	for _, t := range runs {
		toolCalls += len(t.ToolCalls)
		flows += len(t.FlowIDs)
	}
	return
}

// DeriveIterationOutcome classifies this iteration's result for the given
// worker. Precedence (first match wins):
//
//  1. Stopped — worker was stopped this iteration (no longer alive).
//  2. Finding — the verifier explicitly linked a filed finding to one of
//     this worker's candidates via SupersedesCandidateIDs.
//  3. PossibleFinding — a filed finding heuristically matched one of this
//     worker's candidates (title+endpoint tier match) but the verifier did
//     not explicitly link it. Signals to the director that the candidate
//     may have been covered, but the relationship is uncertain and warrants
//     follow-up. A finding outcome should be explicit; tier matches are a
//     hint, not a confirmation.
//  4. Dismissed — a candidate this worker reported was dismissed.
//  5. Candidate — reported a candidate that's still pending at iter end.
//  6. Fall-through to escalation reason: error / budget / silent.
//
// workerCandidates is the slice of candidate IDs this worker reported in
// this iteration (typically from candidates.IDsSinceForWorker).
func DeriveIterationOutcome(
	w *WorkerState,
	runs []agent.TurnSummary,
	decisions *DecisionQueue,
	candidates *CandidatePool,
	workerCandidates []string,
) IterationOutcome {
	_ = runs // reserved for future signals (tool-call patterns, flow churn)
	if !w.Alive {
		return OutcomeStopped
	}

	// Build a lookup for this worker's candidate IDs for O(1) membership.
	mine := make(map[string]bool, len(workerCandidates))
	for _, id := range workerCandidates {
		mine[id] = true
	}

	// Snapshot this worker's candidates once for tier matching below.
	var mineSnapshots []FindingCandidate
	for id := range mine {
		if c := candidates.ByID(id); c != nil {
			mineSnapshots = append(mineSnapshots, *c)
		}
	}

	// One pass over findings: explicit link wins immediately; otherwise
	// remember whether any tier match fired and decide after.
	var tierMatched bool
	for _, f := range decisions.Findings {
		for _, cid := range f.SupersedesCandidateIDs {
			if mine[cid] {
				return OutcomeFinding
			}
		}
		if !tierMatched && len(mineSnapshots) > 0 {
			ids, _ := MatchPendingCandidatesTiered(f, mineSnapshots)
			if len(ids) > 0 {
				tierMatched = true
			}
		}
	}
	if tierMatched {
		return OutcomePossibleFinding
	}

	// (4) Dismissed: did the verifier dismiss any of this worker's candidates?
	for _, d := range decisions.Dismissals {
		if mine[d.CandidateID] {
			return OutcomeDismissed
		}
	}

	// (5) Candidate: reported one, still pending.
	for id := range mine {
		if c := candidates.ByID(id); c != nil && c.Status == CandidateStatusPending {
			return OutcomeCandidate
		}
	}

	// (6) Fall through to escalation.
	switch w.EscalationReason {
	case EscalationError:
		return OutcomeError
	case EscalationBudget:
		return OutcomeBudget
	}
	return OutcomeSilent
}
