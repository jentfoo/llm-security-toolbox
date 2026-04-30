package orchestrator

import (
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/go-appsec/secagent/agent"
)

// appendIterationHistory appends one IterationEntry to each worker that
// was alive at iteration start.
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

// truncateAngle returns s with whitespace normalized, truncated to at
// most angleMaxLen bytes (including the trailing ellipsis).
func truncateAngle(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= angleMaxLen {
		return s
	}
	const ellipsis = "…"
	return s[:angleMaxLen-len(ellipsis)] + ellipsis
}

// countToolCallsAndFlows returns the total tool call and flow ID counts
// across runs.
func countToolCallsAndFlows(runs []agent.TurnSummary) (toolCalls, flows int) {
	for _, t := range runs {
		toolCalls += len(t.ToolCalls)
		flows += len(t.FlowIDs)
	}
	return
}

// DeriveIterationOutcome classifies this iteration's outcome for w.
// Precedence: stopped, finding (explicit link), possible-finding (tier
// match), dismissed, candidate, then escalation reason. workerCandidates
// is the candidate IDs reported by this worker in this iteration.
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
	mine := bulk.SliceToSet(workerCandidates)

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
			if _, ok := mine[cid]; ok {
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
		if _, ok := mine[d.CandidateID]; ok {
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
