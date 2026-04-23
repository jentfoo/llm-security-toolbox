package orchestrator

import (
	"context"

	"github.com/go-appsec/secagent/agent"
)

// DirectionMaxSubsteps is the hard cap on director substeps before self-review.
const DirectionMaxSubsteps = 4

// DirectionSelfReviewMaxRounds caps tool-dispatch rounds inside the
// self-review substep (spec §7.5).
const DirectionSelfReviewMaxRounds = 2

// RunDirectionPhase drives the director over up to DirectionMaxSubsteps,
// followed by a mandatory self-review substep.
func RunDirectionPhase(
	ctx context.Context,
	director agent.Agent,
	decisions *DecisionQueue,
	workers []*WorkerState,
	workerRuns map[int][]agent.TurnSummary,
	verificationSummary, findingsSummary, stallWarnings, followUpHints string,
	iteration, maxIter, findingsCount, maxWorkers int,
	log *Logger,
) {
	decisions.BeginPhase(agent.PhaseDirection)
	aliveIDs := map[int]bool{}
	for _, w := range workers {
		if w.Alive {
			aliveIDs[w.ID] = true
		}
	}

	// Track consecutive substeps where the director's cumulative decision
	// state didn't change, so we can short-circuit when the director is
	// just re-pondering without producing any new action.
	noProgressStreak := 0
	var lastDecisionCount int
	for substep := 1; substep <= DirectionMaxSubsteps; substep++ {
		covered := coveredIDs(decisions)
		pendingWIDs := diffSet(aliveIDs, covered)

		var prompt string
		if substep == 1 {
			prompt = BuildDirectorPrompt(
				workers, workerRuns, verificationSummary, findingsSummary, stallWarnings, followUpHints,
				iteration, maxIter, findingsCount, maxWorkers,
			)
		} else {
			prompt = BuildDirectorContinuePrompt(pendingWIDs, substep, DirectionMaxSubsteps)
		}
		director.Query(prompt)
		if _, err := director.Drain(ctx); err != nil {
			if log != nil {
				log.Log("direct", "drain error", map[string]any{"iter": iteration, "substep": substep, "err": err.Error()})
			}
			break
		}
		emitStatusIfDue(ctx, director, "direct", substep, log)
		if decisions.HasDirectionDone || decisions.HasEndRun {
			break
		}
		covered = coveredIDs(decisions)
		if len(diffSet(aliveIDs, covered)) == 0 {
			break
		}

		// D1: break after two consecutive no-progress substeps.
		current := totalDecisionCount(decisions)
		if current == lastDecisionCount {
			noProgressStreak++
			if noProgressStreak >= 2 {
				if log != nil {
					log.Log("direct", "early-exit no progress", map[string]any{
						"iter": iteration, "substep": substep,
					})
				}
				break
			}
		} else {
			noProgressStreak = 0
		}
		lastDecisionCount = current
	}

	// D2: skip the self-review substep entirely when the phase produced no
	// decisions — nothing to review, and the director would just re-enter
	// the same narration loop.
	if len(decisions.WorkerDecisions) == 0 && len(decisions.Plan) == 0 {
		if log != nil {
			log.Log("direct", "self-review skipped no decisions", map[string]any{"iter": iteration})
		}
		emitStatusIfDue(ctx, director, "direct", DirectionMaxSubsteps+1, log)
		return
	}

	// self-review substep, bounded to 2 tool-call rounds per spec §7.5
	director.Query(BuildDirectorSelfReviewPrompt())
	if _, err := director.DrainBounded(ctx, DirectionSelfReviewMaxRounds); err != nil {
		if log != nil {
			log.Log("direct", "self-review drain error", map[string]any{"err": err.Error()})
		}
		return
	}
	emitStatusIfDue(ctx, director, "direct", DirectionMaxSubsteps+1, log)
}

// totalDecisionCount returns the cumulative count of director-produced
// actions this phase, used to detect no-progress substeps.
func totalDecisionCount(d *DecisionQueue) int {
	return len(d.WorkerDecisions) + len(d.Plan) + len(d.Findings) + len(d.Dismissals)
}

func coveredIDs(d *DecisionQueue) map[int]bool {
	covered := map[int]bool{}
	for _, wd := range d.WorkerDecisions {
		covered[wd.WorkerID] = true
	}
	if d.HasPlan {
		for _, p := range d.Plan {
			covered[p.WorkerID] = true
		}
	}
	return covered
}

func diffSet(a, b map[int]bool) map[int]bool {
	out := map[int]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}
