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
//
// The substep-1 directive is already in the director's long-lived history
// — the controller called director.MarkIterationBoundary() and
// director.Query(directorDirective) before invoking. Substep 1 must NOT
// call director.Query again. Substeps 2..N enqueue continue prompts via
// Query as today.
//
// On context pressure the director's agent runs the boundary-summarize
// callback (configured at director-construction time) which collapses the
// oldest contiguous block of director iterations into a single concise
// recap. This happens transparently inside the agent's maybeCompact path.
func RunDirectionPhase(
	ctx context.Context,
	director agent.Agent,
	decisions *DecisionQueue,
	workers []*WorkerState,
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

		if substep > 1 {
			director.Query(BuildDirectorContinuePrompt(pendingWIDs, substep, DirectionMaxSubsteps))
		}
		// Capture the substep number so the recover closure re-queues only
		// for substeps 2..N (substep 1's directive was Query'd by the
		// controller before this function; re-Query'ing it on retry would
		// duplicate the user message).
		s := substep
		_, err := RunPhaseAttempt(ctx,
			func(c context.Context) (agent.TurnSummary, error) { return director.Drain(c) },
			PhaseRecover{
				Compact: func() {
					director.Interrupt()
					if s > 1 {
						director.Query(BuildDirectorContinuePrompt(pendingWIDs, s, DirectionMaxSubsteps))
					}
				},
				OnExhausted: func(err error) {
					// Preserve any decisions already made this phase and
					// signal completion so the controller moves forward
					// with the next iteration instead of carrying the wedge.
					decisions.SetDirectionDone("auto: director unavailable after retry")
				},
			}, log, "direct")
		if err != nil {
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
						"substep": substep,
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
			log.Log("direct", "self-review skipped no decisions", nil)
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
