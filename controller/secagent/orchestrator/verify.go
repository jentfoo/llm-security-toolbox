package orchestrator

import (
	"context"
	"fmt"

	"github.com/go-appsec/secagent/agent"
)

// VerificationMaxSubsteps is the hard cap on verifier substeps per iteration.
const VerificationMaxSubsteps = 6

// RunVerificationPhase drives the verifier over up to VerificationMaxSubsteps.
// Returns the summary string for the director prompt.
func RunVerificationPhase(
	ctx context.Context,
	verifier agent.Agent,
	decisions *DecisionQueue,
	candidates *CandidatePool,
	writer *FindingWriter,
	workerRuns map[int][]agent.TurnSummary,
	workers []*WorkerState,
	iteration, maxIter int,
	log *Logger,
) string {
	decisions.BeginPhase(agent.PhaseVerification)
	if len(candidates.Pending()) == 0 {
		if log != nil {
			log.Log("verify", "no pending candidates; skipping", nil)
		}
		return "No pending candidates this iteration."
	}
	appliedFindings := 0
	appliedDismissals := 0
	for substep := 1; substep <= VerificationMaxSubsteps; substep++ {
		pending := candidates.Pending()
		if len(pending) == 0 {
			break
		}
		var prompt string
		if substep == 1 {
			prompt = BuildVerifierPrompt(
				workers, workerRuns, pending,
				writer.SummaryForOrchestrator(),
				iteration, maxIter, writer.Count,
			)
		} else {
			prompt = BuildVerifierContinuePrompt(
				pending, appliedFindings, appliedDismissals,
				substep, VerificationMaxSubsteps,
			)
		}
		verifier.Query(prompt)
		if _, err := verifier.Drain(ctx); err != nil {
			if log != nil {
				log.Log("verify", "drain error", map[string]any{"iter": iteration, "substep": substep, "err": err.Error()})
			}
			break
		}
		emitStatusIfDue(ctx, verifier, "verify", substep, log)
		// Apply new findings.
		for _, filed := range decisions.Findings[appliedFindings:] {
			if writer.IsDuplicate(filed) {
				if log != nil {
					log.Log("finding", "duplicate skipped", map[string]any{"title": filed.Title})
				}
			} else {
				path, err := writer.Write(filed)
				if err != nil {
					if log != nil {
						log.Log("finding", "write failed", map[string]any{"err": err.Error()})
					}
				} else if log != nil {
					log.Log("finding", "written", map[string]any{"path": path, "title": filed.Title})
				}
			}
			resolved := append([]string{}, filed.SupersedesCandidateIDs...)
			if len(resolved) == 0 {
				resolved = MatchPendingCandidates(filed, candidates.Pending())
			}
			for _, cid := range resolved {
				candidates.Mark(cid, "verified")
			}
		}
		appliedFindings = len(decisions.Findings)

		// Apply new dismissals.
		for _, dm := range decisions.Dismissals[appliedDismissals:] {
			candidates.Mark(dm.CandidateID, "dismissed")
			if log != nil {
				log.Log("finding", "candidate dismissed", map[string]any{"candidate_id": dm.CandidateID})
			}
		}
		appliedDismissals = len(decisions.Dismissals)

		if decisions.HasVerificationDone {
			break
		}
	}

	if decisions.HasVerificationDone && decisions.VerificationDoneSummary != "" {
		return decisions.VerificationDoneSummary
	}
	return autoSummary(appliedFindings, appliedDismissals, len(candidates.Pending()))
}

func autoSummary(filed, dismissed, stillPending int) string {
	return fmt.Sprintf(
		"Verification phase ended with %d filed, %d dismissed, %d still pending.",
		filed, dismissed, stillPending,
	)
}
