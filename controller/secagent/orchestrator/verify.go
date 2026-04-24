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
//
// dedupReviewer arbitrates softer title matches that pass TitlesSimilar but
// not exact-slug equality. Pass nil to disable agent-mediated dedup (tests).
func RunVerificationPhase(
	ctx context.Context,
	verifier agent.Agent,
	decisions *DecisionQueue,
	candidates *CandidatePool,
	writer *FindingWriter,
	dedupReviewer DedupReviewer,
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
				iteration, maxIter, writer.RunCount,
			)
		} else {
			prompt = BuildVerifierContinuePrompt(
				pending,
				decisions.Findings[:appliedFindings],
				decisions.Dismissals[:appliedDismissals],
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
		// Apply new findings through the dedup pipeline (exact-slug skip,
		// agent review for soft matches, fall through to a fresh write).
		// Skip titles already processed this substep so a verifier repeatedly
		// calling file_finding in one burst doesn't emit N log lines.
		seenTitles := map[string]bool{}
		for _, filed := range decisions.Findings[appliedFindings:] {
			if seenTitles[filed.Title] {
				continue
			}
			seenTitles[filed.Title] = true
			wrote, path, err := ReviewAndWrite(ctx, dedupReviewer, writer, filed, log)
			if err != nil {
				if log != nil {
					log.Log("finding", "write failed", map[string]any{"err": err.Error()})
				}
			} else if wrote && log != nil {
				log.Log("finding", "written", map[string]any{"path": path, "title": filed.Title})
			}
			resolved := append([]string{}, filed.SupersedesCandidateIDs...)
			matchTier := MatchNone
			if len(resolved) == 0 {
				resolved, matchTier = MatchPendingCandidatesTiered(filed, candidates.Pending())
			}
			for _, cid := range resolved {
				candidates.Mark(cid, "verified")
			}
			if log != nil {
				switch {
				case len(filed.SupersedesCandidateIDs) > 0:
					// Verifier explicitly linked; nothing to flag.
				case matchTier != MatchNone && matchTier != MatchTitleAndEndpoint:
					// Looser tier matched — worth surfacing so operators can
					// see when titles/endpoints are diverging between workers
					// and the verifier.
					log.Log("finding", "candidate match-fallback", map[string]any{
						"tier":     matchTier.String(),
						"title":    filed.Title,
						"endpoint": filed.Endpoint,
						"resolved": resolved,
					})
				case len(candidates.Pending()) > 0:
					// Finding was written but NO pending candidate resolved.
					// Those candidates will otherwise loop forever because
					// the verifier keeps trying to reproduce them.
					pending := candidates.Pending()
					pendingIDs := make([]string, len(pending))
					for i, c := range pending {
						pendingIDs[i] = c.CandidateID
					}
					log.Log("finding", "orphan — no pending candidate matched", map[string]any{
						"title":    filed.Title,
						"endpoint": filed.Endpoint,
						"pending":  pendingIDs,
					})
				}
			}
		}
		appliedFindings = len(decisions.Findings)

		// Apply new dismissals. Only log on actual state transition so the
		// verifier repeatedly calling dismiss_candidate on the same id doesn't
		// emit a log line each time.
		for _, dm := range decisions.Dismissals[appliedDismissals:] {
			c := candidates.ByID(dm.CandidateID)
			if c == nil || c.Status != "pending" {
				continue
			}
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
