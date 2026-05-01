package orchestrator

import (
	"context"
	"fmt"

	"github.com/go-appsec/secagent/agent"
)

// VerificationMaxSubsteps is the hard cap on verifier substeps per iteration.
const VerificationMaxSubsteps = 6

// RunVerificationPhase drives the verifier through up to VerificationMaxSubsteps,
// returning the summary for the director prompt. dedupReviewer may be nil to
// disable agent-mediated dedup.
func RunVerificationPhase(
	ctx context.Context,
	verifier agent.Agent,
	decisions *DecisionQueue,
	candidates *CandidatePool,
	writer *FindingWriter,
	dedupReviewer DedupReviewer,
	log *Logger,
) string {
	decisions.BeginPhase(agent.PhaseVerification)
	if len(candidates.Pending()) == 0 {
		if log != nil {
			log.Log("verify", "no pending candidates; skipping", nil)
		}
		return "No pending candidates this iteration."
	}
	var appliedFindings, appliedDismissals int
	for substep := 1; substep <= VerificationMaxSubsteps; substep++ {
		pending := candidates.Pending()
		if len(pending) == 0 {
			break
		}
		// Substep 1's directive is already installed via ReplaceHistory by
		// the controller. Substeps 2..N enqueue a continue prompt.
		if substep > 1 {
			prompt := BuildVerifierContinuePrompt(
				pending,
				decisions.Findings[:appliedFindings],
				decisions.Dismissals[:appliedDismissals],
				substep, VerificationMaxSubsteps,
			)
			verifier.Query(prompt)
		}
		_, err := RunPhaseAttempt(ctx,
			func(c context.Context) (agent.TurnSummary, error) { return verifier.Drain(c) },
			PhaseRecover{
				Compact: func() {
					verifier.Interrupt()
					// Re-queue the LAST user message that was already in
					// history (substep 1: nothing — the installed compose
					// IS the directive; substeps 2..N: the continue prompt
					// just queued above).
					if substep > 1 {
						verifier.Query(BuildVerifierContinuePrompt(
							pending,
							decisions.Findings[:appliedFindings],
							decisions.Dismissals[:appliedDismissals],
							substep, VerificationMaxSubsteps,
						))
					}
				},
				OnExhausted: func(err error) {
					// Drain failed twice; nothing more to do this phase.
					// Pending candidates carry to the next iteration where
					// the verifier's freshly composed history gets a clean
					// shot. The controller separately watches the
					// OnContextOverflow signal — if the rerun was over
					// budget, it will dismiss the pending pool there.
				},
			}, log, "verify")
		if err != nil {
			break
		}
		emitStatusIfDue(ctx, verifier, "verify", substep, log)
		// Apply new findings through the dedup pipeline (exact-slug skip,
		// agent review for soft matches, fall through to a fresh write).
		// Skip exact same-title/same-endpoint filings already processed this
		// substep so a verifier repeatedly calling file_finding in one burst
		// doesn't emit N log lines or duplicate state transitions.
		seenFindings := map[string]bool{}
		for _, filed := range decisions.Findings[appliedFindings:] {
			key := processedFindingKey(filed)
			if seenFindings[key] {
				continue
			}
			seenFindings[key] = true
			wrote, path, err := ReviewAndWrite(ctx, dedupReviewer, writer, filed, log)
			if err != nil {
				if log != nil {
					log.Log("finding", "write failed", map[string]any{"err": err.Error()})
				}
				continue
			} else if wrote && log != nil {
				log.Log("finding", "written", map[string]any{"path": path, "title": filed.Title})
			}
			resolved := append([]string{}, filed.SupersedesCandidateIDs...)
			matchTier := MatchNone
			pendingNow := candidates.Pending()
			if len(resolved) == 0 {
				resolved, matchTier = MatchPendingCandidatesTiered(filed, pendingNow)
			}
			for _, cid := range resolved {
				candidates.Mark(cid, CandidateStatusVerified)
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
				case len(resolved) == 0 && len(pendingNow) > 0:
					// Finding was written but NO pending candidate resolved.
					// Those candidates will otherwise loop forever because
					// the verifier keeps trying to reproduce them.
					pendingIDs := make([]string, len(pendingNow))
					for i, c := range pendingNow {
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
			if c == nil || c.Status != CandidateStatusPending {
				continue
			}
			candidates.Mark(dm.CandidateID, CandidateStatusDismissed)
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

// AutoDismissOnContextOverflow marks every pending candidate as dismissed
// with a "context budget exhausted" reason and records each dismissal on
// the decision queue.
func AutoDismissOnContextOverflow(
	candidates *CandidatePool,
	decisions *DecisionQueue,
	log *Logger,
) {
	pending := candidates.Pending()
	for _, c := range pending {
		candidates.Mark(c.CandidateID, CandidateStatusDismissed)
		decisions.AddDismissal(CandidateDismissal{
			CandidateID: c.CandidateID,
			Reason:      "auto: verifier context budget exhausted after fresh compose",
		})
		if log != nil {
			log.Log("verify", "auto-dismiss on context-budget overflow", map[string]any{
				"candidate_id": c.CandidateID,
			})
		}
	}
}

func autoSummary(filed, dismissed, stillPending int) string {
	return fmt.Sprintf(
		"Verification phase ended with %d filed, %d dismissed, %d still pending.",
		filed, dismissed, stillPending,
	)
}

func processedFindingKey(f FindingFiled) string {
	titleKey := Slugify(f.Title)
	if titleKey == "" {
		titleKey = f.Title
	}
	return fmt.Sprintf("%s|%s", titleKey, CanonicalEndpoint(f.Endpoint))
}
