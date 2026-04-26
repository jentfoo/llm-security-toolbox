package orchestrator

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
)

func short(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

func formatToolCalls(calls []agent.ToolCallRecord, limit int) string {
	if len(calls) == 0 {
		return "  (no tool calls)"
	}
	if limit <= 0 {
		limit = 20
	}
	var lines []string
	shown := calls
	if len(shown) > limit {
		shown = shown[:limit]
	}
	for i, c := range shown {
		status := ""
		if c.IsError {
			status = " [ERROR]"
		}
		line := fmt.Sprintf("  %d. %s(%s)%s", i+1, c.Name, c.InputSummary, status)
		if c.ResultSummary != "" {
			line += "\n     → " + c.ResultSummary
		}
		lines = append(lines, line)
	}
	if len(calls) > limit {
		lines = append(lines, fmt.Sprintf("  … and %d more tool call(s) omitted.", len(calls)-limit))
	}
	return strings.Join(lines, "\n")
}

func formatAutonomousRun(workerID int, turns []agent.TurnSummary, escalationReason string) string {
	if len(turns) == 0 {
		return fmt.Sprintf(
			"### Worker %d\n(No autonomous turns this iteration. escalation_reason=%s)",
			workerID, orDefault(escalationReason, "unknown"),
		)
	}
	var parts []string
	parts = append(parts, fmt.Sprintf(
		"### Worker %d — %d autonomous turn(s), escalated: %s",
		workerID, len(turns), orDefault(escalationReason, "unknown"),
	))
	for i, s := range turns {
		var names []string
		for _, c := range s.ToolCalls {
			names = append(names, c.Name)
		}
		calls := "(no tool calls)"
		if len(names) > 0 {
			calls = strings.Join(names, ", ")
		}
		flows := "(no flows)"
		if len(s.FlowIDs) > 0 {
			flows = strings.Join(s.FlowIDs, ", ")
		}
		firstLine := firstNonEmptyLine(s.AssistantText)
		if firstLine == "" {
			firstLine = "(no text)"
		}
		parts = append(parts, fmt.Sprintf(
			"  Turn %d: tools=[%s] flows=[%s]\n    text: %s",
			i+1, short(calls, 200), flows, short(firstLine, 240),
		))
	}
	last := turns[len(turns)-1]
	parts = append(parts, "")
	parts = append(parts, fmt.Sprintf("Last turn tool calls (%d):", len(last.ToolCalls)))
	parts = append(parts, formatToolCalls(last.ToolCalls, 10))
	return strings.Join(parts, "\n")
}

func firstNonEmptyLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func formatPendingCandidates(pending []FindingCandidate) string {
	if len(pending) == 0 {
		return "No pending finding candidates."
	}
	var lines []string
	lines = append(lines, "**Pending finding candidates (awaiting verification):**")
	for _, c := range pending {
		flows := strings.Join(c.FlowIDs, ", ")
		if flows == "" {
			flows = noneSentinel
		}
		lines = append(lines, fmt.Sprintf(
			"- `%s` [%s] %s — %s\n  worker: %d\n  flows: %s\n  summary: %s\n  reproduction hint: %s",
			c.CandidateID, c.Severity, c.Title, c.Endpoint, c.WorkerID, flows,
			short(c.Summary, 200), short(c.ReproductionHint, 200),
		))
	}
	return strings.Join(lines, "\n")
}

func statusLine(iteration, maxIter, findings int) string {
	return fmt.Sprintf("**Status:** iteration %d/%d, findings filed: %d", iteration, maxIter, findings)
}

// BuildVerifierPrompt renders the initial verifier substep.
func BuildVerifierPrompt(
	workers []*WorkerState,
	workerRuns map[int][]agent.TurnSummary,
	pending []FindingCandidate,
	findingsSummary string,
	iteration, maxIter, findingsCount int,
) string {
	var parts []string
	parts = append(parts, statusLine(iteration, maxIter, findingsCount))
	parts = append(parts, "", findingsSummary, "", formatPendingCandidates(pending), "", "**Worker autonomous runs this iteration:**", "")
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		parts = append(parts, formatAutonomousRun(w.ID, workerRuns[w.ID], w.EscalationReason), "")
	}
	parts = append(parts, "Reproduce and dispose of every pending candidate. `verification_done(summary)` when all are filed or dismissed.")
	return strings.Join(parts, "\n")
}

// BuildVerifierContinuePrompt renders substeps 2..N. The filed/dismissed
// slices are what the verifier has processed in this phase so far; their
// titles are surfaced so the verifier stops re-announcing the same
// candidates each substep.
func BuildVerifierContinuePrompt(
	pending []FindingCandidate,
	filedThisPhase []FindingFiled,
	dismissedThisPhase []CandidateDismissal,
	substep, maxSubsteps int,
) string {
	parts := []string{
		fmt.Sprintf("**Verification substep %d/%d.** Filed %d, dismissed %d so far this phase.",
			substep, maxSubsteps, len(filedThisPhase), len(dismissedThisPhase)),
	}
	if len(filedThisPhase) > 0 {
		parts = append(parts, "", "**Already filed this phase (do not re-file):**")
		for _, f := range filedThisPhase {
			parts = append(parts, "- "+f.Title)
		}
	}
	if len(dismissedThisPhase) > 0 {
		parts = append(parts, "", "**Already dismissed this phase:**")
		for _, d := range dismissedThisPhase {
			parts = append(parts, "- "+d.CandidateID)
		}
	}
	parts = append(parts, "", formatPendingCandidates(pending))
	return strings.Join(parts, "\n")
}

// FormatFollowUpHints renders optional verifier follow-up hints for the director.
// Returns "" when no hints are present.
func FormatFollowUpHints(findings []FindingFiled, dismissals []CandidateDismissal) string {
	var lines []string
	for _, f := range findings {
		h := strings.TrimSpace(f.FollowUpHint)
		if h == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- (filed: %s) %s", short(f.Title, 80), h))
	}
	for _, d := range dismissals {
		h := strings.TrimSpace(d.FollowUpHint)
		if h == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- (dismissed: %s) %s", d.CandidateID, h))
	}
	if len(lines) == 0 {
		return ""
	}
	return "**Verifier follow-up hints (advisory — you decide whether to act):**\n" + strings.Join(lines, "\n")
}

// BuildDirectorPrompt renders the initial director substep.
//
// Director-input contract (load-bearing — preserve when modifying):
//   - workerRuns is the RAW per-iter TurnSummary for currently alive
//     workers. The director sees individual tool calls, flow IDs, and
//     last-turn raw tool records via formatAutonomousRun. NO summarization
//     is applied to in-flight worker actions — the director makes its
//     direction decisions against unfiltered evidence.
//   - For prior iters of alive workers, RecentHistory provides high-level
//     per-iter outcome rows (Iteration / Angle / Outcome / ToolCalls /
//     FlowsTouched). This is categorical, not a prose summary of actions.
//   - verificationSummary is the verifier phase's own decision report
//     (filings/dismissals/done), not a summary of worker actions.
//   - completed is the ONLY summarized input. These workers are retired,
//     IDs are gone, and the LLM-generated CompletedWorker.Summary stands
//     in for them as historical reference. Live-direction decisions never
//     consume action summaries; only retired-worker reference does.
func BuildDirectorPrompt(
	workers []*WorkerState,
	workerRuns map[int][]agent.TurnSummary,
	verificationSummary, findingsSummary, stallWarnings, followUpHints string,
	completed []CompletedWorker,
	iteration, maxIter, findingsCount int,
	maxWorkers int,
) string {
	var parts []string
	parts = append(parts, statusLine(iteration, maxIter, findingsCount), "", findingsSummary, "", "**Verification:** "+verificationSummary)
	if stallWarnings != "" {
		parts = append(parts, "", stallWarnings)
	}
	if followUpHints != "" {
		parts = append(parts, "", followUpHints)
	}
	if len(completed) > 0 {
		// Render the retired-workers block. At most completedWorkersRenderCap
		// most-recent entries appear; older entries fold into a single
		// "(N earlier completed worker(s) omitted)" line so the prompt
		// stays bounded across long runs. Each summary is truncated only
		// as a safety net (completedSummaryRenderCap) — the summarizer is
		// instructed to be exhaustive.
		lines := []string{
			"",
			"**Workers completed earlier this run** (reference context only — these IDs are gone, do NOT plan, fork, or narrate against them):",
		}
		start := 0
		if len(completed) > completedWorkersRenderCap {
			omitted := len(completed) - completedWorkersRenderCap
			start = omitted
			lines = append(lines, fmt.Sprintf("(%d earlier completed worker(s) omitted)", omitted))
		}
		for _, c := range completed[start:] {
			reason := c.Reason
			if reason == "" {
				reason = "(no reason given)"
			}
			summary := short(c.Summary, completedSummaryRenderCap)
			if summary == "" {
				summary = "(summary unavailable)"
			}
			lines = append(lines, fmt.Sprintf(
				"- Worker %d (stopped iter %d, reason: %s):\n  %s",
				c.ID, c.StoppedAt, short(reason, 200), summary,
			))
		}
		parts = append(parts, lines...)
	}
	parts = append(parts, "", "**Worker autonomous runs this iteration:**", "")
	aliveCount := 0
	aliveIDs := make([]string, 0, len(workers))
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		aliveCount++
		aliveIDs = append(aliveIDs, strconv.Itoa(w.ID))
		parts = append(parts, formatAutonomousRun(w.ID, workerRuns[w.ID], w.EscalationReason), "")
	}
	if block := formatWorkerHistory(workers); block != "" {
		parts = append(parts, "", block)
	}
	aliveStr := noneSentinel
	if len(aliveIDs) > 0 {
		aliveStr = strings.Join(aliveIDs, ", ")
	}
	parts = append(parts, fmt.Sprintf("**Alive:** [%s]  **Parallelism:** %d/%d.", aliveStr, aliveCount, maxWorkers))

	// Iteration 1: worker 1 has just done recon; prompt the director to
	// dispatch specialised parallel workers rather than pile more onto one.
	if iteration == 1 && aliveCount < maxWorkers {
		parts = append(parts, "",
			"Iteration 1 is the attack-surface dispatch moment. If the assignment has a broad surface, split it across 3–4 specialised workers via `plan_workers` using fresh worker_ids now.")
	}
	return strings.Join(parts, "\n")
}

// completedSummaryRenderCap caps the rendered length of each per-worker
// summary in the director prompt. The summarizer is instructed to be
// exhaustive on detail (length follows content), so this is a safety net
// for an absurdly long output — not a primary compaction mechanism.
const completedSummaryRenderCap = 8000

// completedWorkersRenderCap is the maximum number of completed workers
// rendered in any one director prompt. Beyond that, the oldest are folded
// into a single "(N earlier completed worker(s) omitted)" line.
const completedWorkersRenderCap = 10

// formatWorkerHistory renders the per-worker iteration history block for
// the director prompt. Returns "" when no worker has recorded entries yet
// (e.g. iteration 1). Entries are shown oldest → newest so the director
// reads the trajectory in chronological order. Dead workers are skipped —
// their canonical record lives in the completed-workers block instead.
func formatWorkerHistory(workers []*WorkerState) string {
	var perWorker []string
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		entries := w.RecentHistory()
		if len(entries) == 0 {
			continue
		}
		lines := []string{fmt.Sprintf("- Worker %d:", w.ID)}
		for _, e := range entries {
			angle := e.Angle
			if angle == "" {
				angle = "(no instruction)"
			}
			lines = append(lines, fmt.Sprintf(
				"  - iter %d [%s] %q — %d tools, %d flows",
				e.Iteration, e.Outcome, angle, e.ToolCalls, e.FlowsTouched,
			))
		}
		perWorker = append(perWorker, strings.Join(lines, "\n"))
	}
	if len(perWorker) == 0 {
		return ""
	}
	return "**Recent worker history (up to 6 iters each):**\n" + strings.Join(perWorker, "\n")
}

// BuildDirectorContinuePrompt renders direction substeps 2..N.
func BuildDirectorContinuePrompt(pendingWIDs map[int]bool, substep, maxSubsteps int) string {
	ids := bulk.MapKeysSlice(pendingWIDs)
	sort.Ints(ids)
	pending := noneSentinel
	if len(ids) > 0 {
		ss := make([]string, 0, len(ids))
		for _, id := range ids {
			ss = append(ss, strconv.Itoa(id))
		}
		pending = strings.Join(ss, ", ")
	}
	return fmt.Sprintf("**Direction substep %d/%d.** Workers still uncovered: [%s].", substep, maxSubsteps, pending)
}

// BuildDirectorSelfReviewPrompt prompts the director to re-check coverage.
func BuildDirectorSelfReviewPrompt() string {
	return "**Self-review.** Any alive worker uncovered or misassigned? Make final adjustments, then `direction_done(summary)`."
}
