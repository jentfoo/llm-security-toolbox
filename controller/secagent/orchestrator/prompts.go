package orchestrator

import (
	"fmt"
	"strconv"
	"strings"

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

// BuildVerifierPrompt renders the initial verifier substep. Structure:
// status → context (recon, findings, candidates, worker runs) → action.
//
// reconSummary, when non-empty, is the iter-1 recon worker's
// investigation summary; included as a header so the verifier knows
// the surface mapped during recon. Empty before iter 2.
func BuildVerifierPrompt(
	workers []*WorkerState,
	workerRuns map[int][]agent.TurnSummary,
	pending []FindingCandidate,
	findingsSummary, reconSummary string,
	iteration, maxIter, findingsCount int,
) string {
	var parts []string
	parts = append(parts, statusLine(iteration, maxIter, findingsCount))
	if reconSummary != "" {
		parts = append(parts, "", "## Recon summary (initial scope mapping by retired worker 1)", "", reconSummary)
	}
	parts = append(parts, "", findingsSummary, "", formatPendingCandidates(pending), "", "## Worker autonomous runs this iteration", "")
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		parts = append(parts, formatAutonomousRun(w.ID, workerRuns[w.ID], w.EscalationReason), "")
	}
	parts = append(parts, "Reproduce and dispose of every pending candidate. Call `verification_done(summary)` when all are filed or dismissed.")
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

// FormatFollowUpHints renders optional verifier follow-up hints for the
// director's synthesis prompt. Returns "" when no hints are present.
//
// Per-worker decision prompts deliberately do NOT include hints — hints
// are advisory for run-wide direction (spawn / end), not per-worker pivots.
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

// BuildPerWorkerDecisionPrompt renders the user message appended after the
// director's selectively-compacted chat view for one per-worker decision
// call. Structure: status → single-tool restriction (primacy effect) →
// worker context → action lines.
//
// peerSummary is a one-line snapshot of every other alive worker's
// current angle so the director can avoid duplicating efforts. takenIDs
// is the set of worker IDs that must NOT be picked as fork.new_worker_id.
// iterationStatus is the run-level "iter N/M, findings filed K" line.
func BuildPerWorkerDecisionPrompt(
	workerID int,
	w *WorkerState,
	turns []agent.TurnSummary,
	peerSummary, iterationStatus string,
	takenIDs map[int]bool,
) string {
	idStr := strconv.Itoa(workerID)
	var parts []string
	parts = append(parts, iterationStatus)
	parts = append(parts, "", fmt.Sprintf(
		"**Single tool call: `decide_worker(worker_id=%s, ...)`.** Only `decide_worker` is registered for this prompt — every other tool errors out. Output exactly one call.",
		idStr,
	))
	parts = append(parts, "", fmt.Sprintf(
		"## Worker %s activity (escalation: %s, %d autonomous turn(s))",
		idStr, orDefault(w.EscalationReason, "unknown"), len(turns),
	), "", formatAutonomousRun(workerID, turns, w.EscalationReason))
	if peerSummary != "" {
		parts = append(parts, "", "## Other alive workers (current angles, for coordination — do not duplicate)", "", peerSummary)
	}
	if hist := formatSingleWorkerHistory(w); hist != "" {
		parts = append(parts, "", hist)
	}
	parts = append(parts, "", "## decide_worker(worker_id="+idStr+", ...)",
		"- `action=\"continue\"`: keep the worker on its current angle. Provide `instruction` (next-iter directive).",
		"- `action=\"expand\"`: pivot to a new angle. Provide `instruction` (new directive).",
		"- `action=\"stop\"`: retire the worker. Provide `reason` (informs the recap).",
		"- Optional `fork={new_worker_id, instruction}`: spawn a child that inherits this worker's chronicle. `new_worker_id` must NOT be in the taken set.",
	)
	if len(takenIDs) > 0 {
		parts = append(parts, "",
			"Taken worker IDs (alive + completed — never reuse): ["+formatTakenIDs(takenIDs)+"].")
	}
	return strings.Join(parts, "\n")
}

// formatSingleWorkerHistory renders the per-worker iteration history
// for one worker — the recent-iter outcome rows surfaced to the director.
// Returns "" when no entries are recorded yet.
func formatSingleWorkerHistory(w *WorkerState) string {
	entries := w.RecentHistory()
	if len(entries) == 0 {
		return ""
	}
	lines := []string{fmt.Sprintf("**Worker %d recent iter history (up to %d):**", w.ID, WorkerHistoryRing)}
	for _, e := range entries {
		angle := e.Angle
		if angle == "" {
			angle = "(no instruction)"
		}
		lines = append(lines, fmt.Sprintf(
			"- iter %d [%s] %q — %d tools, %d flows",
			e.Iteration, e.Outcome, angle, e.ToolCalls, e.FlowsTouched,
		))
	}
	return strings.Join(lines, "\n")
}

// FormatPeerSummary renders one line per OTHER alive worker (excluding
// the worker being asked about) so the director can avoid duplicating
// angles. Excludes workers whose decision has already landed earlier in
// the per-worker loop — they're still alive but already retargeted.
func FormatPeerSummary(workers []*WorkerState, exceptID int) string {
	var lines []string
	for _, w := range workers {
		if !w.Alive || w.ID == exceptID {
			continue
		}
		angle := w.LastInstruction
		if angle == "" {
			angle = "(no instruction)"
		}
		lines = append(lines, fmt.Sprintf("- Worker %d: %s", w.ID, short(angle, 200)))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// BuildSynthesisPrompt renders the user message for the synthesis call
// after the per-worker decision loop completes. Structure:
// status → tool restriction → run-wide context → action lines.
func BuildSynthesisPrompt(
	workers []*WorkerState,
	completed []CompletedWorker,
	verificationSummary, findingsSummary, stallWarnings, followUpHints string,
	iterationStatus string,
	maxWorkers int,
) string {
	parts := make([]string, 0, 16)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Synthesis call.** Registered tools: `plan_workers` (optional), `direction_done` (close this iteration), `end_run` (close the entire run, rarely). `decide_worker` is NOT registered — per-worker decisions are already recorded above.",
	)
	parts = append(parts, "", findingsSummary, "", "**Verification:** "+verificationSummary)
	if stallWarnings != "" {
		parts = append(parts, "", stallWarnings)
	}
	if followUpHints != "" {
		parts = append(parts, "", followUpHints)
	}
	if block := formatCompletedRoster(completed); block != "" {
		parts = append(parts, "", block)
	}
	aliveCount := 0
	aliveIDs := make([]string, 0, len(workers))
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		aliveCount++
		aliveIDs = append(aliveIDs, strconv.Itoa(w.ID))
	}
	aliveStr := noneSentinel
	if len(aliveIDs) > 0 {
		aliveStr = strings.Join(aliveIDs, ", ")
	}
	parts = append(parts, "", fmt.Sprintf("**Alive workers (after this iter's per-worker decisions):** [%s]  **Parallelism:** %d/%d.", aliveStr, aliveCount, maxWorkers))
	parts = append(parts, "", "## Action",
		"- `plan_workers`: spawn fresh workers and/or retarget alive ones. Use when uncovered surface remains.",
		"- `direction_done(summary)`: close this iteration. Use for almost every iteration.",
		"- `end_run(summary)`: close the entire run. Only after many iterations when the assignment is exhausted and findings have been filed.",
	)
	return strings.Join(parts, "\n")
}

// formatCompletedRoster renders the retired-workers reference block for
// the synthesis prompt. At most completedWorkersRenderCap most-recent
// entries are shown; older entries fold into a single "(N omitted)" line.
func formatCompletedRoster(completed []CompletedWorker) string {
	if len(completed) == 0 {
		return ""
	}
	lines := []string{
		"**Workers completed earlier this run** (reference context — these IDs are gone, do NOT plan or fork against them):",
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
	return strings.Join(lines, "\n")
}

// completedSummaryRenderCap caps the rendered length of each per-worker
// summary in the synthesis prompt. The summarizer is instructed to be
// exhaustive on detail (length follows content), so this is a safety net
// for an absurdly long output — not a primary compaction mechanism.
const completedSummaryRenderCap = 8000

// completedWorkersRenderCap is the maximum number of completed workers
// rendered in any one synthesis prompt. Beyond that, the oldest are folded
// into a single "(N earlier completed worker(s) omitted)" line.
const completedWorkersRenderCap = 10

// BuildIter1ReconReviewPrompt is the FIRST iter-1 synthesis prompt:
// the director reads the recon summary above in dirChat and produces a
// free-form text response describing scope understanding and proposed
// iter-2 worker assignments. NO tools are registered for this call —
// the response IS the deliverable, captured into dirChat for the
// subsequent plan call.
//
// The split exists because constrained / local models often try to do
// "review the recon AND plan_workers AND direction_done" in one shot
// and drop one or more steps. Splitting the cognitive task into
// "understand first, then formalize" is more reliable.
func BuildIter1ReconReviewPrompt(iterationStatus string, maxWorkers int) string {
	parts := make([]string, 0, 8)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Step 1 of 2: text response, NO tool calls.** No tools are registered for this call — every tool errors out. Plan in plain text; the next prompt will ask you to formalize via `plan_workers`.",
		"",
		"## Recon iteration complete",
		"",
		"The recon worker (worker 1) has finished its scope-mapping pass — pure exploration, no planning, no proposals. The recon record above is a factual map of what exists, not a testing plan. Planning is your job now.",
		"",
		"## Your response",
		"",
		"1. Describe the target's scope, attack surface, technology stack, and authentication boundaries as you now understand them.",
		fmt.Sprintf("2. Propose **at least 2 and up to %d** concrete, mutually-exclusive worker assignments for iteration 2. A single worker is not enough — parallelism across distinct angles is the whole point of the loop. Each assignment names a specific endpoint, technique, or attack vector. Number them starting from 2 (worker 1 is retired).", maxWorkers),
	)
	return strings.Join(parts, "\n")
}

// BuildIter1ReconPlanPrompt is the SECOND iter-1 synthesis prompt:
// the director now has its own review response in dirChat (appended by
// RunIter1ReconReviewCall) and is asked to formalize the iter-2 roster
// via plan_workers + direction_done.
func BuildIter1ReconPlanPrompt(iterationStatus string, maxWorkers int) string {
	parts := make([]string, 0, 8)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Step 2 of 2: formalize the iter-2 roster.** Registered tools: `plan_workers`, `direction_done`. `decide_worker` and `end_run` are NOT registered — worker 1 is already retired and the run is just starting.",
		"",
		fmt.Sprintf("1. Call `plan_workers` once with the assignments you proposed above. Include **at least 2 entries and up to %d**. Pick fresh integer worker_ids starting from 2.", maxWorkers),
		"2. Call `direction_done(summary)` to close this iteration. The summary briefly recaps the recon findings and the iter-2 plan.",
	)
	return strings.Join(parts, "\n")
}

// BuildIter1ReconPlanRetryPrompt is the pointed retry message used
// when the iter-1 plan call returned without plan_workers being
// called. Without a worker roster the run cannot continue, so this is
// a hard ask: call plan_workers now with at least 2 entries.
func BuildIter1ReconPlanRetryPrompt() string {
	return "**You did NOT call `plan_workers` in your last response.** A worker roster is required to continue. Call `plan_workers` now with **at least 2** `{worker_id, assignment}` entries on distinct angles (worker_ids starting from 2; each assignment names a specific endpoint or technique). Then call `direction_done(summary)` to close. This is your last chance — without a `plan_workers` call the run ends."
}
