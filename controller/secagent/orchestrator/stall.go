package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// Worker escalation reasons. A worker's autonomous run ends by setting
// EscalationReason to one of these values.
const (
	EscalationSilent    = "silent"
	EscalationError     = "error"
	EscalationBudget    = "budget"
	EscalationCandidate = "candidate"
)

// UpdateStallStreaks walks every worker and adjusts ProgressNoneStreak
// based on the outcome of the last autonomous run. Both "silent"
// (timeout or model chose not to escalate) and "error" (HTTP error, crashed
// mid-drain) increment the streak so both failure modes feed the existing
// StallStopAfter threshold. A worker stuck issuing the same tool error
// repeatedly (RecentToolErrors) is also treated as silent. "candidate" or
// any turn that produced flows resets the streak.
//
// When the repeated-error path fires for a signature we haven't coached on
// yet, a one-shot coaching message is queued to the worker via Agent.Query.
func UpdateStallStreaks(workers []*WorkerState) {
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		producedFlows := false
		for _, t := range w.AutonomousTurns {
			if len(t.FlowIDs) > 0 {
				producedFlows = true
				break
			}
		}
		repeatedSig, repeated := repeatedErrorSignature(w.RecentToolErrors)
		switch {
		case w.EscalationReason == EscalationSilent || w.EscalationReason == EscalationError:
			// Silent/error wins over flows (preserved precedence: a worker
			// that touched a flow but escalated silent is still stalling).
			w.ProgressNoneStreak++
		case w.EscalationReason == EscalationCandidate || producedFlows:
			w.ProgressNoneStreak = 0
			w.StallWarned = false
		case repeated:
			w.ProgressNoneStreak++
		}
		if repeated && w.CoachedErrorSig != repeatedSig && w.Agent != nil {
			w.Agent.Query(buildRepeatedErrorCoaching(repeatedSig))
			w.CoachedErrorSig = repeatedSig
		}
	}
}

// repeatedErrorSignature returns (signature, true) when the window contains
// at least RepeatedErrorThreshold identical entries.
func repeatedErrorSignature(sigs []string) (string, bool) {
	if len(sigs) < RepeatedErrorThreshold {
		return "", false
	}
	counts := map[string]int{}
	for _, s := range sigs {
		counts[s]++
		if counts[s] >= RepeatedErrorThreshold {
			return s, true
		}
	}
	return "", false
}

// buildRepeatedErrorCoaching renders the one-shot nudge queued to workers
// stuck on the same tool error repeatedly.
func buildRepeatedErrorCoaching(sig string) string {
	return fmt.Sprintf(
		"Your last several tool calls returned the same error: %q. Try a different tool or approach. If you're stuck, report what you've learned via report_finding_candidate and describe the blocker.",
		sig,
	)
}

// hasProductiveTurn returns true when any turn in the slice made real
// progress — tool calls issued or flow IDs touched. Prompt tokens alone
// don't count: any successful round-trip (including the model saying "I'll
// keep looking" with no tool calls) consumes them. Used by applyPlanAndFire
// so the director's retarget cannot reset the stall counter when the
// worker was dead this iteration.
func hasProductiveTurn(turns []agent.TurnSummary) bool {
	for _, t := range turns {
		if len(t.ToolCalls) > 0 || len(t.FlowIDs) > 0 {
			return true
		}
	}
	return false
}

// FormatStallWarnings returns a block for the director prompt, or "" when
// no worker is currently at/above warnAfter with an un-latched warning.
func FormatStallWarnings(workers []*WorkerState, warnAfter int) string {
	ids := make([]int, 0, len(workers))
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		if w.ProgressNoneStreak >= warnAfter && !w.StallWarned {
			ids = append(ids, w.ID)
		}
	}
	sort.Ints(ids)
	byID := map[int]*WorkerState{}
	for _, w := range workers {
		byID[w.ID] = w
	}
	warnings := make([]string, 0, len(ids))
	for _, id := range ids {
		w := byID[id]
		warnings = append(warnings, fmt.Sprintf(
			"- Worker %d has had %d consecutive silent autonomous runs. Expand its plan with concrete next steps or stop it.",
			w.ID, w.ProgressNoneStreak,
		))
	}
	if len(warnings) == 0 {
		return ""
	}
	return "**Stall warnings:**\n" + strings.Join(warnings, "\n")
}

// LatchStallWarnings sets StallWarned for any worker at/above the warn
// threshold. Called after the director prompt has been rendered.
func LatchStallWarnings(workers []*WorkerState, warnAfter int) {
	for _, w := range workers {
		if w.Alive && w.ProgressNoneStreak >= warnAfter {
			w.StallWarned = true
		}
	}
}
