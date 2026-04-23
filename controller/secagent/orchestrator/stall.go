package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// UpdateStallStreaks walks every worker and adjusts ProgressNoneStreak
// based on the outcome of the last autonomous run. Both "silent"
// (timeout or model chose not to escalate) and "error" (HTTP error, crashed
// mid-drain) increment the streak so both failure modes feed the existing
// StallStopAfter threshold. "candidate" or any turn that produced flows
// resets the streak.
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
		switch {
		case w.EscalationReason == "silent" || w.EscalationReason == "error":
			w.ProgressNoneStreak++
		case w.EscalationReason == "candidate" || producedFlows:
			w.ProgressNoneStreak = 0
			w.StallWarned = false
		}
	}
}

// hasProductiveTurn returns true when any turn in the slice made real
// progress — tool calls issued or flow IDs touched. Prompt tokens alone
// don't count: any successful round-trip (including the model saying "I'll
// keep looking" with no tool calls) consumes them. Used by applyPlanDiff
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
