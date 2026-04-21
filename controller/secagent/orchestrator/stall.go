package orchestrator

import (
	"fmt"
	"sort"
	"strings"
)

// UpdateStallStreaks walks every worker and adjusts ProgressNoneStreak
// based on its escalation_reason and whether any flow IDs were touched
// during the autonomous run.
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
		case w.EscalationReason == "silent":
			w.ProgressNoneStreak++
		case w.EscalationReason == "candidate" || producedFlows:
			w.ProgressNoneStreak = 0
			w.StallWarned = false
		}
	}
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
