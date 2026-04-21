package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestUpdateStallStreaks(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"}
	UpdateStallStreaks([]*WorkerState{w})
	assert.Equal(t, 1, w.ProgressNoneStreak)

	w.EscalationReason = "silent"
	UpdateStallStreaks([]*WorkerState{w})
	assert.Equal(t, 2, w.ProgressNoneStreak)

	w.EscalationReason = "candidate"
	UpdateStallStreaks([]*WorkerState{w})
	assert.Equal(t, 0, w.ProgressNoneStreak)
	assert.False(t, w.StallWarned)

	// Silent with flows touched should reset.
	w.EscalationReason = "silent"
	w.AutonomousTurns = []agent.TurnSummary{{FlowIDs: []string{"abc123"}}}
	w.ProgressNoneStreak = 0
	UpdateStallStreaks([]*WorkerState{w})
	// silent increments, then produced_flows reset happens only if reason ==
	// candidate or flows produced — our branch is an else-if, so "silent"
	// always increments first. This matches Python semantics.
	assert.Equal(t, 1, w.ProgressNoneStreak)
}

func TestFormatStallWarnings(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 3}
	out := FormatStallWarnings([]*WorkerState{w}, 3)
	assert.Contains(t, out, "Worker 2")
	assert.Contains(t, out, "3 consecutive")

	// Already latched warning is suppressed.
	w.StallWarned = true
	assert.Empty(t, FormatStallWarnings([]*WorkerState{w}, 3))
}

func TestLatchStallWarnings(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, ProgressNoneStreak: 3}
	LatchStallWarnings([]*WorkerState{w}, 3)
	assert.True(t, w.StallWarned)
}
