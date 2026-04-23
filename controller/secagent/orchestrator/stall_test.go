package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestUpdateStallStreaks(t *testing.T) {
	t.Parallel()
	flowsTurn := []agent.TurnSummary{{FlowIDs: []string{"abc123"}}}
	cases := []struct {
		name          string
		initial       *WorkerState
		wantStreak    int
		wantStallWarn bool
	}{
		{
			name:       "silent_increments_from_zero",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"},
			wantStreak: 1,
		},
		{
			name:       "silent_increments_further",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent", ProgressNoneStreak: 1},
			wantStreak: 2,
		},
		{
			name:       "candidate_resets_streak_and_warn",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "candidate", ProgressNoneStreak: 2, StallWarned: true},
			wantStreak: 0,
		},
		{
			// silent always increments before flow-reset check (else-if ordering)
			name:       "silent_wins_over_flows",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent", AutonomousTurns: flowsTurn},
			wantStreak: 1,
		},
		{
			name:       "flows_reset_without_silent",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "error", AutonomousTurns: flowsTurn, ProgressNoneStreak: 2, StallWarned: true},
			wantStreak: 0,
		},
		{
			name:          "dead_worker_untouched",
			initial:       &WorkerState{ID: 1, Alive: false, EscalationReason: "silent", ProgressNoneStreak: 4, StallWarned: true},
			wantStreak:    4,
			wantStallWarn: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			UpdateStallStreaks([]*WorkerState{c.initial})
			assert.Equal(t, c.wantStreak, c.initial.ProgressNoneStreak)
			assert.Equal(t, c.wantStallWarn, c.initial.StallWarned)
		})
	}
}

func TestFormatStallWarnings(t *testing.T) {
	t.Parallel()

	t.Run("warns_when_streak_met", func(t *testing.T) {
		w := &WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 3}
		out := FormatStallWarnings([]*WorkerState{w}, 3)
		assert.Contains(t, out, "Worker 2")
		assert.Contains(t, out, "3 consecutive")
	})

	t.Run("suppresses_when_latched", func(t *testing.T) {
		w := &WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 3, StallWarned: true}
		assert.Empty(t, FormatStallWarnings([]*WorkerState{w}, 3))
	})
}

func TestLatchStallWarnings(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, ProgressNoneStreak: 3}
	LatchStallWarnings([]*WorkerState{w}, 3)
	assert.True(t, w.StallWarned)
}
