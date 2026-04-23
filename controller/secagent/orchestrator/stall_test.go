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
			// Hard errors (HTTP 400, crashed drain) feed the same threshold
			// as silent so consistently-crashing workers die naturally.
			name:       "error_increments_like_silent",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "error", ProgressNoneStreak: 2},
			wantStreak: 3,
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
			// "error" loses to flows only when the error branch doesn't match —
			// here the worker escalated with a non-matching reason but the
			// producedFlows branch wins by ordering. Not exercised today but
			// documents the precedence for future edits.
			name:       "flows_reset_without_silent_or_error",
			initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "budget", AutonomousTurns: flowsTurn, ProgressNoneStreak: 2, StallWarned: true},
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

func TestHasProductiveTurn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []agent.TurnSummary
		want bool
	}{
		{"empty_slice", nil, false},
		{"single_zero_turn", []agent.TurnSummary{{}}, false},
		{"tokens_in_alone_is_not_productive", []agent.TurnSummary{{TokensIn: 50}}, false},
		{"tool_call_is_productive", []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}, true},
		{"flow_id_is_productive", []agent.TurnSummary{{FlowIDs: []string{"f1"}}}, true},
		{"mixed_recovers_from_leading_dead", []agent.TurnSummary{{}, {ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, hasProductiveTurn(c.in))
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
