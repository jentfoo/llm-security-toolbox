package orchestrator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRunDirectionPhase(t *testing.T) {
	t.Parallel()

	t.Run("first_substep_covers_everyone", func(t *testing.T) {
		decisions := NewDecisionQueue()

		// Scripted: one substep that emits decisions for both workers + self-review.
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "substep 1"},
			{AssistantText: "self-review — nothing to add"},
		}}
		step := 0
		director.OnDrain = func(_ int) {
			step++
			if step == 1 {
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1, Instruction: "keep going"})
				decisions.AddDecision(WorkerDecision{Kind: "expand", WorkerID: 2, Instruction: "new scope"})
				decisions.SetDirectionDone("both covered")
			}
		}

		workers := []*WorkerState{
			{ID: 1, Alive: true, Agent: director},
			{ID: 2, Alive: true, Agent: director},
		}
		RunDirectionPhase(t.Context(), director, decisions, workers, nil)

		assert.Equal(t, 2, step)
		require.NotEmpty(t, director.MaxRoundsSeen)
		assert.Equal(t, DirectionSelfReviewMaxRounds, director.MaxRoundsSeen[0])
	})

	t.Run("self_review_adds_missed_decision", func(t *testing.T) {
		decisions := NewDecisionQueue()

		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "substep 1"},
			{AssistantText: "substep 2"},
			{AssistantText: "substep 3"},
			{AssistantText: "self-review catch"},
		}}
		phaseTurn := 0
		director.OnDrain = func(_ int) {
			phaseTurn++
			switch phaseTurn {
			case 1:
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1})
			case 4:
				// D1 breaks the main loop after 2 & 3 no-progress, so phaseTurn 4
				// is the self-review substep, not the fourth main substep.
				decisions.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 2, Reason: "dead end"})
				decisions.SetDirectionDone("late save")
			}
		}

		workers := []*WorkerState{
			{ID: 1, Alive: true, Agent: director},
			{ID: 2, Alive: true, Agent: director},
		}
		RunDirectionPhase(t.Context(), director, decisions, workers, nil)

		ids := map[int]string{}
		for _, d := range decisions.WorkerDecisions {
			ids[d.WorkerID] = d.Kind
		}
		assert.Equal(t, "continue", ids[1])
		assert.Equal(t, "stop", ids[2])
		assert.Equal(t, 4, phaseTurn)
	})

	t.Run("skip_self_review_no_decisions", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "substep 1 idle"},
			{AssistantText: "substep 2 idle"},
			{AssistantText: "substep 3 idle"},
		}}
		phaseTurn := 0
		director.OnDrain = func(_ int) { phaseTurn++ }

		workers := []*WorkerState{{ID: 1, Alive: true, Agent: director}}
		RunDirectionPhase(t.Context(), director, decisions, workers, nil)

		assert.Empty(t, decisions.WorkerDecisions)
		assert.Empty(t, decisions.Plan)
		assert.Empty(t, director.MaxRoundsSeen)
		assert.LessOrEqual(t, phaseTurn, DirectionMaxSubsteps)
	})

	t.Run("early_exit_on_no_progress", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "substep 1"},
			{AssistantText: "substep 2 idle"},
			{AssistantText: "substep 3 idle"},
			{AssistantText: "self-review"},
		}}
		phaseTurn := 0
		director.OnDrain = func(_ int) {
			phaseTurn++
			if phaseTurn == 1 {
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1})
			}
		}

		workers := []*WorkerState{
			{ID: 1, Alive: true, Agent: director},
			{ID: 2, Alive: true, Agent: director},
		}
		RunDirectionPhase(t.Context(), director, decisions, workers, nil)

		assert.Equal(t, 4, phaseTurn)
		require.NotEmpty(t, director.MaxRoundsSeen)
	})

	t.Run("drain_error_retries_then_auto_direction_done", func(t *testing.T) {
		// Director's first substep fails; phase retry exhausts; OnExhausted
		// sets direction_done with an auto summary so the iteration loop
		// advances instead of blocking on a wedged director.
		decisions := NewDecisionQueue()
		boom := errors.New("simulated director error")
		director := &agent.FakeAgent{
			Turns:  []agent.TurnSummary{{}, {}},
			Errors: []error{boom, boom},
		}
		workers := []*WorkerState{{ID: 1, Alive: true, Agent: director}}
		RunDirectionPhase(t.Context(), director, decisions, workers, nil)

		assert.True(t, decisions.HasDirectionDone)
		assert.Contains(t, decisions.DirectionDoneSummary, "auto: director unavailable after retry")
		// Initial + retry consumed both scripted turns.
		assert.Empty(t, director.Turns)
	})
}

func TestDiffSet(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a    map[int]bool
		b    map[int]bool
		want map[int]bool
	}{
		{
			"subset_removed",
			map[int]bool{1: true, 2: true, 3: true},
			map[int]bool{2: true},
			map[int]bool{1: true, 3: true},
		},
		{
			"empty_a",
			map[int]bool{},
			map[int]bool{1: true},
			map[int]bool{},
		},
		{
			"empty_b_returns_a",
			map[int]bool{1: true, 2: true},
			map[int]bool{},
			map[int]bool{1: true, 2: true},
		},
		{
			"identical",
			map[int]bool{1: true, 2: true},
			map[int]bool{1: true, 2: true},
			map[int]bool{},
		},
		{
			"disjoint",
			map[int]bool{1: true},
			map[int]bool{2: true},
			map[int]bool{1: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, diffSet(c.a, c.b))
		})
	}
}
