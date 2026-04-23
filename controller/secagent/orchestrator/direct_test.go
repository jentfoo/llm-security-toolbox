package orchestrator

import (
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
		RunDirectionPhase(t.Context(), director, decisions, workers,
			nil, "verif summary", "no findings", "", "", 1, 10, 0, 4, nil)

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
			{AssistantText: "substep 4"},
			{AssistantText: "self-review catch"},
		}}
		phaseTurn := 0
		director.OnDrain = func(_ int) {
			phaseTurn++
			switch phaseTurn {
			case 1:
				// Worker 1 covered, worker 2 forgotten.
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1})
			case 5:
				// Self-review catches worker 2 (main phase exhausted its 4 substeps).
				decisions.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 2, Reason: "dead end"})
				decisions.SetDirectionDone("late save")
			}
		}

		workers := []*WorkerState{
			{ID: 1, Alive: true, Agent: director},
			{ID: 2, Alive: true, Agent: director},
		}
		RunDirectionPhase(t.Context(), director, decisions, workers,
			nil, "v", "f", "", "", 1, 10, 0, 4, nil)

		ids := map[int]string{}
		for _, d := range decisions.WorkerDecisions {
			ids[d.WorkerID] = d.Kind
		}
		assert.Equal(t, "continue", ids[1])
		assert.Equal(t, "stop", ids[2])
		// 4 main substeps + 1 self-review
		assert.Equal(t, 5, phaseTurn)
	})
}

func TestCoveredIDs(t *testing.T) {
	t.Parallel()
	d := NewDecisionQueue()
	d.AddDecision(WorkerDecision{WorkerID: 1})
	d.SetPlan([]PlanEntry{{WorkerID: 2}, {WorkerID: 3}})
	covered := coveredIDs(d)
	assert.True(t, covered[1])
	assert.True(t, covered[2])
	assert.True(t, covered[3])
	assert.False(t, covered[4])
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
