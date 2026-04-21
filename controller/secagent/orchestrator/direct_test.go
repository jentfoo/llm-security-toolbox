package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRunDirectionPhase_FirstSubstepCoversEveryone(t *testing.T) {
	t.Parallel()
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
	RunDirectionPhase(context.Background(), director, decisions, workers,
		nil, "verif summary", "no findings", "", 1, 10, 0, 4, nil)

	// Main phase ran once, then self-review ran once.
	assert.Equal(t, 2, step)
	// Self-review must be bounded to DirectionSelfReviewMaxRounds.
	require.NotEmpty(t, director.MaxRoundsSeen)
	assert.Equal(t, DirectionSelfReviewMaxRounds, director.MaxRoundsSeen[0])
}

func TestRunDirectionPhase_SelfReviewAddsMissedDecision(t *testing.T) {
	t.Parallel()
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
	RunDirectionPhase(context.Background(), director, decisions, workers,
		nil, "v", "f", "", 1, 10, 0, 4, nil)

	ids := map[int]string{}
	for _, d := range decisions.WorkerDecisions {
		ids[d.WorkerID] = d.Kind
	}
	assert.Equal(t, "continue", ids[1])
	assert.Equal(t, "stop", ids[2], "self-review adds the missed decision")
	assert.Equal(t, 5, phaseTurn, "4 main substeps + 1 self-review")
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
	a := map[int]bool{1: true, 2: true, 3: true}
	b := map[int]bool{2: true}
	out := diffSet(a, b)
	assert.Equal(t, map[int]bool{1: true, 3: true}, out)
}
