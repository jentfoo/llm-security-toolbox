package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// stubSpawn returns a workerSpawnFunc that produces a FakeAgent-backed
// worker and counts how many times it was invoked.
func stubSpawn(counter *int) workerSpawnFunc {
	return func(_ context.Context, id, _ int, assignment string) (*WorkerState, error) {
		*counter++
		return &WorkerState{
			ID:              id,
			Agent:           &agent.FakeAgent{},
			Alive:           true,
			Assignment:      assignment,
			LastInstruction: assignment,
		}, nil
	}
}

func TestApplyPlanDiff(t *testing.T) {
	t.Parallel()
	t.Run("spawn", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: true},
		}
		var built int
		applyPlanDiff(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "new plan"}, {WorkerID: 2, Assignment: "second"}},
			&workers, stubSpawn(&built), 5, nil,
		)
		require.Len(t, workers, 2)
		assert.Equal(t, "new plan", workers[0].Assignment)
		assert.Equal(t, 2, workers[1].ID)
		assert.Equal(t, 1, built)
	})

	t.Run("retarget_preserves_streak_on_dead_iteration", func(t *testing.T) {
		// Regression: the director was retargeting dead workers every
		// iteration, resetting ProgressNoneStreak and preventing the stall
		// force-stop from ever firing. Retarget must only clear the counter
		// when the worker actually produced something this iteration.
		w := &WorkerState{
			ID:                 1,
			Agent:              &agent.FakeAgent{},
			Alive:              true,
			ProgressNoneStreak: 3,
			StallWarned:        true,
			AutonomousTurns:    []agent.TurnSummary{{}, {}}, // all dead
		}
		workers := []*WorkerState{w}
		var built int
		applyPlanDiff(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "try something new"}},
			&workers, stubSpawn(&built), 5, nil,
		)
		assert.Equal(t, 3, w.ProgressNoneStreak, "dead-iteration retarget must not reset streak")
		assert.True(t, w.StallWarned, "dead-iteration retarget must not clear warn latch")
	})

	t.Run("retarget_resets_streak_when_productive", func(t *testing.T) {
		w := &WorkerState{
			ID:                 1,
			Agent:              &agent.FakeAgent{},
			Alive:              true,
			ProgressNoneStreak: 3,
			StallWarned:        true,
			AutonomousTurns:    []agent.TurnSummary{{TokensIn: 200, FlowIDs: []string{"f1"}}},
		}
		workers := []*WorkerState{w}
		var built int
		applyPlanDiff(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "continue"}},
			&workers, stubSpawn(&built), 5, nil,
		)
		assert.Equal(t, 0, w.ProgressNoneStreak)
		assert.False(t, w.StallWarned)
	})

	t.Run("max_workers_cap", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: true},
			{ID: 2, Agent: &agent.FakeAgent{}, Alive: true},
		}
		var built int
		applyPlanDiff(t.Context(),
			[]PlanEntry{
				{WorkerID: 3, Assignment: "x"},
				{WorkerID: 4, Assignment: "y"},
				{WorkerID: 5, Assignment: "z"},
			},
			&workers, stubSpawn(&built), 2, nil,
		)
		// max=2 existing → no spawns allowed.
		assert.Len(t, workers, 2)
		assert.Equal(t, 0, built)
	})
}
