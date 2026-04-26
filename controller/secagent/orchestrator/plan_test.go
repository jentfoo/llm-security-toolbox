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

func TestApplyForkDiff(t *testing.T) {
	t.Parallel()
	t.Run("inherits_parent_chronicle_with_header", func(t *testing.T) {
		parent := &WorkerState{
			ID: 1, Agent: &agent.FakeAgent{}, Alive: true,
			Chronicle: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "I tested /admin"},
			},
		}
		workers := []*WorkerState{parent}
		var built int
		applyForkDiff(t.Context(),
			[]ForkEntry{{ParentWorkerID: 1, NewWorkerID: 2, Instruction: "follow up X"}},
			&workers, stubSpawn(&built), 5, 3, nil,
		)
		require.Len(t, workers, 2)
		child := workers[1]
		assert.Equal(t, 2, child.ID)
		require.Len(t, child.Chronicle, 3, "child gets inheritance header + parent's 2 chronicle msgs")
		assert.Equal(t, "user", child.Chronicle[0].Role)
		assert.Contains(t, child.Chronicle[0].Content, "Inherited investigative history from worker 1",
			"header names parent worker")
		assert.Contains(t, child.Chronicle[0].Content, "iter 3", "header includes the fork iter")
		assert.Contains(t, child.Chronicle[0].Content, "you are now worker 2", "header reframes for child")
		assert.Equal(t, "I tested /admin", child.Chronicle[2].Content,
			"parent's chronicle follows the header verbatim")
		assert.Equal(t, 1, built)
	})

	t.Run("skips_when_parent_dead", func(t *testing.T) {
		parent := &WorkerState{ID: 1, Agent: &agent.FakeAgent{}, Alive: false}
		workers := []*WorkerState{parent}
		var built int
		applyForkDiff(t.Context(),
			[]ForkEntry{{ParentWorkerID: 1, NewWorkerID: 2, Instruction: "x"}},
			&workers, stubSpawn(&built), 5, 1, nil,
		)
		assert.Len(t, workers, 1)
		assert.Equal(t, 0, built)
	})

	t.Run("skips_when_new_id_collides_with_alive", func(t *testing.T) {
		parent := &WorkerState{ID: 1, Agent: &agent.FakeAgent{}, Alive: true}
		other := &WorkerState{ID: 2, Agent: &agent.FakeAgent{}, Alive: true}
		workers := []*WorkerState{parent, other}
		var built int
		applyForkDiff(t.Context(),
			[]ForkEntry{{ParentWorkerID: 1, NewWorkerID: 2, Instruction: "x"}},
			&workers, stubSpawn(&built), 5, 1, nil,
		)
		assert.Len(t, workers, 2)
		assert.Equal(t, 0, built)
	})

	t.Run("respects_max_workers_cap", func(t *testing.T) {
		w1 := &WorkerState{ID: 1, Agent: &agent.FakeAgent{}, Alive: true}
		w2 := &WorkerState{ID: 2, Agent: &agent.FakeAgent{}, Alive: true}
		workers := []*WorkerState{w1, w2}
		var built int
		applyForkDiff(t.Context(),
			[]ForkEntry{{ParentWorkerID: 1, NewWorkerID: 3, Instruction: "x"}},
			&workers, stubSpawn(&built), 2, 1, nil,
		)
		assert.Len(t, workers, 2)
		assert.Equal(t, 0, built)
	})
}
