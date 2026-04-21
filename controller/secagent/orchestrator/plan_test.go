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
		applyPlanDiff(context.Background(),
			[]PlanEntry{{WorkerID: 1, Assignment: "new plan"}, {WorkerID: 2, Assignment: "second"}},
			&workers, stubSpawn(&built), 5, nil,
		)
		require.Len(t, workers, 2)
		assert.Equal(t, "new plan", workers[0].Assignment)
		assert.Equal(t, 2, workers[1].ID)
		assert.Equal(t, 1, built)
	})

	t.Run("max_workers_cap", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: true},
			{ID: 2, Agent: &agent.FakeAgent{}, Alive: true},
		}
		var built int
		applyPlanDiff(context.Background(),
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
