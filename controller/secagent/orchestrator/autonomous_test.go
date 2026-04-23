package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRunWorkerUntilEscalation(t *testing.T) {
	t.Parallel()
	t.Run("budget", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
			},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 3}
		pool := NewCandidatePool()
		runs, err := RunWorkerUntilEscalation(t.Context(), w, pool, nil)
		require.NoError(t, err)
		assert.Len(t, runs, 3)
		assert.Equal(t, "budget", w.EscalationReason)
	})

	t.Run("silent", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{AssistantText: "nothing more"},
			},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), nil)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "silent", w.EscalationReason)
	})

	t.Run("candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "report_finding_candidate"}}},
			},
		}
		// turnIdx tracks len(QueriedInputs)-1: -1 for the first Drain (no
		// Query emitted yet), then 0 for the second Drain after the worker
		// injects the continue prompt. Fire on turnIdx=0 so the candidate is
		// in the pool when the 2nd turn (the report_finding_candidate call) is
		// classified.
		fake.OnDrain = func(turnIdx int) {
			if turnIdx == 0 {
				pool.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
			}
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		runs, err := RunWorkerUntilEscalation(t.Context(), w, pool, nil)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "candidate", w.EscalationReason)
	})
}
