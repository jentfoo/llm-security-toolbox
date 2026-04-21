package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// injectingFake wraps FakeAgent to run a callback before each Drain.
type injectingFake struct {
	*agent.FakeAgent
	onDrain map[int]func()
	turn    int
}

func (i *injectingFake) Drain(ctx context.Context) (agent.TurnSummary, error) {
	if f, ok := i.onDrain[i.turn]; ok {
		f()
	}
	i.turn++
	return i.FakeAgent.Drain(ctx)
}

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
		runs, err := RunWorkerUntilEscalation(context.Background(), w, pool, nil)
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
		runs, err := RunWorkerUntilEscalation(context.Background(), w, NewCandidatePool(), nil)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "silent", w.EscalationReason)
	})

	t.Run("candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		// FakeAgent can't call handlers; inject the candidate from a wrapper.
		candidateInjector := func() {
			pool.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
		}
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "report_finding_candidate"}}},
			},
		}
		wrapper := &injectingFake{FakeAgent: fake, onDrain: map[int]func(){1: candidateInjector}}
		w := &WorkerState{ID: 1, Agent: wrapper, Alive: true, AutonomousBudget: 5}
		runs, err := RunWorkerUntilEscalation(context.Background(), w, pool, nil)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "candidate", w.EscalationReason)
	})
}
