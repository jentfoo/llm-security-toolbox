package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestDecisionQueue(t *testing.T) {
	t.Parallel()

	t.Run("lifecycle", func(t *testing.T) {
		q := NewDecisionQueue()
		assert.Equal(t, agent.PhaseIdle, q.Phase())

		q.BeginPhase(agent.PhaseVerification)
		assert.Equal(t, agent.PhaseVerification, q.Phase())

		q.SetPlan([]PlanEntry{{WorkerID: 1, Assignment: "x"}})
		assert.True(t, q.HasPlan)
		q.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1})
		q.AddFinding(FindingFiled{Title: "xss"})
		q.AddDismissal(CandidateDismissal{CandidateID: "c1", Reason: "no repro"})
		q.SetVerificationDone("all set")
		assert.True(t, q.HasVerificationDone)

		q.BeginPhase(agent.PhaseDirection)
		assert.True(t, q.HasVerificationDone)
		q.SetDirectionDone("planned")
		assert.True(t, q.HasDirectionDone)

		q.SetEndRun("run over")
		assert.True(t, q.HasEndRun)

		q.Reset()
		assert.False(t, q.HasPlan)
		assert.Empty(t, q.WorkerDecisions)
		assert.Empty(t, q.Findings)
		assert.Empty(t, q.Dismissals)
		assert.False(t, q.HasEndRun)
		assert.False(t, q.HasVerificationDone)
		assert.False(t, q.HasDirectionDone)
		assert.Equal(t, agent.PhaseIdle, q.Phase())
	})

	t.Run("begin_phase_clears_only_own_phase", func(t *testing.T) {
		q := NewDecisionQueue()
		q.SetVerificationDone("v")
		q.SetDirectionDone("d")
		q.BeginPhase(agent.PhaseVerification)
		assert.False(t, q.HasVerificationDone)
		assert.True(t, q.HasDirectionDone)

		q.SetVerificationDone("v2")
		q.BeginPhase(agent.PhaseDirection)
		assert.True(t, q.HasVerificationDone)
		assert.False(t, q.HasDirectionDone)
	})
}

func TestCoalesceDecisions(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, coalesceDecisions(nil, nil))
	})

	t.Run("single_decision_kept", func(t *testing.T) {
		in := []WorkerDecision{{Kind: "continue", WorkerID: 1, Instruction: "a"}}
		assert.Equal(t, in, coalesceDecisions(in, nil))
	})

	t.Run("last_continue_wins_over_earlier_continue", func(t *testing.T) {
		in := []WorkerDecision{
			{Kind: "continue", WorkerID: 1, Instruction: "first"},
			{Kind: "continue", WorkerID: 1, Instruction: "second"},
			{Kind: "continue", WorkerID: 1, Instruction: "third"},
		}
		out := coalesceDecisions(in, nil)
		assert.Len(t, out, 1)
		assert.Equal(t, "third", out[0].Instruction)
	})

	t.Run("stop_then_continue_last_writer_wins", func(t *testing.T) {
		in := []WorkerDecision{
			{Kind: "stop", WorkerID: 1},
			{Kind: "continue", WorkerID: 1, Instruction: "resumed"},
		}
		out := coalesceDecisions(in, nil)
		assert.Len(t, out, 1)
		assert.Equal(t, "continue", out[0].Kind)
	})

	t.Run("continue_then_stop_last_writer_wins", func(t *testing.T) {
		in := []WorkerDecision{
			{Kind: "continue", WorkerID: 1, Instruction: "a"},
			{Kind: "stop", WorkerID: 1, Reason: "done"},
		}
		out := coalesceDecisions(in, nil)
		assert.Len(t, out, 1)
		assert.Equal(t, "stop", out[0].Kind)
	})

	t.Run("mixed_workers_preserved", func(t *testing.T) {
		in := []WorkerDecision{
			{Kind: "continue", WorkerID: 1, Instruction: "a1"},
			{Kind: "continue", WorkerID: 2, Instruction: "b1"},
			{Kind: "continue", WorkerID: 1, Instruction: "a2"},
			{Kind: "expand", WorkerID: 3, Instruction: "c1"},
		}
		out := coalesceDecisions(in, nil)
		want := map[int]string{1: "a2", 2: "b1", 3: "c1"}
		assert.Len(t, out, len(want))
		for _, d := range out {
			assert.Equal(t, want[d.WorkerID], d.Instruction)
		}
	})

	t.Run("plan_entry_drops_continue_expand", func(t *testing.T) {
		plan := []PlanEntry{{WorkerID: 1, Assignment: "planned work"}}
		in := []WorkerDecision{
			{Kind: "continue", WorkerID: 1, Instruction: "redundant"},
			{Kind: "expand", WorkerID: 2, Instruction: "kept"},
		}
		out := coalesceDecisions(in, plan)
		assert.Len(t, out, 1)
		assert.Equal(t, 2, out[0].WorkerID)
	})

	t.Run("plan_entry_does_not_drop_stop", func(t *testing.T) {
		plan := []PlanEntry{{WorkerID: 1, Assignment: "planned work"}}
		in := []WorkerDecision{
			{Kind: "stop", WorkerID: 1, Reason: "contradictory but explicit"},
		}
		out := coalesceDecisions(in, plan)
		assert.Len(t, out, 1)
		assert.Equal(t, "stop", out[0].Kind)
	})
}
