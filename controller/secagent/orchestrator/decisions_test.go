package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestDecisionQueue_Lifecycle(t *testing.T) {
	t.Parallel()
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
	assert.True(t, q.HasVerificationDone, "BeginPhase(Direction) must not clear verifier done")
	q.SetDirectionDone("planned")
	assert.True(t, q.HasDirectionDone)

	q.SetEndRun("run over")
	assert.True(t, q.HasEndRun)

	// Reset wipes everything.
	q.Reset()
	assert.False(t, q.HasPlan)
	assert.Empty(t, q.WorkerDecisions)
	assert.Empty(t, q.Findings)
	assert.Empty(t, q.Dismissals)
	assert.False(t, q.HasEndRun)
	assert.False(t, q.HasVerificationDone)
	assert.False(t, q.HasDirectionDone)
	assert.Equal(t, agent.PhaseIdle, q.Phase())
}

func TestDecisionQueue_BeginPhaseClearsOnlyOwnPhase(t *testing.T) {
	t.Parallel()
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
}
