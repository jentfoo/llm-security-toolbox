package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/config"
)

func TestAliveWorkers(t *testing.T) {
	t.Parallel()
	ws := []*WorkerState{
		{ID: 1, Alive: true},
		{ID: 2, Alive: false},
		{ID: 3, Alive: true},
	}
	out := aliveWorkers(ws)
	require.Len(t, out, 2)
	assert.Equal(t, 1, out[0].ID)
	assert.Equal(t, 3, out[1].ID)
}

func TestFindWorker(t *testing.T) {
	t.Parallel()
	ws := []*WorkerState{{ID: 1}, {ID: 7}}
	assert.Equal(t, 7, findWorker(ws, 7).ID)
	assert.Nil(t, findWorker(ws, 99))
}

func TestApplyDecision_Stop(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{}
	w := &WorkerState{ID: 1, Alive: true, Agent: a}
	applyDecision(WorkerDecision{Kind: "stop", WorkerID: 1, Reason: "done"}, w, nil)
	assert.False(t, w.Alive)
	assert.True(t, a.Closed)
}

func TestApplyDecision_ContinueClampsBudget(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{}
	w := &WorkerState{ID: 1, Alive: true, Agent: a}
	applyDecision(WorkerDecision{
		Kind: "continue", WorkerID: 1, Instruction: "keep going",
		AutonomousBudget: 999, // clamped
	}, w, nil)
	assert.Equal(t, 20, w.AutonomousBudget)
	assert.Equal(t, "keep going", w.LastInstruction)
	assert.Equal(t, []string{"keep going"}, a.QueriedInputs)
}

func TestApplyDecision_ContinueDefaultsBudget(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{}
	w := &WorkerState{ID: 1, Alive: true, Agent: a}
	applyDecision(WorkerDecision{Kind: "expand", WorkerID: 1, Instruction: "new scope"}, w, nil)
	assert.Equal(t, defaultAutonomousBudget, w.AutonomousBudget)
}

func TestRunAllWorkersUntilEscalation_ConcurrentIsolated(t *testing.T) {
	t.Parallel()
	// Two workers; one yields a candidate on turn 1, the other runs silent
	// and stays. Neither affects the other's escalation reason.
	a1 := &agent.FakeAgent{Turns: []agent.TurnSummary{
		{ToolCalls: []agent.ToolCallRecord{{Name: "report_finding_candidate"}}},
	}}
	a2 := &agent.FakeAgent{Turns: []agent.TurnSummary{
		{AssistantText: "nothing to report"},
	}}
	candidates := NewCandidatePool()
	// Attribute candidate to worker 1 so the classifier fires.
	a1.OnDrain = func(_ int) {
		candidates.Add(AddInput{WorkerID: 1, Title: "x"})
	}

	w1 := &WorkerState{ID: 1, Alive: true, Agent: a1, AutonomousBudget: 1, LastInstruction: "go"}
	w2 := &WorkerState{ID: 2, Alive: true, Agent: a2, AutonomousBudget: 1, LastInstruction: "go"}
	results := RunAllWorkersUntilEscalation(
		context.Background(),
		[]*WorkerState{w1, w2}, candidates, nil,
	)

	require.Len(t, results, 2)
	assert.Equal(t, "candidate", w1.EscalationReason)
	assert.Equal(t, "silent", w2.EscalationReason)
}

func TestBuildClientPoolDefaults(t *testing.T) {
	t.Parallel()
	pool := buildClientPool("http://localhost:9999/v1", "", 4)
	assert.Equal(t, 4, pool.Size())
	// buildClientPool with n<1 clamps to 1.
	pool2 := buildClientPool("", "", 0)
	assert.Equal(t, 1, pool2.Size())
}

func TestRunAllWorkersUntilEscalation_RecoveryPath(t *testing.T) {
	t.Parallel()
	// First Drain errors out; the controller re-queues LastInstruction and
	// runs one more Drain which succeeds, landing the recovered turn in results.
	a := &agent.FakeAgent{
		Turns: []agent.TurnSummary{
			{},
			{AssistantText: "recovered", FlowIDs: []string{"abc12345"}},
		},
		Errors: []error{errors.New("transient"), nil},
	}
	candidates := NewCandidatePool()
	w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 1, LastInstruction: "go"}
	results := RunAllWorkersUntilEscalation(context.Background(), []*WorkerState{w}, candidates, nil)
	require.Len(t, results[1], 1, "recovery added one successful turn")
	assert.Equal(t, []string{"go"}, a.QueriedInputs, "recovery re-queues LastInstruction")
}

func TestAutoSummary(t *testing.T) {
	t.Parallel()
	s := autoSummary(2, 3, 1)
	assert.Contains(t, s, "2 filed")
	assert.Contains(t, s, "3 dismissed")
	assert.Contains(t, s, "1 still pending")
}

func TestWorkerStateClose(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{}
	w := &WorkerState{ID: 1, Agent: a}
	w.Close()
	assert.True(t, a.Closed)
	// Close is safe on nil WorkerState and nil fields.
	(*WorkerState)(nil).Close()
	(&WorkerState{}).Close()
}

func TestRunWorkerUntilEscalation_BudgetExhausted(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{Turns: []agent.TurnSummary{
		{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}},
		{ToolCalls: []agent.ToolCallRecord{{Name: "y"}}},
	}}
	w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 2, LastInstruction: "go"}
	runs, err := RunWorkerUntilEscalation(context.Background(), w, NewCandidatePool(), nil)
	require.NoError(t, err)
	assert.Len(t, runs, 2)
	assert.Equal(t, "budget", w.EscalationReason)
	// Second turn (attempt>0) injects the continue prompt.
	require.Len(t, a.QueriedInputs, 1)
	assert.Contains(t, a.QueriedInputs[0], "Continue")
}

func TestOpenAIFactory_ConstructsAgentsWithMalformedWired(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		WorkerModel: "worker-m", OrchestratorModel: "orch-m",
		MaxWorkers: 2, WorkerMaxContext: 4096, OrchestratorMaxContext: 4096,
		TurnTimeout: time.Second, MaxTurnsPerAgent: 10,
	}
	pool := buildClientPool("", "", 1)
	counter := NewMalformedCounter(nil)
	f := &OpenAIFactory{Cfg: cfg, WorkerPool: pool, OrchPool: pool, Malformed: counter}

	w, err := f.NewWorker(1, 1)
	require.NoError(t, err)
	assert.NotNil(t, w)

	v, err := f.NewVerifier()
	require.NoError(t, err)
	assert.NotNil(t, v)

	d, err := f.NewDirector()
	require.NoError(t, err)
	assert.NotNil(t, d)

	require.NoError(t, f.Close())

	// malformedCallback returns nil when no counter is configured.
	f.Malformed = nil
	assert.Nil(t, f.malformedCallback("m"))
}

func TestRunWorkerUntilEscalation_BudgetClamps(t *testing.T) {
	t.Parallel()
	a := &agent.FakeAgent{Turns: []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}}
	w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 0}
	// Budget<1 clamps to 1 so only one turn drains.
	runs, err := RunWorkerUntilEscalation(context.Background(), w, NewCandidatePool(), nil)
	require.NoError(t, err)
	assert.Len(t, runs, 1)
}
