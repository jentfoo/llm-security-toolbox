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

func TestIsDeadIteration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		runs        map[int][]agent.TurnSummary
		candsBefore int
		candsAfter  int
		wantDead    bool
	}{
		{
			name:        "all_empty_no_new_candidates",
			runs:        map[int][]agent.TurnSummary{1: {{}, {}}, 2: {{}}},
			candsBefore: 0,
			candsAfter:  0,
			wantDead:    true,
		},
		{
			name:        "any_tool_call_not_dead",
			runs:        map[int][]agent.TurnSummary{1: {{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}},
			candsBefore: 0,
			candsAfter:  0,
			wantDead:    false,
		},
		{
			name:        "new_candidate_not_dead",
			runs:        map[int][]agent.TurnSummary{1: {{}}},
			candsBefore: 0,
			candsAfter:  1,
			wantDead:    false,
		},
		{
			name:        "empty_runs_map_is_dead",
			runs:        map[int][]agent.TurnSummary{},
			candsBefore: 5,
			candsAfter:  5,
			wantDead:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.wantDead, isDeadIteration(c.runs, c.candsBefore, c.candsAfter))
		})
	}
}

func TestApplyDecision(t *testing.T) {
	t.Parallel()
	t.Run("stop_without_retire_closes_directly", func(t *testing.T) {
		a := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Alive: true, Agent: a}
		applyDecision(t.Context(), WorkerDecision{Kind: "stop", WorkerID: 1, Reason: "done"}, w, nil, 5, nil)
		assert.False(t, w.Alive)
		assert.True(t, a.Closed)
	})

	t.Run("stop_invokes_retire_with_iter", func(t *testing.T) {
		a := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Alive: true, Agent: a}
		var capturedReason string
		var capturedIter int
		retire := func(_ context.Context, ww *WorkerState, reason string, iter int) {
			capturedReason = reason
			capturedIter = iter
			ww.Alive = false
			_ = ww.Agent.Close()
		}
		applyDecision(t.Context(), WorkerDecision{Kind: "stop", WorkerID: 1, Reason: "exhausted"}, w, retire, 7, nil)
		assert.Equal(t, "exhausted", capturedReason)
		assert.Equal(t, 7, capturedIter, "iter parameter is threaded into retire")
		assert.False(t, w.Alive)
		assert.True(t, a.Closed)
	})

	t.Run("continue_clamps_budget", func(t *testing.T) {
		a := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Alive: true, Agent: a}
		applyDecision(t.Context(), WorkerDecision{
			Kind: "continue", WorkerID: 1, Instruction: "keep going",
			AutonomousBudget: 999,
		}, w, nil, 1, nil)
		assert.Equal(t, 20, w.AutonomousBudget)
		assert.Equal(t, "keep going", w.LastInstruction)
		// v4: applyDecision does NOT call Query — the next iter's
		// installChronicle re-installs the chronicle and Queries
		// w.LastInstruction itself.
		assert.Empty(t, a.QueriedInputs,
			"applyDecision must not pre-Query; chronicle install does it")
	})

	t.Run("expand_defaults_budget", func(t *testing.T) {
		a := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Alive: true, Agent: a}
		applyDecision(t.Context(), WorkerDecision{Kind: "expand", WorkerID: 1, Instruction: "new scope"}, w, nil, 1, nil)
		assert.Equal(t, defaultAutonomousBudget, w.AutonomousBudget)
	})
}

func TestRunAllWorkersUntilEscalation(t *testing.T) {
	t.Parallel()

	t.Run("concurrent_isolated", func(t *testing.T) {
		// Two workers; one yields a candidate on turn 1, the other runs silent
		// and stays. Neither affects the other's escalation reason.
		a1 := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{ToolCalls: []agent.ToolCallRecord{{Name: "report_finding_candidate"}}},
		}}
		a2 := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "nothing to report"},
		}}
		candidates := NewCandidatePool()
		a1.OnDrain = func(_ int) {
			candidates.Add(AddInput{WorkerID: 1, Title: "x"})
		}

		w1 := &WorkerState{ID: 1, Alive: true, Agent: a1, AutonomousBudget: 1, LastInstruction: "go"}
		w2 := &WorkerState{ID: 2, Alive: true, Agent: a2, AutonomousBudget: 1, LastInstruction: "go"}
		results := RunAllWorkersUntilEscalation(
			t.Context(),
			[]*WorkerState{w1, w2}, candidates, nil,
		)

		require.Len(t, results, 2)
		assert.Equal(t, "candidate", w1.EscalationReason)
		assert.Equal(t, "silent", w2.EscalationReason)
	})

	t.Run("recovery_path", func(t *testing.T) {
		// First Drain errors out; the controller re-queues LastInstruction and
		// runs one more Drain which succeeds, landing the recovered turn in results.
		a := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{},
				{AssistantText: "recovered", FlowIDs: []string{"abc12345"}},
			},
			Errors: []error{errors.New("transient"), nil},
		}
		w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 1, LastInstruction: "go"}
		results := RunAllWorkersUntilEscalation(t.Context(), []*WorkerState{w}, NewCandidatePool(), nil)
		require.Len(t, results[1], 1)
		assert.Equal(t, []string{"go"}, a.QueriedInputs)
	})
}

func TestBuildClientPoolDefaults(t *testing.T) {
	t.Parallel()
	pool := buildClientPool("http://localhost:9999/v1", "", 4, 0)
	assert.Equal(t, 4, pool.Size())
	pool2 := buildClientPool("", "", 0, 0)
	assert.Equal(t, 1, pool2.Size())
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
	assert.NotPanics(t, func() {
		(*WorkerState)(nil).Close()
		(&WorkerState{}).Close()
	})
}

func TestRunWorkerUntilEscalationBudget(t *testing.T) {
	t.Parallel()

	t.Run("exhausted", func(t *testing.T) {
		a := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}},
			{ToolCalls: []agent.ToolCallRecord{{Name: "y"}}},
		}}
		w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 2, LastInstruction: "go"}
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), nil)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "budget", w.EscalationReason)
		// second turn (attempt>0) injects the continue prompt
		require.Len(t, a.QueriedInputs, 1)
		assert.Contains(t, a.QueriedInputs[0], "Continue")
	})

	t.Run("clamps_zero_to_one", func(t *testing.T) {
		a := &agent.FakeAgent{Turns: []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}}
		w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 0}
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), nil)
		require.NoError(t, err)
		assert.Len(t, runs, 1)
	})
}

func TestOpenAIFactory(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Model:      "main-m",
		MaxWorkers: 2, MaxContext: 4096,
		TurnTimeout: time.Second, MaxTurnsPerAgent: 10,
	}
	pool := buildClientPool("", "", 1, 0)
	counter := NewMalformedCounter(nil)
	f := &OpenAIFactory{Cfg: cfg, Pool: pool, Malformed: counter}

	w, err := f.NewWorker(1, 1)
	require.NoError(t, err)
	assert.NotNil(t, w)

	v, err := f.NewVerifier(nil)
	require.NoError(t, err)
	assert.NotNil(t, v)

	d, err := f.NewDirector()
	require.NoError(t, err)
	assert.NotNil(t, d)

	require.NoError(t, f.Close())

	f.Malformed = nil
	assert.Nil(t, f.malformedCallback("m"))
}

// v4 controller-side chronicle install/extract is exercised by
// chronicle_test.go via installChronicle and extractAndAppend. The
// per-iter loop's chronicle wiring (loop body) is exercised by integration
// scenarios that drive RunAllWorkersUntilEscalation against FakeAgent
// chains; covered in autonomous_test.go.
