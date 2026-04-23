package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func findTool(defs []agent.ToolDef, name string) *agent.ToolDef {
	for i, d := range defs {
		if d.Name == name {
			return &defs[i]
		}
	}
	return nil
}

func TestWorkerToolDefs(t *testing.T) {
	t.Parallel()
	t.Run("report_candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		defs := WorkerToolDefs(pool, 7)
		require.Len(t, defs, 1)
		rc := findTool(defs, "report_finding_candidate")
		require.NotNil(t, rc)

		args, _ := json.Marshal(map[string]any{
			"title":             "XSS",
			"severity":          "high",
			"endpoint":          "GET /",
			"flow_ids":          []string{"abc123"},
			"summary":           "s",
			"evidence_notes":    "e",
			"reproduction_hint": "r",
		})
		res := rc.Handler(context.Background(), args)
		assert.False(t, res.IsError, res.Text)
		assert.Contains(t, res.Text, "Candidate c001 recorded")
		pending := pool.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, 7, pending[0].WorkerID)
	})

	t.Run("rejects_bad_severity", func(t *testing.T) {
		pool := NewCandidatePool()
		defs := WorkerToolDefs(pool, 1)
		rc := defs[0]
		args, _ := json.Marshal(map[string]any{
			"title": "x", "severity": "nope", "endpoint": "/x",
			"flow_ids": []string{"abc123"}, "summary": "s",
			"evidence_notes": "e", "reproduction_hint": "r",
		})
		res := rc.Handler(context.Background(), args)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "severity")
	})

	t.Run("rejects_empty_flow_ids", func(t *testing.T) {
		pool := NewCandidatePool()
		defs := WorkerToolDefs(pool, 1)
		rc := defs[0]
		args, _ := json.Marshal(map[string]any{
			"title": "x", "severity": "high", "endpoint": "/x",
			"flow_ids": []string{}, "summary": "s",
			"evidence_notes": "e", "reproduction_hint": "r",
		})
		res := rc.Handler(context.Background(), args)
		assert.True(t, res.IsError)
	})
}

func TestVerifierToolDefs(t *testing.T) {
	t.Parallel()
	t.Run("phase_gated", func(t *testing.T) {
		dq := NewDecisionQueue()
		defs := VerifierToolDefs(dq)
		ff := findTool(defs, "file_finding")
		require.NotNil(t, ff)

		args, _ := json.Marshal(map[string]any{
			"title": "t", "severity": "high", "endpoint": "GET /",
			"description": "d", "reproduction_steps": "r",
			"evidence": "e", "impact": "i", "verification_notes": "v",
		})
		// Idle → reject.
		res := ff.Handler(context.Background(), args)
		assert.True(t, res.IsError)
		assert.Contains(t, strings.ToLower(res.Text), "phase")

		// Verification → accepted.
		dq.BeginPhase(agent.PhaseVerification)
		res = ff.Handler(context.Background(), args)
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, dq.Findings, 1)
	})
}

// guardAccept is a guardState closure that always permits end_run. Used by
// director-tool tests that aren't exercising the premature-end_run path.
func guardAccept() (int, int) { return MinIterationsForDone, 0 }

// guardPremature is a guardState closure that always produces a rejection
// from the end_run handler (iter below threshold, zero findings this run).
func guardPremature() (int, int) { return 1, 0 }

func TestDirectorToolDefs(t *testing.T) {
	t.Parallel()
	t.Run("phase_gated_and_budget_clamp", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		defs := DirectorToolDefs(dq, guardAccept)
		cw := findTool(defs, "continue_worker")
		require.NotNil(t, cw)
		args, _ := json.Marshal(map[string]any{
			"worker_id":         2,
			"instruction":       "go",
			"progress":          "incremental",
			"autonomous_budget": 999,
		})
		res := cw.Handler(context.Background(), args)
		assert.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, 20, dq.WorkerDecisions[0].AutonomousBudget)
	})

	t.Run("continue_rejects_bad_progress", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		cw := findTool(DirectorToolDefs(dq, guardAccept), "continue_worker")
		args, _ := json.Marshal(map[string]any{
			"worker_id": 1, "instruction": "go", "progress": "bogus",
		})
		res := cw.Handler(context.Background(), args)
		assert.True(t, res.IsError)
	})

	t.Run("plan_rejects_empty", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		args, _ := json.Marshal(map[string]any{"plans": []any{}})
		res := pw.Handler(context.Background(), args)
		assert.True(t, res.IsError)
	})

	t.Run("plan_records_valid_entries", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		args, _ := json.Marshal(map[string]any{
			"plans": []map[string]any{
				{"worker_id": 1, "assignment": "scan auth"},
				{"worker_id": 0, "assignment": "invalid"}, // filtered
				{"worker_id": 2, "assignment": "   "},     // filtered
				{"worker_id": 3, "assignment": "scan admin"},
			},
		})
		res := pw.Handler(context.Background(), args)
		assert.False(t, res.IsError)
		require.Len(t, dq.Plan, 2)
		assert.Equal(t, 1, dq.Plan[0].WorkerID)
		assert.Equal(t, 3, dq.Plan[1].WorkerID)
	})

	t.Run("stop_and_end_run", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		defs := DirectorToolDefs(dq, guardAccept)

		stop := findTool(defs, "stop_worker")
		args, _ := json.Marshal(map[string]any{"worker_id": 2, "reason": "dead end"})
		res := stop.Handler(context.Background(), args)
		assert.False(t, res.IsError)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, "stop", dq.WorkerDecisions[0].Kind)

		dd := findTool(defs, "direction_done")
		args, _ = json.Marshal(map[string]any{"summary": "all covered"})
		res = dd.Handler(context.Background(), args)
		assert.False(t, res.IsError)
		assert.True(t, dq.HasDirectionDone)

		er := findTool(defs, "end_run")
		args, _ = json.Marshal(map[string]any{"summary": "run over"})
		res = er.Handler(context.Background(), args)
		assert.False(t, res.IsError)
		assert.True(t, dq.HasEndRun)
	})

	t.Run("phase_mismatch_rejects_all", func(t *testing.T) {
		dq := NewDecisionQueue() // idle
		defs := DirectorToolDefs(dq, guardAccept)
		for _, name := range []string{"plan_workers", "continue_worker", "expand_worker", "stop_worker", "direction_done", "end_run"} {
			d := findTool(defs, name)
			require.NotNil(t, d, name)
			res := d.Handler(context.Background(), []byte(`{}`))
			assert.True(t, res.IsError, name)
		}
	})

	t.Run("end_run_premature_rejected", func(t *testing.T) {
		// Director is in the right phase but called end_run on iteration 1
		// with zero findings filed this run — the guard inside the handler
		// must reject with IsError so the model sees the rejection same-turn
		// and can course-correct to direction_done.
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		er := findTool(DirectorToolDefs(dq, guardPremature), "end_run")
		require.NotNil(t, er)
		args, _ := json.Marshal(map[string]any{"summary": "fabricated dispatch summary"})
		res := er.Handler(context.Background(), args)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "premature")
		assert.Contains(t, res.Text, "direction_done")
		assert.False(t, dq.HasEndRun, "premature end_run must not flip HasEndRun")
		assert.Empty(t, dq.EndRunSummary)
	})

	t.Run("end_run_accepted_after_threshold", func(t *testing.T) {
		// Reaching MinIterationsForDone without findings is the intended
		// "nothing found, stop" escape hatch — the guard should accept.
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		er := findTool(DirectorToolDefs(dq, func() (int, int) {
			return MinIterationsForDone, 0
		}), "end_run")
		args, _ := json.Marshal(map[string]any{"summary": "exhausted after 5 iterations"})
		res := er.Handler(context.Background(), args)
		assert.False(t, res.IsError, res.Text)
		assert.True(t, dq.HasEndRun)
	})

	t.Run("end_run_accepted_with_findings_this_run", func(t *testing.T) {
		// One filed finding on iteration 2 is also fine — model has made
		// concrete progress, so it can end the run even before iter 5.
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		er := findTool(DirectorToolDefs(dq, func() (int, int) { return 2, 1 }), "end_run")
		args, _ := json.Marshal(map[string]any{"summary": "one finding, nothing else to probe"})
		res := er.Handler(context.Background(), args)
		assert.False(t, res.IsError, res.Text)
		assert.True(t, dq.HasEndRun)
	})
}

func TestVerifierToolDefs_DismissAndDone(t *testing.T) {
	t.Parallel()
	dq := NewDecisionQueue()
	dq.BeginPhase(agent.PhaseVerification)
	defs := VerifierToolDefs(dq)

	dc := findTool(defs, "dismiss_candidate")
	args, _ := json.Marshal(map[string]any{"candidate_id": "c1", "reason": "noise"})
	res := dc.Handler(context.Background(), args)
	assert.False(t, res.IsError)
	require.Len(t, dq.Dismissals, 1)

	// Empty candidate_id rejected.
	empty, _ := json.Marshal(map[string]any{"candidate_id": "", "reason": "x"})
	assert.True(t, dc.Handler(context.Background(), empty).IsError)

	vd := findTool(defs, "verification_done")
	args, _ = json.Marshal(map[string]any{"summary": "done verifying"})
	res = vd.Handler(context.Background(), args)
	assert.False(t, res.IsError)
	assert.True(t, dq.HasVerificationDone)
}
