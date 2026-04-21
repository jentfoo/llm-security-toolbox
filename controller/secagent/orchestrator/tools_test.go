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

func TestDirectorToolDefs(t *testing.T) {
	t.Parallel()
	t.Run("phase_gated_and_budget_clamp", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		defs := DirectorToolDefs(dq)
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
		cw := findTool(DirectorToolDefs(dq), "continue_worker")
		args, _ := json.Marshal(map[string]any{
			"worker_id": 1, "instruction": "go", "progress": "bogus",
		})
		res := cw.Handler(context.Background(), args)
		assert.True(t, res.IsError)
	})

	t.Run("plan_rejects_empty", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq), "plan_workers")
		args, _ := json.Marshal(map[string]any{"plans": []any{}})
		res := pw.Handler(context.Background(), args)
		assert.True(t, res.IsError)
	})

	t.Run("plan_records_valid_entries", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq), "plan_workers")
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

	t.Run("stop_and_done", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		defs := DirectorToolDefs(dq)

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

		done := findTool(defs, "done")
		args, _ = json.Marshal(map[string]any{"summary": "run over"})
		res = done.Handler(context.Background(), args)
		assert.False(t, res.IsError)
		assert.True(t, dq.HasDone)
	})

	t.Run("phase_mismatch_rejects_all", func(t *testing.T) {
		dq := NewDecisionQueue() // idle
		defs := DirectorToolDefs(dq)
		for _, name := range []string{"plan_workers", "continue_worker", "expand_worker", "stop_worker", "direction_done", "done"} {
			d := findTool(defs, name)
			require.NotNil(t, d, name)
			res := d.Handler(context.Background(), []byte(`{}`))
			assert.True(t, res.IsError, name)
		}
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
