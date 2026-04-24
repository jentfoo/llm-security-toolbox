package orchestrator

import (
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

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestWorkerToolDefs(t *testing.T) {
	t.Parallel()
	baseArgs := func() map[string]any {
		return map[string]any{
			"title":             "XSS",
			"severity":          "high",
			"endpoint":          "GET /",
			"flow_ids":          []string{"abc123"},
			"summary":           "s",
			"evidence_notes":    "e",
			"reproduction_hint": "r",
		}
	}

	t.Run("report_candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		defs := WorkerToolDefs(pool, 7)
		require.Len(t, defs, 1)
		rc := findTool(defs, "report_finding_candidate")
		require.NotNil(t, rc)

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Contains(t, res.Text, "Candidate c001 recorded")
		pending := pool.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, 7, pending[0].WorkerID)
	})

	t.Run("rejects_bad_severity", func(t *testing.T) {
		pool := NewCandidatePool()
		rc := findTool(WorkerToolDefs(pool, 1), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["severity"] = "nope"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "severity")
	})

	t.Run("rejects_empty_flow_ids", func(t *testing.T) {
		pool := NewCandidatePool()
		rc := findTool(WorkerToolDefs(pool, 1), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["flow_ids"] = []string{}
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
	})
}

func TestVerifierToolDefs(t *testing.T) {
	t.Parallel()
	fileFindingArgs := map[string]any{
		"title": "t", "severity": "high", "endpoint": "GET /",
		"description": "d", "reproduction_steps": "r",
		"evidence": "e", "impact": "i", "verification_notes": "v",
	}

	t.Run("rejects_before_phase_begin", func(t *testing.T) {
		dq := NewDecisionQueue()
		ff := findTool(VerifierToolDefs(dq), "file_finding")
		require.NotNil(t, ff)
		res := ff.Handler(t.Context(), mustMarshal(t, fileFindingArgs))
		assert.True(t, res.IsError)
		assert.Contains(t, strings.ToLower(res.Text), "phase")
	})

	t.Run("accepts_in_verification_phase", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		ff := findTool(VerifierToolDefs(dq), "file_finding")
		require.NotNil(t, ff)
		res := ff.Handler(t.Context(), mustMarshal(t, fileFindingArgs))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, dq.Findings, 1)
	})

	t.Run("dismiss_candidate", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		dc := findTool(VerifierToolDefs(dq), "dismiss_candidate")
		require.NotNil(t, dc)
		res := dc.Handler(t.Context(), mustMarshal(t, map[string]any{"candidate_id": "c1", "reason": "noise"}))
		assert.False(t, res.IsError)
		require.Len(t, dq.Dismissals, 1)
	})

	t.Run("dismiss_rejects_empty_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		dc := findTool(VerifierToolDefs(dq), "dismiss_candidate")
		require.NotNil(t, dc)
		res := dc.Handler(t.Context(), mustMarshal(t, map[string]any{"candidate_id": "", "reason": "x"}))
		assert.True(t, res.IsError)
	})

	t.Run("verification_done", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		vd := findTool(VerifierToolDefs(dq), "verification_done")
		require.NotNil(t, vd)
		res := vd.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "done verifying"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasVerificationDone)
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

	t.Run("continue_worker_clamps_budget", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		cw := findTool(DirectorToolDefs(dq, guardAccept), "continue_worker")
		require.NotNil(t, cw)
		res := cw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id":         2,
			"instruction":       "go",
			"progress":          "incremental",
			"autonomous_budget": 999,
		}))
		assert.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, 20, dq.WorkerDecisions[0].AutonomousBudget)
	})

	t.Run("continue_rejects_bad_progress", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		cw := findTool(DirectorToolDefs(dq, guardAccept), "continue_worker")
		res := cw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "instruction": "go", "progress": "bogus",
		}))
		assert.True(t, res.IsError)
	})

	t.Run("plan_rejects_empty", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		res := pw.Handler(t.Context(), mustMarshal(t, map[string]any{"plans": []any{}}))
		assert.True(t, res.IsError)
	})

	t.Run("plan_records_valid_entries", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		res := pw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"plans": []map[string]any{
				{"worker_id": 1, "assignment": "scan auth"},
				{"worker_id": 0, "assignment": "invalid"},
				{"worker_id": 2, "assignment": "   "},
				{"worker_id": 3, "assignment": "scan admin"},
			},
		}))
		assert.False(t, res.IsError)
		require.Len(t, dq.Plan, 2)
		assert.Equal(t, 1, dq.Plan[0].WorkerID)
		assert.Equal(t, 3, dq.Plan[1].WorkerID)
		// Skipped entries are surfaced in the response so the director can fix them.
		assert.Contains(t, res.Text, "plans[1]")
		assert.Contains(t, res.Text, "plans[2]")
	})

	t.Run("plan_parse_error_returns_detail", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		res := pw.Handler(t.Context(), json.RawMessage(`{"plans": "not an array"}`))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "cannot parse arguments")
		assert.Contains(t, res.Text, `{"plans"`)
	})

	t.Run("plan_all_invalid_returns_per_entry_reasons", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		res := pw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"plans": []map[string]any{
				{"worker_id": 0, "assignment": "oops"},
				{"worker_id": 2, "assignment": "   "},
			},
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "plans[0]")
		assert.Contains(t, res.Text, "worker_id must be >= 1")
		assert.Contains(t, res.Text, "plans[1]")
		assert.Contains(t, res.Text, "assignment is empty")
	})

	t.Run("stop_worker", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		stop := findTool(DirectorToolDefs(dq, guardAccept), "stop_worker")
		require.NotNil(t, stop)
		res := stop.Handler(t.Context(), mustMarshal(t, map[string]any{"worker_id": 2, "reason": "dead end"}))
		assert.False(t, res.IsError)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, "stop", dq.WorkerDecisions[0].Kind)
	})

	t.Run("direction_done", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dd := findTool(DirectorToolDefs(dq, guardAccept), "direction_done")
		require.NotNil(t, dd)
		res := dd.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "all covered"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasDirectionDone)
	})

	t.Run("phase_mismatch_rejects_all", func(t *testing.T) {
		dq := NewDecisionQueue()
		defs := DirectorToolDefs(dq, guardAccept)
		for _, name := range []string{"plan_workers", "continue_worker", "expand_worker", "stop_worker", "direction_done", "end_run"} {
			d := findTool(defs, name)
			require.NotNil(t, d, name)
			res := d.Handler(t.Context(), []byte(`{}`))
			assert.True(t, res.IsError, name)
		}
	})

	endRunCases := []struct {
		name        string
		guard       func() (int, int)
		wantErr     bool
		wantTexts   []string
		wantHasFlag bool
	}{
		{
			name:      "premature_rejected",
			guard:     guardPremature,
			wantErr:   true,
			wantTexts: []string{"premature", "direction_done"},
		},
		{
			name:        "accepted_after_threshold",
			guard:       func() (int, int) { return MinIterationsForDone, 0 },
			wantHasFlag: true,
		},
		{
			name:        "accepted_with_findings",
			guard:       func() (int, int) { return 2, 1 },
			wantHasFlag: true,
		},
	}
	for _, c := range endRunCases {
		t.Run("end_run_"+c.name, func(t *testing.T) {
			dq := NewDecisionQueue()
			dq.BeginPhase(agent.PhaseDirection)
			er := findTool(DirectorToolDefs(dq, c.guard), "end_run")
			require.NotNil(t, er)
			res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
			assert.Equal(t, c.wantErr, res.IsError, res.Text)
			for _, want := range c.wantTexts {
				assert.Contains(t, res.Text, want)
			}
			assert.Equal(t, c.wantHasFlag, dq.HasEndRun)
			if !c.wantHasFlag {
				assert.Empty(t, dq.EndRunSummary)
			}
		})
	}
}
