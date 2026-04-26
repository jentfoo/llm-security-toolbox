package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
		defs := WorkerToolDefs(pool, nil, 7, nil, nil)
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
		rc := findTool(WorkerToolDefs(pool, nil, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["severity"] = "nope"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "severity")
	})

	t.Run("rejects_empty_flow_ids", func(t *testing.T) {
		pool := NewCandidatePool()
		rc := findTool(WorkerToolDefs(pool, nil, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["flow_ids"] = []string{}
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
	})

	t.Run("rejects_filed_duplicate_exact_slug", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "XSS",
			Severity: "high",
			Endpoint: "GET /",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "already-filed")
		assert.Contains(t, res.Text, "XSS")
		assert.Empty(t, pool.Pending(), "candidate must not be added to pool")
	})

	t.Run("rejects_filed_duplicate_endpoint_plus_similar_title", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "Reflected XSS in search",
			Severity: "high",
			Endpoint: "GET /search",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		args := baseArgs()
		args["title"] = "Reflected XSS in search endpoint"
		args["endpoint"] = "GET /search"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "already-filed")
		assert.Empty(t, pool.Pending())
	})

	t.Run("admits_distinct_title_and_endpoint", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "XSS",
			Severity: "high",
			Endpoint: "GET /",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		args := baseArgs()
		args["title"] = "SQL Injection in login"
		args["endpoint"] = "POST /login"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, pool.Pending(), 1)
	})
}

// fakeCandidateDedup is a scripted CandidateDedupReviewer for tool tests.
type fakeCandidateDedup struct {
	verdict CandidateDedupVerdict
	err     error
	calls   int
}

func (f *fakeCandidateDedup) ClassifyCandidate(_ context.Context, _ AddInput, _ []FindingDigest) (CandidateDedupVerdict, error) {
	f.calls++
	return f.verdict, f.err
}

// fakeMerger collects async merge submissions for assertion.
type fakeMerger struct {
	mu          sync.Mutex
	submissions []fakeMergerSubmission
}

type fakeMergerSubmission struct {
	matched  string
	incoming AddInput
}

func (f *fakeMerger) Submit(matched string, in AddInput) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submissions = append(f.submissions, fakeMergerSubmission{matched, in})
}

func TestWorkerToolDefsLLMDedup(t *testing.T) {
	t.Parallel()
	baseArgs := func() map[string]any {
		return map[string]any{
			"title":             "Reflected XSS in search",
			"severity":          "high",
			"endpoint":          "GET /search",
			"flow_ids":          []string{"abc123"},
			"summary":           "user input reflected",
			"evidence_notes":    "saw <script> echoed",
			"reproduction_hint": "send q=<script>alert(1)</script>",
		}
	}
	primeWriter := func(t *testing.T) *FindingWriter {
		t.Helper()
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(FindingFiled{
			Title: "Open redirect on /go", Severity: "medium", Endpoint: "GET /go",
			Description: "Existing description.",
		})
		require.NoError(t, err)
		return w
	}

	t.Run("unique_admits_to_pool", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{Action: "unique"}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Equal(t, 1, dedup.calls)
		assert.Len(t, pool.Pending(), 1)
	})

	t.Run("duplicate_rejects_with_cite", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		// matched filename will be the only finding's filename
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		require.NotEmpty(t, matchedName)
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "duplicate", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, matchedName)
		assert.Empty(t, pool.Pending())
	})

	t.Run("merge_acks_and_submits_async", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		merger := &fakeMerger{}
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "merge", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, merger), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, "merge ack must not be marked error so the worker treats it as success")
		assert.Contains(t, res.Text, matchedName)
		assert.Contains(t, res.Text, "merged")
		assert.Empty(t, pool.Pending(), "merge candidates do not enter the pool")
		merger.mu.Lock()
		require.Len(t, merger.submissions, 1)
		assert.Equal(t, matchedName, merger.submissions[0].matched)
		merger.mu.Unlock()
	})

	t.Run("merge_without_merger_falls_back_to_reject", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "merge", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, nil), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.True(t, res.IsError)
		assert.Empty(t, pool.Pending())
	})

	t.Run("classifier_error_fails_open", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		dedup := &fakeCandidateDedup{err: errors.New("boom")}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, "classifier error should fall open and admit the candidate")
		assert.Len(t, pool.Pending(), 1, "candidate must enter pool when classifier errors")
	})

	t.Run("empty_index_skips_dedup", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir()) // no findings written
		dedup := &fakeCandidateDedup{}          // would error if called (but we won't increment if not invoked)
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Equal(t, 0, dedup.calls, "no findings means no LLM call")
		assert.Len(t, pool.Pending(), 1)
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

	t.Run("plan_recovers_string_encoded_array", func(t *testing.T) {
		// Models sometimes emit `plans` as a JSON-encoded string instead of
		// an array. Recover that one shape rather than burning a retry.
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(DirectorToolDefs(dq, guardAccept), "plan_workers")
		res := pw.Handler(t.Context(), json.RawMessage(
			`{"plans": "[{\"worker_id\":1,\"assignment\":\"scan auth\"},{\"worker_id\":2,\"assignment\":\"scan admin\"}]"}`,
		))
		assert.False(t, res.IsError)
		require.Len(t, dq.Plan, 2)
		assert.Equal(t, 1, dq.Plan[0].WorkerID)
		assert.Equal(t, "scan auth", dq.Plan[0].Assignment)
		assert.Equal(t, 2, dq.Plan[1].WorkerID)
		assert.Equal(t, "scan admin", dq.Plan[1].Assignment)
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

	t.Run("fork_worker_records", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		fw := findTool(DirectorToolDefs(dq, guardAccept), "fork_worker")
		require.NotNil(t, fw)
		res := fw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"parent_worker_id": 3,
			"new_worker_id":    9,
			"instruction":      "Pursue the JWT alg=none variant on /oauth2/userinfo",
		}))
		assert.False(t, res.IsError)
		require.Len(t, dq.Forks, 1)
		assert.Equal(t, 3, dq.Forks[0].ParentWorkerID)
		assert.Equal(t, 9, dq.Forks[0].NewWorkerID)
		assert.Contains(t, dq.Forks[0].Instruction, "alg=none")
	})

	t.Run("fork_worker_rejects_same_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		fw := findTool(DirectorToolDefs(dq, guardAccept), "fork_worker")
		res := fw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"parent_worker_id": 3, "new_worker_id": 3, "instruction": "x",
		}))
		assert.True(t, res.IsError)
		assert.Empty(t, dq.Forks)
	})

	t.Run("fork_worker_rejects_empty_instruction", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		fw := findTool(DirectorToolDefs(dq, guardAccept), "fork_worker")
		res := fw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"parent_worker_id": 3, "new_worker_id": 4, "instruction": "   ",
		}))
		assert.True(t, res.IsError)
		assert.Empty(t, dq.Forks)
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
		for _, name := range []string{"plan_workers", "fork_worker", "continue_worker", "expand_worker", "stop_worker", "direction_done", "end_run"} {
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
