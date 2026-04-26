package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestBuildVerifierContinuePrompt(t *testing.T) {
	t.Parallel()

	t.Run("no_progress_yet_keeps_pending_only", func(t *testing.T) {
		out := BuildVerifierContinuePrompt(
			[]FindingCandidate{{CandidateID: "c001", Title: "Pending X"}},
			nil, nil, 2, 6,
		)
		assert.Contains(t, out, "Filed 0, dismissed 0 so far this phase.")
		assert.NotContains(t, out, "Already filed this phase")
		assert.NotContains(t, out, "Already dismissed this phase")
		assert.Contains(t, out, "c001")
	})

	t.Run("lists_filed_and_dismissed_titles", func(t *testing.T) {
		filed := []FindingFiled{
			{Title: "Admin PUT JSON Injection"},
			{Title: "Federation Role Manipulation"},
		}
		dismissed := []CandidateDismissal{
			{CandidateID: "c004"},
		}
		out := BuildVerifierContinuePrompt(
			[]FindingCandidate{{CandidateID: "c005", Title: "Still pending"}},
			filed, dismissed, 3, 6,
		)
		assert.Contains(t, out, "Filed 2, dismissed 1 so far this phase.")
		assert.Contains(t, out, "Admin PUT JSON Injection")
		assert.Contains(t, out, "Federation Role Manipulation")
		assert.Contains(t, out, "c004")
		assert.Contains(t, out, "c005")
	})
}

func TestBuildSynthesisPrompt(t *testing.T) {
	t.Parallel()

	t.Run("completed_block_renders", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 4, Alive: true},
			{ID: 8, Alive: true},
		}
		completed := []CompletedWorker{
			{ID: 1, StoppedAt: 2, Reason: "exhausted angle", Summary: "the worker tested /admin endpoints with user-role tokens; all returned 403."},
			{ID: 7, StoppedAt: 3, Reason: "stall-force-stop", Summary: "the worker probed mass-assignment on /account/api/profile; no privileged fields accepted."},
		}
		out := BuildSynthesisPrompt(
			workers, completed, "vs", "fs", "", "", statusLine(3, 10, 2), 5,
		)
		assert.Contains(t, out, "**Alive workers")
		assert.Contains(t, out, "[4, 8]")
		assert.Contains(t, out, "**Workers completed earlier this run**")
		assert.Contains(t, out, "Worker 1 (stopped iter 2, reason: exhausted angle)")
		assert.Contains(t, out, "Worker 7 (stopped iter 3, reason: stall-force-stop)")
		assert.Contains(t, out, "the worker tested /admin")
		assert.Contains(t, out, "do NOT plan or fork")
	})

	t.Run("completed_block_omitted", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Alive: true},
			{ID: 2, Alive: true},
		}
		out := BuildSynthesisPrompt(
			workers, nil, "vs", "fs", "", "", statusLine(1, 10, 0), 5,
		)
		assert.Contains(t, out, "[1, 2]")
		assert.NotContains(t, out, "**Workers completed earlier this run**")
	})

	t.Run("completed_caps_oldest", func(t *testing.T) {
		workers := []*WorkerState{{ID: 100, Alive: true}}
		var completed []CompletedWorker
		for i := 1; i <= 13; i++ {
			completed = append(completed, CompletedWorker{
				ID: i, StoppedAt: i, Reason: "r", Summary: "s",
			})
		}
		out := BuildSynthesisPrompt(
			workers, completed, "vs", "fs", "", "", statusLine(14, 20, 0), 5,
		)
		// cap=10, so oldest 3 fold into the omitted note.
		assert.Contains(t, out, "(3 earlier completed worker(s) omitted)")
		assert.Contains(t, out, "Worker 4 (stopped iter 4")
		assert.Contains(t, out, "Worker 13 (stopped iter 13")
		assert.NotContains(t, out, "Worker 1 (stopped iter 1")
	})

	t.Run("action_block_lists_tools", func(t *testing.T) {
		out := BuildSynthesisPrompt(
			[]*WorkerState{{ID: 1, Alive: true}}, nil, "vs", "fs", "", "",
			statusLine(2, 10, 0), 5,
		)
		assert.Contains(t, out, "plan_workers")
		assert.Contains(t, out, "direction_done")
		assert.Contains(t, out, "end_run")
	})
}

func TestBuildPerWorkerDecisionPrompt(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 5, Alive: true, EscalationReason: "candidate"}
	w.AppendHistory(IterationEntry{
		Iteration: 4, Angle: "probe /admin", Outcome: OutcomeFinding,
		ToolCalls: 7, FlowsTouched: 2,
	})
	taken := map[int]bool{5: true, 6: true, 99: true}
	turns := []agent.TurnSummary{{AssistantText: "found it", ToolCalls: []agent.ToolCallRecord{{Name: "replay_send"}}}}
	out := BuildPerWorkerDecisionPrompt(5, w, turns, "- Worker 6: scanning /api/users", "iter status line", taken)
	assert.Contains(t, out, "iter status line")
	// Single-tool restriction is the leading line after status (primacy effect).
	assert.Contains(t, out, "Single tool call: `decide_worker(worker_id=5")
	assert.Contains(t, out, "Only `decide_worker` is registered")
	assert.Contains(t, out, "every other tool errors out")
	assert.Contains(t, out, "candidate")
	assert.Contains(t, out, "Worker 5")
	assert.Contains(t, out, "replay_send")
	assert.Contains(t, out, "Worker 6: scanning /api/users")
	assert.Contains(t, out, "Taken worker IDs")
}

func TestBuildIter1ReconReviewPrompt(t *testing.T) {
	t.Parallel()
	out := BuildIter1ReconReviewPrompt(statusLine(1, 10, 0), 5)
	assert.Contains(t, out, "Recon iteration complete")
	assert.Contains(t, out, "Step 1 of 2")
	assert.Contains(t, out, "NO tool calls")
	assert.Contains(t, out, "scope")
	assert.Contains(t, out, "starting from 2")
}

func TestBuildIter1ReconPlanPrompt(t *testing.T) {
	t.Parallel()
	out := BuildIter1ReconPlanPrompt(statusLine(1, 10, 0), 5)
	assert.Contains(t, out, "Step 2 of 2")
	assert.Contains(t, out, "plan_workers")
	assert.Contains(t, out, "direction_done")
	// Tool restriction is named explicitly (decide_worker / end_run unregistered).
	assert.Contains(t, out, "decide_worker")
	assert.Contains(t, out, "end_run")
	assert.Contains(t, out, "NOT registered")
}

func TestBuildIter1ReconPlanRetryPrompt(t *testing.T) {
	t.Parallel()
	out := BuildIter1ReconPlanRetryPrompt()
	assert.Contains(t, out, "did NOT call `plan_workers`")
	assert.Contains(t, out, "worker roster is required")
	assert.Contains(t, out, "last chance")
}

func TestFormatPeerSummary(t *testing.T) {
	t.Parallel()
	workers := []*WorkerState{
		{ID: 1, Alive: true, LastInstruction: "probe /admin"},
		{ID: 2, Alive: false, LastInstruction: "stopped"},
		{ID: 3, Alive: true, LastInstruction: "probe /api"},
	}
	out := FormatPeerSummary(workers, 3)
	assert.Contains(t, out, "Worker 1: probe /admin")
	assert.NotContains(t, out, "Worker 3")
	assert.NotContains(t, out, "Worker 2")
}

func TestShort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		max      int
		expected string
	}{
		{"fits", "hi", 10, "hi"},
		{"truncated", "abcdef", 2, "a…"},
		{"zero_max", "abcdef", 0, "…"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, short(c.in, c.max))
		})
	}
}

func TestFirstNonEmptyLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"leading_blank_then_first", "\n  first\nsecond", "first"},
		{"single_line", "only", "only"},
		{"empty", "", ""},
		{"whitespace_only", "   \n\t  ", ""},
		{"trailing_whitespace", "hello  ", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, firstNonEmptyLine(c.in))
		})
	}
}

func TestFormatToolCalls(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		assert.Contains(t, formatToolCalls(nil, 0), "no tool calls")
	})

	t.Run("with_calls", func(t *testing.T) {
		out := formatToolCalls([]agent.ToolCallRecord{
			{Name: "a", InputSummary: `{"x":1}`, ResultSummary: "ok"},
			{Name: "b", InputSummary: "{}", IsError: true},
		}, 20)
		assert.Contains(t, out, "1. a")
		assert.Contains(t, out, "2. b")
		assert.Contains(t, out, "[ERROR]")
		assert.Contains(t, out, "→ ok")
	})

	t.Run("truncated", func(t *testing.T) {
		many := make([]agent.ToolCallRecord, 30)
		for i := range many {
			many[i] = agent.ToolCallRecord{Name: "t"}
		}
		assert.Contains(t, formatToolCalls(many, 5), "and 25 more")
	})
}

func TestFormatAutonomousRun(t *testing.T) {
	t.Parallel()

	t.Run("empty_turns", func(t *testing.T) {
		out := formatAutonomousRun(1, nil, "silent")
		assert.Contains(t, out, "No autonomous turns")
		assert.Contains(t, out, "silent")
	})

	t.Run("with_turns", func(t *testing.T) {
		turns := []agent.TurnSummary{{
			AssistantText: "looking into it\nmore detail",
			ToolCalls:     []agent.ToolCallRecord{{Name: "flow_get"}, {Name: "replay_send"}},
			FlowIDs:       []string{"abc12345"},
		}}
		out := formatAutonomousRun(2, turns, "candidate")
		assert.Contains(t, out, "Worker 2")
		assert.Contains(t, out, "candidate")
		assert.Contains(t, out, "flow_get, replay_send")
		assert.Contains(t, out, "abc12345")
		assert.Contains(t, out, "looking into it")
	})
}

func TestFormatPendingCandidates(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "No pending finding candidates.", formatPendingCandidates(nil))
	})

	t.Run("with_candidate", func(t *testing.T) {
		out := formatPendingCandidates([]FindingCandidate{{
			CandidateID: "c1", Title: "xss", Severity: "high",
			Endpoint: "/x", WorkerID: 2, FlowIDs: []string{"abc12345"},
		}})
		assert.Contains(t, out, "c1")
		assert.Contains(t, out, "/x")
		assert.Contains(t, out, "abc12345")
	})
}
