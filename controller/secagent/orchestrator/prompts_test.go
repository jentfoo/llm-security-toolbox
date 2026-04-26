package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestIntraPhaseContinuePrompt(t *testing.T) {
	t.Parallel()
	// Sanity check on the bare intra-phase directive — the cross-iteration
	// directive lives in the per-iteration compose now, so this is the
	// only between-turns Query a worker still receives in a phase.
	assert.Equal(t, "Continue your current testing plan. Take the next concrete step.", intraPhaseContinuePrompt)
}

func TestBuildVerifierContinuePrompt_PhaseProgress(t *testing.T) {
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

func TestBuildDirectorPrompt_RosterSections(t *testing.T) {
	t.Parallel()

	t.Run("completed_block_renders_when_workers_retired", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 4, Alive: true},
			{ID: 8, Alive: true},
		}
		completed := []CompletedWorker{
			{ID: 1, StoppedAt: 2, Reason: "exhausted angle", Summary: "the worker tested /admin endpoints with user-role tokens; all returned 403."},
			{ID: 7, StoppedAt: 3, Reason: "stall-force-stop", Summary: "the worker probed mass-assignment on /account/api/profile; no privileged fields accepted."},
		}
		out := BuildDirectorPrompt(
			workers, map[int][]agent.TurnSummary{},
			"vs", "fs", "", "", completed,
			3, 10, 2, 5,
		)
		assert.Contains(t, out, "**Alive:** [4, 8]")
		assert.Contains(t, out, "**Workers completed earlier this run**")
		assert.Contains(t, out, "Worker 1 (stopped iter 2, reason: exhausted angle)")
		assert.Contains(t, out, "Worker 7 (stopped iter 3, reason: stall-force-stop)")
		assert.Contains(t, out, "the worker tested /admin")
		assert.Contains(t, out, "do NOT plan, fork, or narrate")
	})

	t.Run("completed_block_omitted_when_empty", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Alive: true},
			{ID: 2, Alive: true},
		}
		out := BuildDirectorPrompt(
			workers, map[int][]agent.TurnSummary{},
			"vs", "fs", "", "", nil,
			1, 10, 0, 5,
		)
		assert.Contains(t, out, "**Alive:** [1, 2]")
		assert.NotContains(t, out, "**Workers completed earlier this run**")
	})

	t.Run("completed_block_caps_oldest_with_omitted_note", func(t *testing.T) {
		workers := []*WorkerState{{ID: 100, Alive: true}}
		var completed []CompletedWorker
		for i := 1; i <= 13; i++ {
			completed = append(completed, CompletedWorker{
				ID: i, StoppedAt: i, Reason: "r", Summary: "s",
			})
		}
		out := BuildDirectorPrompt(
			workers, map[int][]agent.TurnSummary{},
			"vs", "fs", "", "", completed,
			14, 20, 0, 5,
		)
		// Rendered: cap=10, so oldest 3 are folded into the omitted note.
		assert.Contains(t, out, "(3 earlier completed worker(s) omitted)")
		assert.Contains(t, out, "Worker 4 (stopped iter 4")
		assert.Contains(t, out, "Worker 13 (stopped iter 13")
		assert.NotContains(t, out, "Worker 1 (stopped iter 1")
	})
}

func TestBuildDirectorPrompt_IncludesWorkerHistory(t *testing.T) {
	t.Parallel()

	t.Run("renders_history_block_when_entries_present", func(t *testing.T) {
		w := &WorkerState{ID: 1, Alive: true}
		w.AppendHistory(IterationEntry{
			Iteration: 4, Angle: "probe /admin for IDOR", Outcome: OutcomeSilent,
			ToolCalls: 12, FlowsTouched: 2,
		})
		w.AppendHistory(IterationEntry{
			Iteration: 5, Angle: "probe /admin for IDOR variants", Outcome: OutcomeSilent,
			ToolCalls: 8, FlowsTouched: 1,
		})
		out := BuildDirectorPrompt(
			[]*WorkerState{w}, map[int][]agent.TurnSummary{},
			"vs", "fs", "", "", nil,
			6, 10, 0, 5,
		)
		assert.Contains(t, out, "Recent worker history")
		assert.Contains(t, out, "Worker 1:")
		assert.Contains(t, out, "iter 4 [silent]")
		assert.Contains(t, out, "iter 5 [silent]")
		assert.Contains(t, out, `"probe /admin for IDOR"`)
		assert.Contains(t, out, "12 tools, 2 flows")
	})

	t.Run("history_block_omitted_when_empty", func(t *testing.T) {
		w := &WorkerState{ID: 1, Alive: true}
		out := BuildDirectorPrompt(
			[]*WorkerState{w}, map[int][]agent.TurnSummary{},
			"vs", "fs", "", "", nil,
			1, 10, 0, 5,
		)
		assert.NotContains(t, out, "Recent worker history")
	})
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

func TestBuildDirectorContinuePrompt(t *testing.T) {
	t.Parallel()

	t.Run("with_workers", func(t *testing.T) {
		out := BuildDirectorContinuePrompt(map[int]bool{2: true, 4: true}, 2, 4)
		assert.Contains(t, out, "substep 2/4")
		assert.Contains(t, out, "2, 4")
	})

	t.Run("none", func(t *testing.T) {
		out := BuildDirectorContinuePrompt(nil, 3, 4)
		assert.Contains(t, out, "(none)")
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
