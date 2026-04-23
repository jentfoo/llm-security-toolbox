package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestStatusLine(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "**Status:** iteration 2/10, findings filed: 3", statusLine(2, 10, 3))
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

func TestOrDefault(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "fallback", orDefault("", "fallback"))
	assert.Equal(t, "actual", orDefault("actual", "fallback"))
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

func TestBuildVerifierContinuePrompt(t *testing.T) {
	t.Parallel()
	pending := []FindingCandidate{{CandidateID: "c1", Title: "xss", Severity: "high", Endpoint: "/x"}}
	out := BuildVerifierContinuePrompt(pending, 1, 0, 3, 6)
	assert.Contains(t, out, "substep 3/6")
	assert.Contains(t, out, "Filed 1")
	assert.Contains(t, out, "c1")
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
