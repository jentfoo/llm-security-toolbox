package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestStatusLine(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "**Status:** iteration 2/10, findings filed: 3", statusLine(2, 10, 3))
}

func TestShortAndOrDefault(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "hi", short("hi", 10))
	assert.Equal(t, "a…", short("abcdef", 2))
	assert.Equal(t, "…", short("abcdef", 0))
	assert.Equal(t, "fallback", orDefault("", "fallback"))
	assert.Equal(t, "actual", orDefault("actual", "fallback"))
}

func TestFirstNonEmptyLine(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "first", firstNonEmptyLine("\n  first\nsecond"))
	assert.Equal(t, "only", firstNonEmptyLine("only"))
}

func TestFormatToolCalls(t *testing.T) {
	t.Parallel()
	out := formatToolCalls(nil, 0)
	assert.Contains(t, out, "no tool calls")

	out = formatToolCalls([]agent.ToolCallRecord{
		{Name: "a", InputSummary: `{"x":1}`, ResultSummary: "ok"},
		{Name: "b", InputSummary: "{}", IsError: true},
	}, 20)
	assert.Contains(t, out, "1. a")
	assert.Contains(t, out, "2. b")
	assert.Contains(t, out, "[ERROR]")
	assert.Contains(t, out, "→ ok")

	// Truncation suffix when over limit.
	many := make([]agent.ToolCallRecord, 30)
	for i := range many {
		many[i] = agent.ToolCallRecord{Name: "t"}
	}
	out = formatToolCalls(many, 5)
	assert.Contains(t, out, "and 25 more")
}

func TestFormatAutonomousRun(t *testing.T) {
	t.Parallel()
	// Empty turns shortcut.
	out := formatAutonomousRun(1, nil, "silent")
	assert.Contains(t, out, "No autonomous turns")
	assert.Contains(t, out, "silent")

	// Populated run summarizes tools and flow IDs.
	turns := []agent.TurnSummary{{
		AssistantText: "looking into it\nmore detail",
		ToolCalls:     []agent.ToolCallRecord{{Name: "flow_get"}, {Name: "replay_send"}},
		FlowIDs:       []string{"abc12345"},
	}}
	out = formatAutonomousRun(2, turns, "candidate")
	assert.Contains(t, out, "Worker 2")
	assert.Contains(t, out, "candidate")
	assert.Contains(t, out, "flow_get, replay_send")
	assert.Contains(t, out, "abc12345")
	assert.Contains(t, out, "looking into it")
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
	out := BuildDirectorContinuePrompt(map[int]bool{2: true, 4: true}, 2, 4)
	assert.Contains(t, out, "substep 2/4")
	assert.Contains(t, out, "2, 4")

	out = BuildDirectorContinuePrompt(nil, 3, 4)
	assert.Contains(t, out, "(none)")
}

func TestBuildDirectorSelfReviewPrompt(t *testing.T) {
	t.Parallel()
	out := BuildDirectorSelfReviewPrompt()
	assert.Contains(t, strings.ToLower(out), "self-review")
}

func TestFormatPendingCandidates(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "No pending finding candidates.", formatPendingCandidates(nil))
	out := formatPendingCandidates([]FindingCandidate{{
		CandidateID: "c1", Title: "xss", Severity: "high",
		Endpoint: "/x", WorkerID: 2, FlowIDs: []string{"abc12345"},
	}})
	assert.Contains(t, out, "c1")
	assert.Contains(t, out, "/x")
	assert.Contains(t, out, "abc12345")
}
