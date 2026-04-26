package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestSummarizeWorkerFromChronicle_HappyPath(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "I tested /admin; flow xY9z; currently waiting on next directive."}
	s := &Summarizer{Pool: poolOf(client), Model: "orch-model", Timeout: time.Second}
	out, err := s.SummarizeWorkerFromChronicle(context.Background(),
		[]agent.Message{
			{Role: "user", Content: "iter1 directive: probe /admin"},
			{Role: "assistant", Content: "ack"},
			{Role: "tool", ToolName: "proxy_poll", Content: "5 flows"},
		},
		"target the SaaS app at https://example.com",
		3,
	)
	require.NoError(t, err)
	assert.Contains(t, out, "I tested /admin")
	require.Len(t, client.requests, 1)
	req := client.requests[0]
	require.Len(t, req.Messages, 2)
	assert.Equal(t, "system", req.Messages[0].Role)
	assert.Contains(t, req.Messages[0].Content, "first-person",
		"system prompt enforces first-person voice")
	user := req.Messages[1].Content
	assert.Contains(t, user, "target the SaaS app at https://example.com",
		"mission included so summarizer knows what to elevate")
	assert.Contains(t, user, "worker 3",
		"worker id rendered into the prompt")
	assert.Contains(t, user, "proxy_poll",
		"tool name from chronicle rendered into the transcript")
	assert.Contains(t, user, "5 flows",
		"tool result content rendered for byte-level texture")
	assert.Equal(t, "orch-model", req.Model)
	assert.Equal(t, agent.CompressionReasoningEffort, req.ReasoningEffort)
}

func TestSummarizeWorkerFromChronicle_StripsThink(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "<think>internal</think>The actual recap"}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	out, err := s.SummarizeWorkerFromChronicle(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}}, "mission", 1)
	require.NoError(t, err)
	assert.Equal(t, "The actual recap", out)
}

func TestSummarizeWorkerFromChronicle_PropagatesError(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{err: errors.New("downstream timeout")}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeWorkerFromChronicle(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}}, "mission", 1)
	require.Error(t, err)
}

func TestSummarizeWorkerFromChronicle_RejectsEmptyOutput(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "   "}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeWorkerFromChronicle(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}}, "mission", 1)
	require.Error(t, err)
}

func TestSummarizeWorkerFromChronicle_NotConfigured(t *testing.T) {
	t.Parallel()
	var s *Summarizer
	_, err := s.SummarizeWorkerFromChronicle(context.Background(), nil, "", 1)
	require.Error(t, err)
	s2 := &Summarizer{}
	_, err = s2.SummarizeWorkerFromChronicle(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}}, "", 1)
	require.Error(t, err)
}

func TestSummarizeWorkerFromChronicle_RejectsEmptyChronicle(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "ok"}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeWorkerFromChronicle(context.Background(), nil, "", 1)
	require.Error(t, err)
}

func TestSummarizeDirectorOldest_HappyPath(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "Iteration 1-4 recap"}
	s := &Summarizer{Pool: poolOf(client), Model: "orch-model", Timeout: time.Second}
	out, err := s.SummarizeDirectorOldest(context.Background(),
		[]agent.Message{
			{Role: "user", Content: "iter1 brief: 4 alive workers, candidate c001 pending"},
			{Role: "assistant", Content: "expand worker 1, continue worker 2"},
			{Role: "user", Content: "iter2 brief: c001 verified as finding-01"},
		},
	)
	require.NoError(t, err)
	assert.Equal(t, "Iteration 1-4 recap", out)
	require.Len(t, client.requests, 1)
	req := client.requests[0]
	require.Len(t, req.Messages, 2)
	assert.Contains(t, req.Messages[0].Content, "third-person",
		"director-oldest system prompt enforces third-person voice")
	assert.NotContains(t, req.Messages[1].Content, "first-person",
		"no first-person framing in director input")
	assert.Contains(t, req.Messages[1].Content, "c001",
		"director input preserves candidate id")
	assert.Equal(t, "orch-model", req.Model)
}

func TestSummarizeDirectorOldest_NoDirectiveSection(t *testing.T) {
	t.Parallel()
	// Director-oldest must NOT carry a section that injects an upcoming
	// directive or current goal — the summary serves all future planning
	// uncertainly, so it must preserve everything load-bearing rather
	// than filter by what the next iter happens to be after.
	client := &scriptedClient{response: "ok"}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeDirectorOldest(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}})
	require.NoError(t, err)
	require.Len(t, client.requests, 1)
	user := client.requests[0].Messages[1].Content
	assert.NotContains(t, user, "## Upcoming directive",
		"director-oldest must not inject a directive section")
	assert.NotContains(t, user, "## Mission",
		"director-oldest must not inject a mission section that would bias the summary")
	assert.NotContains(t, user, "next directive:",
		"director-oldest output is not expected to close with a directive line")
}

func TestRenderSnapshotForSummary(t *testing.T) {
	t.Parallel()
	out := renderSnapshotForSummary([]agent.Message{
		{Role: "user", Content: "directive text"},
		{Role: "assistant", Content: "thinking out loud", ToolCalls: []agent.ToolCall{
			{Function: agent.ToolFunction{Name: "proxy_poll", Arguments: `{"limit":5}`}},
		}},
		{Role: "tool", ToolName: "proxy_poll", Content: "5 flows seen"},
		{Role: "system", Content: "should be skipped"},
	})
	assert.Contains(t, out, "USER: directive text")
	assert.Contains(t, out, "ASSISTANT: thinking out loud")
	assert.Contains(t, out, "call 1: proxy_poll(")
	assert.Contains(t, out, "TOOL [proxy_poll]: 5 flows seen")
	assert.NotContains(t, out, "should be skipped",
		"system messages must NOT appear in summary input")
}

func TestRenderSnapshotForSummary_AssistantWithEmptyText(t *testing.T) {
	t.Parallel()
	// Assistant message with tool calls but no prose still renders the
	// tool calls; assistant message with neither renders an "(empty)"
	// marker so the summarizer sees the turn was a no-op.
	out := renderSnapshotForSummary([]agent.Message{
		{Role: "assistant", Content: "", ToolCalls: []agent.ToolCall{
			{Function: agent.ToolFunction{Name: "x"}},
		}},
		{Role: "assistant", Content: ""},
	})
	assert.Contains(t, out, "call 1: x(")
	assert.Contains(t, out, "ASSISTANT: (empty)")
}

func TestSummarizeCompletedWorker_PromptShape(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "the worker tested /admin and confirmed all endpoints return 403."}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	out, err := s.SummarizeCompletedWorker(context.Background(),
		[]agent.Message{
			{Role: "user", Content: "iter1 directive"},
			{Role: "assistant", Content: "ack"},
			{Role: "tool", ToolName: "proxy_poll", Content: "5 flows"},
		},
		"target the SaaS app",
		"exhausted angle",
		7,
	)
	require.NoError(t, err)
	assert.Equal(t, "the worker tested /admin and confirmed all endpoints return 403.", out)
	require.Len(t, client.requests, 1)
	req := client.requests[0]
	require.Len(t, req.Messages, 2)
	system := req.Messages[0].Content
	assert.Contains(t, system, "EXHAUSTIVE on the process",
		"system prompt instructs exhaustive detail (no aggressive truncation)")
	assert.Contains(t, system, "rendered as a bullet body inside another prompt",
		"system prompt warns about heading/fence usage")
	user := req.Messages[1].Content
	assert.Contains(t, user, "worker_id=7", "worker id rendered into the prompt")
	assert.Contains(t, user, "exhausted angle", "retirement reason included")
	assert.Contains(t, user, "the worker", "third-person framing in user prompt")
	assert.Contains(t, user, "Length should be driven by content",
		"user prompt explicitly disclaims length compression")
}

func TestSummarizeCompletedWorker_PropagatesError(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{err: errors.New("downstream timeout")}
	s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeCompletedWorker(context.Background(),
		[]agent.Message{{Role: "user", Content: "x"}}, "mission", "reason", 1)
	require.Error(t, err)
}

func TestSummarizeCompletedWorker_RejectsEmptyTranscript(t *testing.T) {
	t.Parallel()
	s := &Summarizer{Pool: poolOf(&scriptedClient{}), Model: "m", Timeout: time.Second}
	_, err := s.SummarizeCompletedWorker(context.Background(), nil, "mission", "reason", 1)
	require.Error(t, err)
}
