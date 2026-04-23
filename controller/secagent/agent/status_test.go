package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeStatus_StripsThinkAndReturnsFirstLine(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{
		{Content: "<think>plan</think>Investigating auth; will try replay_send next.\n(second line)"},
	}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	a.Query("earlier user turn")
	before := a.history.Len()

	line, err := SummarizeStatus(t.Context(), a, 40)
	require.NoError(t, err)
	assert.Equal(t, "Investigating auth; will try replay_send next.", line)
	assert.Equal(t, before, a.history.Len(), "status summary must not persist in history")

	require.Len(t, client.calls, 1)
	last := client.calls[0].Messages
	assert.Equal(t, statusSummaryRequest, last[len(last)-1].Content)
	assert.Equal(t, 40, client.calls[0].MaxTokens)
}

func TestSummarizeStatus_ErrorPropagates(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{{}},
		errors:    []error{errors.New("boom")},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	_, err := SummarizeStatus(t.Context(), a, 0)
	require.Error(t, err)
}

func TestSummarizeStatus_ContextCanceledDuringAcquire(t *testing.T) {
	t.Parallel()
	pool := NewClientPool(&fakeChatClient{}, 1)
	held, err := pool.Acquire(t.Context())
	require.NoError(t, err)
	defer pool.Release(held)

	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: pool})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = SummarizeStatus(ctx, a, 0)
	require.Error(t, err)
}

func TestSummarizeStatus_ViaBypassesAgentPool(t *testing.T) {
	t.Parallel()
	// drained agent pool → SummarizeStatusVia routes through the override client
	pool := NewClientPool(&fakeChatClient{}, 1)
	held, err := pool.Acquire(t.Context())
	require.NoError(t, err)
	defer pool.Release(held)

	override := &fakeChatClient{responses: []ChatResponse{{Content: "summary via override"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "agent-model", Pool: pool})
	// Empty model param → fall back to the agent's own model.
	line, tail, err := SummarizeStatusVia(t.Context(), a, override, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "summary via override", line)
	assert.Empty(t, tail)
	require.Len(t, override.calls, 1)
	assert.Equal(t, 20000, override.calls[0].MaxTokens, "default maxTokens should match the reasoning-model budget")
	assert.Empty(t, override.calls[0].Tools, "summary request must not pass tools")
	assert.Equal(t, "none", override.calls[0].ReasoningEffort, "summary requests must disable reasoning")
	assert.Equal(t, "agent-model", override.calls[0].Model, "empty model falls back to agent's own model")
}

func TestSummarizeStatus_ViaModelOverride(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "worker-model-abliterated", Pool: newPoolWith(client)})
	_, _, err := SummarizeStatusVia(t.Context(), a, client, "summary-model", 0)
	require.NoError(t, err)
	require.Len(t, client.calls, 1)
	assert.Equal(t, "summary-model", client.calls[0].Model)
}

func TestSummarizeStatus_ViaReturnsThinkTailOnTruncatedResponse(t *testing.T) {
	t.Parallel()
	// truncation mid-think: no close tag → empty line, tail carries the fragment
	client := &fakeChatClient{responses: []ChatResponse{{
		Content: "<think>I was planning to test the OAuth redirect next",
	}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	line, tail, err := SummarizeStatusVia(t.Context(), a, nil, "", 0)
	require.NoError(t, err)
	assert.Empty(t, line)
	assert.Equal(t, "I was planning to test the OAuth redirect next", tail)
}

func TestSummarizeStatus_RequestOmitsTools(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	a.SetTools([]ToolDef{{Name: "pretend", Description: "x", Schema: map[string]any{"type": "object"}}})
	a.Query("user turn")

	_, err := SummarizeStatus(t.Context(), a, 0)
	require.NoError(t, err)
	require.Len(t, client.calls, 1)
	assert.Empty(t, client.calls[0].Tools, "status request must not pass tools to the model")
}

func TestBuildStatusMessages_DropsToolResultsAndKeepsThink(t *testing.T) {
	t.Parallel()
	hist := []Message{
		{Role: roleSystem, Content: "system prompt"},
		{Role: roleUser, Content: "assignment"},
		{Role: roleAssistant, Content: "<think>planning reproduction</think>running replay",
			ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: ToolFunction{Name: "replay_send", Arguments: "{}"}}}},
		{Role: roleTool, Content: "HTTP/1.1 200 OK\n..." + strings.Repeat("x", 4000), ToolCallID: "c1"},
		{Role: roleAssistant, Content: "<think>next step</think>checking response"},
	}
	msgs := buildStatusMessages(hist, 2000, 2)
	require.GreaterOrEqual(t, len(msgs), 4, "anchor + filtered tail")

	var sawPlaceholder bool
	var toolResultLeaked bool
	var sawThink bool
	for _, m := range msgs {
		if m.Role == roleTool && m.Content == toolResultPlaceholder {
			sawPlaceholder = true
		}
		if m.Role == roleTool && strings.Contains(m.Content, "HTTP/1.1 200 OK") {
			toolResultLeaked = true
		}
		if m.Role == roleAssistant && strings.Contains(m.Content, "<think>") {
			sawThink = true
		}
	}
	assert.True(t, sawPlaceholder)
	assert.False(t, toolResultLeaked)
	assert.True(t, sawThink)

	var foundToolCalls bool
	for _, m := range msgs {
		if m.Role == roleAssistant && len(m.ToolCalls) > 0 && m.ToolCalls[0].Function.Name == "replay_send" {
			foundToolCalls = true
		}
	}
	assert.True(t, foundToolCalls)
}

func TestBuildStatusMessages_TailTruncateRespectsBudget(t *testing.T) {
	t.Parallel()
	hist := []Message{{Role: roleSystem, Content: "sys"}, {Role: roleUser, Content: "do the thing"}}
	// 50 × 500-char assistant messages ≈ 6250 tokens of non-anchor content.
	for i := 0; i < 50; i++ {
		hist = append(hist, Message{Role: roleAssistant, Content: strings.Repeat("x", 500)})
	}
	msgs := buildStatusMessages(hist, 2000, 0)

	total := 0
	for _, m := range msgs {
		total += len(m.Content)/4 + 4
	}
	// Budget applies to the filtered content; a small slack for the anchor
	// count is acceptable. Assert total stays within ~2x so we know
	// truncation actually happened (unbounded would be 6400+).
	assert.LessOrEqual(t, total, 2500, "should have tail-truncated to roughly 2k tokens")

	last := msgs[len(msgs)-1]
	assert.Equal(t, roleAssistant, last.Role)
	assert.Len(t, last.Content, 500)
}

func TestBuildStatusMessages_DropsOrphanLeadingTool(t *testing.T) {
	t.Parallel()
	// truncation would otherwise start on a tool with its assistant parent cut off
	hist := []Message{
		{Role: roleSystem, Content: "sys"},
		{Role: roleUser, Content: "assignment"},
		{Role: roleAssistant, Content: "", ToolCalls: []ToolCall{{ID: "c1", Function: ToolFunction{Name: "t", Arguments: "{}"}}}},
		{Role: roleTool, Content: strings.Repeat("x", 4000), ToolCallID: "c1"},
		{Role: roleAssistant, Content: strings.Repeat("y", 4000)},
	}
	msgs := buildStatusMessages(hist, 200, 0)
	for i, m := range msgs {
		if i == 0 || (i == 1 && m.Role == "user") {
			continue
		}
		assert.NotEqual(t, "tool", m.Role, "post-anchor message %d should not be orphaned tool", i)
		break
	}
}
