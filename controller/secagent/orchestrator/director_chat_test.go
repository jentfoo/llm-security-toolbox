package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestDirectorChatAppend(t *testing.T) {
	t.Parallel()

	c := NewDirectorChat()
	c.Append(agent.Message{Role: "user", Content: "mission anchor"}, 0, 1)
	c.AppendWorkerActivity(3, 1, []agent.Message{
		{Role: "assistant", Content: "<think>plotting</think>I will probe /admin"},
		{Role: "tool", ToolName: "proxy_poll", Content: "5 flows"},
	})
	require.Len(t, c.Messages, 3)
	require.Len(t, c.Meta, 3)
	assert.Equal(t, 0, c.Meta[0].WorkerID)
	assert.Equal(t, 3, c.Meta[1].WorkerID)
	assert.Equal(t, 3, c.Meta[2].WorkerID)
	assert.Equal(t, 1, c.Meta[1].Iter)
}

func TestDirectorChatRenderForWorker(t *testing.T) {
	t.Parallel()

	t.Run("only_current_raw", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: "mission anchor"}, 0, 1)
		c.AppendWorkerActivity(3, 1, []agent.Message{
			{Role: "assistant", Content: "<think>plot 3</think>worker 3 reasoning"},
			{Role: "tool", ToolName: "proxy_poll", Content: "long worker-3 result"},
		})
		c.AppendWorkerActivity(5, 1, []agent.Message{
			{Role: "assistant", Content: "<think>plot 5</think>worker 5 reasoning"},
			{Role: "tool", ToolName: "replay_send", Content: "long worker-5 result"},
		})
		view := c.RenderForWorker(3)
		require.Len(t, view, 5)
		assert.Equal(t, "mission anchor", view[0].Content)
		assert.Contains(t, view[1].Content, "<think>plot 3</think>")
		assert.Equal(t, "long worker-3 result", view[2].Content)
		assert.NotContains(t, view[3].Content, "<think>plot 5</think>")
		assert.Contains(t, view[3].Content, "worker 5 reasoning")
		assert.Contains(t, view[4].Content, "compacted:")
	})

	t.Run("does_not_mutate_canonical", func(t *testing.T) {
		c := NewDirectorChat()
		c.AppendWorkerActivity(3, 1, []agent.Message{
			{Role: "assistant", Content: "<think>plot 3</think>raw text"},
			{Role: "tool", ToolName: "t", Content: "raw long result"},
		})
		_ = c.RenderForWorker(99)
		assert.Equal(t, "<think>plot 3</think>raw text", c.Messages[0].Content)
		assert.Equal(t, "raw long result", c.Messages[1].Content)
	})
}

func TestDirectorChatRenderForSynthesis(t *testing.T) {
	t.Parallel()

	c := NewDirectorChat()
	c.Append(agent.Message{Role: "user", Content: "mission anchor"}, 0, 1)
	c.AppendWorkerActivity(3, 1, []agent.Message{
		{Role: "assistant", Content: "<think>plot 3</think>w3"},
		{Role: "tool", ToolName: "t3", Content: "result3"},
	})
	c.AppendWorkerActivity(5, 1, []agent.Message{
		{Role: "assistant", Content: "<think>plot 5</think>w5"},
		{Role: "tool", ToolName: "t5", Content: "result5"},
	})
	view := c.RenderForSynthesis()
	assert.Equal(t, "mission anchor", view[0].Content)
	assert.NotContains(t, view[1].Content, "<think>")
	assert.NotContains(t, view[3].Content, "<think>")
	assert.Contains(t, view[2].Content, "compacted:")
	assert.Contains(t, view[4].Content, "compacted:")
}

func TestNormalizeEmptyContent(t *testing.T) {
	t.Parallel()

	t.Run("rewrites_empty_tool_user_system", func(t *testing.T) {
		msgs := []agent.Message{
			{Role: "user", Content: ""},
			{Role: "system", Content: ""},
			{Role: "tool", Content: "", ToolName: "proxy_poll"},
		}
		NormalizeEmptyContent(msgs)
		assert.Equal(t, "(no content)", msgs[0].Content)
		assert.Equal(t, "(no content)", msgs[1].Content)
		assert.Equal(t, "(tool returned no output)", msgs[2].Content)
	})

	t.Run("preserves_non_empty_content", func(t *testing.T) {
		msgs := []agent.Message{
			{Role: "user", Content: "hi"},
			{Role: "tool", Content: "{\"flows\":3}"},
		}
		NormalizeEmptyContent(msgs)
		assert.Equal(t, "hi", msgs[0].Content)
		assert.Equal(t, "{\"flows\":3}", msgs[1].Content)
	})

	t.Run("leaves_assistant_alone", func(t *testing.T) {
		msgs := []agent.Message{
			{Role: "assistant", Content: "", ToolCalls: []agent.ToolCall{{ID: "c1"}}},
		}
		NormalizeEmptyContent(msgs)
		assert.Empty(t, msgs[0].Content)
	})
}

func TestRenderNormalizesEmptyContent(t *testing.T) {
	t.Parallel()

	t.Run("render_for_worker_normalizes", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: ""}, 0, 1)
		c.AppendWorkerActivity(3, 1, []agent.Message{
			{Role: "tool", ToolName: "proxy_poll", Content: ""},
		})
		view := c.RenderForWorker(3)
		require.Len(t, view, 2)
		assert.NotEmpty(t, view[0].Content)
		assert.NotEmpty(t, view[1].Content)
		// Canonical record stays unchanged.
		assert.Empty(t, c.Messages[0].Content)
	})

	t.Run("render_for_synthesis_normalizes", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: ""}, 0, 1)
		view := c.RenderForSynthesis()
		require.Len(t, view, 1)
		assert.NotEmpty(t, view[0].Content)
	})
}

func TestDirectorChatReplaceWorkerWithSummary(t *testing.T) {
	t.Parallel()

	t.Run("position_preserved", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: "mission"}, 0, 1)
		c.AppendWorkerActivity(3, 1, []agent.Message{
			{Role: "assistant", Content: "w3 turn 1"},
			{Role: "tool", Content: "result1"},
		})
		c.AppendWorkerActivity(5, 1, []agent.Message{
			{Role: "assistant", Content: "w5 turn 1"},
		})
		c.AppendWorkerActivity(3, 2, []agent.Message{
			{Role: "assistant", Content: "w3 turn 2"},
		})
		require.Len(t, c.Messages, 5)

		c.ReplaceWorkerWithSummary(3, "worker 3 retire summary", 3)

		require.Len(t, c.Messages, 3)
		assert.Equal(t, "mission", c.Messages[0].Content)
		assert.Equal(t, "worker 3 retire summary", c.Messages[1].Content)
		assert.Equal(t, 0, c.Meta[1].WorkerID)
		assert.Equal(t, 3, c.Meta[1].Iter)
		assert.Equal(t, "w5 turn 1", c.Messages[2].Content)
	})

	t.Run("no_match_is_noop", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: "mission"}, 0, 1)
		c.AppendWorkerActivity(5, 1, []agent.Message{{Role: "assistant", Content: "w5"}})
		c.ReplaceWorkerWithSummary(99, "ghost", 2)
		require.Len(t, c.Messages, 2)
		assert.Equal(t, "mission", c.Messages[0].Content)
		assert.Equal(t, "w5", c.Messages[1].Content)
	})

	t.Run("rejects_zero_id", func(t *testing.T) {
		c := NewDirectorChat()
		c.Append(agent.Message{Role: "user", Content: "mission"}, 0, 1)
		pre := len(c.Messages)
		c.ReplaceWorkerWithSummary(0, "would-be-summary", 2)
		assert.Len(t, c.Messages, pre)
	})
}
