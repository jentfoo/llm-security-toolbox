package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterErrorMessages(t *testing.T) {
	t.Parallel()

	t.Run("empty_input", func(t *testing.T) {
		assert.Empty(t, FilterErrorMessages(nil))
		assert.Empty(t, FilterErrorMessages([]Message{}))
	})

	t.Run("no_errors_passthrough", func(t *testing.T) {
		in := []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "u"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
			{Role: roleTool, ToolCallID: "t1", Content: "ok result"},
			{Role: roleAssistant, Content: "done"},
		}
		out := FilterErrorMessages(in)
		assert.Equal(t, in, out)
	})

	t.Run("drops_error_tool_result_and_paired_tool_call", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
			{Role: roleTool, ToolCallID: "t1", Content: "ERROR: unknown tool \"x\""},
			{Role: roleAssistant, Content: "moving on"},
		}
		out := FilterErrorMessages(in)
		require.Len(t, out, 1)
		assert.Equal(t, "moving on", out[0].Content)
	})

	t.Run("keeps_assistant_when_some_tool_calls_succeed", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, Content: "trying both", ToolCalls: []ToolCall{
				{ID: "t1", Function: ToolFunction{Name: "x"}},
				{ID: "t2", Function: ToolFunction{Name: "y"}},
			}},
			{Role: roleTool, ToolCallID: "t1", Content: "ERROR: bad args"},
			{Role: roleTool, ToolCallID: "t2", Content: "good result"},
		}
		out := FilterErrorMessages(in)
		require.Len(t, out, 2)
		require.Len(t, out[0].ToolCalls, 1)
		assert.Equal(t, "t2", out[0].ToolCalls[0].ID)
		assert.Equal(t, "trying both", out[0].Content)
		assert.Equal(t, "good result", out[1].Content)
	})

	t.Run("keeps_assistant_with_content_even_if_all_tool_calls_dropped", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, Content: "narration", ToolCalls: []ToolCall{
				{ID: "t1", Function: ToolFunction{Name: "x"}},
			}},
			{Role: roleTool, ToolCallID: "t1", Content: "ERROR: nope"},
		}
		out := FilterErrorMessages(in)
		require.Len(t, out, 1)
		assert.Equal(t, "narration", out[0].Content)
		assert.Empty(t, out[0].ToolCalls)
	})

	t.Run("drops_repair_error_messages", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
			{Role: roleTool, ToolCallID: "t1", Content: "your arguments did not parse", IsRepairError: true},
			{Role: roleAssistant, Content: "retry"},
		}
		out := FilterErrorMessages(in)
		require.Len(t, out, 1)
		assert.Equal(t, "retry", out[0].Content)
	})

	t.Run("preserves_order", func(t *testing.T) {
		in := []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "go"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "good"}}}},
			{Role: roleTool, ToolCallID: "t1", Content: "great"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2", Function: ToolFunction{Name: "bad"}}}},
			{Role: roleTool, ToolCallID: "t2", Content: "ERROR: unknown"},
			{Role: roleAssistant, Content: "summary"},
		}
		out := FilterErrorMessages(in)
		require.Len(t, out, 5)
		assert.Equal(t, roleSystem, out[0].Role)
		assert.Equal(t, roleUser, out[1].Role)
		assert.Equal(t, "t1", out[2].ToolCalls[0].ID)
		assert.Equal(t, "great", out[3].Content)
		assert.Equal(t, "summary", out[4].Content)
	})
}

func TestHasSubstantiveMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []Message
		want bool
	}{
		{"empty", nil, false},
		{"system_only", []Message{
			{Role: roleSystem, Content: "sys"},
		}, false},
		{"system_and_user_only", []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "u"},
		}, false},
		{"assistant_with_text", []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "u"},
			{Role: roleAssistant, Content: "did a thing"},
		}, true},
		{"assistant_with_tool_calls", []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
		}, true},
		{"assistant_with_only_whitespace_content", []Message{
			{Role: roleAssistant, Content: "   \n\t"},
		}, false},
		{"tool_result_present", []Message{
			{Role: roleTool, ToolCallID: "t1", Content: "result"},
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, HasSubstantiveMessages(c.in))
		})
	}
}

func TestCollapseSameToolErrorStreaks(t *testing.T) {
	t.Parallel()

	t.Run("no_errors_unchanged", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ok"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, in, out)
		assert.Zero(t, dropped)
	})

	t.Run("collapses_streak_of_three", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "replay_send", Content: "ERROR: bad form"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: roleTool, ToolCallID: "t2", ToolName: "replay_send", Content: "ERROR: bad form again"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: roleTool, ToolCallID: "t3", ToolName: "replay_send", Content: "ERROR: still bad"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, 2, dropped)
		require.Len(t, out, 2)
		assert.Equal(t, "t3", out[0].ToolCalls[0].ID)
		assert.Equal(t, "ERROR: still bad", out[1].Content)
	})

	t.Run("different_tool_breaks_streak", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ERROR: a"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: roleTool, ToolCallID: "t2", ToolName: "y", Content: "ERROR: b"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: roleTool, ToolCallID: "t3", ToolName: "x", Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("success_breaks_streak", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ERROR: a"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: roleTool, ToolCallID: "t2", ToolName: "x", Content: "good"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: roleTool, ToolCallID: "t3", ToolName: "x", Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("parallel_calls_strict_semantics", func(t *testing.T) {
		// Assistant calls X and Y in parallel; X errors, Y errors. Next
		// turn calls X again and X errors. The "next tool result" after
		// t1 is t2 (different tool name) — so t1 is NOT collapsed even
		// though a later same-tool error exists.
		in := []Message{
			{Role: roleAssistant, Content: "parallel", ToolCalls: []ToolCall{
				{ID: "t1"}, {ID: "t2"},
			}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ERROR: a"},
			{Role: roleTool, ToolCallID: "t2", ToolName: "y", Content: "ERROR: b"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: roleTool, ToolCallID: "t3", ToolName: "x", Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("collapses_repair_error_streak", func(t *testing.T) {
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", IsRepairError: true, Content: "your arguments did not parse"},
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: roleTool, ToolCallID: "t2", ToolName: "x", IsRepairError: true, Content: "your arguments did not parse v2"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, 1, dropped)
		require.Len(t, out, 2)
		assert.Equal(t, "t2", out[0].ToolCalls[0].ID)
	})

	t.Run("collapses_within_parallel_assistant", func(t *testing.T) {
		// Single assistant turn calls tool X twice in parallel; both
		// error. The second result's "next tool result" check finds
		// nothing later; the first result's check finds the second
		// (same tool, error) — so the first is collapsed and t1 is
		// stripped from the assistant.
		in := []Message{
			{Role: roleAssistant, Content: "parallel x", ToolCalls: []ToolCall{
				{ID: "t1"}, {ID: "t2"},
			}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ERROR: a"},
			{Role: roleTool, ToolCallID: "t2", ToolName: "x", Content: "ERROR: b"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, 1, dropped)
		require.Len(t, out, 2)
		require.Len(t, out[0].ToolCalls, 1)
		assert.Equal(t, "t2", out[0].ToolCalls[0].ID)
		assert.Equal(t, "parallel x", out[0].Content)
		assert.Equal(t, "ERROR: b", out[1].Content)
	})
}
