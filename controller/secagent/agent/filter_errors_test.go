package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterErrorMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []Message
		want []Message
	}{
		{name: "nil_input"},
		{name: "empty_input", in: []Message{}},
		{
			name: "no_errors_passthrough",
			in: []Message{
				{Role: roleSystem, Content: "sys"},
				{Role: roleUser, Content: "u"},
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "ok result"},
				{Role: roleAssistant, Content: "done"},
			},
			want: []Message{
				{Role: roleSystem, Content: "sys"},
				{Role: roleUser, Content: "u"},
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "ok result"},
				{Role: roleAssistant, Content: "done"},
			},
		},
		{
			name: "drops_paired_error_call",
			in: []Message{
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "ERROR: unknown tool \"x\""},
				{Role: roleAssistant, Content: "moving on"},
			},
			want: []Message{{Role: roleAssistant, Content: "moving on"}},
		},
		{
			name: "keeps_partial_success",
			in: []Message{
				{Role: roleAssistant, Content: "trying both", ToolCalls: []ToolCall{
					{ID: "t1", Function: ToolFunction{Name: "x"}},
					{ID: "t2", Function: ToolFunction{Name: "y"}},
				}},
				{Role: roleTool, ToolCallID: "t1", Content: "ERROR: bad args"},
				{Role: roleTool, ToolCallID: "t2", Content: "good result"},
			},
			want: []Message{
				{Role: roleAssistant, Content: "trying both", ToolCalls: []ToolCall{
					{ID: "t2", Function: ToolFunction{Name: "y"}},
				}},
				{Role: roleTool, ToolCallID: "t2", Content: "good result"},
			},
		},
		{
			name: "keeps_narration_only",
			in: []Message{
				{Role: roleAssistant, Content: "narration", ToolCalls: []ToolCall{
					{ID: "t1", Function: ToolFunction{Name: "x"}},
				}},
				{Role: roleTool, ToolCallID: "t1", Content: "ERROR: nope"},
			},
			want: []Message{{Role: roleAssistant, Content: "narration", ToolCalls: []ToolCall{}}},
		},
		{
			name: "drops_repair_errors",
			in: []Message{
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "your arguments did not parse", IsRepairError: true},
				{Role: roleAssistant, Content: "retry"},
			},
			want: []Message{{Role: roleAssistant, Content: "retry"}},
		},
		{
			name: "preserves_order",
			in: []Message{
				{Role: roleSystem, Content: "sys"},
				{Role: roleUser, Content: "go"},
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "good"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "great"},
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t2", Function: ToolFunction{Name: "bad"}}}},
				{Role: roleTool, ToolCallID: "t2", Content: "ERROR: unknown"},
				{Role: roleAssistant, Content: "summary"},
			},
			want: []Message{
				{Role: roleSystem, Content: "sys"},
				{Role: roleUser, Content: "go"},
				{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "good"}}}},
				{Role: roleTool, ToolCallID: "t1", Content: "great"},
				{Role: roleAssistant, Content: "summary"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := FilterErrorMessages(tc.in)
			if tc.want == nil {
				assert.Empty(t, out)
				return
			}
			assert.Equal(t, tc.want, out)
		})
	}
}

func TestHasSubstantiveMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []Message
		want bool
	}{
		{name: "empty"},
		{name: "system_only", in: []Message{
			{Role: roleSystem, Content: "sys"},
		}},
		{name: "system_and_user", in: []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "u"},
		}},
		{name: "assistant_text", in: []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "u"},
			{Role: roleAssistant, Content: "did a thing"},
		}, want: true},
		{name: "assistant_tool_calls", in: []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
		}, want: true},
		{name: "whitespace_only", in: []Message{
			{Role: roleAssistant, Content: "   \n\t"},
		}},
		{name: "tool_result_present", in: []Message{
			{Role: roleTool, ToolCallID: "t1", Content: "result"},
		}, want: true},
		{name: "empty_tool_calls_slice", in: []Message{
			{Role: roleAssistant, Content: "", ToolCalls: []ToolCall{}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasSubstantiveMessages(tc.in))
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

	t.Run("parallel_strict_semantics", func(t *testing.T) {
		// Assistant calls X and Y in parallel; both error. Next turn errors X
		// again. The "next tool result" after t1 is t2 (different tool name)
		// so t1 is NOT collapsed even though a later same-tool error exists.
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

	t.Run("collapses_repair_errors", func(t *testing.T) {
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

	t.Run("collapses_within_parallel", func(t *testing.T) {
		// Single assistant turn calls tool X twice in parallel; both error.
		// First result's "next" finds the second (same tool, error) → collapse.
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

	t.Run("trailing_error_kept", func(t *testing.T) {
		// Final error result with no later tool result must NOT be collapsed.
		in := []Message{
			{Role: roleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: roleTool, ToolCallID: "t1", ToolName: "x", Content: "ERROR: trailing"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})
}
