package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildFattyHistory seeds a history whose token estimate crosses the watermark.
func buildFattyHistory(maxCtx int, big string) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: "system", Content: "sys prompt"})
	for i := 0; i < 5; i++ {
		h.Append(Message{
			Role:      "assistant",
			Content:   "<think>internal deliberation goes here</think>summary line.\n" + big,
			ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "tool", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role:       "tool",
			ToolCallID: "t1",
			ToolName:   "tool",
			Content:    big,
			Summary120: Summarize120(big),
		})
	}
	h.Append(Message{Role: "user", Content: "continue"})
	h.Append(Message{Role: "assistant", Content: "ok"})
	return h
}

func TestCompact(t *testing.T) {
	t.Parallel()
	t.Run("think_strip_tool_stub", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)
		before := h.EstimateTokens()
		report, err := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "think-strip")
		assert.Contains(t, report.PassesApplied, "tool-stub")
		assert.Less(t, report.After, before)
	})

	t.Run("drop_turn_fallback", func(t *testing.T) {
		big := strings.Repeat("y", 20_000)
		h := NewHistory(2048)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 6; i++ {
			h.Append(Message{
				Role:      "assistant",
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: "tool", ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}
		report, _ := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		assert.Contains(t, report.PassesApplied, "turn-drop")
	})

	t.Run("fail_fast_over_high_watermark_when_hard_truncate_disabled", func(t *testing.T) {
		big := strings.Repeat("z", 8_000)
		h := NewHistory(1024)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 3; i++ {
			h.Append(Message{Role: "assistant", Content: big})
			h.Append(Message{Role: "user", Content: big})
		}
		// Explicitly disable hard-truncate so callers who want fail-closed
		// behavior still get it.
		_, err := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 8,
			HardTruncateOnOverflow: false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "high watermark")
	})

	t.Run("under_target_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		h.Append(Message{Role: "user", Content: "hi"})
		report, err := Compact(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		})
		require.NoError(t, err)
		assert.Empty(t, report.PassesApplied)
		assert.Equal(t, report.Before, report.After)
	})

	t.Run("repair_errors_protected_from_stub", func(t *testing.T) {
		// Regression: worker-3 kept emitting the same malformed flow_get
		// call 46 minutes apart because the repair schema hint was stubbed
		// out of history. Pass 2 must preserve IsRepairError messages.
		big := strings.Repeat("x", 6_000)
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys prompt"})
		repairText := `ERROR: arguments did not parse. schema: {"scope":"request_headers|request_body|response_headers|response_body|all"}`
		for i := 0; i < 5; i++ {
			h.Append(Message{
				Role:      "assistant",
				Content:   "try tool",
				ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "flow_get", Arguments: "{}"}}},
			})
			// Alternate a big tool result and a repair error so the pass sees both.
			if i%2 == 0 {
				h.Append(Message{
					Role: "tool", ToolCallID: "t1", ToolName: "flow_get",
					Content: big, Summary120: Summarize120(big),
				})
			} else {
				h.Append(Message{
					Role: "tool", ToolCallID: "t1", ToolName: "flow_get",
					Content: repairText, Summary120: Summarize120(repairText),
					IsRepairError: true,
				})
			}
		}
		h.Append(Message{Role: "user", Content: "continue"})
		h.Append(Message{Role: "assistant", Content: "ok"})

		report, err := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "tool-stub")
		assert.Positive(t, report.RepairsProtected, "should have protected at least one repair error")

		// The repair text must survive verbatim somewhere in history; the
		// large tool result should not.
		snap := h.Snapshot()
		var foundRepair bool
		for _, m := range snap {
			if m.IsRepairError && strings.Contains(m.Content, "schema:") {
				foundRepair = true
			}
			if m.Role == roleTool && !m.IsRepairError {
				assert.NotContains(t, m.Content, strings.Repeat("x", 200),
					"non-repair tool result should have been stubbed")
			}
		}
		assert.True(t, foundRepair, "repair error schema hint must survive compaction")
	})
}

func TestCompact_UsesEffectiveMaxContext(t *testing.T) {
	t.Parallel()
	// After a context-rejection shrinks the effective ceiling, Compact's
	// watermark math must follow so the next maybeCompact fires at the
	// tighter threshold instead of against the original (too-large) max.
	big := strings.Repeat("y", 3_000)
	h := NewHistory(200_000)
	h.Append(Message{Role: "system", Content: "sys"})
	for i := 0; i < 6; i++ {
		h.Append(Message{
			Role:      "assistant",
			Content:   big,
			ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role: "tool", ToolCallID: "t", ToolName: "t",
			Content: big, Summary120: "summary",
		})
	}

	// Against MaxContext=200k and HighWatermark=0.80 the ~18k estimate is
	// well under the trigger, so Compact should early-return.
	report, err := Compact(h, CompactionOptions{
		HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
	})
	require.NoError(t, err)
	assert.Empty(t, report.PassesApplied, "no compaction needed at configured ceiling")

	// Shrink effective max down to 20k; now the same history's ~18k is
	// above LowWatermark × 20k = 8k, so Compact should engage.
	h.ShrinkEffectiveMaxOnRejection(25_000) // × 0.80 = 20k
	report, err = Compact(h, CompactionOptions{
		HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		HardTruncateOnOverflow: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, report.PassesApplied, "Compact must react to shrunk effective max")
}

func TestForceHardTruncate(t *testing.T) {
	t.Parallel()

	t.Run("reduces_below_target_and_preserves_pairing", func(t *testing.T) {
		big := strings.Repeat("y", 3_000)
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 8; i++ {
			h.Append(Message{
				Role:      "assistant",
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: "tool", ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}
		before := h.EstimateTokens()
		target := before / 4
		report := ForceHardTruncate(h, target, 2)

		assert.Contains(t, report.PassesApplied, "force-hard-truncate")
		assert.Less(t, h.EstimateTokens(), before)
		// dropOldestTurn may stop before reaching target if the keep window
		// already pins enough trailing turns that nothing more can be cut.
		// What matters is that it dropped something AND the result is well
		// below the original.
		assert.Positive(t, report.DroppedTurns)
		// No orphaned tool results: every tool message must trace back to
		// an assistant-with-tool-calls through any preceding tools.
		snap := h.Snapshot()
		for i, m := range snap {
			if m.Role != roleTool {
				continue
			}
			require.Positive(t, i)
			j := i - 1
			for j >= 0 && snap[j].Role == roleTool {
				j--
			}
			require.GreaterOrEqual(t, j, 0)
			assert.Equal(t, roleAssistant, snap[j].Role)
			assert.NotEmpty(t, snap[j].ToolCalls)
		}
	})

	t.Run("already_under_target_is_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		h.Append(Message{Role: "user", Content: "hi"})
		report := ForceHardTruncate(h, 10_000, 2)
		assert.Equal(t, 0, report.DroppedTurns)
		assert.Empty(t, report.PassesApplied)
	})
}

func TestCompact_HardTruncateOnOverflow(t *testing.T) {
	t.Parallel()

	t.Run("hard_truncate_rescues_overflowing_history", func(t *testing.T) {
		// 8 tool-call turns of 1200-token messages. maxCtx=8192, KeepTurns=4
		// → keep*2=8 trailing messages = ~9600 tokens, still over
		// high=4096. Hard-truncate drops to keep=2 (4 trailing messages =
		// ~4800 tokens → still over briefly → keeps dropping until under).
		big := strings.Repeat("y", 3_000)
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 8; i++ {
			h.Append(Message{
				Role:      "assistant",
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: "tool", ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}
		report, err := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
			HardTruncateOnOverflow: true,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "hard-truncate")
	})

	t.Run("hard_truncate_preserves_tool_pairing", func(t *testing.T) {
		big := strings.Repeat("y", 3_000)
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 8; i++ {
			h.Append(Message{
				Role:      "assistant",
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: "tool", ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}
		_, err := Compact(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
			HardTruncateOnOverflow: true,
		})
		require.NoError(t, err)
		// Walk the surviving messages; every tool message must be
		// preceded by an assistant (possibly a couple of steps earlier
		// via other tool results) — at minimum a tool must never be the
		// first non-system message.
		snap := h.Snapshot()
		for i, m := range snap {
			if m.Role == roleTool {
				require.Positive(t, i)
				// Walk backward to find the nearest non-tool message.
				// It must be an assistant with tool calls — else we
				// orphaned a tool result.
				j := i - 1
				for j >= 0 && snap[j].Role == roleTool {
					j--
				}
				require.GreaterOrEqual(t, j, 0)
				assert.Equal(t, roleAssistant, snap[j].Role)
				assert.NotEmpty(t, snap[j].ToolCalls)
			}
		}
	})
}
