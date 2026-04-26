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

// buildToolCallHistory seeds n assistant/tool turns of identical bulk payload.
func buildToolCallHistory(maxCtx int, big string, n int) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: "system", Content: "sys"})
	for i := 0; i < n; i++ {
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
	return h
}

// assertToolPairing verifies every tool message traces back to an assistant-with-tool-calls.
func assertToolPairing(t *testing.T, snap []Message) {
	t.Helper()
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

	t.Run("fail_fast_without_hard_truncate", func(t *testing.T) {
		big := strings.Repeat("z", 8_000)
		h := NewHistory(1024)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 3; i++ {
			h.Append(Message{Role: "assistant", Content: big})
			h.Append(Message{Role: "user", Content: big})
		}
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
		// Regression: repair schema hint was stubbed; Pass 2 must preserve IsRepairError.
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
		assert.Positive(t, report.RepairsProtected)

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
	// Watermark math must follow EffectiveMaxContext after a rejection shrink.
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

	// 18k estimate is well under 200k × 0.80 trigger → early-return.
	report, err := Compact(h, CompactionOptions{
		HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
	})
	require.NoError(t, err)
	assert.Empty(t, report.PassesApplied, "no compaction needed at configured ceiling")

	// Shrink effective max to 20k → same history is now above LowWatermark.
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
		h := buildToolCallHistory(8192, big, 8)
		before := h.EstimateTokens()
		report := ForceHardTruncate(h, before/4, 2)

		assert.Contains(t, report.PassesApplied, "force-hard-truncate")
		assert.Less(t, h.EstimateTokens(), before)
		assert.Positive(t, report.DroppedTurns)
		assertToolPairing(t, h.Snapshot())
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
	// KeepTurns=4 trailing window still overflows; hard-truncate must drop further.
	big := strings.Repeat("y", 3_000)
	h := buildToolCallHistory(8192, big, 8)
	report, err := Compact(h, CompactionOptions{
		HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
		HardTruncateOnOverflow: true,
	})
	require.NoError(t, err)
	assert.Contains(t, report.PassesApplied, "hard-truncate")
	assertToolPairing(t, h.Snapshot())
}
