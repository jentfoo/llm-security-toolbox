package agent

import (
	"fmt"
	"strconv"
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

	t.Run("think_strip_early_breaks_at_target", func(t *testing.T) {
		// Small overflow: Pass 1 should stop stripping as soon as estimate hits target.
		think := "<think>" + strings.Repeat("r", 2_000) + "</think>"
		h := NewHistory(4096)
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 6; i++ {
			h.Append(Message{
				Role: "assistant", Content: think + "answer",
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: "tool", ToolCallID: "t", ToolName: "t",
				Content: "ok", Summary120: "ok",
			})
		}
		report, err := Compact(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 2,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "think-strip")
		assert.Positive(t, report.ThinkStripped)
		// 6 assistants total minus the keep*2 trailing window (last 2 assistants) = 4 eligible.
		assert.Less(t, report.ThinkStripped, 4)
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

// buildErrorStreakHistory seeds n consecutive same-tool error tool-results
// after a single assistant tool_calls message. Drives CompactErrorsOnly's
// streak-collapse path.
func buildErrorStreakHistory(maxCtx int, n int) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: "system", Content: "sys"})
	calls := make([]ToolCall, n)
	for i := range calls {
		calls[i] = ToolCall{
			ID:       fmt.Sprintf("err%d", i),
			Function: ToolFunction{Name: "flaky", Arguments: "{}"},
		}
	}
	h.Append(Message{
		Role:      "assistant",
		Content:   "calling flaky " + strconv.Itoa(n) + " times",
		ToolCalls: calls,
	})
	for i := 0; i < n; i++ {
		h.Append(Message{
			Role:       "tool",
			ToolCallID: fmt.Sprintf("err%d", i),
			ToolName:   "flaky",
			Content:    "ERROR: same failure mode " + strconv.Itoa(i) + " " + strings.Repeat("x", 1000),
			Summary120: "ERROR: same failure mode",
		})
	}
	h.Append(Message{Role: "user", Content: "continue"})
	h.Append(Message{Role: "assistant", Content: "ok"})
	return h
}

func TestCompactErrorsOnly(t *testing.T) {
	t.Parallel()
	t.Run("collapses_same_tool_streak", func(t *testing.T) {
		h := buildErrorStreakHistory(4096, 5)
		report := CompactErrorsOnly(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		assert.Contains(t, report.PassesApplied, "error-collapse")
		assert.Positive(t, report.CollapsedErrors)
		assert.Less(t, report.After, report.Before)
		// Should NOT run any pass other than error-collapse.
		assert.NotContains(t, report.PassesApplied, "tool-stub")
		assert.NotContains(t, report.PassesApplied, "think-strip")
	})

	t.Run("under_target_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		h.Append(Message{Role: "user", Content: "hi"})
		report := CompactErrorsOnly(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		})
		assert.Empty(t, report.PassesApplied)
		assert.Equal(t, report.Before, report.After)
	})

	t.Run("no_errors_to_collapse_no_op", func(t *testing.T) {
		// Big history but no error streaks → nothing for pass 0 to do.
		big := strings.Repeat("y", 3_000)
		h := buildToolCallHistory(8192, big, 6)
		report := CompactErrorsOnly(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		assert.Empty(t, report.PassesApplied)
		assert.Equal(t, 0, report.CollapsedErrors)
	})
}

func TestCompactRemainder(t *testing.T) {
	t.Parallel()
	t.Run("runs_mechanical_passes", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)
		before := h.EstimateTokens()
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		// Should NOT run error-collapse; that's CompactErrorsOnly's job.
		assert.NotContains(t, report.PassesApplied, "error-collapse")
		assert.Less(t, h.EstimateTokens(), before)
	})

	t.Run("under_target_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: "system", Content: "sys"})
		h.Append(Message{Role: "user", Content: "hi"})
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		})
		require.NoError(t, err)
		assert.Empty(t, report.PassesApplied)
	})
}

func TestCompact_WrapperRunsBothPhases(t *testing.T) {
	t.Parallel()
	// Compact() should still produce the same end result as before — the
	// thin wrapper runs CompactErrorsOnly then CompactRemainder.
	big := strings.Repeat("x", 3_000)
	// Combine an error streak with a fat history so both phases apply.
	h := NewHistory(8192)
	h.Append(Message{Role: "system", Content: "sys"})
	calls := []ToolCall{
		{ID: "e1", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
		{ID: "e2", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
		{ID: "e3", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
	}
	h.Append(Message{Role: "assistant", Content: "fan out", ToolCalls: calls})
	for i, id := range []string{"e1", "e2", "e3"} {
		h.Append(Message{
			Role: "tool", ToolCallID: id, ToolName: "flaky",
			Content: "ERROR: same " + strconv.Itoa(i),
		})
	}
	for i := 0; i < 4; i++ {
		h.Append(Message{
			Role: "assistant", Content: big,
			ToolCalls: []ToolCall{{ID: "t" + strconv.Itoa(i), Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role: "tool", ToolCallID: "t" + strconv.Itoa(i), ToolName: "t",
			Content: big, Summary120: "summary",
		})
	}
	report, err := Compact(h, CompactionOptions{
		HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
	})
	require.NoError(t, err)
	// Wrapper merges reports from both phases.
	assert.Contains(t, report.PassesApplied, "error-collapse")
	assert.Positive(t, report.CollapsedErrors)
}

func TestIsCompactionStub(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"empty", "", false},
		{"plain_prose", "200 OK with body bytes", false},
		{"compacted_stub", "(compacted: tool returned ~123 tokens — summary)", true},
		{"distilled_batch", "(distilled batch 1: worker probed /admin and got 403)", true},
		{"error_text", "ERROR: invalid argument", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsCompactionStub(tc.content))
		})
	}
}

func TestStubToolResult(t *testing.T) {
	t.Parallel()
	t.Run("preserves_distilled_content", func(t *testing.T) {
		original := "(distilled batch 1: worker probed /admin, got 403)"
		m := Message{
			Role:       roleTool,
			ToolCallID: "t1",
			ToolName:   "proxy_poll",
			Content:    original,
		}
		changed := StubToolResult(&m)
		assert.False(t, changed)
		assert.Equal(t, original, m.Content)
	})

	t.Run("preserves_existing_stub", func(t *testing.T) {
		original := "(compacted: proxy_poll returned ~50 tokens — flow ABC)"
		m := Message{Role: roleTool, ToolCallID: "t1", ToolName: "proxy_poll", Content: original}
		changed := StubToolResult(&m)
		assert.False(t, changed)
		assert.Equal(t, original, m.Content)
	})

	t.Run("stubs_fresh_content", func(t *testing.T) {
		m := Message{
			Role: roleTool, ToolCallID: "t1", ToolName: "proxy_poll",
			Content:    strings.Repeat("x", 500),
			Summary120: "summary",
		}
		changed := StubToolResult(&m)
		assert.True(t, changed)
		assert.True(t, strings.HasPrefix(m.Content, stubPrefix))
	})
}
