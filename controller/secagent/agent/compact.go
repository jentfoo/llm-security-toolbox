package agent

import (
	"fmt"
	"strings"
)

// CompactionOptions controls compaction thresholds.
type CompactionOptions struct {
	HighWatermark float64 // e.g. 0.80
	LowWatermark  float64 // e.g. 0.40
	KeepTurns     int     // e.g. 4
}

// CompactionReport describes what Compact did in one pass.
type CompactionReport struct {
	Before         int
	After          int
	PassesApplied  []string
	StubbedResults int
	DroppedTurns   int
	Truncated      int
	ThinkStripped  int
}

// Compact shrinks history in place until tokens <= LowWatermark * max.
// Returns the report and an error if still over HighWatermark at the end.
func Compact(h *History, opt CompactionOptions) (CompactionReport, error) {
	if opt.HighWatermark <= 0 {
		opt.HighWatermark = 0.80
	}
	if opt.LowWatermark <= 0 {
		opt.LowWatermark = 0.40
	}
	if opt.KeepTurns <= 0 {
		opt.KeepTurns = 4
	}

	before := h.EstimateTokens()
	report := CompactionReport{Before: before}
	maxCtx := h.MaxContext()
	target := int(float64(maxCtx) * opt.LowWatermark)
	high := int(float64(maxCtx) * opt.HighWatermark)

	if before <= target {
		report.After = before
		return report, nil
	}

	msgs := h.Snapshot()
	keep := opt.KeepTurns

	// Pass 1: <think>-strip every message older than last keep turns.
	thinkCount := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != roleAssistant {
			continue
		}
		before := msgs[i].Content
		after := StripThinkBlocks(before)
		if after != before {
			msgs[i].Content = after
			thinkCount++
		}
	}
	if thinkCount > 0 {
		report.PassesApplied = append(report.PassesApplied, "think-strip")
		report.ThinkStripped = thinkCount
	}
	h.ReplaceAll(msgs)
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Pass 2: replace oldest tool results with stubs.
	stubbed := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != roleTool {
			continue
		}
		approxTokens := len(msgs[i].Content) / 4
		stub := fmt.Sprintf(
			"(compacted: %s returned ~%d tokens — %s)",
			fallback(msgs[i].ToolName, "tool"), approxTokens,
			fallback(msgs[i].Summary120, truncate(msgs[i].Content, 120)),
		)
		if msgs[i].Content != stub {
			msgs[i].Content = stub
			stubbed++
			h.ReplaceAll(msgs)
			if h.EstimateTokens() <= target {
				break
			}
		}
	}
	if stubbed > 0 {
		report.PassesApplied = append(report.PassesApplied, "tool-stub")
		report.StubbedResults = stubbed
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Pass 3: truncate older assistant content to first sentence.
	truncCount := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != roleAssistant {
			continue
		}
		if msgs[i].Content == "" {
			continue
		}
		first := firstSentence(msgs[i].Content)
		if first != msgs[i].Content {
			msgs[i].Content = first
			truncCount++
			h.ReplaceAll(msgs)
			if h.EstimateTokens() <= target {
				break
			}
		}
	}
	if truncCount > 0 {
		report.PassesApplied = append(report.PassesApplied, "text-trunc")
		report.Truncated = truncCount
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Pass 4: drop oldest full turn triples until under target or nothing left.
	droppedTurns := 0
	for h.EstimateTokens() > target {
		newMsgs, dropped := dropOldestTurn(msgs, keep)
		if !dropped {
			break
		}
		msgs = newMsgs
		droppedTurns++
		h.ReplaceAll(msgs)
	}
	if droppedTurns > 0 {
		report.PassesApplied = append(report.PassesApplied, "turn-drop")
		report.DroppedTurns = droppedTurns
	}

	after := h.EstimateTokens()
	report.After = after
	if after > high {
		return report, fmt.Errorf(
			"compaction could not reduce context below high watermark: %d > %d",
			after, high,
		)
	}
	return report, nil
}

// dropOldestTurn drops the oldest (assistant-with-tool-calls,
// paired tool results, and the next assistant text) triple from msgs.
// Preserves system prompt and the most recent keep*2 messages.
func dropOldestTurn(msgs []Message, keep int) ([]Message, bool) {
	if keep < 2 {
		keep = 2
	}
	floor := 0
	if len(msgs) > 0 && msgs[0].Role == "system" {
		floor = 1
	}
	ceil := len(msgs) - keep*2
	if ceil <= floor {
		return msgs, false
	}

	for i := floor; i < ceil; i++ {
		if msgs[i].Role != roleAssistant {
			continue
		}
		end := i + 1
		// consume paired tool results
		for end < len(msgs) && msgs[end].Role == roleTool {
			end++
		}
		// consume a trailing assistant text if it immediately follows
		if end < len(msgs) && msgs[end].Role == roleAssistant {
			end++
		}
		if end > ceil {
			return msgs, false
		}
		out := make([]Message, 0, len(msgs)-(end-i))
		out = append(out, msgs[:i]...)
		out = append(out, msgs[end:]...)
		return out, true
	}
	return msgs, false
}

func fallback(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func firstSentence(s string) string {
	for i, r := range s {
		if r == '.' || r == '!' || r == '?' || r == '\n' {
			return strings.TrimSpace(s[:i+1])
		}
	}
	return s
}
