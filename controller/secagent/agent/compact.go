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
	// HardTruncateOnOverflow controls the final fallback. When true (default),
	// drops turns down to a 2-turn window. When false, returns the overflow
	// error (for tests and fail-closed callers).
	HardTruncateOnOverflow bool
	// RecoveryThreshold is the fraction of EffectiveMaxContext that one
	// compaction step must free to skip later, more expensive ones. 0 falls
	// back to defaultRecoveryThreshold.
	RecoveryThreshold float64
}

// TODO: tune defaultRecoveryThreshold once OnCompact telemetry is available.
const defaultRecoveryThreshold = 0.25

// CompactionReport describes what Compact did in one pass.
type CompactionReport struct {
	Before           int
	After            int
	PassesApplied    []string
	StubbedResults   int
	DroppedTurns     int
	Truncated        int
	ThinkStripped    int
	RepairsProtected int // tool-result repair errors skipped from stubbing
	CollapsedErrors  int // redundant same-tool errors dropped
	SelfPrunedCalls  int // tool calls dropped by the self-prune callback
	DistilledResults int // tool results replaced with distilled prose
}

// StripAssistantThink removes inline `<think>...</think>` blocks from m's
// Content. Returns true when Content changed. Non-assistant messages return
// false. Idempotent.
func StripAssistantThink(m *Message) bool {
	if m.Role != roleAssistant {
		return false
	}
	before := m.Content
	after := StripThinkBlocks(before)
	if after == before {
		return false
	}
	m.Content = after
	return true
}

// Markers identifying tool-result content already replaced by a
// compaction step. New replacement formats must be added to IsCompactionStub.
const (
	stubPrefix    = "(compacted: "
	DistillPrefix = "(distilled batch "
)

// IsCompactionStub reports whether content carries any known compaction
// marker.
func IsCompactionStub(content string) bool {
	return strings.HasPrefix(content, stubPrefix) ||
		strings.HasPrefix(content, DistillPrefix)
}

// StubToolResult replaces m's Content with a compact stub and returns true
// when m.Content changed. Skips repair-error messages and content already
// stubbed. Idempotent.
func StubToolResult(m *Message) bool {
	if m.Role != roleTool || m.IsRepairError {
		return false
	}
	if IsCompactionStub(m.Content) {
		return false
	}
	approxTokens := EstimateStringTokens(m.Content)
	stub := fmt.Sprintf(
		"%s%s returned ~%d tokens — %s)",
		stubPrefix, fallback(m.ToolName, "tool"), approxTokens,
		fallback(m.Summary120, truncate(m.Content, 120)),
	)
	if m.Content == stub {
		return false
	}
	m.Content = stub
	return true
}

// applyCompactionDefaults fills zero-value fields with default values.
func applyCompactionDefaults(opt *CompactionOptions) {
	if opt.HighWatermark <= 0 {
		opt.HighWatermark = 0.80
	}
	if opt.LowWatermark <= 0 {
		opt.LowWatermark = 0.40
	}
	if opt.KeepTurns <= 0 {
		opt.KeepTurns = 4
	}
	if opt.RecoveryThreshold <= 0 {
		opt.RecoveryThreshold = defaultRecoveryThreshold
	}
}

// Compact shrinks h in place until tokens <= LowWatermark * max. Returns
// the merged report and an error if still over HighWatermark.
func Compact(h *History, opt CompactionOptions) (CompactionReport, error) {
	applyCompactionDefaults(&opt)
	r0 := CompactErrorsOnly(h, opt)
	r1, err := CompactRemainder(h, opt)
	merged := mergeReports(r0, r1)
	merged.Before = r0.Before
	merged.After = r1.After
	if r1.After == 0 {
		merged.After = r0.After
	}
	return merged, err
}

// CompactErrorsOnly collapses consecutive same-tool error streaks in h in
// place, leaving only the most recent error in each streak. Returns a
// report describing what was done.
func CompactErrorsOnly(h *History, opt CompactionOptions) CompactionReport {
	applyCompactionDefaults(&opt)
	before := h.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	maxCtx := h.EffectiveMaxContext()
	target := int(float64(maxCtx) * opt.LowWatermark)
	if before <= target {
		return report
	}
	msgs := h.Snapshot()
	if collapsed, dropped := collapseSameToolErrorStreaks(msgs); dropped > 0 {
		report.CollapsedErrors = dropped
		report.PassesApplied = append(report.PassesApplied, "error-collapse")
		h.ReplaceAll(collapsed)
	}
	report.After = h.EstimateTokens()
	return report
}

// CompactRemainder runs mechanical fallback compaction on h in place.
// Returns an error if the final estimate is still over HighWatermark.
func CompactRemainder(h *History, opt CompactionOptions) (CompactionReport, error) {
	applyCompactionDefaults(&opt)
	before := h.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	maxCtx := h.EffectiveMaxContext()
	target := int(float64(maxCtx) * opt.LowWatermark)
	high := int(float64(maxCtx) * opt.HighWatermark)
	if before <= target {
		return report, nil
	}

	msgs := h.Snapshot()
	keep := opt.KeepTurns

	// Strip inline `<think>` blocks from oldest assistant messages outside
	// the keep*2 trailing window, breaking early when the estimate drops to
	// target so recent chain-of-thought continuity stays intact.
	thinkCount := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if !StripAssistantThink(&msgs[i]) {
			continue
		}
		thinkCount++
		h.ReplaceAll(msgs)
		if h.EstimateTokens() <= target {
			break
		}
	}
	if thinkCount > 0 {
		report.PassesApplied = append(report.PassesApplied, "think-strip")
		report.ThinkStripped = thinkCount
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Replace oldest tool results with stubs. Repair errors are skipped —
	// they carry schema guidance the worker needs.
	stubbed := 0
	repairsProtected := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != roleTool {
			continue
		}
		if msgs[i].IsRepairError {
			repairsProtected++
			continue
		}
		if StubToolResult(&msgs[i]) {
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
	report.RepairsProtected = repairsProtected
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Truncate older assistant content to its first sentence.
	truncCount := 0
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != roleAssistant {
			continue
		}
		if msgs[i].Content == "" {
			continue
		}
		first := msgs[i].Content
		for j, r := range msgs[i].Content {
			if r == '.' || r == '!' || r == '?' || r == '\n' {
				first = strings.TrimSpace(msgs[i].Content[:j+1])
				break
			}
		}
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

	// Drop oldest full turn triples until under target or nothing left.
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

	// Hard truncate: a single very large tool result can leave history
	// over HighWatermark even after the turn-drop step preserved the
	// keep*2 trailing window. Shrink the keep window to 2 and drop more,
	// still preserving tool-call/tool-result pairing.
	if opt.HardTruncateOnOverflow && h.EstimateTokens() > high {
		hardDropped := 0
		for h.EstimateTokens() > high {
			newMsgs, dropped := dropOldestTurn(msgs, 2)
			if !dropped {
				break
			}
			msgs = newMsgs
			hardDropped++
			h.ReplaceAll(msgs)
		}
		if hardDropped > 0 {
			report.PassesApplied = append(report.PassesApplied, "hard-truncate")
			report.DroppedTurns += hardDropped
		}
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

// mergeReports concatenates PassesApplied and sums counters across a and b.
// Before/After are caller-managed.
func mergeReports(a, b CompactionReport) CompactionReport {
	out := CompactionReport{
		PassesApplied:    append(append([]string{}, a.PassesApplied...), b.PassesApplied...),
		StubbedResults:   a.StubbedResults + b.StubbedResults,
		DroppedTurns:     a.DroppedTurns + b.DroppedTurns,
		Truncated:        a.Truncated + b.Truncated,
		ThinkStripped:    a.ThinkStripped + b.ThinkStripped,
		RepairsProtected: a.RepairsProtected + b.RepairsProtected,
		CollapsedErrors:  a.CollapsedErrors + b.CollapsedErrors,
		SelfPrunedCalls:  a.SelfPrunedCalls + b.SelfPrunedCalls,
		DistilledResults: a.DistilledResults + b.DistilledResults,
	}
	return out
}

// ForceHardTruncate unconditionally drops oldest turns from h until the
// estimated token count is at or below targetTokens or nothing more can be
// dropped. Preserves the system prompt and a trailing window of keep*2
// messages (keep is clamped to a minimum of 2). Returns a report describing
// what was done.
func ForceHardTruncate(h *History, targetTokens, keep int) CompactionReport {
	if keep < 2 {
		keep = 2
	}
	report := CompactionReport{Before: h.EstimateTokens()}
	msgs := h.Snapshot()
	dropped := 0
	for h.EstimateTokens() > targetTokens {
		next, ok := dropOldestTurn(msgs, keep)
		if !ok {
			break
		}
		msgs = next
		dropped++
		h.ReplaceAll(msgs)
	}
	if dropped > 0 {
		report.PassesApplied = append(report.PassesApplied, "force-hard-truncate")
		report.DroppedTurns = dropped
	}
	report.After = h.EstimateTokens()
	return report
}

// dropOldestTurn drops the oldest assistant-with-tool-calls turn (with its
// paired tool results and any trailing assistant text) from msgs. Preserves
// the system prompt and the trailing keep*2 messages. Returns the new slice
// and whether a turn was dropped.
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
		// consume a trailing assistant TEXT (no tool calls of its own) if it
		// immediately follows — it's part of this same turn's final reply.
		// Do NOT swallow the next turn's assistant-with-tool-calls; doing so
		// would orphan its tool results.
		if end < len(msgs) && msgs[end].Role == roleAssistant && len(msgs[end].ToolCalls) == 0 {
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
