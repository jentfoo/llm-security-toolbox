package agent

import (
	"slices"
	"strings"
	"sync"
)

// Message is one entry in an agent's history.
type Message struct {
	Role    string // system | user | assistant | tool
	Content string // for assistant+tool_calls this may be empty
	// HistoryID is an internal stable identity assigned by History so
	// boundary tracking survives compaction/truncation even when multiple
	// messages have identical role/content.
	HistoryID uint64
	// ReasoningContent holds structured reasoning surfaced via the
	// `reasoning_content` field of the OpenAI-compatible response (deepseek /
	// qwen3-style). Inline-think models leave this empty and carry thinking
	// inside Content as <think>...</think>. Stored verbatim as the model
	// emitted it; replay/summary logic lives in the reasoning handler.
	ReasoningContent string
	ToolCalls        []ToolCall // assistant only
	ToolCallID       string     // tool only, pairs with assistant.tool_calls[i].ID
	ToolName         string     // tool only, populated at append for compaction stubs
	Summary120       string     // tool only, first 120 chars of raw content at append
	// IsRepairError marks a tool-result message carrying the synthetic "your
	// arguments did not parse" feedback from RepairToolArgs failure. These
	// messages are small and high-signal (they include schema guidance) so
	// compaction pass 2 skips them to avoid the model repeating the same
	// malformed call after the fix was compacted away.
	IsRepairError bool
}

// History is a goroutine-safe message log for one agent.
type History struct {
	mu       sync.Mutex
	messages []Message
	// token accounting
	lastPromptTokens int
	baselineMsgCount int // messages length when lastPromptTokens was recorded
	maxContext       int
	// effectiveMax is a sticky-downward ceiling set by callers when the
	// upstream rejects a request as too large. 0 means "use maxContext".
	// Shrinks never grow — a worker that got wedged at 180k stays
	// compacted against that lower ceiling for the rest of its life so it
	// doesn't re-hit the same rejection next turn.
	effectiveMax int
	nextID       uint64
}

const (
	// effectiveMaxFloor prevents a runaway rejection from shrinking the
	// ceiling to something the agent cannot function inside.
	effectiveMaxFloor = 4096
	// rejectionShrinkRatio scales the estimate-at-rejection down so the
	// new ceiling is meaningfully below the value the model just refused.
	rejectionShrinkRatio = 0.80
)

// NewHistory returns an empty History with the given context ceiling.
func NewHistory(maxContext int) *History {
	if maxContext <= 0 {
		maxContext = 32768
	}
	return &History{maxContext: maxContext}
}

// Append adds m to history. Callers should pre-populate ToolName and
// Summary120 on tool messages.
func (h *History) Append(m Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m.HistoryID == 0 {
		h.nextID++
		m.HistoryID = h.nextID
	} else if m.HistoryID > h.nextID {
		h.nextID = m.HistoryID
	}
	h.messages = append(h.messages, m)
}

// SetPromptTokens records the server-reported prompt token count n. Used
// by EstimateTokens as the baseline for future growth and feeds the
// package-level calibration EMA.
func (h *History) SetPromptTokens(n int) {
	h.mu.Lock()
	raw := h.rawEstimateRangeLocked(0, len(h.messages))
	h.lastPromptTokens = n
	h.baselineMsgCount = len(h.messages)
	h.mu.Unlock()
	ObservePromptTokens(n, raw)
}

// MaxContext returns the configured ceiling.
func (h *History) MaxContext() int {
	return h.maxContext
}

// EffectiveMaxContext returns the smaller of the configured ceiling and any
// shrinkage learned from context-rejected errors. Use this for watermark
// math so adaptive shrinkage takes effect.
func (h *History) EffectiveMaxContext() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.effectiveMax > 0 && h.effectiveMax < h.maxContext {
		return h.effectiveMax
	}
	return h.maxContext
}

// ShrinkEffectiveMaxOnRejection lowers the effective context ceiling based
// on estimateAtRejection (the token estimate when upstream refused).
// Sticky: only shrinks, never grows. Floors at effectiveMaxFloor.
func (h *History) ShrinkEffectiveMaxOnRejection(estimateAtRejection int) {
	if estimateAtRejection <= 0 {
		return
	}
	candidate := int(float64(estimateAtRejection) * rejectionShrinkRatio)
	if candidate < effectiveMaxFloor {
		candidate = effectiveMaxFloor
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if candidate >= h.maxContext {
		return
	}
	if h.effectiveMax == 0 || candidate < h.effectiveMax {
		h.effectiveMax = candidate
	}
}

// Calibration returns the current learned multiplier.
func (h *History) Calibration() float64 {
	return Calibration()
}

// EstimateTokens returns the estimated total prompt token count for the
// current history. Uses the last server-reported count as a baseline and
// adds an estimate for messages appended since.
func (h *History) EstimateTokens() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastPromptTokens <= 0 {
		return h.estimateRangeLocked(0, len(h.messages))
	}
	growth := 0
	if h.baselineMsgCount < len(h.messages) {
		growth = h.estimateRangeLocked(h.baselineMsgCount, len(h.messages))
	}
	return h.lastPromptTokens + growth
}

// estimateRangeLocked returns the calibrated token estimate for messages
// in [start, end).
func (h *History) estimateRangeLocked(start, end int) int {
	return int(float64(h.rawEstimateRangeLocked(start, end)) * Calibration())
}

// rawEstimateRangeLocked returns the uncalibrated token estimate for
// messages in [start, end).
func (h *History) rawEstimateRangeLocked(start, end int) int {
	if start < 0 {
		start = 0
	}
	if end > len(h.messages) {
		end = len(h.messages)
	}
	total := 0
	for i := start; i < end; i++ {
		total += rawMessageTokens(h.messages[i])
	}
	return total
}

// Snapshot returns a copy of the message list.
func (h *History) Snapshot() []Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.messages)
}

// ReplaceAll replaces the message slice with msgs and resets the token
// baseline.
func (h *History) ReplaceAll(msgs []Message) {
	h.mu.Lock()
	h.nextID = 0
	for i := range msgs {
		if msgs[i].HistoryID == 0 {
			h.nextID++
			msgs[i].HistoryID = h.nextID
			continue
		}
		if msgs[i].HistoryID > h.nextID {
			h.nextID = msgs[i].HistoryID
		}
	}
	h.messages = msgs
	h.lastPromptTokens = 0
	h.baselineMsgCount = 0
	h.mu.Unlock()
}

// Len returns the current message count.
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.messages)
}

// Summarize120 returns the first 120 chars of s, with an ellipsis on
// overflow.
func Summarize120(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 120 {
		return s
	}
	return s[:119] + "…"
}
