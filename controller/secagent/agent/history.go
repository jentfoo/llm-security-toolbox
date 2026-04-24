package agent

import (
	"strings"
	"sync"
)

// Message is one entry in an agent's history.
type Message struct {
	Role    string // system | user | assistant | tool
	Content string // for assistant+tool_calls this may be empty
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
	// calibration is a learned multiplier applied to the char/4 heuristic,
	// smoothed by EMA from observed PromptTokens. Seed at 1.0 preserves the
	// current behavior until a real count gives us something to calibrate
	// against. Bounded to [calibrationMin, calibrationMax] so a single
	// outlier measurement cannot wreck the estimator.
	calibration float64
	// effectiveMax is a sticky-downward ceiling set by callers when the
	// upstream rejects a request as too large. 0 means "use maxContext".
	// Shrinks never grow — a worker that got wedged at 180k stays
	// compacted against that lower ceiling for the rest of its life so it
	// doesn't re-hit the same rejection next turn.
	effectiveMax int
}

// Tunables for the learned token calibration.
const (
	calibrationMin   = 0.5
	calibrationMax   = 3.0
	calibrationAlpha = 0.3 // EMA weight for newest observation
	// effectiveMaxFloor prevents a runaway rejection from shrinking the
	// ceiling to something the agent cannot function inside.
	effectiveMaxFloor = 4096
	// rejectionShrinkRatio scales the estimate-at-rejection down so the
	// new ceiling is meaningfully below the value the model just refused.
	rejectionShrinkRatio = 0.80
)

// NewHistory builds an empty History with a context ceiling.
func NewHistory(maxContext int) *History {
	if maxContext <= 0 {
		maxContext = 32768
	}
	return &History{maxContext: maxContext, calibration: 1.0}
}

// Append adds one message. For tool messages the caller should pre-populate
// ToolName and Summary120.
func (h *History) Append(m Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, m)
}

// SetPromptTokens records the most recent server-reported prompt token count
// along with the message-count baseline that count was measured against, so
// EstimateTokens can add growth since. Also uses the real count to calibrate
// the char/4 estimator against observed behavior — a model whose tokenizer
// emits more tokens per char than English prose (JSON-heavy, non-ASCII) will
// push calibration above 1.0 so future compaction triggers trip at the right
// watermark instead of 30-50% below it.
func (h *History) SetPromptTokens(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > 0 {
		raw := h.rawEstimateRangeLocked(0, len(h.messages))
		if raw > 0 {
			observed := float64(n) / float64(raw)
			prior := h.calibration
			if prior <= 0 {
				prior = 1.0
			}
			next := (1-calibrationAlpha)*prior + calibrationAlpha*observed
			if next < calibrationMin {
				next = calibrationMin
			} else if next > calibrationMax {
				next = calibrationMax
			}
			h.calibration = next
		}
	}
	h.lastPromptTokens = n
	h.baselineMsgCount = len(h.messages)
}

// MaxContext returns the configured ceiling (never adjusted).
func (h *History) MaxContext() int {
	return h.maxContext
}

// EffectiveMaxContext returns the smaller of the configured ceiling and any
// shrinkage learned from context-rejected errors. Use this (not MaxContext)
// for all watermark math so adaptive shrinkage actually takes effect.
func (h *History) EffectiveMaxContext() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.effectiveMax > 0 && h.effectiveMax < h.maxContext {
		return h.effectiveMax
	}
	return h.maxContext
}

// ShrinkEffectiveMaxOnRejection records that the upstream refused a request
// the estimator said was under-ceiling. Uses the estimate at the time of
// rejection as an upper bound on the true ceiling; scales down further so
// the next attempt lands comfortably below the refused size. Sticky: only
// shrinks, never grows. Floors at effectiveMaxFloor so a misleading
// rejection can't cripple the agent outright.
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

// Calibration returns the current learned multiplier. Exposed for tests and
// diagnostics; callers should not mutate it.
func (h *History) Calibration() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calibration
}

// EstimateTokens returns the server-reported prompt count plus a char/4
// estimate of anything appended since that count was recorded. This keeps
// the compaction trigger honest mid-dispatch when large tool results get
// appended between sends. Falls back to a full-history estimate when no
// server count has been seen yet.
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

// estimateRangeLocked returns the calibrated token estimate for the given
// message range. The raw char/4 heuristic under-counts on JSON-heavy and
// non-ASCII payloads; calibration corrects that based on observed real
// counts. Use rawEstimateRangeLocked when computing the calibration ratio
// itself, otherwise the EMA feedback loop self-cancels.
func (h *History) estimateRangeLocked(start, end int) int {
	raw := h.rawEstimateRangeLocked(start, end)
	cal := h.calibration
	if cal <= 0 {
		cal = 1.0
	}
	return int(float64(raw) * cal)
}

// rawEstimateRangeLocked is the uncalibrated char/4 estimate.
func (h *History) rawEstimateRangeLocked(start, end int) int {
	if start < 0 {
		start = 0
	}
	if end > len(h.messages) {
		end = len(h.messages)
	}
	total := 0
	for i := start; i < end; i++ {
		m := h.messages[i]
		total += len(m.Content) / 4
		for _, tc := range m.ToolCalls {
			total += (len(tc.Function.Name) + len(tc.Function.Arguments)) / 4
		}
		total += 4 // per-message overhead
	}
	return total
}

// Snapshot returns a shallow copy of the message list, safe for sending.
func (h *History) Snapshot() []Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Message, len(h.messages))
	copy(out, h.messages)
	return out
}

// ReplaceAll swaps the entire message slice under lock. Resets the token
// baseline so EstimateTokens re-measures against the new shape on the next
// send rather than adding growth against a now-invalid prior count.
func (h *History) ReplaceAll(msgs []Message) {
	h.mu.Lock()
	h.messages = msgs
	h.lastPromptTokens = 0
	h.baselineMsgCount = 0
	h.mu.Unlock()
}

// Len returns message count.
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.messages)
}

// Summarize120 returns the first 120 chars of s with an ellipsis on overflow.
func Summarize120(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 120 {
		return s
	}
	return s[:119] + "…"
}
