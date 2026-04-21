package agent

import (
	"strings"
	"sync"
)

// Message is one entry in an agent's history.
type Message struct {
	Role       string     // system | user | assistant | tool
	Content    string     // for assistant+tool_calls this may be empty
	ToolCalls  []ToolCall // assistant only
	ToolCallID string     // tool only, pairs with assistant.tool_calls[i].ID
	ToolName   string     // tool only, populated at append for compaction stubs
	Summary120 string     // tool only, first 120 chars of raw content at append
}

// History is a goroutine-safe message log for one agent.
type History struct {
	mu       sync.Mutex
	messages []Message
	// token accounting
	lastPromptTokens int
	baselineMsgCount int // messages length when lastPromptTokens was recorded
	maxContext       int
}

// NewHistory builds an empty History with a context ceiling.
func NewHistory(maxContext int) *History {
	if maxContext <= 0 {
		maxContext = 32768
	}
	return &History{maxContext: maxContext}
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
// EstimateTokens can add growth since.
func (h *History) SetPromptTokens(n int) {
	h.mu.Lock()
	h.lastPromptTokens = n
	h.baselineMsgCount = len(h.messages)
	h.mu.Unlock()
}

// MaxContext returns the configured ceiling.
func (h *History) MaxContext() int {
	return h.maxContext
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

func (h *History) estimateRangeLocked(start, end int) int {
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
