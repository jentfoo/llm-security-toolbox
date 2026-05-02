// Package history provides per-worker chronicle storage and LLM-driven
// transcript compaction (distill, self-prune) and summarization
// (recon, retired-worker recap) used by the orchestrator.
package history

import (
	"strings"
)

// Logger is the minimal sink history needs for structured events.
// orchestrator's *Logger satisfies this structurally.
type Logger interface {
	Log(tag, msg string, fields map[string]any)
}

// Short returns s trimmed and truncated to at most n runes, with an
// ellipsis appended on truncation.
func Short(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return "…"
	}
	return s[:n-1] + "…"
}
