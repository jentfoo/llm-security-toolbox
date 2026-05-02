// Package history provides per-worker chronicle storage and LLM-driven
// transcript compaction (distill, self-prune) and summarization
// (recon, retired-worker recap) used by the orchestrator.
package history

// Logger is a minimal structured-event sink.
type Logger interface {
	Log(tag, msg string, fields map[string]any)
}

func fallbackName(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func fallbackArgs(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
