package mcp

import "fmt"

// TruncateResult applies the per-tool-result cap with the instructive notice.
// When s fits under maxBytes (or maxBytes <= 0), s is returned unchanged.
func TruncateResult(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	notice := fmt.Sprintf(
		"\n…(truncated: %d of %d bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)",
		maxBytes, len(s),
	)
	return s[:maxBytes] + notice
}
