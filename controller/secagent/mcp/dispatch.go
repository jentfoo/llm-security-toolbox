package mcp

import "fmt"

// TruncateResult caps s at maxBytes, appending a notice that instructs the
// caller to narrow the next call. maxBytes <= 0 disables the cap.
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
