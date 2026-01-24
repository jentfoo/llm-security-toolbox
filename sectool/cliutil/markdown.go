package cliutil

import "strings"

// EscapeMarkdown escapes characters that break Markdown table cells.
func EscapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
