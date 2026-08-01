package util

import "unicode/utf8"

// TruncateString ensures the returned string is at most maxLen runes,
// truncating on a rune boundary and adding a "..." suffix if necessary.
func TruncateString(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen || maxLen < 3 {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}
