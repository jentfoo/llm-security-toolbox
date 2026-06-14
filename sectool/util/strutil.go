package util

import "unicode/utf8"

// TruncateString ensures the returned string is at most maxLen bytes,
// truncating on a rune boundary and adding a "..." suffix if necessary.
func TruncateString(str string, maxLen int) string {
	if len(str) <= maxLen || maxLen < 3 {
		return str
	}
	cut := maxLen - 3
	for cut > 0 && !utf8.RuneStart(str[cut]) {
		cut--
	}
	return str[:cut] + "..."
}
