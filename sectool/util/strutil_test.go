package util

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestTruncateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		maxLen int
		want   string
	}{
		{"empty", "", 10, ""},
		{"short", "/short", 100, "/short"},
		{"long_ascii", "abcdefghijklmnopqrstuvwxyz", 20, "abcdefghijklmnopq..."},
		{"maxlen_too_small", "abcdef", 2, "abcdef"},
		{"exact_suffix_len", "abcdef", 3, "..."},
		// Truncation must land on a rune boundary, not split it.
		{"multibyte_truncate", "ééééééé", 5, "éé..."},
		{"emoji", "😀😀😀😀😀", 4, "😀..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateString(tt.path, tt.maxLen)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got))
		})
	}
}
