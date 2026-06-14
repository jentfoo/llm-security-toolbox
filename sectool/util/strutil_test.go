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
		{"long", "/very/long/path/that/exceeds/the/maximum/length", 20, "/very/long/path/t..."},
		{"maxlen_too_small", "abcdef", 2, "abcdef"},
		{"exact_suffix_len", "abcdef", 3, "..."},
		// "é" is two bytes; truncation must land on a rune boundary, not split it.
		{"multibyte_split_point", "ééééééé", 8, "éé..."},
		{"multibyte_odd_max", "ééééééé", 9, "ééé..."},
		{"emoji", "😀😀😀😀😀", 10, "😀..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateString(tt.path, tt.maxLen)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got))
		})
	}
}
