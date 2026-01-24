package cliutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeMarkdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no_special_chars",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "pipe_escaped",
			input:    "a|b|c",
			expected: `a\|b\|c`,
		},
		{
			name:     "newline_to_space",
			input:    "line1\nline2",
			expected: "line1 line2",
		},
		{
			name:     "carriage_return_removed",
			input:    "line1\r\nline2",
			expected: "line1 line2",
		},
		{
			name:     "combined",
			input:    "col1|col2\nrow1|row2\r\n",
			expected: `col1\|col2 row1\|row2 `,
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := EscapeMarkdown(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
