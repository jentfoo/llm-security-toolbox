package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateResult(t *testing.T) {
	t.Parallel()

	t.Run("under_cap_unchanged", func(t *testing.T) {
		assert.Equal(t, "small", TruncateResult("small", 100))
	})

	t.Run("equal_cap_unchanged", func(t *testing.T) {
		assert.Equal(t, "abcde", TruncateResult("abcde", 5))
	})

	t.Run("zero_cap_unchanged", func(t *testing.T) {
		assert.Equal(t, "abcde", TruncateResult("abcde", 0))
	})

	t.Run("over_cap_with_notice", func(t *testing.T) {
		in := strings.Repeat("x", 1000)
		expected := strings.Repeat("x", 100) +
			"\n…(truncated: 100 of 1000 bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)"
		assert.Equal(t, expected, TruncateResult(in, 100))
	})
}
