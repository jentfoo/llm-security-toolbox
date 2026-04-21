package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateResult(t *testing.T) {
	t.Parallel()
	t.Run("under_cap_unchanged", func(t *testing.T) {
		out := TruncateResult("small", 100)
		assert.Equal(t, "small", out)
	})
	t.Run("over_cap_with_notice", func(t *testing.T) {
		in := strings.Repeat("x", 1000)
		out := TruncateResult(in, 100)
		assert.True(t, strings.HasPrefix(out, strings.Repeat("x", 100)))
		assert.Contains(t, out, "truncated")
		assert.Contains(t, out, "100 of 1000 bytes shown")
		assert.Contains(t, out, "Reduce scope")
	})
}
