package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// withColors sets useColor for the test and restores it on cleanup.
func withColors(t *testing.T, on bool) {
	t.Helper()
	prev := useColor
	useColor = on
	t.Cleanup(func() { useColor = prev })
}

func TestStyleWrap(t *testing.T) {
	t.Run("disabled_returns_plain", func(t *testing.T) {
		withColors(t, false)
		assert.Equal(t, "hello", styleWrap(ansiRed, "hello"))
	})
	t.Run("enabled_wraps_with_reset", func(t *testing.T) {
		withColors(t, true)
		assert.Equal(t, ansiRed+"hello"+ansiReset, styleWrap(ansiRed, "hello"))
	})
}

func TestStyleAppend(t *testing.T) {
	t.Run("disabled_writes_plain", func(t *testing.T) {
		withColors(t, false)
		var b strings.Builder
		styleAppend(&b, ansiBlue, "tag")
		assert.Equal(t, "tag", b.String())
	})
	t.Run("enabled_writes_escaped", func(t *testing.T) {
		withColors(t, true)
		var b strings.Builder
		styleAppend(&b, ansiBlue, "tag")
		assert.Equal(t, ansiBlue+"tag"+ansiReset, b.String())
	})
}
