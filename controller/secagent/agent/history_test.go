package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHistory_TokenTracking(t *testing.T) {
	t.Parallel()
	h := NewHistory(4096)
	assert.Equal(t, 4096, h.MaxContext())
	h.Append(Message{Role: "system", Content: "sys"})
	h.Append(Message{Role: "user", Content: "hello world hello world"})
	approx := h.EstimateTokens()
	assert.Positive(t, approx)

	// server-reported prompt tokens replace the local estimate as baseline
	h.SetPromptTokens(2048)
	assert.Equal(t, 2048, h.EstimateTokens())

	h.Append(Message{Role: "assistant", Content: "ok"})
	assert.Greater(t, h.EstimateTokens(), 2048)
}
