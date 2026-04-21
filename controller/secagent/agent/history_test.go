package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryEstimationAndSetPromptTokens(t *testing.T) {
	t.Parallel()
	h := NewHistory(4096)
	assert.Equal(t, 4096, h.MaxContext())
	h.Append(Message{Role: "system", Content: "sys"})
	h.Append(Message{Role: "user", Content: "hello world hello world"})
	approx := h.EstimateTokens()
	assert.Positive(t, approx)

	// When the server reports a prompt-token count it replaces the estimate.
	h.SetPromptTokens(2048)
	assert.Equal(t, 2048, h.EstimateTokens())

	// Anything appended after the baseline adds growth on top.
	h.Append(Message{Role: "assistant", Content: "ok"})
	assert.Greater(t, h.EstimateTokens(), 2048)
}

func TestOpenAIAgent_AccessorsAndInterrupt(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client), MaxContext: 4096})

	tokens, max := a.ContextUsage()
	assert.Equal(t, 4096, max)
	assert.GreaterOrEqual(t, tokens, 0)

	assert.NotNil(t, a.History())
	require.NoError(t, a.Close())
	a.Interrupt() // without in-flight ctx, no-op
}
