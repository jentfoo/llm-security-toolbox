package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeStatus_StripsThinkAndReturnsFirstLine(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{
		{Content: "<think>plan</think>Investigating auth; will try replay_send next.\n(second line)"},
	}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	a.Query("earlier user turn")
	before := a.history.Len()

	line, err := SummarizeStatus(t.Context(), a, 40)
	require.NoError(t, err)
	assert.Equal(t, "Investigating auth; will try replay_send next.", line)
	assert.Equal(t, before, a.history.Len(), "status summary must not persist in history")

	require.Len(t, client.calls, 1)
	last := client.calls[0].Messages
	assert.Equal(t, statusSummaryRequest, last[len(last)-1].Content)
	assert.Equal(t, 40, client.calls[0].MaxTokens)
}

func TestSummarizeStatus_ErrorPropagates(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{{}},
		errors:    []error{errors.New("boom")},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	_, err := SummarizeStatus(t.Context(), a, 0)
	require.Error(t, err)
}

func TestSummarizeStatus_ContextCanceledDuringAcquire(t *testing.T) {
	t.Parallel()
	// Drain the pool, then cancel ctx; Acquire must return ctx.Err() rather
	// than blocking.
	pool := NewClientPool(&fakeChatClient{}, 1)
	held, err := pool.Acquire(context.Background())
	require.NoError(t, err)
	defer pool.Release(held)

	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: pool})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = SummarizeStatus(ctx, a, 0)
	require.Error(t, err)
}
