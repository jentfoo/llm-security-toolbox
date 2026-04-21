package agent

import (
	"context"
	"strings"
)

const statusSummaryRequest = "In one sentence, summarize what you're currently investigating and what you'll try next."

// SummarizeStatus sends a hidden summary request to the agent, captures the
// single-line response, and leaves history unchanged by rolling back the
// appended messages. OpenAIAgent-only because rollback requires the concrete
// type; other Agent impls use the public API.
func SummarizeStatus(ctx context.Context, a *OpenAIAgent, maxTokens int) (string, error) {
	if maxTokens <= 0 {
		maxTokens = 80
	}
	a.mu.Lock()
	before := a.history.Len()
	tools := a.tools
	model := a.cfg.Model
	a.mu.Unlock()

	msgs := a.buildChatMessages()
	msgs = append(msgs, ChatMessage{Role: "user", Content: statusSummaryRequest})

	client, err := a.cfg.Pool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer a.cfg.Pool.Release(client)

	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model:     model,
		Messages:  msgs,
		Tools:     tools,
		MaxTokens: maxTokens,
	})
	if err != nil {
		return "", err
	}

	// Rollback anything appended meanwhile (there shouldn't be anything,
	// but this keeps the contract explicit).
	snap := a.history.Snapshot()
	if len(snap) > before {
		a.history.ReplaceAll(snap[:before])
	}

	line := firstLine(StripThinkBlocks(resp.Content))
	return line, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
