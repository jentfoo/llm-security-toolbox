package agent

import (
	"context"
)

const statusSummaryRequest = "Provide a single concise and clearly worded sentence summarizing what you are currently investigating and what you will try next."

// statusTokenBudget is the input-side cap on the history window sent with
// a status-summary request (char/4 heuristic). Separate from the output
// cap passed as MaxTokens.
const statusTokenBudget = 2000

// toolResultPlaceholder replaces role=tool content in the summary prompt. We
// keep the message so assistant.tool_calls stay paired (strict servers reject
// orphaned tool_calls) but drop the bytes, which are almost always the bulk
// of the history and rarely informative for a one-sentence status.
const toolResultPlaceholder = "(tool result omitted for summary)"

// SummarizeStatus returns a one-sentence status summary for a, using the
// agent's own pool and model. Falls back to a truncated reasoning tail
// when the model produced no usable prose. Returns "" when the history
// has nothing substantive to summarize.
func SummarizeStatus(ctx context.Context, a *OpenAIAgent, maxTokens int) (string, error) {
	line, tail, err := SummarizeStatusVia(ctx, a, nil, "", maxTokens)
	if err != nil {
		return "", err
	}
	if line != "" {
		return line, nil
	}
	return tail, nil
}

// SummarizeStatusVia asks client (or the agent's pool when nil) to produce
// a one-sentence status summary for a. An empty model falls back to the
// agent's configured model. Returns the extracted prose line and a
// truncated-think-tail fallback when no confident line was produced. The
// agent's history is not mutated.
func SummarizeStatusVia(ctx context.Context, a *OpenAIAgent, client ChatClient, model string, maxTokens int) (line, thinkTail string, err error) {
	if client == nil {
		client, err = a.cfg.Pool.Acquire(ctx)
		if err != nil {
			return "", "", err
		}
		defer a.cfg.Pool.Release(client)
	}
	return summarizeStatusVia(ctx, a, client, model, maxTokens)
}

func summarizeStatusVia(ctx context.Context, a *OpenAIAgent, client ChatClient, model string, maxTokens int) (line, thinkTail string, err error) {
	if maxTokens <= 0 {
		// Reasoning-format models (deepseek/qwen3) use ~1-5k tokens of
		// reasoning before emitting to content. A low cap truncates mid-
		// reasoning and produces empty content; keep the ceiling generous.
		maxTokens = 20000
	}
	a.mu.Lock()
	before := a.history.Len()
	agentModel := a.cfg.Model
	a.mu.Unlock()
	if model == "" {
		model = agentModel
	}

	// Normalize the agent's history to inline-think shape via the agent's own
	// reasoning handler. Structured-format agents get their reasoning wrapped
	// as <think>...</think> so the summary model sees one consistent shape
	// regardless of which format the underlying agent used.
	normalized := a.cfg.Reasoning.ForSummary(a.history.Snapshot())
	// Strip tool-error noise; if nothing remains worth summarizing, skip
	// the LLM call entirely rather than spend tokens on system+user only.
	filtered := FilterErrorMessages(normalized)
	if !HasSubstantiveMessages(filtered) {
		return "", "", nil
	}
	msgs := buildStatusMessages(filtered, statusTokenBudget, a.cfg.KeepThinkTurns)
	msgs = append(msgs, ChatMessage{Role: "user", Content: statusSummaryRequest})

	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model:           model,
		Messages:        msgs,
		MaxTokens:       maxTokens,
		ReasoningEffort: SummaryReasoningEffort,
	})
	if err != nil {
		return "", "", err
	}

	snap := a.history.Snapshot()
	if len(snap) > before {
		a.history.ReplaceAll(snap[:before])
	}

	// Extract runs the full defensive cascade (strip, JSON parse, marker
	// salvage, structural-line skipping). Tail is reserved for fragments
	// when no confident line could be produced.
	line = a.cfg.Reasoning.Extract(resp)
	if line == "" {
		thinkTail = a.cfg.Reasoning.Tail(resp)
	}
	return line, thinkTail, nil
}

// buildStatusMessages returns the chat-message slice to send for a status
// summary, anchored on the system message and first non-system turn and
// tail-truncated to budget tokens.
func buildStatusMessages(hist []Message, budget, keepThinkTurns int) []ChatMessage {
	if len(hist) == 0 {
		return nil
	}
	hist = FilterThinkBlocks(hist, keepThinkTurns)
	var anchor []Message
	tailStart := 0
	if hist[0].Role == roleSystem {
		anchor = append(anchor, hist[0])
		tailStart = 1
	}
	if tailStart < len(hist) && hist[tailStart].Role != roleTool {
		anchor = append(anchor, hist[tailStart])
		tailStart++
	}

	filtered := make([]Message, 0, len(hist)-tailStart)
	for i := tailStart; i < len(hist); i++ {
		m := hist[i]
		if m.Role == roleTool {
			m.Content = toolResultPlaceholder
		}
		filtered = append(filtered, m)
	}

	anchorCost := 0
	for _, m := range anchor {
		anchorCost += EstimateMessageTokens(m)
	}
	remaining := budget - anchorCost
	if remaining < 0 {
		remaining = 0
	}
	tail := pickTail(filtered, remaining)

	out := make([]ChatMessage, 0, len(anchor)+len(tail))
	for _, m := range anchor {
		out = append(out, ChatMessage{
			Role: m.Role, Content: m.Content, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID,
		})
	}
	for _, m := range tail {
		out = append(out, ChatMessage{
			Role: m.Role, Content: m.Content, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID,
		})
	}
	return out
}

// pickTail returns the trailing slice of msgs whose estimated token sum
// fits within budget. Leading orphaned tool-result messages are dropped.
func pickTail(msgs []Message, budget int) []Message {
	if budget <= 0 || len(msgs) == 0 {
		return nil
	}
	cost := 0
	start := len(msgs)
	for i := len(msgs) - 1; i >= 0; i-- {
		c := EstimateMessageTokens(msgs[i])
		if cost+c > budget && start < len(msgs) {
			break
		}
		cost += c
		start = i
	}
	for start < len(msgs) && msgs[start].Role == roleTool {
		start++
	}
	return msgs[start:]
}
