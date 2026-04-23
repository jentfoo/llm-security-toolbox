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

// SummarizeStatus returns line-or-tail from SummarizeStatusVia routed
// through the agent's own pool and model. Back-compat wrapper.
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

// SummarizeStatusVia asks the summary model for one sentence describing
// what the agent is currently investigating. A nil client routes through
// the agent's own pool; an empty model falls back to the agent's configured
// model (narrator callers pass a specific summary model so all summary
// traffic targets one endpoint). Returns the extracted prose line and,
// separately, a truncated-think-tail fallback for responses that were cut
// off mid-reasoning.
//
// The agent's history is filtered before sending: the system prompt plus
// the first user turn are kept as anchor, tool results are replaced with a
// placeholder, and the remainder is tail-truncated to statusTokenBudget.
// Tools are not attached — the model should produce prose, not dispatch
// calls. The agent's history is never mutated. OpenAIAgent-only.
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
	msgs := buildStatusMessages(normalized, statusTokenBudget, a.cfg.KeepThinkTurns)
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

// buildStatusMessages filters and tail-truncates the agent's history for a
// status-summary prompt. The leading system message (if present) and the
// first non-system turn (typically the assignment) are preserved as anchor
// regardless of budget; the remaining window is trimmed from the tail.
// Tool-result bytes are replaced with a placeholder so pairing stays valid
// without sending the payload. `<think>` blocks are preserved on the last
// keepThinkTurns assistant messages so the summary model can see recent
// reasoning intent; older thinks are stripped to keep the prompt lean.
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
		anchorCost += estimateMessageTokens(m)
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

// pickTail walks msgs from the end, accumulating estimated tokens until
// budget is reached, then drops any leading role=tool messages that lost
// their assistant parent to the cut.
func pickTail(msgs []Message, budget int) []Message {
	if budget <= 0 || len(msgs) == 0 {
		return nil
	}
	cost := 0
	start := len(msgs)
	for i := len(msgs) - 1; i >= 0; i-- {
		c := estimateMessageTokens(msgs[i])
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

// estimateMessageTokens mirrors History.estimateRangeLocked's char/4
// heuristic so summary budgeting stays consistent with compaction.
func estimateMessageTokens(m Message) int {
	total := len(m.Content) / 4
	for _, tc := range m.ToolCalls {
		total += (len(tc.Function.Name) + len(tc.Function.Arguments)) / 4
	}
	total += 4
	return total
}
