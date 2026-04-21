package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// TruncationNotice is appended to truncated tool results. Exported so MCP
// dispatch can share the format.
const TruncationNotice = "\n…(truncated: %d of %d bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)"

// OpenAIAgentConfig configures a single agent instance.
type OpenAIAgentConfig struct {
	Model             string
	SystemPrompt      string
	Pool              *ClientPool
	MaxContext        int
	MaxToolRepairs    int // per-assistant-message
	Compaction        CompactionOptions
	TurnTimeout       time.Duration
	PerToolTimeout    time.Duration // per-tool-call timeout; 0 disables.
	MaxParallelTools  int           // bound on concurrent tool dispatch; <=1 runs serial.
	DrainRetryMax     int
	DrainRetryBackoff time.Duration
	MaxTurnsPerAgent  int // hard cap on tool-dispatch rounds per Drain
	// OnCompact is called with each compaction report (optional).
	OnCompact func(CompactionReport)
	// OnToolStart fires before a tool handler runs (optional).
	OnToolStart func(name string, args json.RawMessage)
	// OnToolEnd fires after a tool handler returns (optional). timedOut is true
	// when PerToolTimeout fired.
	OnToolEnd func(name string, args json.RawMessage, elapsed time.Duration, isError, timedOut bool)
	// OnMalformedCall is called when tool arg repair fails (optional).
	OnMalformedCall func(name string, err error)
	// OnRequestStart fires before each chat-completion HTTP call (optional).
	OnRequestStart func(attempt int)
	// OnRequestEnd fires after each chat-completion HTTP call (optional).
	OnRequestEnd func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error)
	// FlowIDExtractor (optional) extracts flow IDs from inputs/results/text.
	FlowIDExtractor func(sources ...any) []string
}

// OpenAIAgent implements Agent over an OpenAI-compatible endpoint.
type OpenAIAgent struct {
	cfg       OpenAIAgentConfig
	history   *History
	toolDefs  []ToolDef
	tools     []ChatTool
	handlers  map[string]ToolHandler
	mu        sync.Mutex
	cancelCtx func()
}

// NewOpenAIAgent constructs an agent and seeds history with system prompt.
func NewOpenAIAgent(cfg OpenAIAgentConfig) *OpenAIAgent {
	if cfg.MaxContext <= 0 {
		cfg.MaxContext = 32768
	}
	if cfg.MaxToolRepairs <= 0 {
		cfg.MaxToolRepairs = 2
	}
	if cfg.TurnTimeout == 0 {
		cfg.TurnTimeout = 300 * time.Second
	}
	if cfg.DrainRetryMax <= 0 {
		cfg.DrainRetryMax = 2
	}
	if cfg.DrainRetryBackoff == 0 {
		cfg.DrainRetryBackoff = 2 * time.Second
	}
	if cfg.MaxTurnsPerAgent <= 0 {
		cfg.MaxTurnsPerAgent = 100
	}
	if cfg.PerToolTimeout <= 0 {
		cfg.PerToolTimeout = 120 * time.Second
	}
	if cfg.MaxParallelTools <= 0 {
		cfg.MaxParallelTools = 4
	}
	a := &OpenAIAgent{
		cfg:      cfg,
		history:  NewHistory(cfg.MaxContext),
		handlers: map[string]ToolHandler{},
	}
	if cfg.SystemPrompt != "" {
		a.history.Append(Message{Role: "system", Content: cfg.SystemPrompt})
	}
	return a
}

// SetTools replaces the tool registry (active on next Drain).
func (a *OpenAIAgent) SetTools(defs []ToolDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.toolDefs = append(a.toolDefs[:0], defs...)
	a.tools = make([]ChatTool, 0, len(defs))
	a.handlers = make(map[string]ToolHandler, len(defs))
	for _, d := range defs {
		a.tools = append(a.tools, ChatTool{
			Type: "function",
			Function: ChatToolSchema{
				Name:        d.Name,
				Description: d.Description,
				Parameters:  d.Schema,
			},
		})
		if d.Handler != nil {
			a.handlers[d.Name] = d.Handler
		}
	}
}

// Query appends a user message to history. Does not send.
func (a *OpenAIAgent) Query(content string) {
	a.history.Append(Message{Role: "user", Content: content})
}

// Interrupt cancels any in-flight Drain.
func (a *OpenAIAgent) Interrupt() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancelCtx != nil {
		a.cancelCtx()
	}
}

// Close is a no-op for OpenAIAgent (pool + history have no OS handles).
func (a *OpenAIAgent) Close() error { return nil }

// ContextUsage returns (tokens, max).
func (a *OpenAIAgent) ContextUsage() (int, int) {
	return a.history.EstimateTokens(), a.history.MaxContext()
}

// History exposes the agent's history for orchestrator-level diagnostics
// and compaction tests.
func (a *OpenAIAgent) History() *History { return a.history }

// Drain runs the dispatch loop and returns one TurnSummary.
func (a *OpenAIAgent) Drain(ctx context.Context) (TurnSummary, error) {
	return a.DrainBounded(ctx, a.cfg.MaxTurnsPerAgent)
}

// DrainBounded runs the dispatch loop with a caller-supplied round cap.
// A value <=0 falls back to the configured MaxTurnsPerAgent.
func (a *OpenAIAgent) DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error) {
	if maxRounds <= 0 {
		maxRounds = a.cfg.MaxTurnsPerAgent
	}
	inner, cancel := context.WithTimeout(ctx, a.cfg.TurnTimeout)
	a.mu.Lock()
	a.cancelCtx = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.cancelCtx = nil
		a.mu.Unlock()
		cancel()
	}()

	summary := TurnSummary{}
	repairsLeft := a.cfg.MaxToolRepairs
	extractFlow := a.cfg.FlowIDExtractor

	for round := 0; ; round++ {
		if round >= maxRounds {
			// hard cap on runaway tool_calls loop, report silent to penalize it
			a.synthesizePendingToolStubs()
			summary.TimedOut = true
			summary.EscalationReason = escalationSilent
			return summary, nil
		}
		if err := a.maybeCompact(); err != nil {
			summary.EscalationReason = escalationSilent
			return summary, err
		}

		resp, err := a.sendWithRetry(inner)
		if errors.Is(err, context.DeadlineExceeded) {
			a.synthesizePendingToolStubs()
			summary.TimedOut = true
			summary.EscalationReason = escalationSilent
			return summary, nil
		} else if errors.Is(err, context.Canceled) {
			a.synthesizePendingToolStubs()
			return summary, ctx.Err()
		} else if err != nil {
			summary.EscalationReason = escalationError
			return summary, err
		}

		if resp.Usage.PromptTokens > 0 {
			a.history.SetPromptTokens(resp.Usage.PromptTokens)
			summary.TokensIn = resp.Usage.PromptTokens
		}
		summary.TokensOut += resp.Usage.CompletionTokens

		if len(resp.ToolCalls) == 0 {
			content := StripThinkBlocks(resp.Content)
			a.history.Append(Message{Role: roleAssistant, Content: content})
			summary.AssistantText += content
			if extractFlow != nil {
				for _, f := range extractFlow(content) {
					summary.FlowIDs = appendUnique(summary.FlowIDs, f)
				}
			}
			return summary, nil
		}

		content := StripThinkBlocks(resp.Content)
		a.history.Append(Message{
			Role:      roleAssistant,
			Content:   content,
			ToolCalls: resp.ToolCalls,
		})
		if content != "" {
			summary.AssistantText += content
		}
		if extractFlow != nil {
			for _, f := range extractFlow(content) {
				summary.FlowIDs = appendUnique(summary.FlowIDs, f)
			}
		}

		a.dispatchToolCalls(inner, resp.ToolCalls, &summary, &repairsLeft, extractFlow)
		// reset repair budget per assistant response
		repairsLeft = a.cfg.MaxToolRepairs
	}
}

// toolOutcome holds the result of a single tool dispatch so the collector
// loop can append history + summary in the original tool_calls order.
type toolOutcome struct {
	rec     ToolCallRecord
	histMsg Message
	flowIDs []string
	skip    bool // true for repair-failure path that consumed a repair slot
}

// dispatchToolCalls executes handlers concurrently (bounded by
// MaxParallelTools) and then, serially, folds each outcome into history +
// summary in the original order. Tool-call / tool-result messages must stay
// paired in sequence for OpenAI providers.
func (a *OpenAIAgent) dispatchToolCalls(
	inner context.Context,
	calls []ToolCall,
	summary *TurnSummary,
	repairsLeft *int,
	extractFlow func(...any) []string,
) {
	outcomes := make([]toolOutcome, len(calls))

	// Phase 1: synchronous pre-flight (repair + flow-id extraction). We do this
	// single-threaded so repair-budget accounting is deterministic and malformed
	// outcomes land in slot order regardless of handler scheduling.
	parsed := make([]json.RawMessage, len(calls))
	ok := make([]bool, len(calls))
	for i, tc := range calls {
		args, repairErr := RepairToolArgs(tc.Function.Arguments)
		if repairErr != nil {
			if a.cfg.OnMalformedCall != nil {
				a.cfg.OnMalformedCall(tc.Function.Name, repairErr)
			}
			rec := ToolCallRecord{Name: tc.Function.Name, IsError: true}
			rec.InputSummary = truncate(tc.Function.Arguments, 240)
			errText := a.formatRepairError(tc.Function.Name, repairErr)
			rec.ResultSummary = truncate(errText, 300)
			outcomes[i] = toolOutcome{
				rec: rec,
				histMsg: Message{
					Role:       roleTool,
					Content:    errText,
					ToolCallID: tc.ID,
					ToolName:   tc.Function.Name,
					Summary120: Summarize120(errText),
				},
			}
			if *repairsLeft > 0 {
				*repairsLeft--
			}
			continue
		}
		parsed[i] = args
		ok[i] = true
		if extractFlow != nil {
			var anyArgs any
			_ = json.Unmarshal(args, &anyArgs)
			outcomes[i].flowIDs = extractFlow(anyArgs)
		}
	}

	// Phase 2: concurrent handler execution, bounded.
	concurrency := a.cfg.MaxParallelTools
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, tc := range calls {
		if !ok[i] {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tc ToolCall, args json.RawMessage) {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = a.runSingleTool(inner, tc, args, outcomes[i].flowIDs, extractFlow)
		}(i, tc, parsed[i])
	}
	wg.Wait()

	// Phase 3: serial fold — append to history and summary in tool_calls order.
	for _, o := range outcomes {
		if o.skip {
			continue
		}
		summary.ToolCalls = append(summary.ToolCalls, o.rec)
		for _, f := range o.flowIDs {
			summary.FlowIDs = appendUnique(summary.FlowIDs, f)
		}
		a.history.Append(o.histMsg)
	}
}

// runSingleTool wraps one handler invocation with the per-tool timeout and
// start/end callbacks. Must be safe for concurrent use with other invocations
// targeting the same agent — it mutates nothing on `a` other than via the
// callback hooks and returns a self-contained outcome.
func (a *OpenAIAgent) runSingleTool(
	inner context.Context,
	tc ToolCall,
	args json.RawMessage,
	flowIDs []string,
	extractFlow func(...any) []string,
) toolOutcome {
	rec := ToolCallRecord{Name: tc.Function.Name, RawInput: args}
	rec.InputSummary = truncate(string(args), 240)

	if a.cfg.OnToolStart != nil {
		a.cfg.OnToolStart(tc.Function.Name, args)
	}

	handler, known := a.handlers[tc.Function.Name]
	var result ToolResult
	var timedOut bool
	start := time.Now()
	if !known {
		result = ToolResult{
			Text:    fmt.Sprintf("ERROR: unknown tool %q", tc.Function.Name),
			IsError: true,
		}
	} else {
		tctx, cancel := context.WithTimeout(inner, a.cfg.PerToolTimeout)
		result = handler(tctx, args)
		cancel()
		if errors.Is(tctx.Err(), context.DeadlineExceeded) && inner.Err() == nil {
			// Tool exceeded its own budget; rewrite result so the model sees a
			// structured error rather than whatever partial output it produced.
			timedOut = true
			result = ToolResult{
				Text: fmt.Sprintf(
					"ERROR: tool %q timed out after %s",
					tc.Function.Name, a.cfg.PerToolTimeout,
				),
				IsError: true,
			}
		}
	}
	elapsed := time.Since(start)

	rec.IsError = result.IsError
	rec.ResultSummary = truncate(result.Text, 300)
	if a.cfg.OnToolEnd != nil {
		a.cfg.OnToolEnd(tc.Function.Name, args, elapsed, result.IsError, timedOut)
	}
	if extractFlow != nil {
		flowIDs = append(flowIDs, extractFlow(result.Text)...)
	}
	return toolOutcome{
		rec: rec,
		histMsg: Message{
			Role:       roleTool,
			Content:    toolResultBody(result),
			ToolCallID: tc.ID,
			ToolName:   tc.Function.Name,
			Summary120: Summarize120(result.Text),
		},
		flowIDs: flowIDs,
	}
}

func toolResultBody(r ToolResult) string {
	if r.IsError && !strings.HasPrefix(r.Text, "ERROR:") {
		return "ERROR: " + r.Text
	}
	return r.Text
}

// formatRepairError renders the error the model sees when its tool_call
// arguments do not parse. When the tool schema is known it is embedded so
// the model can self-correct without re-discovering the shape.
const maxRepairSchemaBytes = 500

func (a *OpenAIAgent) formatRepairError(toolName string, repairErr error) string {
	a.mu.Lock()
	var schemaJSON []byte
	for _, d := range a.toolDefs {
		if d.Name == toolName && d.Schema != nil {
			schemaJSON, _ = json.Marshal(d.Schema)
			break
		}
	}
	a.mu.Unlock()
	if len(schemaJSON) == 0 {
		return fmt.Sprintf(
			"ERROR: your arguments did not parse: %s. Call again with valid JSON matching the schema.",
			repairErr.Error(),
		)
	}
	if len(schemaJSON) > maxRepairSchemaBytes {
		schemaJSON = append(schemaJSON[:maxRepairSchemaBytes], []byte("…")...)
	}
	return fmt.Sprintf(
		"ERROR: your arguments did not parse: %s. Call again with valid JSON matching %s.",
		repairErr.Error(), string(schemaJSON),
	)
}

func (a *OpenAIAgent) maybeCompact() error {
	high := int(float64(a.history.MaxContext()) * a.cfg.Compaction.HighWatermark)
	if high <= 0 {
		high = int(float64(a.history.MaxContext()) * 0.80)
	}
	if a.history.EstimateTokens() < high {
		return nil
	}
	report, err := Compact(a.history, a.cfg.Compaction)
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(report)
	}
	return err
}

func (a *OpenAIAgent) sendWithRetry(ctx context.Context) (ChatResponse, error) {
	a.mu.Lock()
	tools := a.tools
	a.mu.Unlock()

	msgs := a.buildChatMessages()

	var lastErr error
	for attempt := 0; attempt <= a.cfg.DrainRetryMax; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ChatResponse{}, ctx.Err()
			case <-time.After(a.cfg.DrainRetryBackoff):
			}
		}
		resp, err := a.dispatchChatRequest(ctx, attempt, msgs, tools)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ChatResponse{}, err
		}
	}
	return ChatResponse{}, lastErr
}

// dispatchChatRequest acquires a pooled client, runs one request with
// start/end callbacks, and releases (via defer for panic safety).
func (a *OpenAIAgent) dispatchChatRequest(
	ctx context.Context, attempt int, msgs []ChatMessage, tools []ChatTool,
) (ChatResponse, error) {
	client, err := a.cfg.Pool.Acquire(ctx)
	if err != nil {
		return ChatResponse{}, err
	}
	defer a.cfg.Pool.Release(client)

	if a.cfg.OnRequestStart != nil {
		a.cfg.OnRequestStart(attempt)
	}
	start := time.Now()
	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model:    a.cfg.Model,
		Messages: msgs,
		Tools:    tools,
	})
	if a.cfg.OnRequestEnd != nil {
		a.cfg.OnRequestEnd(attempt, time.Since(start), resp.Usage.PromptTokens, resp.Usage.CompletionTokens, err)
	}
	return resp, err
}

// buildChatMessages returns history filtered to OpenAI-compatible shape.
func (a *OpenAIAgent) buildChatMessages() []ChatMessage {
	snap := a.history.Snapshot()
	out := make([]ChatMessage, 0, len(snap))
	for _, m := range snap {
		out = append(out, ChatMessage{
			Role:       m.Role,
			Content:    m.Content,
			ToolCalls:  m.ToolCalls,
			ToolCallID: m.ToolCallID,
		})
	}
	return out
}

// synthesizePendingToolStubs fills in tool result messages for any
// assistant.tool_calls whose pair is missing at the tail of history.
func (a *OpenAIAgent) synthesizePendingToolStubs() {
	msgs := a.history.Snapshot()
	if len(msgs) == 0 {
		return
	}
	// Find the last assistant.tool_calls and count paired tool results.
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != roleAssistant || len(msgs[i].ToolCalls) == 0 {
			continue
		}
		paired := map[string]bool{}
		for j := i + 1; j < len(msgs); j++ {
			if msgs[j].Role == roleTool {
				paired[msgs[j].ToolCallID] = true
			}
		}
		stubs := 0
		for _, tc := range msgs[i].ToolCalls {
			if !paired[tc.ID] {
				msgs = append(msgs, Message{
					Role:       roleTool,
					Content:    "(interrupted before tool could run)",
					ToolCallID: tc.ID,
					ToolName:   tc.Function.Name,
					Summary120: "(interrupted before tool could run)",
				})
				stubs++
			}
		}
		if stubs > 0 {
			a.history.ReplaceAll(msgs)
		}
		return
	}
}

func appendUnique(slice []string, v string) []string {
	if v == "" || slices.Contains(slice, v) {
		return slice
	}
	return append(slice, v)
}
