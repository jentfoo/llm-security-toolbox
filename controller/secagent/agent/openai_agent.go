package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
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
	// KeepThinkTurns is the count of recent assistant messages that retain
	// <think> blocks on replay. 0 strips all. Inline handler only.
	KeepThinkTurns int
	// Reasoning encapsulates format-specific ingest/replay/summary behaviour.
	// Nil defaults to the inline handler.
	Reasoning ReasoningHandler
	// OnCompact is called with each compaction report (optional).
	OnCompact func(CompactionReport)
	// OnContextOverflow fires once per sendWithRetry call when the model
	// rejected the request as over-context. Mirrors OnCompact / OnMalformedCall
	// shape. The orchestrator uses this signal to drive the verifier's
	// auto-dismiss-on-budget-exhaust path: if a freshly composed verifier still
	// overflows, in-flight candidates can't be reproduced under the current
	// budget and are dismissed rather than carried forward.
	OnContextOverflow func()
	// OnSummarizeBoundary, when non-nil, is called by maybeCompact when normal
	// compaction can't free enough space. It receives messages eligible for
	// summarization and returns a replacement slice or error. On success the
	// agent replaces messages[1:iterationStartIdx] with the result.
	OnSummarizeBoundary func(ctx context.Context, snapshot []Message) ([]Message, error)
	// OnSummarizeError fires when OnSummarizeBoundary returned an error.
	// The agent fails open (proceeds to the next compaction pass) regardless;
	// this callback exists so the orchestrator can log the failure.
	OnSummarizeError func(err error)
	// OnToolStart fires before a tool handler runs (optional).
	OnToolStart func(name string, args json.RawMessage)
	// OnToolEnd fires after a tool handler returns (optional). timedOut is true
	// when PerToolTimeout fired. errText is truncated result text when isError
	// is true, else empty.
	OnToolEnd func(name string, args json.RawMessage, elapsed time.Duration, isError, timedOut bool, errText string)
	// OnMalformedCall is called when tool arg repair fails (optional).
	OnMalformedCall func(name string, err error)
	// OnRequestStart fires before each chat-completion HTTP call (optional).
	OnRequestStart func(attempt int)
	// OnRequestEnd fires after each chat-completion HTTP call (optional).
	OnRequestEnd func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error)
	// FlowIDExtractor (optional) extracts flow IDs from inputs/results/text.
	FlowIDExtractor func(sources ...any) []string
	// Rand is the randomness source used by retry backoff jitter. nil → the
	// package default. Tests inject a seeded *rand.Rand for determinism.
	Rand *rand.Rand
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
	// iterationStartIdx marks where the current iteration's content begins.
	iterationStartIdx int
	// iterationSummarized prevents the boundary-summarize callback from firing
	// twice in the same iteration.
	iterationSummarized bool
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
	if cfg.Reasoning == nil {
		cfg.Reasoning = NewReasoningHandler(ReasoningFormatInline)
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

// EffectiveContextUsage is like ContextUsage but reports the post-shrink
// ceiling. After a context-overflow rejection the effective max stays below
// the configured one for the rest of the run; this method exposes the value
// the agent will actually be measured against on the next send.
func (a *OpenAIAgent) EffectiveContextUsage() (tokens, max int) {
	return a.history.EstimateTokens(), a.history.EffectiveMaxContext()
}

// History exposes the agent's history for orchestrator-level diagnostics
// and compaction tests.
func (a *OpenAIAgent) History() *History { return a.history }

// Snapshot returns a shallow copy of the agent's message history. Safe for
// callers that need to inspect the conversation (e.g. an external
// summarizer) without holding the agent's internal lock.
func (a *OpenAIAgent) Snapshot() []Message { return a.history.Snapshot() }

// ReplaceHistory replaces the agent's working memory with msgs. The leading
// system prompt is preserved: if msgs[0] is not a system message and the
// agent was constructed with a SystemPrompt, the system message is
// re-prepended automatically. Cancels any in-flight Drain so the next call
// starts cleanly. Resets iteration-boundary state — the caller must call
// MarkIterationBoundary again after the install + any subsequent Query
// chain has settled.
//
// Intended for orchestrator-level chronicle install / compression: snapshot
// the agent, produce a recap slice, hand it back here. Tools and handlers
// are untouched.
func (a *OpenAIAgent) ReplaceHistory(msgs []Message) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancelCtx != nil {
		a.cancelCtx()
		a.cancelCtx = nil
	}
	if len(msgs) == 0 || msgs[0].Role != "system" {
		if sys := a.cfg.SystemPrompt; sys != "" {
			msgs = append([]Message{{Role: "system", Content: sys}}, msgs...)
		}
	}
	a.history.ReplaceAll(msgs)
	a.iterationStartIdx = 0
	a.iterationSummarized = false
}

// MarkIterationBoundary records the current history length as the start of
// the active iteration's content. The boundary-summarize path in
// maybeCompact summarizes messages BEFORE this index when the watermark
// fires mid-drain, leaving the iteration's in-flight tool calls and
// assistant responses verbatim.
func (a *OpenAIAgent) MarkIterationBoundary() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.iterationStartIdx = a.history.Len()
	a.iterationSummarized = false
}

// IterationBoundary returns the current iteration-boundary index.
// Orchestrator-side chronicle extraction reads this AFTER a worker drain to
// slice off the iteration's new content for chronicle append.
func (a *OpenAIAgent) IterationBoundary() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.iterationStartIdx
}

// SetOnSummarizeBoundary swaps in a new boundary-summarize callback.
// Lets the orchestrator wire a closure that captures live state
// (per-worker mission/directive) post-construction, since the closure
// often needs to reference the WorkerState pointer that doesn't exist
// at agent-build time.
func (a *OpenAIAgent) SetOnSummarizeBoundary(f func(ctx context.Context, snapshot []Message) ([]Message, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.OnSummarizeBoundary = f
}

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
		if err := a.maybeCompact(inner); err != nil {
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

		// Delegate format-specific storage to the reasoning handler: inline
		// keeps raw <think> in Content; structured splits Content from the
		// dedicated ReasoningContent field. Observability (AssistantText,
		// flow IDs) operates on stripped Content — reasoning is for replay
		// and summary, not for flow extraction.
		storeContent, storeReasoning := a.cfg.Reasoning.Ingest(resp)
		stripped := StripThinkBlocks(storeContent)
		if len(resp.ToolCalls) == 0 {
			a.history.Append(Message{
				Role:             roleAssistant,
				Content:          storeContent,
				ReasoningContent: storeReasoning,
			})
			summary.AssistantText += stripped
			if extractFlow != nil {
				for _, f := range extractFlow(stripped) {
					summary.FlowIDs = appendUnique(summary.FlowIDs, f)
				}
			}
			return summary, nil
		}

		a.history.Append(Message{
			Role:             roleAssistant,
			Content:          storeContent,
			ReasoningContent: storeReasoning,
			ToolCalls:        resp.ToolCalls,
		})
		if stripped != "" {
			summary.AssistantText += stripped
		}
		if extractFlow != nil {
			for _, f := range extractFlow(stripped) {
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
					Role:          roleTool,
					Content:       errText,
					ToolCallID:    tc.ID,
					ToolName:      tc.Function.Name,
					Summary120:    Summarize120(errText),
					IsRepairError: true,
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
		var errText string
		if result.IsError {
			errText = truncate(result.Text, 240)
		}
		a.cfg.OnToolEnd(tc.Function.Name, args, elapsed, result.IsError, timedOut, errText)
	}
	if extractFlow != nil {
		flowIDs = append(flowIDs, extractFlow(result.Text)...)
	}
	content := result.Text
	if result.IsError && !strings.HasPrefix(result.Text, "ERROR:") {
		content = "ERROR: " + result.Text
	}
	return toolOutcome{
		rec: rec,
		histMsg: Message{
			Role:       roleTool,
			Content:    content,
			ToolCallID: tc.ID,
			ToolName:   tc.Function.Name,
			Summary120: Summarize120(result.Text),
		},
		flowIDs: flowIDs,
	}
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

func (a *OpenAIAgent) maybeCompact(ctx context.Context) error {
	// EffectiveMaxContext tracks adaptive shrinkage from past rejections;
	// when none has happened it equals the configured MaxContext.
	maxCtx := a.history.EffectiveMaxContext()
	high := int(float64(maxCtx) * a.cfg.Compaction.HighWatermark)
	if high <= 0 {
		high = int(float64(maxCtx) * 0.80)
	}
	if a.history.EstimateTokens() < high {
		return nil
	}
	// Pass 1: existing compaction (think-strip, stub tool results, drop oldest
	// turn triples). Cheapest option; runs first.
	report, err := a.compactPreservingBoundary()
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(report)
	}
	if err != nil {
		return err
	}
	if a.history.EstimateTokens() < high {
		return nil
	}
	// Pass 2: boundary-summarize callback. Eligible only when an iteration
	// boundary has been marked (iterationStartIdx > 1 — must be past the
	// system message), the callback is wired, and we haven't already done
	// this in the current iteration.
	if a.cfg.OnSummarizeBoundary != nil && !a.iterationSummarized && a.iterationStartIdx > 1 {
		if err := a.runBoundarySummarize(ctx); err != nil && a.cfg.OnSummarizeError != nil {
			// Fail open — fall through to pass 3 below. The orchestrator
			// observes the failure via OnSummarizeError.
			a.cfg.OnSummarizeError(err)
		}
		if a.history.EstimateTokens() < high {
			return nil
		}
	}
	// Pass 3: existing compaction again, now potentially biting into in-iter
	// content. Last line of defense before sendChat hits its own overflow
	// path.
	report, err = a.compactPreservingBoundary()
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(report)
	}
	return err
}

// compactPreservingBoundary wraps Compact so iterationStartIdx stays
// pinned to the message it originally pointed to even when Compact drops
// or modifies messages. The boundary is the controller's contract for
// where in-iter content begins — extractAndAppend reads from there into
// the worker chronicle, and runBoundarySummarize summarizes everything
// before there. A stale boundary silently loses iter content (read past
// the new history end) or summarizes the wrong slice.
//
// Strategy: snapshot the message AT iterationStartIdx (the iter-head
// message — for workers, the directive Query'd after MarkIterationBoundary)
// before Compact, then locate it again afterwards by role+content match.
// Compact only edits assistant/tool content in place (think-strip,
// stubbing, sentence-truncate); it never touches user-role content. The
// iter-head message is a user directive, so equality on Role+Content is
// reliable. If the marker disappeared (the iter itself was dropped by
// dropOldestTurn), the boundary clamps to history end so extractAndAppend
// fails open with no append.
func (a *OpenAIAgent) compactPreservingBoundary() (CompactionReport, error) {
	var marker Message
	hasMarker := false
	preLen := a.history.Len()
	if a.iterationStartIdx > 0 && a.iterationStartIdx < preLen {
		snap := a.history.Snapshot()
		marker = snap[a.iterationStartIdx]
		hasMarker = true
	}
	report, err := Compact(a.history, a.cfg.Compaction)
	if !hasMarker {
		if a.iterationStartIdx > a.history.Len() {
			a.iterationStartIdx = a.history.Len()
		}
		return report, err
	}
	snap := a.history.Snapshot()
	for i := range snap {
		if snap[i].Role == marker.Role &&
			snap[i].Content == marker.Content &&
			snap[i].ToolName == marker.ToolName &&
			snap[i].ToolCallID == marker.ToolCallID {
			a.iterationStartIdx = i
			return report, err
		}
	}
	a.iterationStartIdx = len(snap)
	return report, err
}

// runBoundarySummarize takes a snapshot of messages[1:iterationStartIdx],
// hands it to OnSummarizeBoundary, and splices the returned slice back into
// history in place of the snapshot. Updates iterationStartIdx so that the
// in-flight iteration content stays correctly delimited.
func (a *OpenAIAgent) runBoundarySummarize(ctx context.Context) error {
	full := a.history.Snapshot()
	// Defensive bounds check — iterationStartIdx may be stale if history
	// shrank via prior compaction. Clamp.
	end := a.iterationStartIdx
	if end > len(full) {
		end = len(full)
	}
	if end <= 1 {
		return nil
	}
	preIter := full[1:end]
	replacement, err := a.cfg.OnSummarizeBoundary(ctx, preIter)
	if err != nil {
		return err
	}
	if len(replacement) == 0 {
		// Callback chose not to summarize (e.g. nothing useful to compress).
		// Still mark summarized so we don't re-call this iter.
		a.iterationSummarized = true
		return nil
	}
	// Splice: [system] + replacement + full[end:].
	rebuilt := make([]Message, 0, 1+len(replacement)+len(full)-end)
	rebuilt = append(rebuilt, full[0])
	rebuilt = append(rebuilt, replacement...)
	rebuilt = append(rebuilt, full[end:]...)
	a.history.ReplaceAll(rebuilt)
	a.iterationStartIdx = 1 + len(replacement)
	a.iterationSummarized = true
	return nil
}

// sendWithRetry dispatches one chat-completion request, applying a typed
// retry policy driven by Classify. Categories:
//
//   - ErrDeadline / ErrOther / ErrModelError: propagate immediately.
//   - ErrContextOverflow: hard-truncate the history in-place and retry
//     without consuming a retry attempt. Fires at most once per call so a
//     persistent mismatch still surfaces instead of silently looping.
//   - ErrRateLimit: sleep for the hinted Retry-After (or fall back to
//     exponential backoff with jitter) then retry.
//   - ErrTransientNet: sleep for exponential backoff with jitter, then retry.
//
// The retry budget (DrainRetryMax) applies only to the retryable categories;
// the context-overflow fast-path does not debit it.
func (a *OpenAIAgent) sendWithRetry(ctx context.Context) (ChatResponse, error) {
	a.mu.Lock()
	tools := a.tools
	a.mu.Unlock()

	msgs := a.buildChatMessages()
	hardTruncated := false
	retries := 0

	for attempt := 0; ; attempt++ {
		resp, err := a.dispatchChatRequest(ctx, attempt, msgs, tools)
		if err == nil {
			return resp, nil
		}
		cat, retryAfter := Classify(err)
		switch cat {
		case ErrDeadline, ErrOther, ErrModelError:
			return ChatResponse{}, err

		case ErrContextOverflow:
			// Once-per-call fast-path. Shrink EffectiveMaxContext based on
			// what was just rejected, force-truncate, and retry without
			// debiting the retry budget — the truncate itself is the fix.
			if hardTruncated {
				return ChatResponse{}, err
			}
			hardTruncated = true
			a.history.ShrinkEffectiveMaxOnRejection(a.history.EstimateTokens())
			if a.cfg.OnContextOverflow != nil {
				a.cfg.OnContextOverflow()
			}
			target := a.history.EffectiveMaxContext() / 2
			report := ForceHardTruncate(a.history, target, 2)
			if a.cfg.OnCompact != nil {
				a.cfg.OnCompact(report)
			}
			if report.DroppedTurns == 0 {
				return ChatResponse{}, err
			}
			msgs = a.buildChatMessages()
			continue

		case ErrRateLimit, ErrTransientNet:
			if retries >= a.cfg.DrainRetryMax {
				return ChatResponse{}, err
			}
			wait := BackoffFor(cat, retries, retryAfter, a.cfg.DrainRetryBackoff, a.cfg.Rand)
			if err := sleepCtx(ctx, wait); err != nil {
				return ChatResponse{}, err
			}
			retries++
			continue
		}
	}
}

// sleepCtx sleeps for d, returning ctx.Err() if the context cancels first.
// d <= 0 is a no-op.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// isContextRejectedError reports whether the error came from the upstream
// model rejecting the request as too large. Matches both the OpenAI-style
// `context_length_exceeded` code and local-model phrasing like "Context
// size has been exceeded" seen in the live-run 400 bodies.
func isContextRejectedError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "context size has been exceeded") ||
		strings.Contains(s, "context_length_exceeded") ||
		strings.Contains(s, "maximum context length") ||
		strings.Contains(s, "context window")
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
// The reasoning handler decides format-specific replay semantics: inline
// preserves `<think>` on the last KeepThinkTurns assistant messages;
// structured blanks ReasoningContent so it's never sent back (deepseek
// convention); none passes through. History storage remains raw — only
// the outbound view is filtered.
func (a *OpenAIAgent) buildChatMessages() []ChatMessage {
	snap := a.cfg.Reasoning.Replay(a.history.Snapshot(), a.cfg.KeepThinkTurns)
	out := make([]ChatMessage, 0, len(snap))
	for _, m := range snap {
		out = append(out, ChatMessage{
			Role:             m.Role,
			Content:          m.Content,
			ReasoningContent: m.ReasoningContent,
			ToolCalls:        m.ToolCalls,
			ToolCallID:       m.ToolCallID,
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
