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
	// Reasoning is the format-specific reasoning handler. Nil defaults to
	// the inline handler.
	Reasoning ReasoningHandler
	// OnCompact is called with each compaction report (optional).
	OnCompact func(CompactionReport)
	// OnContextOverflow fires once per sendWithRetry call when the model
	// rejected the request as over-context (optional).
	OnContextOverflow func()
	// OnSummarizeBoundary receives messages eligible for summarization and
	// returns a replacement slice or error. Optional; nil disables this step.
	OnSummarizeBoundary func(ctx context.Context, snapshot []Message) ([]Message, error)
	// OnSummarizeError fires when OnSummarizeBoundary returned an error
	// (optional).
	OnSummarizeError func(err error)
	// OnSelfPruneCandidates receives a history snapshot and returns the set
	// of ToolCallIDs to drop. Optional; nil disables this step.
	OnSelfPruneCandidates func(ctx context.Context, snapshot []Message) ([]string, error)
	// OnDistillResults receives a history snapshot and returns a rewritten
	// snapshot where eligible tool-result Content is replaced. Callers must
	// preserve message order and pairing. Optional; nil disables this step.
	OnDistillResults func(ctx context.Context, snapshot []Message) ([]Message, error)
	// OnToolStart fires before a tool handler runs (optional).
	OnToolStart func(name string, args json.RawMessage)
	// OnToolEnd fires after a tool handler returns (optional). timedOut is
	// true when PerToolTimeout fired. errText is truncated result text when
	// isError is true, else empty.
	OnToolEnd func(name string, args json.RawMessage, elapsed time.Duration, isError, timedOut bool, errText string)
	// OnMalformedCall is called when tool arg repair fails (optional).
	OnMalformedCall func(name string, err error)
	// OnFuzzyToolMatch fires when a tool-name lookup miss was recovered via
	// fuzzy fallback. received is the model-emitted name; resolved is the
	// registered name that ran.
	OnFuzzyToolMatch func(received, resolved string)
	// OnRequestStart fires before each chat-completion HTTP call (optional).
	OnRequestStart func(attempt int)
	// OnRequestEnd fires after each chat-completion HTTP call (optional).
	OnRequestEnd func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error)
	// FlowIDExtractor (optional) extracts flow IDs from inputs/results/text.
	FlowIDExtractor func(sources ...any) []string
	// Rand is the randomness source used by retry backoff jitter. nil → the
	// package default.
	Rand *rand.Rand
	// RetireOnPressure disables compaction. When usage crosses the high
	// watermark the next Drain round returns immediately with
	// EscalationReason="context_exhausted".
	RetireOnPressure bool
}

// OpenAIAgent implements Agent over an OpenAI-compatible endpoint.
type OpenAIAgent struct {
	cfg      OpenAIAgentConfig
	history  *History
	toolDefs []ToolDef
	tools    []ChatTool
	handlers map[string]ToolHandler
	// canonHandlers/canonNames provide fallback lookup when a model emits a
	// near-miss tool name (e.g. `mcp_sectool__proxy_poll` instead of
	// `mcp__sectool__proxy_poll`). Keyed by canonicalToolName.
	canonHandlers map[string]ToolHandler
	canonNames    map[string]string
	mu            sync.Mutex
	cancelCtx     func()
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
	a.canonHandlers = make(map[string]ToolHandler, len(defs))
	a.canonNames = make(map[string]string, len(defs))
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
			c := canonicalToolName(d.Name)
			// First-write wins on canonical collisions — if two registered
			// names canonicalize the same way, only the first is reachable
			// via fuzzy fallback. Exact lookups still distinguish them.
			if _, exists := a.canonHandlers[c]; !exists {
				a.canonHandlers[c] = d.Handler
				a.canonNames[c] = d.Name
			}
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
// ceiling that the agent will be measured against on the next send.
func (a *OpenAIAgent) EffectiveContextUsage() (tokens, max int) {
	return a.history.EstimateTokens(), a.history.EffectiveMaxContext()
}

// History returns the agent's underlying history.
func (a *OpenAIAgent) History() *History { return a.history }

// Snapshot returns a shallow copy of the agent's message history.
func (a *OpenAIAgent) Snapshot() []Message { return a.history.Snapshot() }

// LastHistoryID returns the HistoryID of the last non-system message, or 0
// when only the system message (or nothing) is present.
func (a *OpenAIAgent) LastHistoryID() uint64 {
	snap := a.history.Snapshot()
	if len(snap) == 0 {
		return 0
	}
	last := snap[len(snap)-1]
	if last.Role == roleSystem {
		return 0
	}
	return last.HistoryID
}

// SnapshotSinceID returns post-system messages following the message with
// HistoryID == id, normalized via Reasoning.ForSummary. When id is 0 or has
// been compacted away, returns all post-system messages.
func (a *OpenAIAgent) SnapshotSinceID(id uint64) []Message {
	snap := a.history.Snapshot()
	if len(snap) == 0 {
		return nil
	}
	start := 0
	if snap[0].Role == roleSystem {
		start = 1
	}
	if id != 0 {
		for i := start; i < len(snap); i++ {
			if snap[i].HistoryID == id {
				start = i + 1
				break
			}
		}
	}
	if start >= len(snap) {
		return nil
	}
	tail := snap[start:]
	return a.cfg.Reasoning.ForSummary(tail)
}

// ReplaceHistory replaces the agent's working memory with msgs. If msgs[0]
// is not a system message and the agent was constructed with a SystemPrompt,
// the system message is re-prepended. Cancels any in-flight Drain and resets
// iteration-boundary state. Tools and handlers are untouched.
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
// the active iteration's content.
func (a *OpenAIAgent) MarkIterationBoundary() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.iterationStartIdx = a.history.Len()
	a.iterationSummarized = false
}

// IterationBoundary returns the current iteration-boundary index.
func (a *OpenAIAgent) IterationBoundary() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.iterationStartIdx
}

// SetOnSummarizeBoundary swaps in a new boundary-summarize callback.
func (a *OpenAIAgent) SetOnSummarizeBoundary(f func(ctx context.Context, snapshot []Message) ([]Message, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.OnSummarizeBoundary = f
}

// SetOnSelfPruneCandidates swaps in a new self-prune callback.
func (a *OpenAIAgent) SetOnSelfPruneCandidates(f func(ctx context.Context, snapshot []Message) ([]string, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.OnSelfPruneCandidates = f
}

// SetOnDistillResults swaps in a new distill callback.
func (a *OpenAIAgent) SetOnDistillResults(f func(ctx context.Context, snapshot []Message) ([]Message, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.OnDistillResults = f
}

// Drain runs the dispatch loop and returns one TurnSummary.
func (a *OpenAIAgent) Drain(ctx context.Context) (TurnSummary, error) {
	return a.DrainBounded(ctx, a.cfg.MaxTurnsPerAgent)
}

// DrainBounded runs the dispatch loop, capping tool-dispatch rounds at
// maxRounds. A value <= 0 falls back to the configured MaxTurnsPerAgent.
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
			if errors.Is(err, errRetireOnPressure) {
				// RetireOnPressure agents (currently: recon worker) hit
				// the high-watermark and stop cleanly so the controller
				// can retire and summarize the full chronicle. This is a
				// successful end-of-work signal, not a failure — return
				// nil error so the autonomous loop treats it like any
				// other turn boundary.
				summary.EscalationReason = escalationContextExhausted
				return summary, nil
			}
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

// dispatchToolCalls runs handlers for calls and folds each outcome into
// history and summary in original order.
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

// runSingleTool invokes one handler with the per-tool timeout and start/end
// callbacks, returning a self-contained outcome. Safe for concurrent use.
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
	if !known {
		// Fuzzy-fallback: lower + collapse runs of '_' so the most common
		// model typos (single-vs-double underscore in MCP-prefixed names,
		// stray casing) still route to the real handler. We do NOT rewrite
		// tc.Function.Name in history — the assistant message records what
		// the model emitted, so re-render passes are stable.
		c := canonicalToolName(tc.Function.Name)
		if h, ok := a.canonHandlers[c]; ok {
			handler = h
			known = true
			if a.cfg.OnFuzzyToolMatch != nil {
				a.cfg.OnFuzzyToolMatch(tc.Function.Name, a.canonNames[c])
			}
		}
	}
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
// arguments do not parse. The tool schema is embedded when known.
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

// errRetireOnPressure is returned by maybeCompact when RetireOnPressure is
// set and the high watermark has been crossed.
var errRetireOnPressure = errors.New("retire on context pressure")

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
	if a.cfg.RetireOnPressure {
		return errRetireOnPressure
	}

	opt := a.cfg.Compaction
	threshold := opt.RecoveryThreshold
	if threshold <= 0 {
		threshold = defaultRecoveryThreshold
	}
	recoveryGoal := int(float64(maxCtx) * threshold)
	startTokens := a.history.EstimateTokens()

	// Cheap, deterministic same-tool error-streak collapse first.
	r0 := a.compactErrorsOnlyPreservingBoundary()
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(r0)
	}
	if a.history.EstimateTokens() < high {
		return nil
	}

	// Model-driven self-prune of low-signal tool-call/result pairs. Only
	// fires when the previous step fell short of the recovery threshold
	// and a callback is wired.
	if startTokens-a.history.EstimateTokens() < recoveryGoal && a.cfg.OnSelfPruneCandidates != nil {
		rB := a.runSelfPrunePreservingBoundary(ctx)
		if a.cfg.OnCompact != nil {
			a.cfg.OnCompact(rB)
		}
		if a.history.EstimateTokens() < high {
			return nil
		}
	}

	// Model-driven distillation: replace old tool-result content with
	// prose summaries so load-bearing facts survive byte-count stubbing.
	if startTokens-a.history.EstimateTokens() < recoveryGoal && a.cfg.OnDistillResults != nil {
		rC := a.runDistillPreservingBoundary(ctx)
		if a.cfg.OnCompact != nil {
			a.cfg.OnCompact(rC)
		}
		if a.history.EstimateTokens() < high {
			return nil
		}
	}

	// Mechanical fallback (think-strip, tool-stub, text-trunc, turn-drop,
	// hard-truncate). Always runs if we still need headroom.
	r1, err := a.compactRemainderPreservingBoundary()
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(r1)
	}
	if err != nil {
		return err
	}
	if a.history.EstimateTokens() < high {
		return nil
	}

	// Boundary-summarize callback when an iteration boundary has been
	// marked, the callback is wired, and we haven't summarized yet this iteration.
	if a.cfg.OnSummarizeBoundary != nil && !a.iterationSummarized && a.iterationStartIdx > 1 {
		if err := a.runBoundarySummarize(ctx); err != nil && a.cfg.OnSummarizeError != nil {
			// Fail open and fall through to the final remainder.
			a.cfg.OnSummarizeError(err)
		}
		if a.history.EstimateTokens() < high {
			return nil
		}
	}

	// Last-resort mechanical remainder, potentially biting into in-iter content.
	r2, err := a.compactRemainderPreservingBoundary()
	if a.cfg.OnCompact != nil {
		a.cfg.OnCompact(r2)
	}
	return err
}

// compactErrorsOnlyPreservingBoundary wraps CompactErrorsOnly and rebases
// the iteration-boundary marker afterwards.
func (a *OpenAIAgent) compactErrorsOnlyPreservingBoundary() CompactionReport {
	markerID, hasMarker := a.iterationBoundaryMarker()
	report := CompactErrorsOnly(a.history, a.cfg.Compaction)
	a.rebaseIterationBoundary(markerID, hasMarker)
	return report
}

// compactRemainderPreservingBoundary wraps CompactRemainder and rebases
// the iteration-boundary marker afterwards.
func (a *OpenAIAgent) compactRemainderPreservingBoundary() (CompactionReport, error) {
	markerID, hasMarker := a.iterationBoundaryMarker()
	report, err := CompactRemainder(a.history, a.cfg.Compaction)
	a.rebaseIterationBoundary(markerID, hasMarker)
	return report, err
}

// runSelfPrunePreservingBoundary invokes OnSelfPruneCandidates and applies
// the returned ToolCallID drop set in place. Failures fall through with an
// empty report.
func (a *OpenAIAgent) runSelfPrunePreservingBoundary(ctx context.Context) CompactionReport {
	before := a.history.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	snap := a.history.Snapshot()
	dropIDs, err := a.cfg.OnSelfPruneCandidates(ctx, snap)
	if err != nil {
		if a.cfg.OnSummarizeError != nil {
			a.cfg.OnSummarizeError(err)
		}
		return report
	}
	if len(dropIDs) == 0 {
		return report
	}
	dropSet := make(map[string]bool, len(dropIDs))
	for _, id := range dropIDs {
		if id != "" {
			dropSet[id] = true
		}
	}
	if len(dropSet) == 0 {
		return report
	}
	markerID, hasMarker := a.iterationBoundaryMarker()
	pruned, dropped := applySelfPrune(snap, dropSet)
	if dropped == 0 {
		return report
	}
	a.history.ReplaceAll(pruned)
	a.rebaseIterationBoundary(markerID, hasMarker)
	report.SelfPrunedCalls = dropped
	report.PassesApplied = append(report.PassesApplied, "self-prune")
	report.After = a.history.EstimateTokens()
	return report
}

// runDistillPreservingBoundary invokes OnDistillResults and installs the
// returned snapshot. Counts only tool-result Content changes.
func (a *OpenAIAgent) runDistillPreservingBoundary(ctx context.Context) CompactionReport {
	before := a.history.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	snap := a.history.Snapshot()
	replacement, err := a.cfg.OnDistillResults(ctx, snap)
	if err != nil {
		if a.cfg.OnSummarizeError != nil {
			a.cfg.OnSummarizeError(err)
		}
		return report
	}
	if len(replacement) == 0 {
		return report
	}
	distilled := countDistilledChanges(snap, replacement)
	if distilled == 0 {
		return report
	}
	markerID, hasMarker := a.iterationBoundaryMarker()
	a.history.ReplaceAll(replacement)
	a.rebaseIterationBoundary(markerID, hasMarker)
	report.DistilledResults = distilled
	report.PassesApplied = append(report.PassesApplied, "distill")
	report.After = a.history.EstimateTokens()
	return report
}

// applySelfPrune drops every tool-result whose ToolCallID is in dropSet and
// strips matching ToolCall entries from preceding assistant messages.
// Returns the new slice and the count of tool-result messages dropped.
func applySelfPrune(msgs []Message, dropSet map[string]bool) ([]Message, int) {
	out := make([]Message, 0, len(msgs))
	dropped := 0
	for _, m := range msgs {
		switch m.Role {
		case roleTool:
			if dropSet[m.ToolCallID] {
				dropped++
				continue
			}
			out = append(out, m)
		case roleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, m)
				continue
			}
			kept := m
			kept.ToolCalls = filterToolCalls(m.ToolCalls, dropSet)
			if len(kept.ToolCalls) == 0 && strings.TrimSpace(kept.Content) == "" {
				continue
			}
			out = append(out, kept)
		default:
			out = append(out, m)
		}
	}
	return out, dropped
}

// countDistilledChanges returns the number of tool-result messages whose
// Content differs between before and after, paired by index.
func countDistilledChanges(before, after []Message) int {
	n := len(before)
	if len(after) < n {
		n = len(after)
	}
	changed := 0
	for i := 0; i < n; i++ {
		if before[i].Role != roleTool || after[i].Role != roleTool {
			continue
		}
		if before[i].Content != after[i].Content {
			changed++
		}
	}
	return changed
}

// compactPreservingBoundary wraps Compact and rebases iterationStartIdx
// onto the same message it originally pointed to. Clamps the boundary to
// history end if the marker message was dropped.
func (a *OpenAIAgent) compactPreservingBoundary() (CompactionReport, error) {
	markerID, hasMarker := a.iterationBoundaryMarker()
	report, err := Compact(a.history, a.cfg.Compaction)
	a.rebaseIterationBoundary(markerID, hasMarker)
	return report, err
}

func (a *OpenAIAgent) forceHardTruncatePreservingBoundary(targetTokens, keep int) CompactionReport {
	markerID, hasMarker := a.iterationBoundaryMarker()
	report := ForceHardTruncate(a.history, targetTokens, keep)
	a.rebaseIterationBoundary(markerID, hasMarker)
	return report
}

func (a *OpenAIAgent) iterationBoundaryMarker() (uint64, bool) {
	preLen := a.history.Len()
	if a.iterationStartIdx <= 0 || a.iterationStartIdx >= preLen {
		return 0, false
	}
	snap := a.history.Snapshot()
	return snap[a.iterationStartIdx].HistoryID, true
}

func (a *OpenAIAgent) rebaseIterationBoundary(markerID uint64, hasMarker bool) {
	if !hasMarker {
		if a.iterationStartIdx > a.history.Len() {
			a.iterationStartIdx = a.history.Len()
		}
		return
	}
	snap := a.history.Snapshot()
	for i := range snap {
		if snap[i].HistoryID == markerID {
			a.iterationStartIdx = i
			return
		}
	}
	a.iterationStartIdx = len(snap)
}

// runBoundarySummarize hands messages[1:iterationStartIdx] to
// OnSummarizeBoundary and splices the returned slice back into history in
// place of the snapshot.
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
// retry policy. ErrRateLimit and ErrTransientNet retry up to DrainRetryMax;
// ErrContextOverflow triggers a single in-place hard-truncate retry; other
// categories propagate immediately.
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
			report := a.forceHardTruncatePreservingBoundary(target, 2)
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

// sleepCtx sleeps for d, returning ctx.Err() if ctx cancels first. d <= 0
// is a no-op.
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

// isContextRejectedError reports whether err came from the upstream model
// rejecting the request as too large.
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
// start/end callbacks, and releases the client.
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

// buildChatMessages returns history filtered to OpenAI-compatible shape via
// the agent's reasoning handler. History storage is not mutated.
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

// synthesizePendingToolStubs appends placeholder tool-result messages for
// any assistant.tool_calls missing a paired result at the tail of history.
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
