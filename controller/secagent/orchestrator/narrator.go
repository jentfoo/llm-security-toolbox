package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/secagent/agent"
)

// narratorSystemPrompt avoids word-count constraints — reasoning models echo them in output.
const narratorSystemPrompt = `You narrate autonomous security-testing agent activity to a human operator.
Provide a single concise and clearly worded sentence as a description of the activity shown here.`

// narratorMaxTokens is kept high so reasoning models aren't truncated before emitting content.
const narratorMaxTokens = 20000

// NarratorConfig tunes when and how the Narrator fires.
type NarratorConfig struct {
	Interval time.Duration // 0 disables; else min time between fires.
	Model    string        // log model ID.
	// Pool is the shared ClientPool narration calls route through — the same
	// pool every other role uses. Narration doesn't need a dedicated pool
	// because fireMu enforces "one summary firing in flight at a time" at
	// the narrator level. Pool size affects throughput for the other
	// consumers (compression, dedup, async merge), not narration's
	// serialization guarantee.
	Pool       *agent.ClientPool
	CallBudget time.Duration // per-summary call timeout; 0 defaults to 5m.
	// Summarizer handles reasoning-format specifics for the summary model
	// itself (e.g. pulling a think-tail on truncated structured output).
	// Nil defaults to the inline handler.
	Summarizer agent.ReasoningHandler
	// Parent is the context whose cancellation aborts every in-flight
	// summary HTTP call. When the controller's Run ctx is passed here,
	// ctrl+c propagates immediately to the narrator — no waiting on
	// CallBudget. Nil defaults to context.Background() (fires complete
	// naturally; Close still aborts via its own cancel).
	Parent context.Context
}

// NamedAgent pairs an agent with the label used in its emitted narration
// line (e.g. "worker-3", "verifier", "director").
type NamedAgent struct {
	Name  string
	Agent *agent.OpenAIAgent
}

// Narrator buffers events and periodically dispatches summaries to a model.
// Firings are serialized so output order matches wall-clock.
type Narrator struct {
	cfg NarratorConfig
	log *Logger

	mu           sync.Mutex
	buf          []narratorEvent
	lastFireAt   time.Time
	activeAgents []NamedAgent // snapshot published by the controller; read under mu

	// fireMu is held for the whole async firing (buffer snapshot + every
	// HTTP dispatch inside runSummary). Dispatches happen sequentially in
	// a for-loop so no intra-firing serialization is needed beyond this lock.
	fireMu sync.Mutex
	wg     sync.WaitGroup // so Close can wait on the last in-flight firing.

	// armed gates firing until at least one substantive event has been
	// observed (worker turn, tool done, finding, decision). Phase
	// transitions and iteration-start events at run startup buffer normally
	// but do NOT trigger narration — the first narrator call would block on
	// a pool slot before any real work has happened, delaying the agent's
	// first turn. Sticky once set: armed never resets.
	armed bool

	// shutdownCtx is the parent context for every in-flight summary HTTP
	// call. Cancelled by Close so ctrl+c aborts summaries immediately
	// instead of waiting up to CallBudget per queued call.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	tickerStop chan struct{} // closed by Close to stop the background ticker.
	closed     bool
}

type narratorEvent struct {
	ts     time.Time
	tag    string
	msg    string
	fields map[string]any
}

// NewNarrator returns a Narrator or nil if cfg.Interval <= 0 (disabled).
// A background ticker goroutine is started that calls Tick() every Interval
// so periodic narration fires without requiring external trigger calls.
func NewNarrator(cfg NarratorConfig, log *Logger) *Narrator {
	if cfg.Interval <= 0 || cfg.Pool == nil || cfg.Model == "" {
		return nil
	}
	if cfg.CallBudget <= 0 {
		cfg.CallBudget = 300 * time.Second
	}
	if cfg.Summarizer == nil {
		cfg.Summarizer = agent.NewReasoningHandler(agent.ReasoningFormatInline)
	}
	parent := cfg.Parent
	if parent == nil {
		parent = context.Background()
	}
	shutdownCtx, shutdownCancel := context.WithCancel(parent)
	n := &Narrator{
		cfg:            cfg,
		log:            log,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
		tickerStop:     make(chan struct{}),
	}
	n.wg.Add(1)
	go n.runTicker()
	return n
}

// runSummaryCall acquires a pool client so narration respects the concurrency budget.
func (n *Narrator) runSummaryCall(ctx context.Context, fn func(agent.ChatClient) error) error {
	client, err := n.cfg.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer n.cfg.Pool.Release(client)
	return fn(client)
}

func (n *Narrator) runTicker() {
	defer n.wg.Done()
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-n.tickerStop:
			return
		case <-t.C:
			n.Tick()
		}
	}
}

// isUsableNarration filters out summary outputs that aren't a natural-language
// sentence (single tokens, XML-ish tags). Minimum bar is "contains whitespace".
func isUsableNarration(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return strings.ContainsAny(s, " \t\n")
}

// SetActiveAgents publishes the agents the next firing should summarize.
// The narrator takes its own copy.
func (n *Narrator) SetActiveAgents(agents []NamedAgent) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.activeAgents = append(n.activeAgents[:0], agents...)
	n.mu.Unlock()
}

// Record buffers one event. Lightweight and safe to call from hot paths.
// Also toggles the armed gate once a substantive event arrives so startup
// phase-transitions and seeded-worker events don't force a no-context
// summary before any real work has happened.
func (n *Narrator) Record(tag, msg string, fields map[string]any) {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.buf = append(n.buf, narratorEvent{
		ts: time.Now(), tag: tag, msg: msg, fields: fields,
	})
	if !n.armed && isSubstantiveNarrationEvent(tag, msg) {
		n.armed = true
	}
	n.mu.Unlock()
}

// isSubstantiveNarrationEvent identifies events that indicate real agent
// activity worth narrating. Anything else — phase transitions, iteration
// boundaries, initial worker spawning, server lifecycle — may have been
// buffered already but is not sufficient reason to fire a summary.
func isSubstantiveNarrationEvent(tag, msg string) bool {
	switch tag {
	case "worker":
		return msg == "turn"
	case "tool":
		return msg == toolMsgDone || msg == toolMsgSlow || msg == toolMsgTimeout
	case "finding":
		return msg == "written"
	case "decision":
		return true
	}
	return false
}

// Tick is called by the main loop to give the narrator a chance to fire
// based on cadence. Safe to call every iteration — it no-ops if nothing
// has changed since the last fire or if no substantive event has armed
// the narrator yet.
func (n *Narrator) Tick() {
	if n == nil {
		return
	}
	n.mu.Lock()
	now := time.Now()
	shouldFire := n.armed && len(n.buf) > 0 && now.Sub(n.lastFireAt) >= n.cfg.Interval
	n.mu.Unlock()
	if shouldFire {
		n.fireAsync()
	}
}

// TriggerNow forces a firing regardless of cadence. Use at phase transitions,
// finding writes, and decision applications so narration stays in sync with
// human-meaningful events. No-op until the narrator has been armed by a
// substantive event, so startup phase transitions don't force a pre-work
// summary that would block the first worker turn on a pool slot.
func (n *Narrator) TriggerNow() {
	if n == nil {
		return
	}
	n.mu.Lock()
	skip := !n.armed || len(n.buf) == 0
	n.mu.Unlock()
	if skip {
		return
	}
	n.fireAsync()
}

// fireAsync spawns a single serialised firing. Buffer is snapshotted INSIDE
// the firing goroutine (under fireMu + mu) so coalesced triggers always grab
// the latest events rather than stale ones. We intentionally do NOT short-
// circuit on n.closed here: a firing that was scheduled before shutdown must
// still emit its events, otherwise Close() loses in-flight narrations.
func (n *Narrator) fireAsync() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.fireMu.Lock()
		defer n.fireMu.Unlock()

		n.mu.Lock()
		if len(n.buf) == 0 {
			n.mu.Unlock()
			return
		}
		snapshot := n.buf
		n.buf = nil
		n.lastFireAt = time.Now()
		n.mu.Unlock()

		n.runSummary(snapshot)
	}()
}

// runSummary dispatches one orchestrator-level event summary plus one
// per-active-agent status summary sequentially, under a single shared
// timeout. Serial execution pins narration to at most one pool slot at
// any moment, so the configured concurrency budget stays intact while
// agents keep using the remaining slots. Every outcome — success, empty
// response, or error — is logged so silent drops don't happen; previously
// an empty line from a reasoning model that burned its whole MaxTokens on
// a <think> block left no trace at all.
func (n *Narrator) runSummary(events []narratorEvent) {
	// Parent derived from shutdownCtx — Close cancels it so ctrl+c aborts
	// any in-flight summary HTTP call instead of waiting up to CallBudget.
	ctx, cancel := context.WithTimeout(n.shutdownCtx, n.cfg.CallBudget)
	defer cancel()

	// If shutdown has already fired, skip entirely rather than acquiring
	// a pool slot just to discover the ctx is cancelled inside Acquire.
	if ctx.Err() != nil {
		return
	}

	n.mu.Lock()
	agents := append([]NamedAgent(nil), n.activeAgents...)
	n.mu.Unlock()

	n.runOrchestratorSummary(ctx, events)
	for _, na := range agents {
		if ctx.Err() != nil {
			return
		}
		if na.Agent == nil || na.Name == "" {
			continue
		}
		n.runAgentSummary(ctx, na)
	}
}

func (n *Narrator) runOrchestratorSummary(ctx context.Context, events []narratorEvent) {
	body := buildNarratorPrompt(events)
	var resp agent.ChatResponse
	err := n.runSummaryCall(ctx, func(client agent.ChatClient) error {
		var e error
		resp, e = client.CreateChatCompletion(ctx, agent.ChatRequest{
			Model: n.cfg.Model,
			Messages: []agent.ChatMessage{
				{Role: "system", Content: narratorSystemPrompt},
				{Role: "user", Content: body},
			},
			MaxTokens:       narratorMaxTokens,
			ReasoningEffort: agent.SummaryReasoningEffort,
		})
		return e
	})
	if err != nil {
		if n.log != nil {
			n.log.Log("narrate", "orchestrator: error", map[string]any{
				"err": err.Error(),
			})
		}
		return
	}
	// Confident line first: Extract runs the full defensive cascade
	// (strip think/fences, parse JSON wrappers, salvage Final:/Output:
	// markers). Fall back to Tail only when no usable line was found.
	if line := n.cfg.Summarizer.Extract(resp); isUsableNarration(line) {
		if n.log != nil {
			n.log.Log("narrate", "orchestrator: "+line, map[string]any{
				"events": len(events),
			})
		}
		return
	}
	if tail := n.cfg.Summarizer.Tail(resp); tail != "" {
		if n.log != nil {
			n.log.Log("narrate", "orchestrator: …thinking: "+tail, map[string]any{
				"events":          len(events),
				"truncated_think": true,
			})
		}
		return
	}
	if n.log != nil {
		n.log.Log("narrate", "orchestrator: empty", map[string]any{
			"events":     len(events),
			"tokens_out": resp.Usage.CompletionTokens,
		})
	}
}

func (n *Narrator) runAgentSummary(ctx context.Context, na NamedAgent) {
	var line, tail string
	err := n.runSummaryCall(ctx, func(client agent.ChatClient) error {
		var e error
		// Pass the narrator's summary model so per-agent summaries run
		// through it (and honor its reasoning_effort contract) rather than
		// the agent's own model — keeps all summary traffic targeting one
		// model regardless of which worker/verifier/director we're
		// summarizing.
		line, tail, e = agent.SummarizeStatusVia(ctx, na.Agent, client, n.cfg.Model, narratorMaxTokens)
		return e
	})
	tokens, max := na.Agent.EffectiveContextUsage()
	pct := formatContextPercent(tokens, max)
	ctxField := map[string]any{
		"context_usage":  pct,
		"context_tokens": tokens,
	}
	mergeFields := func(extra map[string]any) map[string]any {
		out := make(map[string]any, len(ctxField)+len(extra))
		for k, v := range ctxField {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	prefix := "agent (" + na.Name + "): "
	if err != nil {
		if n.log != nil {
			n.log.Log("narrate", prefix+"error", mergeFields(map[string]any{"err": err.Error()}))
		}
		return
	}
	if isUsableNarration(line) {
		if n.log != nil {
			n.log.Log("narrate", prefix+line, mergeFields(nil))
		}
		return
	}
	if tail != "" {
		if n.log != nil {
			n.log.Log("narrate", prefix+"…thinking: "+tail, mergeFields(map[string]any{"truncated_think": true}))
		}
		return
	}
	if n.log != nil {
		n.log.Log("narrate", prefix+"empty", mergeFields(nil))
	}
}

// formatContextPercent renders tokens/max as a "23%" string. Returns "?"
// when max is non-positive (effective max not yet established).
func formatContextPercent(tokens, max int) string {
	if max <= 0 {
		return "?"
	}
	pct := float64(tokens) * 100 / float64(max)
	if pct < 0 {
		pct = 0
	}
	rounded := int(pct + 0.5)
	// Clamp the rendered value at 99% so the operator's "we hit the wall"
	// signal isn't muddied by floating-point overshoot at boundary cases.
	if rounded >= 100 {
		rounded = 99
	}
	return fmt.Sprintf("%d%%", rounded)
}

// Close stops the ticker, cancels in-flight summaries, and waits for
// pending firings to return. Does not flush — shutdown is terminal.
//
// Cancel order matters: shutdownCancel must fire BEFORE wg.Wait so
// in-flight summary HTTP calls see context cancellation and return
// promptly. Otherwise wg.Wait could block for up to NarrateTimeout
// (15min default) after run completion.
func (n *Narrator) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	alreadyClosed := n.closed
	n.closed = true
	n.mu.Unlock()
	if !alreadyClosed {
		close(n.tickerStop)
	}
	n.shutdownCancel()
	n.wg.Wait()
}

// buildNarratorPrompt renders events as a compact plaintext log the summary
// model can read. Fields are emitted in a stable order (role, worker_id
// first, then alphabetic) to keep the prompt deterministic.
func buildNarratorPrompt(events []narratorEvent) string {
	var b strings.Builder
	b.WriteString("Events since last narration:\n")
	for _, e := range events {
		b.WriteString(e.ts.Format("15:04:05"))
		b.WriteString(" [")
		b.WriteString(e.tag)
		b.WriteString("] ")
		b.WriteString(e.msg)
		// Put role / worker_id first for readability, then the rest alphabetic.
		if v, ok := e.fields["role"]; ok {
			fmt.Fprintf(&b, " role=%s", formatPrettyValue(v))
		}
		if v, ok := e.fields["worker_id"]; ok {
			fmt.Fprintf(&b, " worker_id=%s", formatPrettyValue(v))
		}
		keys := make([]string, 0, len(e.fields))
		for k := range e.fields {
			if k == "role" || k == "worker_id" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, formatPrettyValue(e.fields[k]))
		}
		b.WriteByte('\n')
	}
	return b.String()
}
