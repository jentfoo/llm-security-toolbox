package orchestrator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// scriptedClient returns a canned response and optionally blocks until a
// release channel is closed, so tests can coordinate concurrent firings.
// inFlight/peak track the concurrency level observed across calls so tests
// can assert bounds (e.g. that summary serialization keeps peak ≤ 1).
// requests captures every incoming ChatRequest so tests can assert what
// params (reasoning_effort, chat_template_kwargs, max_tokens) were sent.
type scriptedClient struct {
	mu       sync.Mutex
	calls    int32
	inFlight int32
	peak     int32
	response string
	err      error
	gate     chan struct{} // if non-nil, each call blocks on it
	requests []agent.ChatRequest
}

func (c *scriptedClient) CreateChatCompletion(ctx context.Context, req agent.ChatRequest) (agent.ChatResponse, error) {
	atomic.AddInt32(&c.calls, 1)
	cur := atomic.AddInt32(&c.inFlight, 1)
	defer atomic.AddInt32(&c.inFlight, -1)
	for {
		prev := atomic.LoadInt32(&c.peak)
		if cur <= prev || atomic.CompareAndSwapInt32(&c.peak, prev, cur) {
			break
		}
	}
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return agent.ChatResponse{}, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, req)
	if c.err != nil {
		return agent.ChatResponse{}, c.err
	}
	return agent.ChatResponse{Content: c.response}, nil
}

// poolOf wraps a single client in a size-1 ClientPool for narrator tests
// that don't care about concurrency. For tests that do care, construct the
// pool directly with the desired capacity.
func poolOf(c agent.ChatClient) *agent.ClientPool {
	return agent.NewClientPoolWithClients([]agent.ChatClient{c})
}

// structuredRespClient always returns a response with an empty Content and
// the given ReasoningContent — simulates a structured-format reasoning
// model that burned its budget on the dedicated reasoning field.
type structuredRespClient struct {
	reasoning string
}

func (c *structuredRespClient) CreateChatCompletion(context.Context, agent.ChatRequest) (agent.ChatResponse, error) {
	return agent.ChatResponse{Content: "", ReasoningContent: c.reasoning}, nil
}

func TestNarrator_DisabledWhenIntervalZero(t *testing.T) {
	t.Parallel()
	n := NewNarrator(NarratorConfig{
		Interval: 0,
		Model:    "m",
		Pool:     poolOf(&scriptedClient{response: "ok"}),
	}, nil)
	assert.Nil(t, n, "zero interval must return nil so callers no-op")
}

func TestNarrator_RecordAndTriggerEmitSummary(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "worker is scanning endpoints"}
	l, path, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval:   time.Millisecond,
		Model:      "m",
		Pool:       poolOf(client),
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
	assert.Contains(t, buf.String(), "orchestrator: worker is scanning endpoints")
	assert.Contains(t, mustReadFile(t, path), `"msg":"orchestrator: worker is scanning endpoints"`)
}

func TestNarrator_CoalescesConcurrentFires(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	client := &scriptedClient{response: "narrated", gate: gate}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow() // firing #1 blocks on gate
	// Wait for firing #1 to acquire fireMu
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&client.calls) == 1
	}, time.Second, time.Millisecond)

	// Second batch of events; trigger 3 more fires while #1 still blocked.
	n.Record("finding", "written", map[string]any{"title": "x"})
	n.TriggerNow()
	n.TriggerNow()
	n.TriggerNow()

	// Release firing #1.
	close(gate)
	n.Close()
	_ = l.Close()

	// Firings 2/3/4 coalesce: at most one additional summary should fire
	// because by the time the fireMu is released, all buffered events have
	// been consumed by one of the waiting goroutines. We expect exactly 2
	// model calls total (1 blocked + 1 draining the coalesced tail).
	calls := atomic.LoadInt32(&client.calls)
	assert.GreaterOrEqual(t, calls, int32(2))
	assert.LessOrEqual(t, calls, int32(3), "concurrent triggers must coalesce")
}

func TestNarrator_FailureDoesNotPanic(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{err: errors.New("boom")}
	l, path, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	logged := mustReadFile(t, path)
	assert.Contains(t, logged, `"msg":"orchestrator: error"`, "failure logs to file")
	assert.Contains(t, logged, "boom")
}

func TestNarrator_CloseDoesNotFlush(t *testing.T) {
	t.Parallel()
	// Close is a shutdown signal — it must NOT fire a final summary. The
	// operator pressed ctrl+c to quit, not to wait another 10-15s for one
	// more summary. Buffer contents at Close are dropped.
	client := &scriptedClient{response: "would-be final narration"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Hour, // never self-ticks
		Model:    "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("finding", "written", map[string]any{"title": "leftover"})
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls),
		"Close must not dispatch a summary — shutdown should be prompt")
	assert.NotContains(t, buf.String(), "would-be final narration")
}

func TestNarrator_ParentCtxCancelAbortsInFlightSummary(t *testing.T) {
	t.Parallel()
	// Summary in flight when the parent context cancels (e.g. ctrl+c on
	// the controller's Run ctx) must receive the cancellation so shutdown
	// doesn't wait up to CallBudget for the HTTP call to finish naturally.
	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	gate := make(chan struct{})
	client := &scriptedClient{response: "narrated", gate: gate}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client),
		CallBudget: time.Minute, // generous — we want to prove cancel, not timeout
		Parent:     parentCtx,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1})
	n.TriggerNow()
	// Wait for the fire to acquire the scripted client (blocked on gate).
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&client.calls) >= 1
	}, time.Second, time.Millisecond)

	// Cancel parent — in-flight HTTP ctx is cancelled transitively.
	start := time.Now()
	parentCancel()
	n.Close()
	elapsed := time.Since(start)
	// Release the scripted client's goroutine so it can finish cleanly.
	close(gate)
	_ = l.Close()

	assert.Less(t, elapsed, 5*time.Second,
		"parent ctx cancel must abort in-flight summaries, not wait on CallBudget")
}

func TestNarrator_TickRespectsInterval(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "tick-ok"}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: 50 * time.Millisecond,
		Model:    "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1})
	n.Tick() // inside interval, must NOT fire
	assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls))

	// Force lastFireAt into the past so the next Tick can fire.
	n.mu.Lock()
	n.lastFireAt = time.Now().Add(-time.Second)
	n.mu.Unlock()
	n.Tick()
	n.Close()
	_ = l.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
}

func TestNarrator_SuppressedUntilSubstantiveEvent(t *testing.T) {
	t.Parallel()
	// Startup burst — phase transitions, iteration starts, worker seeded —
	// all buffer normally but the narrator must NOT fire; acquiring a pool
	// slot before any real work has happened would delay the agent's first
	// turn. Once a substantive event arrives (worker/turn, tool/done,
	// finding/written, decision/*) the next trigger is honored.
	client := &scriptedClient{response: "narration fired"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client),
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	// Pre-work events only.
	n.Record("controller", "transition phase idle to autonomous", nil)
	n.Record("controller", "iteration start", map[string]any{"iter": 1})
	n.Record("worker", "seeded", map[string]any{"id": 1})
	n.TriggerNow()
	// Give any (incorrect) async firing a chance to run.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls),
		"narrator must not fire until a substantive event has been recorded")

	// Now simulate a real worker turn — arms the narrator.
	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls), "first fire lands after arming")
	assert.Contains(t, buf.String(), "narration fired")
}

func TestNarrator_AgentProviderFiresPerAgent(t *testing.T) {
	t.Parallel()
	// One scripted client backs both the orchestrator event-summary and
	// every per-agent SummarizeStatusVia call. Narrator shares the same
	// ClientPool as the agents — matching the runtime configuration — so
	// summary traffic counts against the configured concurrency budget.
	client := &scriptedClient{response: "current focus"}
	l, path, buf := newCapturedLogger(t)

	pool := agent.NewClientPoolWithClients([]agent.ChatClient{client})
	a1 := agent.NewOpenAIAgent(agent.OpenAIAgentConfig{Model: "m", Pool: pool, SystemPrompt: "sys"})
	a1.Query("worker-1 assignment")
	a2 := agent.NewOpenAIAgent(agent.OpenAIAgentConfig{Model: "m", Pool: pool, SystemPrompt: "sys"})
	a2.Query("worker-2 assignment")

	n := NewNarrator(NarratorConfig{
		Interval:   time.Millisecond,
		Model:      "m",
		Pool:       pool,
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)
	n.SetActiveAgents([]NamedAgent{
		{Name: "worker-1", Agent: a1},
		{Name: "worker-2", Agent: a2},
	})

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(3), atomic.LoadInt32(&client.calls), "orchestrator + 2 agent calls")
	assert.Equal(t, int32(1), atomic.LoadInt32(&client.peak),
		"fireMu + sequential dispatch must serialize — peak concurrent summary calls must not exceed 1")

	content := buf.String()
	assert.Contains(t, content, "orchestrator: current focus")
	assert.Contains(t, content, "agent (worker-1): current focus")
	assert.Contains(t, content, "agent (worker-2): current focus")

	jsonLog := mustReadFile(t, path)
	assert.Contains(t, jsonLog, `"msg":"agent (worker-1): current focus"`)
	assert.Contains(t, jsonLog, `"msg":"agent (worker-2): current focus"`)
	assert.NotContains(t, jsonLog, `"role":`, "role field must not be emitted for narrate events")
	assert.NotContains(t, jsonLog, `"agent":`, "agent field must not be emitted for narrate events")
}

func TestNarrator_PerAgentSummaryUsesSummaryModel(t *testing.T) {
	t.Parallel()
	// Per-agent status summaries must go through the narrator's configured
	// summary model, NOT the agent's own model. Otherwise an abliterated
	// worker model receives reasoning_effort=none and LM Studio logs
	// warnings; consolidating on the summary model eliminates that and
	// keeps summary behavior consistent across agents.
	client := &scriptedClient{response: "status"}
	l, _, _ := newCapturedLogger(t)

	agentPool := agent.NewClientPoolWithClients([]agent.ChatClient{client})
	worker := agent.NewOpenAIAgent(agent.OpenAIAgentConfig{
		Model: "worker-model-abliterated",
		Pool:  agentPool,
	})
	worker.Query("worker assignment")

	n := NewNarrator(NarratorConfig{
		Interval:   time.Millisecond,
		Model:      "summary-model",
		Pool:       agentPool,
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)
	n.SetActiveAgents([]NamedAgent{{Name: "worker-1", Agent: worker}})

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Len(t, client.requests, 2, "orchestrator event summary + 1 per-agent summary")
	perAgentReq := client.requests[1]
	assert.Equal(t, "summary-model", perAgentReq.Model,
		"per-agent summary must target the summary model, not the agent's own model")
	assert.Equal(t, "none", perAgentReq.ReasoningEffort,
		"per-agent summary must still carry reasoning_effort=none")
}

func TestNarrator_EmptyResponseLogsEmptyAndSkipsStderr(t *testing.T) {
	t.Parallel()
	// Entire response is a closed think block with nothing after; after
	// stripping, the line is "" and there is no unclosed-think fallback.
	// The JSON file must capture the "empty" event (so operators can
	// diagnose a misbehaving summary model) but stderr must stay clean
	// so these events don't drown out real activity.
	client := &scriptedClient{response: "<think>plan</think>"}
	l, path, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	jsonLog := mustReadFile(t, path)
	assert.Contains(t, jsonLog, `"msg":"orchestrator: empty"`, "empty summary must log to file for diagnostics")
	assert.NotContains(t, buf.String(), "empty",
		"narrate empty must NOT mirror to stderr — keeps the operator's terminal clean")
}

func TestNarrator_StripsCodeFenceFromResponse(t *testing.T) {
	t.Parallel()
	// Reasoning model wraps its answer in a fenced code block — naively
	// surfacing firstLine would emit just "```" as the narrated sentence.
	// The fence stripper must peel both ends so actual prose reaches stderr.
	client := &scriptedClient{response: "```\nworker is scanning OAuth endpoints\n```"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	out := buf.String()
	assert.Contains(t, out, "orchestrator: worker is scanning OAuth endpoints")
	assert.NotContains(t, out, "narrate] ```", "bare fence must not be surfaced as the summary line")
}

func TestNarrator_SummaryCallsDisableReasoning(t *testing.T) {
	t.Parallel()
	// Summary traffic (orchestrator event-summary + per-agent via
	// SummarizeStatusVia) must forward reasoning_effort=none so backends
	// that honor it (LM Studio-hosted qwen3, o-series) skip reasoning;
	// backends that don't ignore silently. Worker/verifier/director drains
	// remain unchanged — covered separately in
	// TestOpenAIAgent_DrainDoesNotSetReasoningEffortOrTemplateKwargs.
	client := &scriptedClient{response: "all good"}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client),
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Len(t, client.requests, 1)
	req := client.requests[0]
	assert.Equal(t, "none", req.ReasoningEffort, "orchestrator summary must disable reasoning")
}

func TestNarrator_StructuredFinalMarkerSurfacesAsCleanLine(t *testing.T) {
	t.Parallel()
	// Real-world case: summary model emits meta-chatter inside reasoning
	// and ends with "Final: <actual summary>". Handler.Extract should
	// salvage the sentence after the marker so the narrator logs a clean
	// "orchestrator: <sentence>" — NOT the "…thinking:" fallback.
	structured := &structuredRespClient{reasoning: "Thinking... Matches constraints. Output matches.✅ Final: worker-1 scanned the admin OAuth client registration endpoint."}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval:   time.Millisecond,
		Model:      "m",
		Pool:       poolOf(structured),
		CallBudget: time.Second,
		Summarizer: agent.NewReasoningHandler(agent.ReasoningFormatStructured),
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	out := buf.String()
	assert.Contains(t, out, "orchestrator: worker-1 scanned the admin OAuth client registration endpoint.")
	assert.NotContains(t, out, "…thinking:", "marker-extracted output must not wear the thinking prefix")
}

func TestNarrator_StructuredReasoningTailSurfaces(t *testing.T) {
	t.Parallel()
	// When the summary model emits reasoning via the structured
	// reasoning_content field (no <think> tags in content), the narrator
	// must still surface a thought fragment via the Summarizer handler
	// rather than logging `empty`.
	client := &scriptedClient{}
	client.response = "" // will not be hit on the response path; use onCall below
	// scriptedClient only populates Content, so stub by swapping for a
	// client that returns the structured field directly.
	structured := &structuredRespClient{reasoning: "probing the admin OAuth client registration flow"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m",
		Pool:       poolOf(structured),
		CallBudget: time.Second,
		Summarizer: agent.NewReasoningHandler(agent.ReasoningFormatStructured),
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	out := buf.String()
	assert.Contains(t, out, "orchestrator: …thinking:")
	assert.Contains(t, out, "admin OAuth client registration flow")
	assert.NotContains(t, out, "empty")
}

func TestNarrator_UnclosedThinkFallsBackToThinkingTail(t *testing.T) {
	t.Parallel()
	// Reasoning model was truncated mid-think (no closing tag). Instead of
	// logging "empty", narrator surfaces the tail of the thought as a
	// best-effort signal so the operator sees what the model was working on.
	client := &scriptedClient{response: "<think>I am about to test the admin client registration endpoint for mass assignment"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	out := buf.String()
	assert.Contains(t, out, "orchestrator: …thinking:")
	assert.Contains(t, out, "admin client registration endpoint for mass assignment")
	assert.NotContains(t, out, "empty", "fallback path should not log the empty event")
}

func TestNarrator_NoActiveAgentsKeepsOrchestratorOnly(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "only orchestrator"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)
	// No SetActiveAgents call.

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls), "no active agents → orchestrator-only")
	assert.Contains(t, buf.String(), "orchestrator: only orchestrator")
}

func TestShouldNarrate(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"controller|phase":     true,
		"decision|expand":      true,
		"finding|written":      true,
		"tool|start":           true,
		"tool|done":            true,
		"tool|other":           false,
		"agent|response":       true,
		"agent|request":        false,
		"agent|malformed-args": false,
		"worker|turn":          true,
		"server|models":        false,
	}
	for key, want := range cases {
		t.Run(key, func(t *testing.T) {
			i := 0
			for ; i < len(key); i++ {
				if key[i] == '|' {
					break
				}
			}
			assert.Equal(t, want, shouldNarrate(key[:i], key[i+1:]))
		})
	}
}
