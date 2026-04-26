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
	calls     int32
}

func (c *structuredRespClient) CreateChatCompletion(context.Context, agent.ChatRequest) (agent.ChatResponse, error) {
	atomic.AddInt32(&c.calls, 1)
	return agent.ChatResponse{Content: "", ReasoningContent: c.reasoning}, nil
}

// waitForCalls polls until the call counter reaches at least want, then
// returns. Use this after TriggerNow/Tick and BEFORE Close so the in-flight
// summary goroutine completes its HTTP call before Close's shutdownCancel
// aborts it. Without this wait the buf/calls assertions race with the
// shutdown path and flake (or fail outright when the goroutine consistently
// loses the race).
//
// Accepts both scriptedClient and structuredRespClient via the *int32 the
// test owns. Tests that don't need to assert call count can still call this
// purely to gate Close on the firing completing.
func waitForCalls(t *testing.T, calls *int32, want int32) {
	t.Helper()
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(calls) >= want
	}, 2*time.Second, time.Millisecond)
}

func TestIsUsableNarration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"whitespace_only", "   \t\n", false},
		{"single_word", "ok", false},
		{"xml_tag", "<tool_call>", false},
		{"natural_sentence", "worker 4 is probing the admin API", true},
		{"two_words", "in progress", true},
		{"leading_trailing_space_preserved", "  ok fine  ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isUsableNarration(c.in))
		})
	}
}

func TestNewNarrator_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	validPool := poolOf(&scriptedClient{response: "ok"})
	cases := []struct {
		name string
		cfg  NarratorConfig
	}{
		{"zero_interval", NarratorConfig{Interval: 0, Model: "m", Pool: validPool}},
		{"negative_interval", NarratorConfig{Interval: -time.Second, Model: "m", Pool: validPool}},
		{"nil_pool", NarratorConfig{Interval: time.Millisecond, Model: "m", Pool: nil}},
		{"empty_model", NarratorConfig{Interval: time.Millisecond, Model: "", Pool: validPool}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Nil(t, NewNarrator(c.cfg, nil))
		})
	}
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
	waitForCalls(t, &client.calls, 1)
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
	// Wait for the coalesced tail firing to complete before Close cancels
	// any in-flight goroutine.
	waitForCalls(t, &client.calls, 2)
	n.Close()
	_ = l.Close()

	// Firings 2/3/4 coalesce: at most one additional summary should fire
	// because by the time the fireMu is released, all buffered events have
	// been consumed by one of the waiting goroutines. We expect exactly 2
	// model calls total (1 blocked + 1 draining the coalesced tail).
	calls := atomic.LoadInt32(&client.calls)
	assert.GreaterOrEqual(t, calls, int32(2))
	assert.LessOrEqual(t, calls, int32(3))
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
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	logged := mustReadFile(t, path)
	assert.Contains(t, logged, `"msg":"orchestrator: error"`)
	assert.Contains(t, logged, "boom")
}

func TestNarrator_CloseDoesNotFlush(t *testing.T) {
	t.Parallel()
	// Close must not fire a final summary; buffer contents at Close are dropped
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
	// in-flight summary receives cancel transitively so shutdown doesn't wait on CallBudget
	parentCtx, parentCancel := context.WithCancel(t.Context())
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
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
}

func TestNarrator_SuppressedUntilSubstantiveEvent(t *testing.T) {
	t.Parallel()
	// narrator suppressed until a substantive event (worker/turn, tool/done, finding/written, decision/*) arms it
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
	// TriggerNow short-circuits synchronously when unarmed — no goroutine
	// is spawned, so the state check + call counter is race-free.
	n.mu.Lock()
	armed := n.armed
	n.mu.Unlock()
	assert.False(t, armed)
	assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls))

	// Now simulate a real worker turn — arms the narrator.
	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
	assert.Contains(t, buf.String(), "narration fired")
}

func TestNarrator_AgentProviderFiresPerAgent(t *testing.T) {
	t.Parallel()
	// narrator shares the agents' ClientPool so summary traffic counts against concurrency budget
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
	waitForCalls(t, &client.calls, 3)
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(3), atomic.LoadInt32(&client.calls), "orchestrator + 2 agent calls")
	assert.Equal(t, int32(1), atomic.LoadInt32(&client.peak),
		"fireMu + sequential dispatch must serialize — peak concurrent summary calls must not exceed 1")

	content := buf.String()
	assert.Contains(t, content, "orchestrator: current focus")
	assert.Contains(t, content, "agent (worker-1):")
	assert.Contains(t, content, "agent (worker-2):")

	jsonLog := mustReadFile(t, path)
	assert.Contains(t, jsonLog, `"msg":"agent (worker-1):`)
	assert.Contains(t, jsonLog, `"msg":"agent (worker-2):`)
	assert.Contains(t, jsonLog, `"context_usage":`)
	assert.NotContains(t, jsonLog, `"role":`)
	assert.NotContains(t, jsonLog, `"agent":`)
}

func TestFormatContextPercent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tokens, max int
		want        string
	}{
		{0, 1000, "0%"},
		{500, 1000, "50%"},
		{999, 1000, "99%"},
		{1000, 1000, "99%"}, // clamp at 99%
		{1500, 1000, "99%"},
		{0, 0, "?"},
		{100, 0, "?"},
		{-5, 1000, "0%"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, formatContextPercent(c.tokens, c.max),
			"tokens=%d max=%d", c.tokens, c.max)
	}
}

func TestNarrator_PerAgentSummaryUsesLogModel(t *testing.T) {
	t.Parallel()
	// per-agent summaries go through the narrator's log model, not the agent's own model
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
		Model:      "log-model",
		Pool:       agentPool,
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)
	n.SetActiveAgents([]NamedAgent{{Name: "worker-1", Agent: worker}})

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	waitForCalls(t, &client.calls, 2)
	n.Close()
	_ = l.Close()

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Len(t, client.requests, 2, "orchestrator event summary + 1 per-agent summary")
	perAgentReq := client.requests[1]
	assert.Equal(t, "log-model", perAgentReq.Model)
	assert.Equal(t, "none", perAgentReq.ReasoningEffort)
}

func TestNarrator_EmptyResponseLogsEmptyAndSkipsStderr(t *testing.T) {
	t.Parallel()
	// empty-after-strip: JSON file captures "empty" for diagnostics; stderr stays clean
	client := &scriptedClient{response: "<think>plan</think>"}
	l, path, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	jsonLog := mustReadFile(t, path)
	assert.Contains(t, jsonLog, `"msg":"orchestrator: empty"`, "empty summary must log to file for diagnostics")
	assert.NotContains(t, buf.String(), "empty",
		"narrate empty must NOT mirror to stderr — keeps the operator's terminal clean")
}

func TestNarrator_StripsCodeFenceFromResponse(t *testing.T) {
	t.Parallel()
	// fence stripper must peel both ends so prose (not "```") reaches stderr
	client := &scriptedClient{response: "```\nworker is scanning OAuth endpoints\n```"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	out := buf.String()
	assert.Contains(t, out, "orchestrator: worker is scanning OAuth endpoints")
	assert.NotContains(t, out, "narrate] ```")
}

func TestNarrator_SummaryCallsDisableReasoning(t *testing.T) {
	t.Parallel()
	// summary traffic forwards reasoning_effort=none for backends that honor it
	client := &scriptedClient{response: "all good"}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Pool: poolOf(client),
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
	n.TriggerNow()
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Len(t, client.requests, 1)
	req := client.requests[0]
	assert.Equal(t, "none", req.ReasoningEffort)
}

func TestNarrator_ReasoningExtraction(t *testing.T) {
	t.Parallel()
	// build returns the pool plus a *int32 the test can pass to waitForCalls
	// — both client types track call counts but live behind agent.ChatClient
	// so we expose the counter directly.
	cases := []struct {
		name           string
		build          func() (*agent.ClientPool, *int32)
		summarizer     agent.ReasoningHandler
		wantContains   []string
		wantNoContains []string
	}{
		{
			// "Final: <sentence>" inside reasoning: Extract salvages it, narrator logs cleanly
			name: "final_marker",
			build: func() (*agent.ClientPool, *int32) {
				c := &structuredRespClient{reasoning: "Thinking... Matches constraints. Output matches.✅ Final: worker-1 scanned the admin OAuth client registration endpoint."}
				return poolOf(c), &c.calls
			},
			summarizer: agent.NewReasoningHandler(agent.ReasoningFormatStructured),
			wantContains: []string{
				"orchestrator: worker-1 scanned the admin OAuth client registration endpoint.",
			},
			// marker-extracted output must not wear the thinking prefix
			wantNoContains: []string{"…thinking:"},
		},
		{
			// structured reasoning_content (no <think> tags): Summarizer handler surfaces a tail instead of "empty"
			name: "reasoning_tail",
			build: func() (*agent.ClientPool, *int32) {
				c := &structuredRespClient{reasoning: "probing the admin OAuth client registration flow"}
				return poolOf(c), &c.calls
			},
			summarizer: agent.NewReasoningHandler(agent.ReasoningFormatStructured),
			wantContains: []string{
				"orchestrator: …thinking:",
				"admin OAuth client registration flow",
			},
			wantNoContains: []string{"empty"},
		},
		{
			// truncated mid-think: narrator surfaces the think tail instead of "empty"
			name: "unclosed_think_tail",
			build: func() (*agent.ClientPool, *int32) {
				c := &scriptedClient{response: "<think>I am about to test the admin client registration endpoint for mass assignment"}
				return poolOf(c), &c.calls
			},
			wantContains: []string{
				"orchestrator: …thinking:",
				"admin client registration endpoint for mass assignment",
			},
			wantNoContains: []string{"empty"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, _, buf := newCapturedLogger(t)
			pool, calls := c.build()
			n := NewNarrator(NarratorConfig{
				Interval:   time.Millisecond,
				Model:      "m",
				Pool:       pool,
				CallBudget: time.Second,
				Summarizer: c.summarizer,
			}, l)
			require.NotNil(t, n)

			n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
			n.TriggerNow()
			waitForCalls(t, calls, 1)
			n.Close()
			_ = l.Close()

			out := buf.String()
			for _, want := range c.wantContains {
				assert.Contains(t, out, want)
			}
			for _, bad := range c.wantNoContains {
				assert.NotContains(t, out, bad)
			}
		})
	}
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
	waitForCalls(t, &client.calls, 1)
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls), "no active agents → orchestrator-only")
	assert.Contains(t, buf.String(), "orchestrator: only orchestrator")
}

func TestShouldNarrate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tag  string
		msg  string
		want bool
	}{
		{"controller_phase", "controller", "phase", true},
		{"decision_expand", "decision", "expand", true},
		{"finding_written", "finding", "written", true},
		{"tool_start", "tool", "start", true},
		{"tool_done", "tool", "done", true},
		{"tool_other", "tool", "other", false},
		{"agent_response", "agent", "response", true},
		{"agent_request", "agent", "request", false},
		{"agent_malformed_args", "agent", "malformed-args", false},
		{"worker_turn", "worker", "turn", true},
		{"server_models", "server", "models", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, shouldNarrate(c.tag, c.msg))
		})
	}
}
