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
	assert.Nil(t, n)
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
	assert.NotContains(t, jsonLog, `"role":`)
	assert.NotContains(t, jsonLog, `"agent":`)
}

func TestNarrator_PerAgentSummaryUsesSummaryModel(t *testing.T) {
	t.Parallel()
	// per-agent summaries go through the narrator's summary model, not the agent's own model
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
	assert.Equal(t, "summary-model", perAgentReq.Model)
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
	cases := []struct {
		name           string
		pool           func() *agent.ClientPool
		summarizer     agent.ReasoningHandler
		wantContains   []string
		wantNoContains []string
	}{
		{
			// "Final: <sentence>" inside reasoning: Extract salvages it, narrator logs cleanly
			name: "final_marker",
			pool: func() *agent.ClientPool {
				return poolOf(&structuredRespClient{reasoning: "Thinking... Matches constraints. Output matches.✅ Final: worker-1 scanned the admin OAuth client registration endpoint."})
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
			pool: func() *agent.ClientPool {
				return poolOf(&structuredRespClient{reasoning: "probing the admin OAuth client registration flow"})
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
			pool: func() *agent.ClientPool {
				return poolOf(&scriptedClient{response: "<think>I am about to test the admin client registration endpoint for mass assignment"})
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
			n := NewNarrator(NarratorConfig{
				Interval:   time.Millisecond,
				Model:      "m",
				Pool:       c.pool(),
				CallBudget: time.Second,
				Summarizer: c.summarizer,
			}, l)
			require.NotNil(t, n)

			n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
			n.TriggerNow()
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
