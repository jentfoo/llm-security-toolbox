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
// inFlight/peak track concurrency level so tests can assert serialization.
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

func poolOf(c agent.ChatClient) *agent.ClientPool {
	return agent.NewClientPoolWithClients([]agent.ChatClient{c})
}

// structuredRespClient simulates a structured-format reasoning model that
// returns empty Content with reasoning isolated in ReasoningContent.
type structuredRespClient struct {
	reasoning string
	calls     int32
}

func (c *structuredRespClient) CreateChatCompletion(context.Context, agent.ChatRequest) (agent.ChatResponse, error) {
	atomic.AddInt32(&c.calls, 1)
	return agent.ChatResponse{Content: "", ReasoningContent: c.reasoning}, nil
}

// waitForCalls polls until calls reaches want, then returns. Use this BEFORE
// Close so the in-flight summary goroutine completes its HTTP call before
// shutdownCancel aborts it — without this gate, buf/calls assertions race
// with the shutdown path.
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

func TestNarrator(t *testing.T) {
	t.Parallel()

	t.Run("disabled_returns_nil", func(t *testing.T) {
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
	})

	t.Run("record_and_trigger_fires", func(t *testing.T) {
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
	})

	t.Run("coalesces_concurrent_fires", func(t *testing.T) {
		gate := make(chan struct{})
		client := &scriptedClient{response: "narrated", gate: gate}
		l, _, _ := newCapturedLogger(t)
		n := NewNarrator(NarratorConfig{
			Interval: time.Millisecond, Model: "m", Pool: poolOf(client), CallBudget: time.Second,
		}, l)
		require.NotNil(t, n)

		n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
		n.TriggerNow() // firing #1 blocks on gate
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&client.calls) == 1
		}, time.Second, time.Millisecond)

		n.Record("finding", "written", map[string]any{"title": "x"})
		n.TriggerNow()
		n.TriggerNow()
		n.TriggerNow()

		close(gate)
		waitForCalls(t, &client.calls, 2)
		n.Close()
		_ = l.Close()

		// Firings 2/3/4 coalesce — buffered events are drained by one of the
		// waiting goroutines, so total ends up at 2 (sometimes 3 under race).
		calls := atomic.LoadInt32(&client.calls)
		assert.GreaterOrEqual(t, calls, int32(2))
		assert.LessOrEqual(t, calls, int32(3))
	})

	t.Run("failure_does_not_panic", func(t *testing.T) {
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
	})

	t.Run("close_does_not_flush", func(t *testing.T) {
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
	})

	t.Run("parent_cancel_aborts_summary", func(t *testing.T) {
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
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&client.calls) >= 1
		}, time.Second, time.Millisecond)

		start := time.Now()
		parentCancel()
		n.Close()
		elapsed := time.Since(start)
		close(gate)
		_ = l.Close()

		assert.Less(t, elapsed, 5*time.Second,
			"parent ctx cancel must abort in-flight summaries, not wait on CallBudget")
	})

	t.Run("tick_respects_interval", func(t *testing.T) {
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

		n.mu.Lock()
		n.lastFireAt = time.Now().Add(-time.Second)
		n.mu.Unlock()
		n.Tick()
		waitForCalls(t, &client.calls, 1)
		n.Close()
		_ = l.Close()
		assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
	})

	t.Run("suppressed_until_substantive_event", func(t *testing.T) {
		client := &scriptedClient{response: "narration fired"}
		l, _, buf := newCapturedLogger(t)
		n := NewNarrator(NarratorConfig{
			Interval: time.Millisecond, Model: "m", Pool: poolOf(client),
			CallBudget: time.Second,
		}, l)
		require.NotNil(t, n)

		n.Record("controller", "transition phase idle to autonomous", nil)
		n.Record("controller", "iteration start", map[string]any{"iter": 1})
		n.Record("worker", "seeded", map[string]any{"id": 1})
		n.TriggerNow()
		// TriggerNow short-circuits synchronously when unarmed — no goroutine
		// is spawned, so the state check is race-free.
		n.mu.Lock()
		armed := n.armed
		n.mu.Unlock()
		assert.False(t, armed)
		assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls))

		n.Record("worker", "turn", map[string]any{"worker_id": 1, "turn": 1})
		n.TriggerNow()
		waitForCalls(t, &client.calls, 1)
		n.Close()
		_ = l.Close()

		assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
		assert.Contains(t, buf.String(), "narration fired")
	})

	t.Run("summary_disables_reasoning", func(t *testing.T) {
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
	})
}

func TestNarratorContent(t *testing.T) {
	t.Parallel()

	t.Run("empty_response_logs_empty", func(t *testing.T) {
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
	})

	t.Run("strips_code_fence", func(t *testing.T) {
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
	})

	t.Run("reasoning_extraction", func(t *testing.T) {
		// build returns the pool + a *int32 the test passes to waitForCalls;
		// both client types track call counts but live behind agent.ChatClient.
		cases := []struct {
			name           string
			build          func() (*agent.ClientPool, *int32)
			summarizer     agent.ReasoningHandler
			wantContains   []string
			wantNoContains []string
		}{
			{
				name: "final_marker",
				build: func() (*agent.ClientPool, *int32) {
					c := &structuredRespClient{reasoning: "Thinking... Matches constraints. Output matches.✅ Final: worker-1 scanned the admin OAuth client registration endpoint."}
					return poolOf(c), &c.calls
				},
				summarizer: agent.NewReasoningHandler(agent.ReasoningFormatStructured),
				wantContains: []string{
					"orchestrator: worker-1 scanned the admin OAuth client registration endpoint.",
				},
				wantNoContains: []string{"…thinking:"},
			},
			{
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
	})
}

func TestNarratorAgentDispatch(t *testing.T) {
	t.Parallel()

	t.Run("fires_per_active_agent", func(t *testing.T) {
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
	})

	t.Run("per_agent_uses_log_model", func(t *testing.T) {
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
	})

	t.Run("no_active_agents_orchestrator_only", func(t *testing.T) {
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
	})
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
