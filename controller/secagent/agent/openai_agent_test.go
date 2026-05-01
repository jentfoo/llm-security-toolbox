package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scripted ChatClient; captures outbound requests for assertion.
type fakeChatClient struct {
	responses []ChatResponse
	errors    []error
	calls     []ChatRequest
	idx       int32
	onCall    func(ChatRequest)
}

func (c *fakeChatClient) CreateChatCompletion(_ context.Context, req ChatRequest) (ChatResponse, error) {
	i := int(atomic.AddInt32(&c.idx, 1)) - 1
	c.calls = append(c.calls, req)
	if c.onCall != nil {
		c.onCall(req)
	}
	if i >= len(c.responses) {
		return ChatResponse{}, errors.New("fake: out of scripted responses")
	}
	var err error
	if i < len(c.errors) {
		err = c.errors[i]
	}
	return c.responses[i], err
}

func newPoolWith(c ChatClient) *ClientPool {
	return NewClientPoolWithClients([]ChatClient{c})
}

func TestOpenAIAgent_QueryAppendsWithoutSending(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys", Pool: newPoolWith(client),
	})
	a.Query("first")
	a.Query("second")
	assert.Empty(t, client.calls)

	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	require.Len(t, client.calls, 1)
	msgs := client.calls[0].Messages
	require.GreaterOrEqual(t, len(msgs), 3)
	assert.Equal(t, roleSystem, msgs[0].Role)
	assert.Equal(t, roleUser, msgs[1].Role)
	assert.Equal(t, "first", msgs[1].Content)
	assert.Equal(t, roleUser, msgs[2].Role)
	assert.Equal(t, "second", msgs[2].Content)
}

func TestOpenAIAgent_ToolDispatchLoop(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{
			{
				ToolCalls: []ToolCall{{
					ID: "c1", Type: "function",
					Function: ToolFunction{Name: "echo", Arguments: `{"x":1}`},
				}},
			},
			{Content: "done"},
		},
	}
	var handlerCalls int
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
	})
	a.SetTools([]ToolDef{{
		Name:   "echo",
		Schema: map[string]any{"type": "object"},
		Handler: func(_ context.Context, args json.RawMessage) ToolResult {
			handlerCalls++
			return ToolResult{Text: "echoed " + string(args)}
		},
	}})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, handlerCalls)
	require.Len(t, sum.ToolCalls, 1)
	assert.Equal(t, "echo", sum.ToolCalls[0].Name)
	assert.False(t, sum.ToolCalls[0].IsError)
	assert.Len(t, client.calls, 2)
	secondMsgs := client.calls[1].Messages
	var sawTool bool
	for _, m := range secondMsgs {
		if m.Role == roleTool && m.ToolCallID == "c1" {
			sawTool = true
			assert.Contains(t, m.Content, "echoed")
		}
	}
	assert.True(t, sawTool)
}

func TestOpenAIAgent_FuzzyToolNameFallback(t *testing.T) {
	t.Parallel()

	t.Run("collapses_underscore_typo", func(t *testing.T) {
		client := &fakeChatClient{
			responses: []ChatResponse{
				{ToolCalls: []ToolCall{{
					ID: "c1", Type: "function",
					Function: ToolFunction{Name: "mcp_sectool__proxy_poll", Arguments: `{}`},
				}}},
				{Content: "done"},
			},
		}
		var fuzzyReceived, fuzzyResolved string
		var handlerCalls int
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", Pool: newPoolWith(client),
			OnFuzzyToolMatch: func(received, resolved string) {
				fuzzyReceived, fuzzyResolved = received, resolved
			},
		})
		a.SetTools([]ToolDef{{
			Name:   "mcp__sectool__proxy_poll",
			Schema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, _ json.RawMessage) ToolResult {
				handlerCalls++
				return ToolResult{Text: "ok"}
			},
		}})
		a.Query("go")
		sum, err := a.Drain(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, handlerCalls)
		require.Len(t, sum.ToolCalls, 1)
		assert.False(t, sum.ToolCalls[0].IsError)
		assert.Equal(t, "mcp_sectool__proxy_poll", fuzzyReceived)
		assert.Equal(t, "mcp__sectool__proxy_poll", fuzzyResolved)
	})

	t.Run("contains_match_resolves_prefix_overgeneralization", func(t *testing.T) {
		client := &fakeChatClient{
			responses: []ChatResponse{
				{ToolCalls: []ToolCall{{
					ID: "c1", Type: "function",
					Function: ToolFunction{Name: "mcp_sectool_decide_worker", Arguments: `{}`},
				}}},
				{Content: "done"},
			},
		}
		var fuzzyReceived, fuzzyResolved string
		var handlerCalls int
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", Pool: newPoolWith(client),
			OnFuzzyToolMatch: func(received, resolved string) {
				fuzzyReceived, fuzzyResolved = received, resolved
			},
		})
		a.SetTools([]ToolDef{{
			Name:   "decide_worker",
			Schema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, _ json.RawMessage) ToolResult {
				handlerCalls++
				return ToolResult{Text: "ok"}
			},
		}})
		a.Query("go")
		sum, err := a.Drain(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, handlerCalls)
		require.Len(t, sum.ToolCalls, 1)
		assert.False(t, sum.ToolCalls[0].IsError)
		assert.Equal(t, "mcp_sectool_decide_worker", fuzzyReceived)
		assert.Equal(t, "decide_worker", fuzzyResolved)
	})

	t.Run("unknown_tool_errors", func(t *testing.T) {
		client := &fakeChatClient{
			responses: []ChatResponse{
				{ToolCalls: []ToolCall{{
					ID: "c1", Type: "function",
					Function: ToolFunction{Name: "totally_unrelated", Arguments: `{}`},
				}}},
				{Content: "done"},
			},
		}
		var fuzzyFired bool
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", Pool: newPoolWith(client),
			OnFuzzyToolMatch: func(_, _ string) { fuzzyFired = true },
		})
		a.SetTools([]ToolDef{{
			Name:   "echo",
			Schema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, _ json.RawMessage) ToolResult {
				return ToolResult{Text: "ok"}
			},
		}})
		a.Query("go")
		sum, err := a.Drain(t.Context())
		require.NoError(t, err)
		require.Len(t, sum.ToolCalls, 1)
		assert.True(t, sum.ToolCalls[0].IsError)
		assert.Contains(t, sum.ToolCalls[0].ResultSummary, "unknown tool")
		assert.False(t, fuzzyFired)
	})
}

func TestOpenAIAgent_MalformedArgsReportsSchemaAndCapsRepairs(t *testing.T) {
	t.Parallel()
	bad := []ToolCall{
		{ID: "a", Type: "function", Function: ToolFunction{Name: "echo", Arguments: "not json"}},
		{ID: "b", Type: "function", Function: ToolFunction{Name: "echo", Arguments: "still not"}},
		{ID: "c", Type: "function", Function: ToolFunction{Name: "echo", Arguments: "nope"}},
	}
	client := &fakeChatClient{
		responses: []ChatResponse{
			{ToolCalls: bad},
			{Content: "giving up"},
		},
	}
	var malformed int32
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client), MaxToolRepairs: 2,
		OnMalformedCall: func(_ string, _ error) { atomic.AddInt32(&malformed, 1) },
	})
	a.SetTools([]ToolDef{{
		Name:   "echo",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"x": map[string]any{"type": "number"}}},
	}})
	a.Query("trigger")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(3), malformed)

	require.Len(t, sum.ToolCalls, 3)
	for _, rec := range sum.ToolCalls {
		assert.True(t, rec.IsError)
	}

	second := client.calls[1].Messages
	var errMsgs []string
	for _, m := range second {
		if m.Role == roleTool {
			errMsgs = append(errMsgs, m.Content)
		}
	}
	require.Len(t, errMsgs, 3)
	assert.Contains(t, errMsgs[0], "ERROR: your arguments did not parse")
	assert.Contains(t, errMsgs[0], `"properties"`)
}

func TestOpenAIAgent_PerTurnTimeoutSilent(t *testing.T) {
	t.Parallel()
	slow := &slowClient{delay: 100 * time.Millisecond}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(slow),
		TurnTimeout: 20 * time.Millisecond,
	})
	a.Query("hi")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.True(t, sum.TimedOut)
	assert.Equal(t, escalationSilent, sum.EscalationReason)
}

type slowClient struct{ delay time.Duration }

func (s *slowClient) CreateChatCompletion(ctx context.Context, _ ChatRequest) (ChatResponse, error) {
	select {
	case <-time.After(s.delay):
		return ChatResponse{Content: "too late"}, nil
	case <-ctx.Done():
		return ChatResponse{}, ctx.Err()
	}
}

func TestOpenAIAgent_SendWithRetry(t *testing.T) {
	t.Parallel()
	// Errors must classify as ErrTransientNet (connection-reset family) or
	// ErrRateLimit for the retry loop to engage. Arbitrary error strings fall
	// to ErrOther and propagate without retry — that's intentional per the
	// retry policy.
	flaky := &fakeChatClient{
		responses: []ChatResponse{{}, {}, {Content: "ok"}},
		errors:    []error{errors.New("connection reset by peer"), errors.New("EOF"), nil},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(flaky),
		DrainRetryMax: 2, DrainRetryBackoff: 1 * time.Millisecond,
	})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Empty(t, sum.EscalationReason)
	assert.Equal(t, 3, int(flaky.idx))
}

func TestIsContextRejectedError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated_net_err", errors.New("connection refused"), false},
		{"local_model_phrasing", errors.New(`error, status code: 400, status: 400 Bad Request, message: , body: {"error":"Context size has been exceeded."}`), true},
		{"openai_code", errors.New("context_length_exceeded"), true},
		{"maximum_context_length", errors.New("This model's maximum context length is 8192 tokens"), true},
		{"context_window_phrasing", errors.New("request exceeds context window"), true},
		{"case_insensitive", errors.New("CONTEXT_LENGTH_EXCEEDED"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isContextRejectedError(c.err))
		})
	}
}

func TestOpenAIAgent_SendWithRetry_ContextRejectedRecovery(t *testing.T) {
	t.Parallel()
	// First call returns a context-exceeded 400; second call succeeds.
	// The recovery path should force-hard-truncate the history and retry
	// WITHOUT consuming a retry attempt.
	client := &fakeChatClient{
		responses: []ChatResponse{{}, {Content: "ok after truncate"}},
		errors: []error{
			errors.New(`error, status code: 400, status: 400 Bad Request, message: , body: {"error":"Context size has been exceeded."}`),
			nil,
		},
	}

	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m",
		Pool:  newPoolWith(client),
		// MaxContext well above seeded history so ShrinkEffectiveMaxOnRejection
		// can land below MaxContext (it's rejected when the candidate >= max).
		MaxContext:    64_000,
		DrainRetryMax: 1, // one retry allowed — recovery must not consume it
		// sub-millisecond backoff keeps the test fast.
		DrainRetryBackoff: time.Microsecond,
	})
	// Seed history with droppable turns so the force-truncate has something
	// to remove.
	big := strings.Repeat("y", 1_500)
	for range 6 {
		a.history.Append(Message{
			Role:      roleAssistant,
			Content:   big,
			ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		a.history.Append(Message{
			Role: roleTool, ToolCallID: "t", ToolName: "t",
			Content: big, Summary120: "summary",
		})
	}
	beforeTokens := a.history.EstimateTokens()

	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Empty(t, sum.EscalationReason)
	// One send for the rejection, one for the post-truncate retry.
	assert.Equal(t, 2, int(client.idx))
	assert.Less(t, a.history.EstimateTokens(), beforeTokens)
	// Adaptive effective-max must have shrunk below the configured ceiling
	// so the next turn's compaction triggers at the tighter watermark
	// instead of re-hitting the same rejection.
	assert.Less(t, a.history.EffectiveMaxContext(), a.history.MaxContext())
}

func TestOpenAIAgent_SendWithRetry_ContextRejectedFiresOncePerSend(t *testing.T) {
	t.Parallel()
	// Model keeps rejecting even after truncate — recovery must not loop
	// forever. Expected: one rejection → force-truncate → one retry with
	// same error → propagate. Total attempts = DrainRetryMax + 1 + 1
	// (the rejection, the truncate-retry; DrainRetryMax normal retries).
	rejectErr := errors.New(`error, status code: 400, body: {"error":"Context size has been exceeded."}`)
	client := &fakeChatClient{
		responses: []ChatResponse{{}, {}, {}, {}},
		errors:    []error{rejectErr, rejectErr, rejectErr, rejectErr},
	}

	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model:             "m",
		Pool:              newPoolWith(client),
		MaxContext:        4096,
		DrainRetryMax:     1,
		DrainRetryBackoff: time.Microsecond,
	})
	// Seed just enough history that ForceHardTruncate can drop something.
	big := strings.Repeat("z", 1_500)
	for range 4 {
		a.history.Append(Message{
			Role:      roleAssistant,
			Content:   big,
			ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		a.history.Append(Message{
			Role: roleTool, ToolCallID: "t", ToolName: "t",
			Content: big, Summary120: "summary",
		})
	}

	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.Error(t, err)
	assert.Equal(t, escalationError, sum.EscalationReason)
	// Attempts: initial rejection (1) + free retry after truncate (2) +
	// DrainRetryMax follow-up retries (1) = 3. Must not loop forever.
	assert.LessOrEqual(t, int(client.idx), 4)
}

func TestOpenAIAgent_SendWithRetry_ModelErrorNotRetried(t *testing.T) {
	t.Parallel()
	// 4xx non-overflow must propagate on the first attempt — retrying won't
	// fix a bad request, and widening the retry net to cover arbitrary 4xx
	// was the anti-pattern we deliberately avoided.
	apiErr := &openai.APIError{HTTPStatusCode: 400, Message: "bad request"}
	client := &fakeChatClient{
		responses: []ChatResponse{{}, {Content: "ok"}},
		errors:    []error{apiErr, nil},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		DrainRetryMax: 3, DrainRetryBackoff: time.Microsecond,
	})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.Error(t, err)
	assert.Equal(t, 1, int(client.idx))
}

func TestOpenAIAgent_SendWithRetry_RateLimitHonorsRetryAfter(t *testing.T) {
	t.Parallel()
	// 429 with a Retry-After ms hint: sendWithRetry must wait at least that
	// long before the follow-up attempt. Uses a small ms hint to keep the
	// test deterministic without requiring a clock injection.
	apiErr := &openai.APIError{HTTPStatusCode: 429, Message: "slow down; retry after 100 ms"}
	client := &fakeChatClient{
		responses: []ChatResponse{{}, {Content: "ok"}},
		errors:    []error{apiErr, nil},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		DrainRetryMax: 1, DrainRetryBackoff: time.Microsecond,
	})
	a.Query("go")
	start := time.Now()
	_, err := a.Drain(t.Context())
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 90*time.Millisecond)
	assert.Equal(t, 2, int(client.idx))
}

func TestOpenAIAgent_SendWithRetryExhausted(t *testing.T) {
	t.Parallel()
	flaky := &fakeChatClient{
		responses: []ChatResponse{{}, {}, {}},
		errors: []error{
			errors.New("connection refused"),
			errors.New("connection reset"),
			errors.New("broken pipe"),
		},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(flaky),
		DrainRetryMax: 2, DrainRetryBackoff: 1 * time.Millisecond,
	})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.Error(t, err)
	assert.Equal(t, escalationError, sum.EscalationReason)
}

func TestOpenAIAgent_ParallelToolsPreserveOrder(t *testing.T) {
	t.Parallel()
	const n = 5
	calls := make([]ToolCall, n)
	for i := range calls {
		calls[i] = ToolCall{
			ID:       fmt.Sprintf("c%d", i),
			Type:     "function",
			Function: ToolFunction{Name: "probe", Arguments: fmt.Sprintf(`{"n":%d}`, i)},
		}
	}
	client := &fakeChatClient{
		responses: []ChatResponse{{ToolCalls: calls}, {Content: "done"}},
	}
	// gates[i] releases handler i (closed in reverse); started[i] fires when
	// handler i begins, so we can wait until all n are in-flight before releasing.
	gates := make([]chan struct{}, n)
	started := make([]chan struct{}, n)
	for i := range gates {
		gates[i] = make(chan struct{})
		started[i] = make(chan struct{})
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client), MaxParallelTools: n,
	})
	a.SetTools([]ToolDef{{
		Name:   "probe",
		Schema: map[string]any{"type": "object"},
		Handler: func(_ context.Context, args json.RawMessage) ToolResult {
			var p struct {
				N int `json:"n"`
			}
			_ = json.Unmarshal(args, &p)
			close(started[p.N])
			<-gates[p.N]
			return ToolResult{Text: fmt.Sprintf("n=%d", p.N)}
		},
	}})
	a.Query("go")
	done := make(chan struct {
		sum TurnSummary
		err error
	}, 1)
	go func() {
		sum, err := a.Drain(t.Context())
		done <- struct {
			sum TurnSummary
			err error
		}{sum, err}
	}()
	for i := range started {
		<-started[i]
	}
	for i := n - 1; i >= 0; i-- {
		close(gates[i])
	}
	result := <-done
	require.NoError(t, result.err)
	require.Len(t, result.sum.ToolCalls, n)
	for i, rec := range result.sum.ToolCalls {
		assert.Contains(t, rec.ResultSummary, fmt.Sprintf("n=%d", i))
	}
	second := client.calls[1].Messages
	var toolOrder []string
	for _, m := range second {
		if m.Role == roleTool {
			toolOrder = append(toolOrder, m.ToolCallID)
		}
	}
	assert.Equal(t, []string{"c0", "c1", "c2", "c3", "c4"}, toolOrder)
}

func TestOpenAIAgent_PerToolTimeout(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{
			{ToolCalls: []ToolCall{{
				ID: "c1", Type: "function",
				Function: ToolFunction{Name: "slow", Arguments: "{}"},
			}}},
			{Content: "done"},
		},
	}
	var ended int32
	var endTimedOut bool
	var endIsErr bool
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		PerToolTimeout: 20 * time.Millisecond,
		OnToolEnd: func(_ string, _ json.RawMessage, _ time.Duration, isErr, timedOut bool, _ string) {
			atomic.AddInt32(&ended, 1)
			endTimedOut = timedOut
			endIsErr = isErr
		},
	})
	a.SetTools([]ToolDef{{
		Name:   "slow",
		Schema: map[string]any{"type": "object"},
		Handler: func(ctx context.Context, _ json.RawMessage) ToolResult {
			// Honour ctx so the timeout fires deterministically.
			<-ctx.Done()
			return ToolResult{Text: "unused"}
		},
	}})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	require.Len(t, sum.ToolCalls, 1)
	assert.True(t, sum.ToolCalls[0].IsError)
	assert.Contains(t, sum.ToolCalls[0].ResultSummary, "timed out")
	assert.Equal(t, int32(1), atomic.LoadInt32(&ended))
	assert.True(t, endTimedOut)
	assert.True(t, endIsErr)
}

func TestOpenAIAgent_OnToolStartEndSequencing(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{
			{ToolCalls: []ToolCall{{
				ID: "c1", Type: "function",
				Function: ToolFunction{Name: "echo", Arguments: `{}`},
			}}},
			{Content: "done"},
		},
	}
	var seq []string
	var mu sync.Mutex
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		OnToolStart: func(name string, _ json.RawMessage) {
			mu.Lock()
			seq = append(seq, "start:"+name)
			mu.Unlock()
		},
		OnToolEnd: func(name string, _ json.RawMessage, _ time.Duration, _, _ bool, _ string) {
			mu.Lock()
			seq = append(seq, "end:"+name)
			mu.Unlock()
		},
	})
	a.SetTools([]ToolDef{{
		Name:    "echo",
		Schema:  map[string]any{"type": "object"},
		Handler: func(_ context.Context, _ json.RawMessage) ToolResult { return ToolResult{Text: "ok"} },
	}})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"start:echo", "end:echo"}, seq)
}

func TestOpenAIAgent_OnToolEndErrTextPopulated(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{
			{ToolCalls: []ToolCall{
				{ID: "c1", Type: "function", Function: ToolFunction{Name: "ok", Arguments: `{}`}},
				{ID: "c2", Type: "function", Function: ToolFunction{Name: "reject", Arguments: `{}`}},
			}},
			{Content: "done"},
		},
	}
	var mu sync.Mutex
	seen := map[string]string{}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		OnToolEnd: func(name string, _ json.RawMessage, _ time.Duration, isErr, _ bool, errText string) {
			mu.Lock()
			defer mu.Unlock()
			if isErr {
				seen[name] = errText
			} else {
				seen[name] = "<clean>"
			}
		},
	})
	a.SetTools([]ToolDef{
		{
			Name:    "ok",
			Schema:  map[string]any{"type": "object"},
			Handler: func(_ context.Context, _ json.RawMessage) ToolResult { return ToolResult{Text: "success body"} },
		},
		{
			Name:   "reject",
			Schema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, _ json.RawMessage) ToolResult {
				return ToolResult{Text: "Rejected: boom because of a reason", IsError: true}
			},
		},
	})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "<clean>", seen["ok"])
	assert.Contains(t, seen["reject"], "Rejected: boom because of a reason")
}

func TestOpenAIAgent_RequestLifecycleCallbacks(t *testing.T) {
	// Not parallel: PromptTokens=12 in the fake response feeds the
	// process-wide calibration EMA via SetPromptTokens. Resetting on
	// cleanup keeps parallel tests from observing the perturbation.
	t.Cleanup(resetCalibrationForTest)
	client := &fakeChatClient{
		responses: []ChatResponse{{Content: "ok", Usage: Usage{PromptTokens: 12, CompletionTokens: 3}}},
	}
	var starts, ends int32
	var lastIn, lastOut int
	var lastErr error
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		OnRequestStart: func(_ int) { atomic.AddInt32(&starts, 1) },
		OnRequestEnd: func(_ int, _ time.Duration, in, out int, err error) {
			atomic.AddInt32(&ends, 1)
			lastIn, lastOut, lastErr = in, out, err
		},
	})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&starts))
	assert.Equal(t, int32(1), atomic.LoadInt32(&ends))
	assert.Equal(t, 12, lastIn)
	assert.Equal(t, 3, lastOut)
	assert.NoError(t, lastErr)
}

func TestOpenAIAgent_RequestLifecycleCallbacksOnRetry(t *testing.T) {
	t.Parallel()
	flaky := &fakeChatClient{
		responses: []ChatResponse{{}, {Content: "ok"}},
		errors:    []error{errors.New("connection reset"), nil},
	}
	var starts, ends int32
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(flaky),
		DrainRetryMax: 1, DrainRetryBackoff: 1 * time.Millisecond,
		OnRequestStart: func(_ int) { atomic.AddInt32(&starts, 1) },
		OnRequestEnd:   func(_ int, _ time.Duration, _, _ int, _ error) { atomic.AddInt32(&ends, 1) },
	})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&starts))
	assert.Equal(t, int32(2), atomic.LoadInt32(&ends))
}

func TestOpenAIAgent_SynthesizePendingToolStubs(t *testing.T) {
	t.Parallel()
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(&fakeChatClient{})})
	a.history.Append(Message{Role: roleUser, Content: "go"})
	a.history.Append(Message{
		Role: roleAssistant,
		ToolCalls: []ToolCall{
			{ID: "a", Function: ToolFunction{Name: "t"}},
			{ID: "b", Function: ToolFunction{Name: "t"}},
			{ID: "c", Function: ToolFunction{Name: "t"}},
		},
	})
	a.history.Append(Message{Role: roleTool, ToolCallID: "a", Content: "ok"})

	a.synthesizePendingToolStubs()

	msgs := a.history.Snapshot()
	paired := map[string]string{}
	for _, m := range msgs {
		if m.Role == roleTool {
			paired[m.ToolCallID] = m.Content
		}
	}
	assert.Equal(t, "ok", paired["a"])
	assert.Contains(t, paired["b"], "interrupted before tool could run")
	assert.Contains(t, paired["c"], "interrupted before tool could run")
}

func TestOpenAIAgent_DrainStoresRawThink_SendStripsOlderThanKeepN(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{
		{Content: "<think>plan A</think>result A"},
		{Content: "<think>plan B</think>result B"},
		{Content: "done"},
	}}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client), KeepThinkTurns: 1,
	})
	a.Query("first")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	a.Query("second")
	_, err = a.Drain(t.Context())
	require.NoError(t, err)
	a.Query("third")
	_, err = a.Drain(t.Context())
	require.NoError(t, err)

	snap := a.history.Snapshot()
	var assistants []Message
	for _, m := range snap {
		if m.Role == roleAssistant {
			assistants = append(assistants, m)
		}
	}
	require.Len(t, assistants, 3)
	assert.Contains(t, assistants[0].Content, "<think>plan A</think>")
	assert.Contains(t, assistants[1].Content, "<think>plan B</think>")

	sent := client.calls[2].Messages
	var sentAssistants []ChatMessage
	for _, m := range sent {
		if m.Role == roleAssistant {
			sentAssistants = append(sentAssistants, m)
		}
	}
	require.GreaterOrEqual(t, len(sentAssistants), 2)
	for i := range len(sentAssistants) - 1 {
		assert.NotContains(t, sentAssistants[i].Content, "<think>")
	}
	last := sentAssistants[len(sentAssistants)-1]
	assert.Contains(t, last.Content, "<think>plan B</think>")
}

func TestOpenAIAgent_DrainStoresStructuredReasoning(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{
		{Content: "", ReasoningContent: "I was thinking about X"},
	}}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model:     "m",
		Pool:      newPoolWith(client),
		Reasoning: NewReasoningHandler(ReasoningFormatStructured),
	})
	a.Query("prompt")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)

	snap := a.history.Snapshot()
	var asst Message
	for _, m := range snap {
		if m.Role == roleAssistant {
			asst = m
		}
	}
	assert.Empty(t, asst.Content)
	assert.Equal(t, "I was thinking about X", asst.ReasoningContent)
}

func TestOpenAIAgent_StructuredReasoningNotReplayed(t *testing.T) {
	t.Parallel()
	// Structured handler blanks assistant.ReasoningContent on replay so the
	// reasoning field stays output-only on the wire (deepseek convention).
	client := &fakeChatClient{responses: []ChatResponse{
		{Content: "", ReasoningContent: "prior turn reasoning"},
		{Content: "final answer"},
	}}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model:     "m",
		Pool:      newPoolWith(client),
		Reasoning: NewReasoningHandler(ReasoningFormatStructured),
	})
	a.Query("first")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	a.Query("second")
	_, err = a.Drain(t.Context())
	require.NoError(t, err)

	sent := client.calls[1].Messages
	for _, m := range sent {
		if m.Role == roleAssistant {
			assert.Empty(t, m.ReasoningContent)
		}
	}
	// History retains raw reasoning for summaries.
	snap := a.history.Snapshot()
	assert.True(t, slices.ContainsFunc(snap, func(m Message) bool {
		return m.Role == roleAssistant && m.ReasoningContent == "prior turn reasoning"
	}))
}

func TestOpenAIAgent_FlowIDExtraction(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "I touched flow_id=abc12345 and then done."}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		FlowIDExtractor: func(sources ...any) []string {
			// Minimal stand-in: find any literal token matching test data.
			out := []string{}
			for _, s := range sources {
				if str, ok := s.(string); ok && strings.Contains(str, "abc12345") {
					out = append(out, "abc12345")
				}
			}
			return out
		},
	})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Contains(t, sum.FlowIDs, "abc12345")
}

func TestOpenAIAgent_ReplaceHistory(t *testing.T) {
	t.Parallel()

	t.Run("preserves_system", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		})
		a.Query("noisy first")
		a.Query("noisy second")

		a.ReplaceHistory([]Message{{Role: roleUser, Content: "recap"}})
		snap := a.Snapshot()
		require.Len(t, snap, 2)
		assert.Equal(t, roleSystem, snap[0].Role)
		assert.Equal(t, "sys", snap[0].Content)
		assert.Equal(t, roleUser, snap[1].Role)
		assert.Equal(t, "recap", snap[1].Content)
	})

	t.Run("accepts_explicit_system", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "original-sys",
			Pool: newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		})
		a.ReplaceHistory([]Message{
			{Role: roleSystem, Content: "explicit-sys"},
			{Role: roleUser, Content: "recap"},
		})
		snap := a.Snapshot()
		require.Len(t, snap, 2)
		assert.Equal(t, "explicit-sys", snap[0].Content)
	})

	t.Run("empty_keeps_system_only", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		})
		a.Query("noise")
		a.ReplaceHistory(nil)
		snap := a.Snapshot()
		require.Len(t, snap, 1)
		assert.Equal(t, roleSystem, snap[0].Role)
	})
}

func TestOpenAIAgent_SnapshotSinceID(t *testing.T) {
	t.Parallel()
	t.Run("zero_returns_post_system", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{}),
		})
		a.Query("hello")
		a.History().Append(Message{Role: roleAssistant, Content: "world"})
		got := a.SnapshotSinceID(0)
		require.Len(t, got, 2)
		assert.Equal(t, roleUser, got[0].Role)
		assert.Equal(t, roleAssistant, got[1].Role)
	})
	t.Run("cursor_returns_only_after", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{}),
		})
		a.Query("first")
		firstID := a.LastHistoryID()
		a.History().Append(Message{Role: roleAssistant, Content: "second"})
		a.History().Append(Message{Role: roleAssistant, Content: "third"})
		got := a.SnapshotSinceID(firstID)
		require.Len(t, got, 2)
		assert.Equal(t, "second", got[0].Content)
		assert.Equal(t, "third", got[1].Content)
	})
	t.Run("compacted_cursor_returns_all_post_system", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{}),
		})
		a.Query("kept")
		got := a.SnapshotSinceID(99999)
		require.Len(t, got, 1)
		assert.Equal(t, "kept", got[0].Content)
	})
	t.Run("system_only_returns_nil", func(t *testing.T) {
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool: newPoolWith(&fakeChatClient{}),
		})
		assert.Nil(t, a.SnapshotSinceID(0))
	})
}

func TestOpenAIAgent_MarkIterationBoundary(t *testing.T) {
	t.Parallel()
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool: newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
	})
	assert.Zero(t, a.IterationBoundary())
	a.Query("hello")
	a.MarkIterationBoundary()
	// After [system, user], boundary records position 2.
	assert.Equal(t, 2, a.IterationBoundary())
	a.ReplaceHistory([]Message{{Role: roleUser, Content: "fresh"}})
	// ReplaceHistory resets the boundary index.
	assert.Zero(t, a.IterationBoundary())
}

func TestOpenAIAgent_MaybeCompactRunsBoundarySummarizeBeforeFallthrough(t *testing.T) {
	t.Parallel()
	// Set a deliberately tight watermark so any history triggers it.
	var summarizeCalls int
	var summarizeCallSnapshotLen int
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		MaxContext: 200,
		Compaction: CompactionOptions{HighWatermark: 0.01, KeepTurns: 1},
		OnSummarizeBoundary: func(_ context.Context, snap []Message) ([]Message, error) {
			summarizeCalls++
			summarizeCallSnapshotLen = len(snap)
			return []Message{{Role: roleUser, Content: "<recap>"}}, nil
		},
	})
	// Fill chronicle with several user/assistant turns. These all sit
	// BEFORE the iteration boundary.
	for i := range 3 {
		a.Query("noisy chronicle " + strconv.Itoa(i))
		a.History().Append(Message{Role: roleAssistant, Content: "asst response " + strconv.Itoa(i)})
	}
	// Mark the boundary, then add one more user message representing the
	// in-iter directive that should be preserved verbatim.
	a.MarkIterationBoundary()
	a.Query("iter directive")

	require.NoError(t, a.maybeCompact(t.Context()))
	require.Equal(t, 1, summarizeCalls)
	assert.Positive(t, summarizeCallSnapshotLen)

	snap := a.Snapshot()
	// Expect: [system, user:<recap>, user:iter directive]
	require.GreaterOrEqual(t, len(snap), 3)
	assert.Equal(t, roleSystem, snap[0].Role)
	assert.Equal(t, roleUser, snap[1].Role)
	assert.Equal(t, "<recap>", snap[1].Content)
	assert.Equal(t, roleUser, snap[len(snap)-1].Role)
	assert.Equal(t, "iter directive", snap[len(snap)-1].Content)
}

func TestOpenAIAgent_MaybeCompactBoundaryCallbackOncePerIter(t *testing.T) {
	t.Parallel()
	var summarizeCalls int
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		MaxContext: 200,
		Compaction: CompactionOptions{HighWatermark: 0.01, KeepTurns: 1},
		OnSummarizeBoundary: func(_ context.Context, _ []Message) ([]Message, error) {
			summarizeCalls++
			return []Message{{Role: roleUser, Content: "<recap>"}}, nil
		},
	})
	for i := range 3 {
		a.Query("noise " + strconv.Itoa(i))
		a.History().Append(Message{Role: roleAssistant, Content: "asst " + strconv.Itoa(i)})
	}
	a.MarkIterationBoundary()
	a.Query("iter directive")
	require.NoError(t, a.maybeCompact(t.Context()))
	// Second call within the same iter must NOT re-fire the callback.
	require.NoError(t, a.maybeCompact(t.Context()))
	assert.Equal(t, 1, summarizeCalls)
}

func TestOpenAIAgent_RunBoundarySummarize_EmptyReplacement(t *testing.T) {
	t.Parallel()
	// Empty replacement still latches iterationSummarized so the callback
	// isn't re-invoked over the same pre-boundary slice.
	var calls int
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool: newPoolWith(&fakeChatClient{}),
		OnSummarizeBoundary: func(_ context.Context, _ []Message) ([]Message, error) {
			calls++
			return nil, nil
		},
	})
	for i := range 3 {
		a.Query("pre " + strconv.Itoa(i))
		a.History().Append(Message{Role: roleAssistant, Content: "ack " + strconv.Itoa(i)})
	}
	a.MarkIterationBoundary()
	a.Query("iter directive")

	preLen := a.history.Len()
	require.NoError(t, a.runBoundarySummarize(t.Context()))
	assert.Equal(t, 1, calls)
	assert.Equal(t, preLen, a.history.Len(), "history must be unchanged on empty replacement")
	assert.True(t, a.iterationSummarized, "latch must fire so a second call no-ops via maybeCompact")

	require.NoError(t, a.maybeCompact(t.Context()))
	assert.Equal(t, 1, calls, "maybeCompact must not re-invoke when latch is set")
}

func TestOpenAIAgent_MaybeCompactTieredFlow(t *testing.T) {
	t.Parallel()

	// buildBigHistory seeds history past the 80% high watermark so
	// maybeCompact engages. No same-tool error streaks unless requested,
	// so pass 0 (error-collapse) is a no-op by default.
	buildBigHistory := func(maxCtx int, withErrorStreak bool) *History {
		h := NewHistory(maxCtx)
		h.Append(Message{Role: roleSystem, Content: "sys"})
		big := strings.Repeat("y", 800)
		if withErrorStreak {
			calls := []ToolCall{
				{ID: "e1", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
				{ID: "e2", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
				{ID: "e3", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
				{ID: "e4", Function: ToolFunction{Name: "flaky", Arguments: "{}"}},
			}
			h.Append(Message{Role: roleAssistant, Content: "fan out", ToolCalls: calls})
			for _, id := range []string{"e1", "e2", "e3", "e4"} {
				h.Append(Message{
					Role:       roleTool,
					ToolCallID: id,
					ToolName:   "flaky",
					Content:    "ERROR: same failure " + strings.Repeat("z", 600),
				})
			}
		}
		for i := range 4 {
			h.Append(Message{
				Role: roleAssistant, Content: big,
				ToolCalls: []ToolCall{{ID: "t" + strconv.Itoa(i), Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: roleTool, ToolCallID: "t" + strconv.Itoa(i), ToolName: "t",
				Content: big, Summary120: "s",
			})
		}
		return h
	}

	t.Run("pass_0_clears_threshold", func(t *testing.T) {
		var bCalls, cCalls int
		// RecoveryThreshold tiny → pass 0 alone clears it on a history
		// with a large error streak.
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
			MaxContext: 4096,
			Compaction: CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.01, // any drop above 41 tokens skips B
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []Message) ([]string, error) {
				bCalls++
				return nil, nil
			},
			OnDistillResults: func(_ context.Context, _ []Message) ([]Message, error) {
				cCalls++
				return nil, nil
			},
		})
		// Replace the auto-system-prompt with the seeded history that has
		// the error streak.
		a.history.ReplaceAll(buildBigHistory(4096, true).Snapshot())
		require.NoError(t, a.maybeCompact(t.Context()))
		assert.Zero(t, bCalls)
		assert.Zero(t, cCalls)
	})

	t.Run("pass_0_short_runs_b", func(t *testing.T) {
		var bCalls, cCalls int
		var bSnapshotLen int
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
			MaxContext: 4096,
			Compaction: CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				// Threshold larger than what the absent error streak could
				// possibly free → Pass 0 always falls short.
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, snap []Message) ([]string, error) {
				bCalls++
				bSnapshotLen = len(snap)
				// Return drop set that frees significant space (drop tool ids).
				return []string{"t0", "t1", "t2", "t3"}, nil
			},
			OnDistillResults: func(_ context.Context, _ []Message) ([]Message, error) {
				cCalls++
				return nil, nil
			},
		})
		a.history.ReplaceAll(buildBigHistory(4096, false).Snapshot())
		// maybeCompact may return an error if mechanical passes can't fully
		// clear the watermark after B's drops; that's OK for this test —
		// we only verify B fires when Pass 0 fell short of the threshold.
		_ = a.maybeCompact(t.Context())
		assert.Equal(t, 1, bCalls)
		assert.Positive(t, bSnapshotLen)
	})

	t.Run("b_empty_runs_c", func(t *testing.T) {
		var bCalls, cCalls int
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
			MaxContext: 4096,
			Compaction: CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []Message) ([]string, error) {
				bCalls++
				return nil, nil // B has nothing to prune
			},
			OnDistillResults: func(_ context.Context, snap []Message) ([]Message, error) {
				cCalls++
				// Return the snapshot with first eligible tool result rewritten.
				out := make([]Message, len(snap))
				copy(out, snap)
				for i := range out {
					if out[i].Role == roleTool {
						out[i].Content = "(distilled batch 1: brief summary)"
						break
					}
				}
				return out, nil
			},
		})
		a.history.ReplaceAll(buildBigHistory(4096, false).Snapshot())
		require.NoError(t, a.maybeCompact(t.Context()))
		assert.Equal(t, 1, bCalls)
		assert.Equal(t, 1, cCalls)
	})

	t.Run("nil_callbacks_mechanical_only", func(t *testing.T) {
		// Without B/C wired, maybeCompact must reduce to its prior behaviour
		// (mechanical passes only).
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
			MaxContext: 4096,
			Compaction: CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				HardTruncateOnOverflow: true,
			},
		})
		a.history.ReplaceAll(buildBigHistory(4096, false).Snapshot())
		require.NoError(t, a.maybeCompact(t.Context()))
		// Just verify the call returned cleanly — the existing mechanical
		// passes do their job; behaviour is byte-for-byte equivalent to
		// pre-change Compact().
	})

	t.Run("b_error_falls_through", func(t *testing.T) {
		var summarizeErrs int
		a := NewOpenAIAgent(OpenAIAgentConfig{
			Model: "m", SystemPrompt: "sys",
			Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
			MaxContext: 4096,
			Compaction: CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []Message) ([]string, error) {
				return nil, errors.New("boom")
			},
			OnSummarizeError: func(_ error) { summarizeErrs++ },
		})
		a.history.ReplaceAll(buildBigHistory(4096, false).Snapshot())
		// B callback errors must not propagate; mechanical passes still run.
		require.NoError(t, a.maybeCompact(t.Context()))
		assert.Equal(t, 1, summarizeErrs)
	})
}

func TestOpenAIAgent_MaybeCompactFailOpenWhenCallbackErrors(t *testing.T) {
	t.Parallel()
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		MaxContext: 200,
		Compaction: CompactionOptions{HighWatermark: 0.01, KeepTurns: 1},
		OnSummarizeBoundary: func(_ context.Context, _ []Message) ([]Message, error) {
			return nil, errors.New("downstream summarize failure")
		},
	})
	for i := range 5 {
		a.Query("noise " + strconv.Itoa(i))
		a.History().Append(Message{Role: roleAssistant, Content: "asst " + strconv.Itoa(i)})
	}
	a.MarkIterationBoundary()
	a.Query("iter directive")
	// Callback errors are absorbed; existing Compact is the safety net.
	assert.NoError(t, a.maybeCompact(t.Context()))
}

func TestOpenAIAgent_CompactPreservingBoundary_TracksDirectiveAcrossDeletions(t *testing.T) {
	t.Parallel()
	// MaxContext sized so that pre-iter bulk content trips Compact's
	// dropOldestTurn pass (which deletes oldest assistant-headed turn
	// triples), but with enough headroom that the operation completes.
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		MaxContext: 4000,
		Compaction: CompactionOptions{
			HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
			HardTruncateOnOverflow: true,
		},
	})
	bulk := strings.Repeat("xy", 200)
	for i := range 4 {
		a.History().Append(Message{Role: roleUser, Content: "noise " + strconv.Itoa(i) + " " + bulk})
		a.History().Append(Message{Role: roleAssistant, Content: "asst " + strconv.Itoa(i) + " " + bulk})
	}
	a.MarkIterationBoundary()
	boundaryBefore := a.IterationBoundary()
	require.Greater(t, boundaryBefore, 1)
	a.Query("DIRECTIVE-MARKER")
	a.History().Append(Message{Role: roleAssistant, Content: "in-iter assistant"})

	_, err := a.compactPreservingBoundary()
	require.NoError(t, err)

	snap := a.Snapshot()
	boundaryAfter := a.IterationBoundary()
	require.Less(t, boundaryAfter, boundaryBefore)
	require.Less(t, boundaryAfter, len(snap))
	assert.Equal(t, "DIRECTIVE-MARKER", snap[boundaryAfter].Content)
}

func TestOpenAIAgent_CompactPreservingBoundary_ClampsWhenMarkerDropped(t *testing.T) {
	t.Parallel()
	// HardTruncateOnOverflow=true with very tight watermarks lets Compact's
	// last-resort hard-truncate pass eat past the boundary if needed.
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:       newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
		MaxContext: 200,
		Compaction: CompactionOptions{
			HighWatermark: 0.05, LowWatermark: 0.01, KeepTurns: 1,
			HardTruncateOnOverflow: true,
		},
	})
	bulk := strings.Repeat("xy", 400)
	a.History().Append(Message{Role: roleUser, Content: "DIRECTIVE-MARKER"})
	a.MarkIterationBoundary()
	a.History().Append(Message{Role: roleAssistant, Content: "iter1 " + bulk})
	a.History().Append(Message{Role: roleAssistant, Content: "iter2 " + bulk})

	_, _ = a.compactPreservingBoundary()
	// If the marker was dropped, boundary must clamp into [0, len(history)].
	assert.LessOrEqual(t, a.IterationBoundary(), a.History().Len())
}

func TestOpenAIAgent_RetireOnPressure_StopsCleanlyAtHighWatermark(t *testing.T) {
	t.Parallel()
	// fakeChatClient with no responses scripted — the test asserts the
	// agent must NOT issue an LLM call once pressure is hit.
	client := &fakeChatClient{}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:             newPoolWith(client),
		MaxContext:       200,
		Compaction:       CompactionOptions{HighWatermark: 0.5, KeepTurns: 2},
		RetireOnPressure: true,
	})
	// Bulk content above the high watermark (200 * 0.5 = 100 tokens =
	// 400 chars at default charsPerToken=4).
	bulk := strings.Repeat("x", 600)
	a.History().Append(Message{Role: roleAssistant, Content: bulk})

	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, escalationContextExhausted, sum.EscalationReason)
	assert.Empty(t, client.calls)
}

func TestOpenAIAgent_RetireOnPressure_RunsNormallyBelowWatermark(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{{Content: "done"}},
	}
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", SystemPrompt: "sys",
		Pool:             newPoolWith(client),
		MaxContext:       4096,
		Compaction:       CompactionOptions{HighWatermark: 0.8, KeepTurns: 2},
		RetireOnPressure: true,
	})
	a.Query("go")
	sum, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, escalationContextExhausted, sum.EscalationReason)
	assert.Len(t, client.calls, 1)
}
