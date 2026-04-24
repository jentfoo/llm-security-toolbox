package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	assert.Equal(t, "system", msgs[0].Role)
	assert.Equal(t, "user", msgs[1].Role)
	assert.Equal(t, "first", msgs[1].Content)
	assert.Equal(t, "user", msgs[2].Role)
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
		if m.Role == "tool" && m.ToolCallID == "c1" {
			sawTool = true
			assert.Contains(t, m.Content, "echoed")
		}
	}
	assert.True(t, sawTool)
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
		OnMalformedCall: func(name string, err error) { atomic.AddInt32(&malformed, 1) },
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
		if m.Role == "tool" {
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
	flaky := &fakeChatClient{
		responses: []ChatResponse{{}, {}, {Content: "ok"}},
		errors:    []error{errors.New("net1"), errors.New("net2"), nil},
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
		Model:         "m",
		Pool:          newPoolWith(client),
		MaxContext:    4096,
		DrainRetryMax: 1, // one retry allowed — recovery must not consume it
		// sub-millisecond backoff keeps the test fast.
		DrainRetryBackoff: time.Microsecond,
	})
	// Seed history with droppable turns so the force-truncate has something
	// to remove.
	big := strings.Repeat("y", 1_500)
	for i := 0; i < 6; i++ {
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
	assert.Equal(t, 2, int(client.idx), "exactly two send attempts: the rejected one and the post-truncate retry")
	assert.Less(t, a.history.EstimateTokens(), beforeTokens)
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
	for i := 0; i < 4; i++ {
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

func TestOpenAIAgent_SendWithRetryExhausted(t *testing.T) {
	t.Parallel()
	flaky := &fakeChatClient{
		responses: []ChatResponse{{}, {}, {}},
		errors:    []error{errors.New("e1"), errors.New("e2"), errors.New("e3")},
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
		if m.Role == "tool" {
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
			// Honour ctx so the timeout actually fires rather than running the
			// full 200ms and racing us.
			select {
			case <-time.After(200 * time.Millisecond):
				return ToolResult{Text: "should not reach"}
			case <-ctx.Done():
				return ToolResult{Text: "unused"}
			}
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
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{{Content: "ok", Usage: Usage{PromptTokens: 12, CompletionTokens: 3}}},
	}
	var starts, ends int32
	var lastIn, lastOut int
	var lastErr error
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(client),
		OnRequestStart: func(attempt int) { atomic.AddInt32(&starts, 1) },
		OnRequestEnd: func(attempt int, d time.Duration, in, out int, err error) {
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
		errors:    []error{errors.New("net1"), nil},
	}
	var starts, ends int32
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m", Pool: newPoolWith(flaky),
		DrainRetryMax: 1, DrainRetryBackoff: 1 * time.Millisecond,
		OnRequestStart: func(attempt int) { atomic.AddInt32(&starts, 1) },
		OnRequestEnd:   func(attempt int, d time.Duration, in, out int, err error) { atomic.AddInt32(&ends, 1) },
	})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&starts))
	assert.Equal(t, int32(2), atomic.LoadInt32(&ends))
}

func TestSynthesizePendingToolStubs(t *testing.T) {
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
		if m.Role == "assistant" {
			sentAssistants = append(sentAssistants, m)
		}
	}
	require.GreaterOrEqual(t, len(sentAssistants), 2)
	for i := 0; i < len(sentAssistants)-1; i++ {
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
		if m.Role == "assistant" {
			assert.Empty(t, m.ReasoningContent)
		}
	}
	// History retains raw reasoning for summaries.
	snap := a.history.Snapshot()
	var found bool
	for _, m := range snap {
		if m.Role == roleAssistant && m.ReasoningContent == "prior turn reasoning" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestOpenAIAgent_DrainDoesNotSetReasoningEffort(t *testing.T) {
	t.Parallel()
	// summary-only reasoning_effort knob must not leak into agent Drain
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
	a.Query("go")
	_, err := a.Drain(t.Context())
	require.NoError(t, err)
	require.Len(t, client.calls, 1)
	assert.Empty(t, client.calls[0].ReasoningEffort)
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

func TestOpenAIAgent_ContextUsage(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
	a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client), MaxContext: 4096})

	tokens, max := a.ContextUsage()
	assert.Equal(t, 4096, max)
	assert.GreaterOrEqual(t, tokens, 0)
	assert.NotNil(t, a.History())
	require.NoError(t, a.Close())
}

func TestOpenAIAgent_InterruptNoop(t *testing.T) {
	t.Parallel()
	a := NewOpenAIAgent(OpenAIAgentConfig{
		Model: "m",
		Pool:  newPoolWith(&fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}),
	})
	a.Interrupt()
}
