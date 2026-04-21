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
type scriptedClient struct {
	mu       sync.Mutex
	calls    int32
	response string
	err      error
	gate     chan struct{} // if non-nil, each call blocks on it
}

func (c *scriptedClient) CreateChatCompletion(ctx context.Context, _ agent.ChatRequest) (agent.ChatResponse, error) {
	atomic.AddInt32(&c.calls, 1)
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return agent.ChatResponse{}, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return agent.ChatResponse{}, c.err
	}
	return agent.ChatResponse{Content: c.response}, nil
}

func TestNarrator_DisabledWhenIntervalZero(t *testing.T) {
	t.Parallel()
	n := NewNarrator(NarratorConfig{
		Interval: 0,
		Model:    "m",
		Client:   &scriptedClient{response: "ok"},
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
		Client:     client,
		CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("controller", "phase", map[string]any{"from": "idle", "to": "autonomous"})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
	assert.Contains(t, buf.String(), "[narrate] worker is scanning endpoints")
	assert.Contains(t, mustReadFile(t, path), `"msg":"worker is scanning endpoints"`)
}

func TestNarrator_CoalescesConcurrentFires(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	client := &scriptedClient{response: "narrated", gate: gate}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Millisecond, Model: "m", Client: client, CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("controller", "phase", map[string]any{"from": "idle", "to": "autonomous"})
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
		Interval: time.Millisecond, Model: "m", Client: client, CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("controller", "phase", map[string]any{"from": "idle", "to": "autonomous"})
	n.TriggerNow()
	n.Close()
	_ = l.Close()

	logged := mustReadFile(t, path)
	assert.Contains(t, logged, `"msg":"error"`, "failure logs to file")
	assert.Contains(t, logged, "boom")
}

func TestNarrator_CloseFlushesPending(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "final narration"}
	l, _, buf := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: time.Hour, // never self-ticks
		Model:    "m", Client: client, CallBudget: time.Second,
	}, l)
	require.NotNil(t, n)

	n.Record("finding", "written", map[string]any{"title": "leftover"})
	n.Close() // should flush leftover event
	_ = l.Close()

	assert.Contains(t, buf.String(), "final narration")
	assert.Equal(t, int32(1), atomic.LoadInt32(&client.calls))
}

func TestNarrator_TickRespectsInterval(t *testing.T) {
	t.Parallel()
	client := &scriptedClient{response: "tick-ok"}
	l, _, _ := newCapturedLogger(t)
	n := NewNarrator(NarratorConfig{
		Interval: 50 * time.Millisecond,
		Model:    "m", Client: client, CallBudget: time.Second,
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
