package history

import (
	"context"
	"sync"
	"sync/atomic"

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
