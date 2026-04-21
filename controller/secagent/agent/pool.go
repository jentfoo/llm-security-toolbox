package agent

import (
	"context"
	"errors"
)

// ClientPool is a bounded-concurrency gate over one or more ChatClient
// instances. Drain() acquires one client, runs one API request, releases.
type ClientPool struct {
	clients chan ChatClient
	size    int
}

// NewClientPool stores the given client n times into a buffered channel.
// Prefer NewClientPoolWithClients in production; this helper is kept for
// tests where a single fake is enough.
func NewClientPool(client ChatClient, n int) *ClientPool {
	if n < 1 {
		n = 1
	}
	p := &ClientPool{clients: make(chan ChatClient, n), size: n}
	for i := 0; i < n; i++ {
		p.clients <- client
	}
	return p
}

// NewClientPoolWithClients wraps exactly the clients it is given.
func NewClientPoolWithClients(clients []ChatClient) *ClientPool {
	n := len(clients)
	if n < 1 {
		n = 1
	}
	p := &ClientPool{clients: make(chan ChatClient, n), size: n}
	for _, c := range clients {
		p.clients <- c
	}
	return p
}

// Size returns the pool capacity.
func (p *ClientPool) Size() int { return p.size }

// Acquire blocks until a client is available or ctx is done.
func (p *ClientPool) Acquire(ctx context.Context) (ChatClient, error) {
	if p == nil {
		return nil, errors.New("nil pool")
	}
	select {
	case c := <-p.clients:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Release returns a client to the pool. Must match an Acquire.
func (p *ClientPool) Release(c ChatClient) {
	if p == nil || c == nil {
		return
	}
	p.clients <- c
}
