package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubClient struct{ id int }

func (s stubClient) CreateChatCompletion(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	return ChatResponse{}, nil
}

func TestClientPool(t *testing.T) {
	t.Parallel()
	t.Run("acquire_release", func(t *testing.T) {
		c1 := stubClient{id: 1}
		c2 := stubClient{id: 2}
		pool := NewClientPoolWithClients([]ChatClient{c1, c2})
		ctx := t.Context()

		a1, err := pool.Acquire(ctx)
		require.NoError(t, err)
		a2, err := pool.Acquire(ctx)
		require.NoError(t, err)

		var got ChatClient
		started := make(chan struct{})
		done := make(chan struct{})
		go func() {
			close(started)
			got, _ = pool.Acquire(ctx)
			close(done)
		}()
		<-started
		// Once the goroutine is runnable, Acquire must be blocked on the empty pool.
		require.Never(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}, 20*time.Millisecond, time.Millisecond)
		pool.Release(a1)
		<-done
		assert.NotNil(t, got)
		pool.Release(a2)
		pool.Release(got)
	})

	t.Run("context_cancel", func(t *testing.T) {
		pool := NewClientPool(stubClient{id: 1}, 1)
		first, err := pool.Acquire(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err = pool.Acquire(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		pool.Release(first)
	})

	t.Run("concurrent_acquire_cap", func(t *testing.T) {
		pool := NewClientPool(stubClient{id: 1}, 2)
		var peak int32
		var current int32
		var wg sync.WaitGroup
		release := make(chan struct{})
		ctx := t.Context()
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := pool.Acquire(ctx)
				if err != nil {
					return
				}
				n := atomic.AddInt32(&current, 1)
				for {
					p := atomic.LoadInt32(&peak)
					if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
						break
					}
				}
				<-release
				atomic.AddInt32(&current, -1)
				pool.Release(c)
			}()
		}
		// Wait until pool is saturated so peak reflects the cap.
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&current) == 2
		}, time.Second, time.Millisecond)
		close(release)
		wg.Wait()
		assert.LessOrEqual(t, peak, int32(2))
	})
}
