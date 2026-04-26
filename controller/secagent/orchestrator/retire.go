package orchestrator

import (
	"context"
	"sync"
)

// retireResult holds one completed retirement summary.
// Empty Summary indicates summarize failure; the retirement is still recorded.
type retireResult struct {
	WorkerID int
	Iter     int
	Reason   string
	Summary  string
}

// RetireQueue summarizes retired workers asynchronously under a bounded
// semaphore. Results buffer on a channel for polling at iteration boundaries.
type RetireQueue struct {
	ctx     context.Context
	sum     *Summarizer
	mission string
	log     *Logger
	sem     chan struct{}
	wg      sync.WaitGroup
	results chan retireResult
}

// newRetireQueue constructs a queue. capacity caps simultaneous summarize
// calls so a wave of stalls can't saturate the shared LLM pool. results
// is buffered up to 4×capacity so DrainCompleted has slack for bursts —
// the main loop polls at every iter boundary so this should never block
// in practice, but the buffer protects against a stall-then-burst pattern.
func newRetireQueue(ctx context.Context, sum *Summarizer, mission string, log *Logger, capacity int) *RetireQueue {
	if capacity < 1 {
		capacity = 1
	}
	return &RetireQueue{
		ctx:     ctx,
		sum:     sum,
		mission: mission,
		log:     log,
		sem:     make(chan struct{}, capacity),
		results: make(chan retireResult, capacity*4),
	}
}

// Submit closes the worker's agent and queues a background summarize call.
// w.Alive flips to false before return. Caller must not submit the same
// worker twice.
func (q *RetireQueue) Submit(w *WorkerState, reason string, iter int) {
	if q == nil {
		return
	}
	w.Alive = false
	chronicle := w.Chronicle
	_ = w.Agent.Close()
	if q.log != nil {
		q.log.Log("retire", "enqueued", map[string]any{
			"worker_id": w.ID, "reason": reason, "iter": iter,
			"chronicle_msgs": len(chronicle),
		})
	}
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		// Fast bail when run is already cancelled.
		if err := q.ctx.Err(); err != nil {
			return
		}
		select {
		case q.sem <- struct{}{}:
		case <-q.ctx.Done():
			return
		}
		defer func() { <-q.sem }()
		summary := ""
		if len(chronicle) > 0 && q.sum != nil {
			s, err := q.sum.SummarizeCompletedWorker(q.ctx, chronicle, q.mission, reason, w.ID)
			if err != nil {
				if q.log != nil {
					q.log.Log("retire", "summarize-fallback", map[string]any{
						"worker_id": w.ID, "err": err.Error(),
					})
				}
			} else {
				summary = s
			}
		}
		res := retireResult{WorkerID: w.ID, Iter: iter, Reason: reason, Summary: summary}
		select {
		case q.results <- res:
		case <-q.ctx.Done():
			return
		}
		if q.log != nil {
			q.log.Log("retire", "summary-ready", map[string]any{
				"worker_id": w.ID, "iter": iter, "summary_chars": len(summary),
			})
		}
	}()
}

// DrainCompleted returns every retire result that has finished since the
// last poll. Non-blocking. Returns nil when nothing is ready.
func (q *RetireQueue) DrainCompleted() []retireResult {
	if q == nil {
		return nil
	}
	var out []retireResult
	for {
		select {
		case r := <-q.results:
			out = append(out, r)
		default:
			return out
		}
	}
}

// WaitOne blocks until one retire result is available (or ctx is done),
// then returns it. Used by the iter-1 recon path where we MUST have the
// recon summary before iter 2 starts.
func (q *RetireQueue) WaitOne(ctx context.Context) (retireResult, bool) {
	if q == nil {
		return retireResult{}, false
	}
	select {
	case r := <-q.results:
		return r, true
	case <-ctx.Done():
		return retireResult{}, false
	}
}

// Wait blocks until every submitted retire completes. Idempotent. Does
// NOT drain results — call DrainCompleted afterwards if the caller wants
// remaining summaries.
func (q *RetireQueue) Wait() {
	if q == nil {
		return
	}
	q.wg.Wait()
}
