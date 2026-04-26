package orchestrator

import (
	"context"
	"sync"
)

// asyncMerger implements MergeSubmitter by spawning a bounded-concurrency
// goroutine per submitted merge. Wait() blocks until every in-flight merge
// completes; called at shutdown so the user doesn't lose work mid-merge.
//
// The merge itself: ask the dedup reviewer to coalesce the existing finding
// (read from FindingWriter's in-memory index by filename) with a synthetic
// FindingFiled built from the worker's AddInput, then writer.Replace the
// existing file in place.
type asyncMerger struct {
	ctx      context.Context
	reviewer DedupReviewer
	writer   *FindingWriter
	log      *Logger
	sem      chan struct{}
	wg       sync.WaitGroup
}

// newAsyncMerger constructs an asyncMerger. capacity caps simultaneous
// merges so a candidate burst can't overload the summary pool.
func newAsyncMerger(ctx context.Context, reviewer DedupReviewer, writer *FindingWriter, log *Logger, capacity int) *asyncMerger {
	if capacity < 1 {
		capacity = 1
	}
	return &asyncMerger{
		ctx:      ctx,
		reviewer: reviewer,
		writer:   writer,
		log:      log,
		sem:      make(chan struct{}, capacity),
	}
}

// Submit queues a merge of incoming into the finding at matchedFilename.
// Returns immediately; the work runs in the background. Cancellation of the
// run-level ctx aborts in-flight merges.
func (m *asyncMerger) Submit(matchedFilename string, incoming AddInput) {
	if m == nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		// Fast-path bail when the run is already cancelled — important
		// because select picks randomly when both cases are ready, so a
		// pre-cancelled ctx would otherwise still race the semaphore send.
		if err := m.ctx.Err(); err != nil {
			return
		}
		select {
		case m.sem <- struct{}{}:
		case <-m.ctx.Done():
			return
		}
		defer func() { <-m.sem }()
		m.runOne(matchedFilename, incoming)
	}()
}

// Wait blocks until every submitted merge completes. Idempotent.
func (m *asyncMerger) Wait() {
	if m == nil {
		return
	}
	m.wg.Wait()
}

func (m *asyncMerger) runOne(matchedFilename string, incoming AddInput) {
	existing, path, ok := m.writer.LookupByFilename(matchedFilename)
	if !ok {
		if m.log != nil {
			m.log.Log("finding", "async-merge target missing", map[string]any{
				"matched_filename": matchedFilename,
			})
		}
		return
	}
	secondary := candidateAsFindingFiled(incoming)
	merged, err := m.reviewer.Merge(m.ctx, existing, secondary)
	if err != nil {
		if m.log != nil {
			m.log.Log("finding", "async-merge classify error", map[string]any{
				"matched_filename": matchedFilename,
				"err":              err.Error(),
			})
		}
		return
	}
	newPath, err := m.writer.Replace(path, merged)
	if err != nil {
		if m.log != nil {
			m.log.Log("finding", "async-merge replace error", map[string]any{
				"matched_filename": matchedFilename,
				"err":              err.Error(),
			})
		}
		return
	}
	if m.log != nil {
		m.log.Log("finding", "async-merge applied", map[string]any{
			"matched_filename": matchedFilename,
			"path":             newPath,
		})
	}
}

// candidateAsFindingFiled adapts a worker's AddInput shape to the
// FindingFiled shape expected by reviewer.Merge. Worker-side fields map
// onto the file format's fields most-similar-first.
func candidateAsFindingFiled(in AddInput) FindingFiled {
	return FindingFiled{
		Title:             in.Title,
		Severity:          in.Severity,
		Endpoint:          in.Endpoint,
		Description:       in.Summary,
		ReproductionSteps: in.ReproductionHint,
		Evidence:          in.EvidenceNotes,
	}
}
