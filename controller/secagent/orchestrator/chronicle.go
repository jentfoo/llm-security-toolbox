package orchestrator

// Worker chronicle: per-worker canonical investigative history accumulated
// across iterations. Lives at the controller as raw messages — never
// loaded into the worker agent's chat history directly. Instead, at iter
// start the chronicle is summarized fresh (one-shot from the canonical
// raw record, never from a prior summary) and the resulting summary is
// installed as the worker agent's pre-iter context. This avoids the
// summary-of-summary dilution that biased workers back to their original
// angle.
//
// Lifecycle per iteration:
//
//  1. installChronicle(ctx, w, directive, summarizer, mission)
//     - If the chronicle is empty (iter 1): ReplaceHistory(nil); just the
//       system prompt remains.
//     - Otherwise: Summarizer.SummarizeWorkerFromChronicle(chronicle, ...)
//       produces a fresh first-person recap; ReplaceHistory installs it as
//       a single user-role message under the system prompt.
//     - MarkIterationBoundary records the position right after the
//       installed context — anything before that index is the (possibly
//       summarized) memory; anything from there on is this iter's work.
//     - Query(directive) appends the iter's directive as a user message.
//
//  2. The agent drains. The pre-iter content is just one short summary
//     message, so context pressure within an iteration is bounded by the
//     iter's tool calls; no boundary-summarize callback is needed for
//     workers (it would be summarizing a summary).
//
//  3. extractAndAppend(w) reads everything from the iteration boundary
//     through the end of the agent's history, and appends to w.Chronicle.
//     The chronicle therefore accumulates raw byte-level texture (tool
//     calls, tool results, assistant turns) — the canonical record from
//     which every future summary is freshly derived.

import (
	"context"

	"github.com/go-appsec/secagent/agent"
)

// chronicleSummarizeFn produces a fresh first-person recap from a worker's
// canonical chronicle. *Summarizer.SummarizeWorkerFromChronicle satisfies
// this in production; tests pass simpler stubs.
type chronicleSummarizeFn func(ctx context.Context, chronicle []agent.Message, mission string, workerID int) (string, error)

// installChronicle prepares the worker agent for a new iteration. When the
// chronicle is non-empty and a summarize function is supplied:
//
//   - Cache hit: when w.SummaryCache is populated AND the cached summary
//     was generated against the same directive AND the chronicle has not
//     grown since (len match), reuse the cached summary verbatim — saves
//     one LLM call per no-op iter while preserving the "always derived
//     from raw chronicle" invariant (the cache IS a fresh-from-raw output,
//     just one we already paid for).
//   - Cache miss: re-summarize from the raw chronicle and store the result
//     in the cache for next iter.
//   - Summarize error with cache available: fall back to the cached
//     summary so the worker keeps its memory of prior work. A stale cache
//     is far better than an empty pre-iter (which makes the worker forget
//     everything and likely repeat itself).
//   - Summarize error with no cache: install with empty pre-iter (only
//     option). The chronicle itself is preserved for the next attempt.
//
// Order is load-bearing:
//
//  1. ReplaceHistory(...) — clears boundary state, installs the (possibly
//     empty) pre-iter context under the system prompt.
//  2. MarkIterationBoundary — records boundary just past the install and
//     BEFORE the directive Query.
//  3. Query(directive) — appends the directive as a user message.
func installChronicle(
	ctx context.Context,
	w *WorkerState,
	directive string,
	summarize chronicleSummarizeFn,
	mission string,
	log *Logger,
) {
	var preIter []agent.Message
	if len(w.Chronicle) > 0 && summarize != nil {
		if w.SummaryCache != "" &&
			w.SummaryCacheDirective == directive &&
			w.SummaryCacheChronLen == len(w.Chronicle) {
			preIter = []agent.Message{{Role: "user", Content: w.SummaryCache}}
			if log != nil {
				log.Log("summarize", "worker chronicle install cache-hit", map[string]any{
					"worker_id":      w.ID,
					"chronicle_msgs": len(w.Chronicle),
				})
			}
		} else {
			summary, err := summarize(ctx, w.Chronicle, mission, w.ID)
			switch {
			case err == nil && summary != "":
				preIter = []agent.Message{{Role: "user", Content: summary}}
				w.SummaryCache = summary
				w.SummaryCacheDirective = directive
				w.SummaryCacheChronLen = len(w.Chronicle)
			case err != nil && w.SummaryCache != "":
				preIter = []agent.Message{{Role: "user", Content: w.SummaryCache}}
				if log != nil {
					log.Log("summarize", "worker chronicle install cache-fallback", map[string]any{
						"worker_id": w.ID, "err": err.Error(),
					})
				}
			case err != nil:
				if log != nil {
					log.Log("summarize", "worker chronicle install empty-fallback", map[string]any{
						"worker_id": w.ID, "err": err.Error(),
					})
				}
			}
		}
	}
	w.Agent.ReplaceHistory(preIter)
	w.Agent.MarkIterationBoundary()
	w.Agent.Query(directive)
}

// snapshotter is the subset of *agent.OpenAIAgent we need to extract the
// iteration's new content. Defined as an interface so chronicle extraction
// works with FakeAgent as well as the real agent.
type snapshotter interface {
	Snapshot() []agent.Message
}

// extractAndAppend reads the worker agent's current history, takes
// everything from the iteration boundary onward (the iter's new turns),
// and appends it to w.Chronicle.
//
// If the agent doesn't expose Snapshot (i.e. the agent isn't an
// *OpenAIAgent or a FakeAgent that implements it), this is a no-op — the
// chronicle simply doesn't grow this iter, which is correct fail-open
// behavior for test fakes that didn't script any post-install activity.
func extractAndAppend(w *WorkerState) {
	s, ok := w.Agent.(snapshotter)
	if !ok {
		return
	}
	full := s.Snapshot()
	boundary := boundaryOf(w.Agent)
	if boundary < 0 || boundary >= len(full) {
		return
	}
	w.Chronicle = append(w.Chronicle, full[boundary:]...)
}

// boundaryReader is implemented by agents that expose their iteration
// boundary index for chronicle extraction. *agent.OpenAIAgent satisfies
// this; tests provide their own implementations as needed.
type boundaryReader interface {
	IterationBoundary() int
}

// boundaryOf returns the agent's iteration boundary index, or -1 when the
// agent doesn't expose one. Returning -1 causes extractAndAppend to skip
// the append — a safe no-op for fakes that don't track a real boundary.
func boundaryOf(a agent.Agent) int {
	if br, ok := a.(boundaryReader); ok {
		return br.IterationBoundary()
	}
	return -1
}
