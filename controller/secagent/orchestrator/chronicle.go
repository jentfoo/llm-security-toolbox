package orchestrator

// Worker chronicle: per-worker investigative history accumulated across
// iterations. Stored at the controller and installed onto each worker at
// iteration start. In-place compaction folds older iterations' think blocks
// and tool-result bodies into stubs to bound message growth.
//
// See per-function godocs (installChronicle, extractAndAppend,
// compactChronicle) for lifecycle details.

import (
	"github.com/go-appsec/secagent/agent"
)

// ChronicleKeepRecentIters is the number of trailing iterations whose
// chronicle messages stay raw. Older iters get compacted in place.
const ChronicleKeepRecentIters = 2

// installChronicle installs the worker's chronicle and queues the iter's
// directive. The three-step order (ReplaceHistory, MarkIterationBoundary,
// Query) is load-bearing for boundary-based extraction next iter.
func installChronicle(w *WorkerState, directive string) {
	w.Agent.ReplaceHistory(w.Chronicle)
	w.Agent.MarkIterationBoundary()
	w.Agent.Query(directive)
}

// snapshotter is the subset of *agent.OpenAIAgent we need to extract the
// iteration's new content. Defined as an interface so chronicle extraction
// works with FakeAgent as well as the real agent.
type snapshotter interface {
	Snapshot() []agent.Message
}

// extractAndAppend appends the iter's new turns (everything past the
// iteration boundary) onto w.Chronicle, tagging each with iter.
// No-op when the agent doesn't expose Snapshot.
func extractAndAppend(w *WorkerState, iter int) {
	s, ok := w.Agent.(snapshotter)
	if !ok {
		return
	}
	full := s.Snapshot()
	boundary := boundaryOf(w.Agent)
	if boundary < 0 || boundary >= len(full) {
		return
	}
	newMsgs := full[boundary:]
	w.Chronicle = append(w.Chronicle, newMsgs...)
	for range newMsgs {
		w.ChronicleIter = append(w.ChronicleIter, iter)
	}
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

// compactChronicle applies in-place compaction to chronicle messages
// tagged with an iter older than (currentIter - keepRecentIters + 1):
//   - assistant messages get their <think>...</think> blocks stripped.
//   - tool-result messages (non-repair) get replaced with a compact stub
//     ("(compacted: <tool> returned ~N tokens — ...)").
//
// Idempotent: re-running on an already-compacted message does nothing.
// Returns counts of stripped/stubbed messages for logging.
//
// Length-preserving by design: we never drop messages, so the parallel
// w.ChronicleIter stays in lockstep with w.Chronicle indexes.
func compactChronicle(w *WorkerState, currentIter, keepRecentIters int) (stripped, stubbed int) {
	if len(w.Chronicle) == 0 || keepRecentIters < 1 {
		return 0, 0
	}
	cutoff := currentIter - keepRecentIters + 1
	for i := range w.Chronicle {
		if i >= len(w.ChronicleIter) {
			// Defensive: lengths drifted (shouldn't happen). Stop early so
			// we don't mis-classify uncached messages.
			break
		}
		if w.ChronicleIter[i] >= cutoff {
			continue
		}
		if agent.StripAssistantThink(&w.Chronicle[i]) {
			stripped++
		}
		if agent.StubToolResult(&w.Chronicle[i]) {
			stubbed++
		}
	}
	return stripped, stubbed
}
