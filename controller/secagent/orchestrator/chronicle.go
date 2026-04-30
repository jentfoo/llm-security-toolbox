package orchestrator

// Worker chronicle: per-worker investigative history accumulated across
// iterations. Installed onto each worker at iter start, with in-place
// compaction for older iters.

import (
	"github.com/go-appsec/secagent/agent"
)

// ChronicleKeepRecentIters is the trailing iteration window kept raw;
// older iters are compacted in place.
const ChronicleKeepRecentIters = 2

// installChronicle installs w.Chronicle on the agent, marks the iteration
// boundary, and queues directive.
func installChronicle(w *WorkerState, directive string) {
	w.Agent.ReplaceHistory(w.Chronicle)
	w.Agent.MarkIterationBoundary()
	w.Agent.Query(directive)
}

// snapshotter is implemented by agents exposing the full message history.
type snapshotter interface {
	Snapshot() []agent.Message
}

// extractAndAppend appends the iter's new agent messages to w.Chronicle,
// each tagged with iter. No-op when the agent has no boundary.
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

// boundaryReader is implemented by agents exposing an iteration boundary
// index.
type boundaryReader interface {
	IterationBoundary() int
}

// boundaryOf returns the agent's iteration boundary index, or -1 when
// the agent doesn't expose one.
func boundaryOf(a agent.Agent) int {
	if br, ok := a.(boundaryReader); ok {
		return br.IterationBoundary()
	}
	return -1
}

// compactChronicle applies in-place think-strip and tool-stub compaction
// to chronicle messages older than the keepRecentIters window. Returns
// counts of stripped and stubbed messages.
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
