package history

import (
	"slices"

	"github.com/go-appsec/secagent/agent"
)

// ChronicleKeepRecentIters is the trailing iteration window kept raw;
// older iters are compacted in place by Chronicle.Compact.
const ChronicleKeepRecentIters = 2

// Chronicle holds a worker's investigative chat history accumulated
// across iterations alongside the per-message iteration index, and owns
// the parallel-array invariant.
type Chronicle struct {
	messages []agent.Message
	iters    []int
}

// NewChronicle returns a Chronicle seeded with messages and their
// per-message iteration indices. iters may be nil or shorter than
// messages; in that case Compact will break early on the missing tail.
func NewChronicle(messages []agent.Message, iters []int) Chronicle {
	return Chronicle{messages: messages, iters: iters}
}

// Messages returns the chronicle's current message slice. The returned
// slice aliases internal storage; callers must not mutate it.
func (c *Chronicle) Messages() []agent.Message {
	if c == nil {
		return nil
	}
	return c.messages
}

// Len returns the number of chronicle messages.
func (c *Chronicle) Len() int {
	if c == nil {
		return 0
	}
	return len(c.messages)
}

// Install replaces a's history with the chronicle, marks the iteration
// boundary, and queues directive.
func (c *Chronicle) Install(a agent.Agent, directive string) {
	a.ReplaceHistory(c.messages)
	a.MarkIterationBoundary()
	a.Query(directive)
}

// snapshotter is implemented by agents exposing the full message history.
type snapshotter interface {
	Snapshot() []agent.Message
}

// boundaryReader is implemented by agents exposing an iteration boundary
// index.
type boundaryReader interface {
	IterationBoundary() int
}

// SnapshotSinceBoundary returns a clone of a's history from its iteration
// boundary onward, or nil when the agent doesn't expose a snapshot or
// boundary, or when the boundary is out of range.
func SnapshotSinceBoundary(a agent.Agent) []agent.Message {
	tail := snapshotSinceBoundary(a)
	if tail == nil {
		return nil
	}
	return slices.Clone(tail)
}

// snapshotSinceBoundary returns a's history from the iteration boundary
// onward without cloning. Internal callers that immediately copy via
// append skip the extra allocation.
func snapshotSinceBoundary(a agent.Agent) []agent.Message {
	s, ok := a.(snapshotter)
	if !ok {
		return nil
	}
	full := s.Snapshot()
	boundary := -1
	if br, ok := a.(boundaryReader); ok {
		boundary = br.IterationBoundary()
	}
	if boundary < 0 || boundary >= len(full) {
		return nil
	}
	return full[boundary:]
}

// ExtractAndAppend appends a's iter messages onto the chronicle, each
// tagged with iter. No-op when a doesn't expose a snapshot or boundary.
func (c *Chronicle) ExtractAndAppend(a agent.Agent, iter int) {
	newMsgs := snapshotSinceBoundary(a)
	if len(newMsgs) == 0 {
		return
	}
	c.messages = append(c.messages, newMsgs...)
	for range newMsgs {
		c.iters = append(c.iters, iter)
	}
}

// Compact applies in-place think-strip and tool-stub compaction to
// chronicle messages older than the keepRecentIters window. Returns
// counts of stripped and stubbed messages.
func (c *Chronicle) Compact(currentIter, keepRecentIters int) (stripped, stubbed int) {
	if c == nil || len(c.messages) == 0 || keepRecentIters < 1 {
		return 0, 0
	}
	cutoff := currentIter - keepRecentIters + 1
	for i := range c.messages {
		if i >= len(c.iters) {
			break
		}
		if c.iters[i] >= cutoff {
			continue
		}
		if agent.StripAssistantThink(&c.messages[i]) {
			stripped++
		}
		if agent.StubToolResult(&c.messages[i]) {
			stubbed++
		}
	}
	return stripped, stubbed
}

// Reset clears the chronicle.
func (c *Chronicle) Reset() {
	if c == nil {
		return
	}
	c.messages = nil
	c.iters = nil
}

// CloneWithDirective returns a new Chronicle that prepends a user-role
// directive (tagged with iter) onto a clone of the existing messages.
func (c *Chronicle) CloneWithDirective(directive string, iter int) Chronicle {
	srcMsgs := c.Messages()
	srcIters := c.iter()
	msgs := make([]agent.Message, 0, 1+len(srcMsgs))
	msgs = append(msgs, agent.Message{Role: "user", Content: directive})
	msgs = append(msgs, srcMsgs...)
	iters := make([]int, 0, 1+len(srcIters))
	iters = append(iters, iter)
	iters = append(iters, srcIters...)
	return Chronicle{messages: msgs, iters: iters}
}

func (c *Chronicle) iter() []int {
	if c == nil {
		return nil
	}
	return c.iters
}
