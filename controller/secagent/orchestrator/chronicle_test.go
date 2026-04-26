package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestInstallChronicle(t *testing.T) {
	t.Parallel()

	t.Run("installs_raw_and_queries", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		w := &WorkerState{
			ID:    1,
			Agent: fake,
			Chronicle: []agent.Message{
				{Role: "user", Content: "iter 1 directive"},
				{Role: "assistant", Content: "I tested /admin"},
			},
		}
		installChronicle(w, "investigate /api this iteration")
		require.Len(t, fake.LastReplacedHistory, 2)
		assert.Equal(t, "iter 1 directive", fake.LastReplacedHistory[0].Content)
		assert.Equal(t, "I tested /admin", fake.LastReplacedHistory[1].Content)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /api this iteration", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})

	t.Run("empty_chronicle_iter_one", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Agent: fake}
		installChronicle(w, "investigate /login")
		assert.Empty(t, fake.LastReplacedHistory)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /login", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})
}

func TestExtractAndAppend(t *testing.T) {
	t.Parallel()

	t.Run("tags_messages_with_iter", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryIdx: 1,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "thinking"},
				{Role: "tool", ToolName: "proxy_poll", Content: "result"},
			},
		}
		w := &WorkerState{ID: 1, Agent: fake}
		extractAndAppend(w, 5)
		require.Len(t, w.Chronicle, 2)
		require.Len(t, w.ChronicleIter, 2)
		assert.Equal(t, []int{5, 5}, w.ChronicleIter)
		assert.Equal(t, "assistant", w.Chronicle[0].Role)
		assert.Equal(t, "tool", w.Chronicle[1].Role)
	})

	t.Run("no_snapshotter_is_noop", func(t *testing.T) {
		w := &WorkerState{ID: 1, Agent: &noopAgent{}}
		w.Chronicle = []agent.Message{{Role: "user", Content: "preexisting"}}
		w.ChronicleIter = []int{1}
		extractAndAppend(w, 2)
		assert.Len(t, w.Chronicle, 1)
		assert.Equal(t, []int{1}, w.ChronicleIter)
	})
}

func TestCompactChronicle(t *testing.T) {
	t.Parallel()

	t.Run("strips_and_stubs_old", func(t *testing.T) {
		w := &WorkerState{
			Chronicle: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>I will fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "(very long tool output here that should be stubbed)"},
				{Role: "user", Content: "iter 2 directive"},
				{Role: "assistant", Content: "<think>recent reasoning</think>Trying again"},
				{Role: "tool", ToolName: "replay_send", Content: "fresh result"},
			},
			ChronicleIter: []int{1, 1, 2, 2, 2},
		}
		stripped, stubbed := compactChronicle(w, 3, 2)
		assert.Equal(t, 1, stripped)
		assert.Equal(t, 1, stubbed)
		assert.NotContains(t, w.Chronicle[0].Content, "<think>")
		assert.Contains(t, w.Chronicle[0].Content, "I will fetch /admin")
		assert.Contains(t, w.Chronicle[1].Content, "compacted:")
		assert.Contains(t, w.Chronicle[3].Content, "<think>recent reasoning</think>")
		assert.Equal(t, "fresh result", w.Chronicle[4].Content)
	})

	t.Run("idempotent", func(t *testing.T) {
		w := &WorkerState{
			Chronicle: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "long output"},
			},
			ChronicleIter: []int{1, 1},
		}
		stripped1, stubbed1 := compactChronicle(w, 5, 2)
		require.Equal(t, 1, stripped1)
		require.Equal(t, 1, stubbed1)
		stripped2, stubbed2 := compactChronicle(w, 5, 2)
		assert.Equal(t, 0, stripped2)
		assert.Equal(t, 0, stubbed2)
	})

	t.Run("preserves_length_and_order", func(t *testing.T) {
		w := &WorkerState{
			Chronicle: []agent.Message{
				{Role: "user", Content: "directive 1"},
				{Role: "assistant", Content: "<think>x</think>y"},
				{Role: "tool", ToolName: "t", Content: "long"},
				{Role: "user", Content: "directive 2"},
			},
			ChronicleIter: []int{1, 1, 1, 2},
		}
		preLen := len(w.Chronicle)
		compactChronicle(w, 3, 2)
		assert.Len(t, w.Chronicle, preLen)
		assert.Equal(t, "directive 1", w.Chronicle[0].Content)
		assert.Equal(t, "directive 2", w.Chronicle[3].Content)
	})

	t.Run("nothing_old_is_noop", func(t *testing.T) {
		w := &WorkerState{
			Chronicle: []agent.Message{
				{Role: "assistant", Content: "<think>x</think>recent"},
			},
			ChronicleIter: []int{5},
		}
		stripped, stubbed := compactChronicle(w, 5, 2)
		assert.Equal(t, 0, stripped)
		assert.Equal(t, 0, stubbed)
		assert.Equal(t, "<think>x</think>recent", w.Chronicle[0].Content)
	})

	t.Run("repair_errors_protected", func(t *testing.T) {
		w := &WorkerState{
			Chronicle: []agent.Message{
				{Role: "tool", ToolName: "t", IsRepairError: true,
					Content: "ERROR: your arguments did not parse..."},
			},
			ChronicleIter: []int{1},
		}
		_, stubbed := compactChronicle(w, 5, 2)
		assert.Equal(t, 0, stubbed)
		assert.Contains(t, w.Chronicle[0].Content, "did not parse")
	})
}

// noopAgent is a minimal agent.Agent that exposes neither Snapshot nor
// IterationBoundary. Used to verify extractAndAppend's fail-open path.
type noopAgent struct{}

func (n *noopAgent) Query(string) {}
func (n *noopAgent) Drain(context.Context) (agent.TurnSummary, error) {
	return agent.TurnSummary{}, nil
}
func (n *noopAgent) DrainBounded(context.Context, int) (agent.TurnSummary, error) {
	return agent.TurnSummary{}, nil
}
func (n *noopAgent) Close() error                   { return nil }
func (n *noopAgent) Interrupt()                     {}
func (n *noopAgent) SetTools([]agent.ToolDef)       {}
func (n *noopAgent) ReplaceHistory([]agent.Message) {}
func (n *noopAgent) MarkIterationBoundary()         {}
func (n *noopAgent) ContextUsage() (int, int)       { return 0, 0 }
