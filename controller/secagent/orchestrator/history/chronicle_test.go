package history

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestChronicle_Install(t *testing.T) {
	t.Parallel()

	t.Run("installs_raw_and_queries", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		c := Chronicle{
			messages: []agent.Message{
				{Role: "user", Content: "iter 1 directive"},
				{Role: "assistant", Content: "I tested /admin"},
			},
			iters: []int{1, 1},
		}
		c.Install(fake, "investigate /api this iteration")
		require.Len(t, fake.LastReplacedHistory, 2)
		assert.Equal(t, "iter 1 directive", fake.LastReplacedHistory[0].Content)
		assert.Equal(t, "I tested /admin", fake.LastReplacedHistory[1].Content)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /api this iteration", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})

	t.Run("empty_chronicle_iter_one", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		var c Chronicle
		c.Install(fake, "investigate /login")
		assert.Empty(t, fake.LastReplacedHistory)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /login", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})
}

func TestChronicle_ExtractAndAppend(t *testing.T) {
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
		var c Chronicle
		c.ExtractAndAppend(fake, 5)
		require.Len(t, c.messages, 2)
		require.Len(t, c.iters, 2)
		assert.Equal(t, []int{5, 5}, c.iters)
		assert.Equal(t, "assistant", c.messages[0].Role)
		assert.Equal(t, "tool", c.messages[1].Role)
	})

	t.Run("no_snapshotter_is_noop", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{{Role: "user", Content: "preexisting"}},
			iters:    []int{1},
		}
		c.ExtractAndAppend(&noopAgent{}, 2)
		assert.Len(t, c.messages, 1)
		assert.Equal(t, []int{1}, c.iters)
	})
}

func TestChronicle_Compact(t *testing.T) {
	t.Parallel()

	t.Run("strips_and_stubs_old", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>I will fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "(very long tool output here that should be stubbed)"},
				{Role: "user", Content: "iter 2 directive"},
				{Role: "assistant", Content: "<think>recent reasoning</think>Trying again"},
				{Role: "tool", ToolName: "replay_send", Content: "fresh result"},
			},
			iters: []int{1, 1, 2, 2, 2},
		}
		stripped, stubbed := c.Compact(3, 2)
		assert.Equal(t, 1, stripped)
		assert.Equal(t, 1, stubbed)
		assert.NotContains(t, c.messages[0].Content, "<think>")
		assert.Contains(t, c.messages[0].Content, "I will fetch /admin")
		assert.Contains(t, c.messages[1].Content, "compacted:")
		assert.Contains(t, c.messages[3].Content, "<think>recent reasoning</think>")
		assert.Equal(t, "fresh result", c.messages[4].Content)
	})

	t.Run("idempotent", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "long output"},
			},
			iters: []int{1, 1},
		}
		stripped1, stubbed1 := c.Compact(5, 2)
		require.Equal(t, 1, stripped1)
		require.Equal(t, 1, stubbed1)
		stripped2, stubbed2 := c.Compact(5, 2)
		assert.Equal(t, 0, stripped2)
		assert.Equal(t, 0, stubbed2)
	})

	t.Run("preserves_length_and_order", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "user", Content: "directive 1"},
				{Role: "assistant", Content: "<think>x</think>y"},
				{Role: "tool", ToolName: "t", Content: "long"},
				{Role: "user", Content: "directive 2"},
			},
			iters: []int{1, 1, 1, 2},
		}
		preLen := len(c.messages)
		c.Compact(3, 2)
		assert.Len(t, c.messages, preLen)
		assert.Equal(t, "directive 1", c.messages[0].Content)
		assert.Equal(t, "directive 2", c.messages[3].Content)
	})

	t.Run("nothing_old_is_noop", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>x</think>recent"},
			},
			iters: []int{5},
		}
		stripped, stubbed := c.Compact(5, 2)
		assert.Equal(t, 0, stripped)
		assert.Equal(t, 0, stubbed)
		assert.Equal(t, "<think>x</think>recent", c.messages[0].Content)
	})

	t.Run("repair_errors_protected", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "tool", ToolName: "t", IsRepairError: true,
					Content: "ERROR: your arguments did not parse..."},
			},
			iters: []int{1},
		}
		_, stubbed := c.Compact(5, 2)
		assert.Equal(t, 0, stubbed)
		assert.Contains(t, c.messages[0].Content, "did not parse")
	})
}

func TestChronicle_CloneWithDirective(t *testing.T) {
	t.Parallel()

	src := Chronicle{
		messages: []agent.Message{
			{Role: "user", Content: "iter 1 directive"},
			{Role: "assistant", Content: "tested /admin"},
		},
		iters: []int{1, 1},
	}
	clone := src.CloneWithDirective("new fork directive", 2)
	require.Len(t, clone.messages, 3)
	assert.Equal(t, "new fork directive", clone.messages[0].Content)
	assert.Equal(t, "user", clone.messages[0].Role)
	assert.Equal(t, "iter 1 directive", clone.messages[1].Content)
	assert.Equal(t, []int{2, 1, 1}, clone.iters)
	// Source untouched.
	assert.Len(t, src.messages, 2)
	assert.Equal(t, []int{1, 1}, src.iters)
}

func TestChronicle_Reset(t *testing.T) {
	t.Parallel()
	c := Chronicle{
		messages: []agent.Message{{Role: "user", Content: "x"}},
		iters:    []int{1},
	}
	c.Reset()
	assert.Empty(t, c.messages)
	assert.Empty(t, c.iters)
	assert.Equal(t, 0, c.Len())
}

func TestSnapshotSinceBoundary(t *testing.T) {
	t.Parallel()

	t.Run("no_snapshotter_returns_nil", func(t *testing.T) {
		assert.Nil(t, SnapshotSinceBoundary(&noopAgent{}))
	})

	t.Run("missing_boundary_returns_nil", func(t *testing.T) {
		// LastBoundaryIdx zero-value is 0, but FakeAgent reports
		// IterationBoundary() as -1 when not yet marked.
		fake := &agent.FakeAgent{
			LastBoundaryIdx:  -1,
			SnapshotMessages: []agent.Message{{Role: "user", Content: "x"}},
		}
		assert.Nil(t, SnapshotSinceBoundary(fake))
	})

	t.Run("boundary_past_end_returns_nil", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryIdx:  3,
			SnapshotMessages: []agent.Message{{Role: "user", Content: "x"}},
		}
		assert.Nil(t, SnapshotSinceBoundary(fake))
	})

	t.Run("returns_tail_clone", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryIdx: 1,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "thinking"},
				{Role: "tool", ToolName: "proxy_poll", Content: "result"},
			},
		}
		out := SnapshotSinceBoundary(fake)
		require.Len(t, out, 2)
		assert.Equal(t, "assistant", out[0].Role)
		assert.Equal(t, "tool", out[1].Role)
		// Mutate the returned slice; the agent's internal snapshot must be
		// untouched.
		out[0].Content = "mutated"
		assert.Equal(t, "thinking", fake.SnapshotMessages[1].Content)
	})

	t.Run("boundary_zero_returns_full_history", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryIdx: 0,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "ack"},
			},
		}
		out := SnapshotSinceBoundary(fake)
		require.Len(t, out, 2)
	})
}

// noopAgent is a minimal agent.Agent that exposes neither Snapshot nor
// IterationBoundary. Used to verify ExtractAndAppend's fail-open path.
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
