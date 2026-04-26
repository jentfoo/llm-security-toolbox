package agent

import (
	"context"
	"errors"
	"sync"
)

// FakeAgent is a scripted Agent for tests. Each Drain pops the next
// configured TurnSummary in order; Query appends the content to QueriedInputs.
type FakeAgent struct {
	mu            sync.Mutex
	Turns         []TurnSummary // scripted sequence consumed in order
	Errors        []error       // per-turn errors; len may be < len(Turns)
	QueriedInputs []string
	Tools         []ToolDef
	ContextTokens int
	ContextMax    int
	Closed        bool
	MaxRoundsSeen []int // records bounds passed to DrainBounded for assertions
	// OnDrain, when non-nil, fires just before a scripted turn is returned.
	// Tests use it to simulate side effects (e.g. decision-queue mutations)
	// that a real agent would produce through its tool handlers.
	OnDrain func(turnIndex int)
	// LastReplacedHistory is the most recent slice passed to ReplaceHistory.
	// Tests assert on shape (length, roles, content) of installed history.
	LastReplacedHistory []Message
	// ReplacedHistories records every ReplaceHistory call in order so tests
	// can assert "exactly one ReplaceHistory per phase entry" semantics.
	ReplacedHistories [][]Message
	// OverflowOnDrain, when true, invokes OnContextOverflow (if non-nil)
	// before returning the scripted turn. Lets tests exercise the verifier's
	// context-budget auto-dismiss path without a real OpenAIAgent.
	OverflowOnDrain   bool
	OnContextOverflow func()
	// BoundaryCalls counts MarkIterationBoundary invocations so tests can
	// assert "exactly one boundary mark per iter per agent" semantics.
	BoundaryCalls int
	// LastBoundaryIdx is what IterationBoundary() returns. Set by
	// MarkIterationBoundary; tests may overwrite for chronicle extraction
	// scenarios.
	LastBoundaryIdx int
	// SnapshotMessages, when non-nil, is what Snapshot() returns. Lets
	// tests script a synthetic chat history for chronicle-extraction
	// assertions without driving a full Drain sequence.
	SnapshotMessages []Message
}

// Query records the content.
func (f *FakeAgent) Query(content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.QueriedInputs = append(f.QueriedInputs, content)
}

// Drain pops the next scripted turn.
func (f *FakeAgent) Drain(ctx context.Context) (TurnSummary, error) {
	return f.DrainBounded(ctx, 0)
}

// DrainBounded records the round cap and pops the next scripted turn.
// MaxRoundsSeen is exposed for tests that assert a caller-imposed bound.
func (f *FakeAgent) DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error) {
	f.mu.Lock()
	cb := f.OnDrain
	overflow := f.OverflowOnDrain
	overflowCb := f.OnContextOverflow
	turnIdx := len(f.QueriedInputs) - 1
	if maxRounds > 0 {
		f.MaxRoundsSeen = append(f.MaxRoundsSeen, maxRounds)
	}
	if ctx.Err() != nil {
		f.mu.Unlock()
		return TurnSummary{}, ctx.Err()
	}
	if len(f.Turns) == 0 {
		f.mu.Unlock()
		return TurnSummary{}, errors.New("FakeAgent: no scripted turns")
	}
	t := f.Turns[0]
	f.Turns = f.Turns[1:]
	var err error
	if len(f.Errors) > 0 {
		err = f.Errors[0]
		f.Errors = f.Errors[1:]
	}
	f.mu.Unlock()
	if overflow && overflowCb != nil {
		overflowCb()
	}
	if cb != nil {
		cb(turnIdx)
	}
	return t, err
}

// MarkIterationBoundary increments the call counter and records the
// current "history length" (computed from QueriedInputs + LastReplacedHistory
// for tests that want a meaningful boundary value).
func (f *FakeAgent) MarkIterationBoundary() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.BoundaryCalls++
	f.LastBoundaryIdx = len(f.LastReplacedHistory) + len(f.QueriedInputs)
}

// IterationBoundary returns the boundary index recorded by the most recent
// MarkIterationBoundary call. Tests that exercise chronicle extraction can
// override LastBoundaryIdx and then synthesize a snapshot to assert the
// extraction logic.
func (f *FakeAgent) IterationBoundary() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.LastBoundaryIdx
}

// Snapshot returns a synthetic message slice for chronicle-extraction tests.
// Tests can set SnapshotMessages explicitly; otherwise the default builds a
// best-effort approximation from LastReplacedHistory and QueriedInputs.
func (f *FakeAgent) Snapshot() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SnapshotMessages != nil {
		out := make([]Message, len(f.SnapshotMessages))
		copy(out, f.SnapshotMessages)
		return out
	}
	out := make([]Message, 0, len(f.LastReplacedHistory)+len(f.QueriedInputs))
	out = append(out, f.LastReplacedHistory...)
	for _, q := range f.QueriedInputs {
		out = append(out, Message{Role: "user", Content: q})
	}
	return out
}

// ReplaceHistory records the installed history for test assertions.
// Mirrors OpenAIAgent.ReplaceHistory but does not preserve a system
// prompt — tests installing history pass exactly the slice they want
// recorded.
func (f *FakeAgent) ReplaceHistory(msgs []Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]Message, len(msgs))
	copy(cp, msgs)
	f.LastReplacedHistory = cp
	f.ReplacedHistories = append(f.ReplacedHistories, cp)
}

// Interrupt is a no-op in fake.
func (f *FakeAgent) Interrupt() {}

// SetTools records tools.
func (f *FakeAgent) SetTools(defs []ToolDef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Tools = append(f.Tools[:0], defs...)
}

// ContextUsage returns configured fake values.
func (f *FakeAgent) ContextUsage() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ContextTokens, f.ContextMax
}

// Close marks the fake closed.
func (f *FakeAgent) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Closed = true
	return nil
}
