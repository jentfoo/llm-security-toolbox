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
	if cb != nil {
		cb(turnIdx)
	}
	return t, err
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
