package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidatePool(t *testing.T) {
	t.Parallel()
	p := NewCandidatePool()
	before := p.Counter()
	c1 := p.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
	c2 := p.Add(AddInput{WorkerID: 2, Title: "y", Severity: "low", FlowIDs: []string{"def456"}})
	assert.Equal(t, "c001", c1)
	assert.Equal(t, "c002", c2)
	assert.Equal(t, []string{"c001"}, p.IDsSinceForWorker(before, 1))
	assert.Equal(t, []string{"c002"}, p.IDsSinceForWorker(before, 2))
	p.Mark("c001", "verified")
	pending := p.Pending()
	require.Len(t, pending, 1)
	assert.Equal(t, "c002", pending[0].CandidateID)
}

func TestCandidatePool_ByID(t *testing.T) {
	t.Parallel()

	t.Run("returns_copy", func(t *testing.T) {
		p := NewCandidatePool()
		id := p.Add(AddInput{WorkerID: 1, Title: "x", FlowIDs: []string{"f1"}})
		got := p.ByID(id)
		require.NotNil(t, got)
		assert.Equal(t, id, got.CandidateID)
		assert.Equal(t, []string{"f1"}, got.FlowIDs)
		// Mutations on the returned copy do not bleed back.
		got.FlowIDs[0] = "mutated"
		again := p.ByID(id)
		assert.Equal(t, "f1", again.FlowIDs[0])
	})

	t.Run("nil_for_unknown", func(t *testing.T) {
		p := NewCandidatePool()
		assert.Nil(t, p.ByID("nope"))
	})
}

func TestCandidatePool_MarkRejectsBackwardsTransition(t *testing.T) {
	t.Parallel()

	t.Run("verified_cannot_become_dismissed", func(t *testing.T) {
		p := NewCandidatePool()
		id := p.Add(AddInput{WorkerID: 1, Title: "x"})
		p.Mark(id, "verified")
		p.Mark(id, "dismissed")
		assert.Equal(t, "verified", p.ByID(id).Status)
	})

	t.Run("dismissed_cannot_become_verified", func(t *testing.T) {
		p := NewCandidatePool()
		id := p.Add(AddInput{WorkerID: 1, Title: "x"})
		p.Mark(id, "dismissed")
		p.Mark(id, "verified")
		assert.Equal(t, "dismissed", p.ByID(id).Status)
	})

	t.Run("invalid_status_rejected", func(t *testing.T) {
		p := NewCandidatePool()
		id := p.Add(AddInput{WorkerID: 1, Title: "x"})
		p.Mark(id, "nonsense")
		assert.Equal(t, "pending", p.ByID(id).Status)
	})

	t.Run("unknown_id_noop", func(t *testing.T) {
		p := NewCandidatePool()
		p.Mark("c999", "verified") // must not panic
	})
}
