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
