package agent

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFakeAgent_QueryDrainScripted(t *testing.T) {
	t.Parallel()
	f := &FakeAgent{
		Turns:  []TurnSummary{{AssistantText: "one"}, {AssistantText: "two"}},
		Errors: []error{nil, errors.New("boom")},
	}
	f.Query("hi")
	assert.Equal(t, []string{"hi"}, f.QueriedInputs)

	sum1, err := f.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "one", sum1.AssistantText)

	_, err = f.Drain(t.Context())
	require.Error(t, err)
}

func TestFakeAgent_DrainEmptyErrors(t *testing.T) {
	t.Parallel()
	f := &FakeAgent{}
	_, err := f.Drain(t.Context())
	require.Error(t, err)
}

func TestFakeAgent_DrainBoundedRecordsCap(t *testing.T) {
	t.Parallel()
	f := &FakeAgent{Turns: []TurnSummary{{}, {}, {}}}
	_, _ = f.DrainBounded(t.Context(), 2)
	_, _ = f.DrainBounded(t.Context(), 5)
	_, _ = f.Drain(t.Context()) // bound 0 not recorded
	assert.Equal(t, []int{2, 5}, f.MaxRoundsSeen)
}

func TestFakeAgent_SetToolsAndContext(t *testing.T) {
	t.Parallel()
	f := &FakeAgent{ContextTokens: 123, ContextMax: 1000}
	f.SetTools([]ToolDef{{Name: "a"}, {Name: "b"}})
	assert.Len(t, f.Tools, 2)
	tokens, max := f.ContextUsage()
	assert.Equal(t, 123, tokens)
	assert.Equal(t, 1000, max)
	require.NoError(t, f.Close())
	assert.True(t, f.Closed)
	f.Interrupt() // no-op
}
