package agent

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFakeAgent_Drain(t *testing.T) {
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
