package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkerState_AppendHistoryRingWraps(t *testing.T) {
	t.Parallel()
	var w WorkerState
	// Append 8 entries; ring capacity is 6. Expect newest 6 in chronological
	// order; iterations 1 and 2 must be gone.
	for i := 1; i <= 8; i++ {
		w.AppendHistory(IterationEntry{
			Iteration: i,
			Angle:     "angle",
			Outcome:   OutcomeSilent,
		})
	}
	entries := w.RecentHistory()
	require := assert.New(t)
	require.Len(entries, WorkerHistoryRing)
	require.Equal(3, entries[0].Iteration, "oldest retained is iter 3")
	require.Equal(8, entries[len(entries)-1].Iteration, "newest is iter 8")
	// Strictly increasing iteration numbers.
	for i := 1; i < len(entries); i++ {
		require.Greater(entries[i].Iteration, entries[i-1].Iteration)
	}
}

func TestWorkerState_RecentHistoryEmpty(t *testing.T) {
	t.Parallel()
	var w WorkerState
	assert.Nil(t, w.RecentHistory())
}

func TestWorkerState_AppendHistoryBeforeWrap(t *testing.T) {
	t.Parallel()
	var w WorkerState
	for i := 1; i <= 3; i++ {
		w.AppendHistory(IterationEntry{Iteration: i})
	}
	entries := w.RecentHistory()
	assert.Len(t, entries, 3)
	assert.Equal(t, 1, entries[0].Iteration)
	assert.Equal(t, 3, entries[2].Iteration)
}
