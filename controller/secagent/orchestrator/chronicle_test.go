package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestInstallChronicle_FirstIterationEmpty(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{ID: 1, Agent: fake}
	installChronicle(t.Context(), w, "investigate /login", nil, "", nil)
	require.Equal(t, 1, fake.BoundaryCalls, "exactly one boundary mark per install")
	assert.Empty(t, fake.LastReplacedHistory,
		"empty chronicle on iter 1 → ReplaceHistory called with empty slice")
	require.Len(t, fake.QueriedInputs, 1)
	assert.Equal(t, "investigate /login", fake.QueriedInputs[0])
}

func TestInstallChronicle_NonEmptyChronicleSummarized(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID:    1,
		Agent: fake,
		Chronicle: []agent.Message{
			{Role: "user", Content: "iter 1 directive"},
			{Role: "assistant", Content: "I tested /admin and found nothing"},
		},
	}
	var calledWith []agent.Message
	summarize := func(_ context.Context, chronicle []agent.Message, _ string, _ int) (string, error) {
		calledWith = chronicle
		return "I previously tested /admin and confirmed it is locked down.", nil
	}
	installChronicle(t.Context(), w, "investigate /api this iteration", summarize, "the mission", nil)
	// The chronicle was summarized from the raw record; the summary is
	// installed as a single user-role message, NOT the raw chronicle.
	require.Len(t, calledWith, 2, "summarize sees the raw chronicle")
	require.Len(t, fake.LastReplacedHistory, 1, "single summary message installed")
	assert.Equal(t, "I previously tested /admin and confirmed it is locked down.",
		fake.LastReplacedHistory[0].Content)
	assert.Equal(t, "user", fake.LastReplacedHistory[0].Role)
	require.Len(t, fake.QueriedInputs, 1)
	assert.Equal(t, "investigate /api this iteration", fake.QueriedInputs[0])
	assert.Equal(t, 1, fake.BoundaryCalls)
	// Boundary fires AFTER ReplaceHistory (1 summary msg installed) and
	// BEFORE Query, so it equals 1.
	assert.Equal(t, 1, fake.LastBoundaryIdx)
	// Crucially: w.Chronicle is unchanged — the canonical raw record is
	// preserved for the next install's fresh summarization.
	require.Len(t, w.Chronicle, 2)
	assert.Equal(t, "iter 1 directive", w.Chronicle[0].Content)
}

func TestInstallChronicle_SummarizeFailureFallsBackToEmpty(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID:        1,
		Agent:     fake,
		Chronicle: []agent.Message{{Role: "user", Content: "prior work"}},
	}
	summarize := func(_ context.Context, _ []agent.Message, _ string, _ int) (string, error) {
		return "", assert.AnError
	}
	installChronicle(t.Context(), w, "next directive", summarize, "", nil)
	// Failure path with no cached fallback: empty pre-iter, directive
	// Query'd, chronicle preserved.
	assert.Empty(t, fake.LastReplacedHistory)
	require.Len(t, fake.QueriedInputs, 1)
	assert.Equal(t, "next directive", fake.QueriedInputs[0])
	require.Len(t, w.Chronicle, 1, "chronicle is untouched on summarize failure")
	assert.Empty(t, w.SummaryCache, "no cache populated when summarize failed")
}

func TestInstallChronicle_ReusesCacheWhenDirectiveAndChronicleUnchanged(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID:        1,
		Agent:     fake,
		Chronicle: []agent.Message{{Role: "user", Content: "prior"}, {Role: "assistant", Content: "work"}},
	}
	calls := 0
	summarize := func(_ context.Context, _ []agent.Message, _ string, _ int) (string, error) {
		calls++
		return "fresh recap", nil
	}
	// First install: cache miss, summarize called once, cache populated.
	installChronicle(t.Context(), w, "directive A", summarize, "mission", nil)
	require.Equal(t, 1, calls)
	require.Equal(t, "fresh recap", w.SummaryCache)
	require.Equal(t, "directive A", w.SummaryCacheDirective)
	require.Equal(t, 2, w.SummaryCacheChronLen)

	// Second install with same directive and same chronicle length: cache hit.
	fake2 := &agent.FakeAgent{}
	w.Agent = fake2
	installChronicle(t.Context(), w, "directive A", summarize, "mission", nil)
	assert.Equal(t, 1, calls, "summarize must NOT be called when cache is valid")
	require.Len(t, fake2.LastReplacedHistory, 1)
	assert.Equal(t, "fresh recap", fake2.LastReplacedHistory[0].Content,
		"cached summary installed verbatim")
}

func TestInstallChronicle_InvalidatesCacheOnDirectiveChange(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID:        1,
		Agent:     fake,
		Chronicle: []agent.Message{{Role: "user", Content: "prior"}, {Role: "assistant", Content: "work"}},
		// Pre-populated cache from a prior install under directive A.
		SummaryCache:          "old recap for A",
		SummaryCacheDirective: "directive A",
		SummaryCacheChronLen:  2,
	}
	calls := 0
	summarize := func(_ context.Context, _ []agent.Message, _ string, _ int) (string, error) {
		calls++
		return "new recap for B", nil
	}
	installChronicle(t.Context(), w, "directive B", summarize, "mission", nil)
	assert.Equal(t, 1, calls, "directive change forces re-summarize")
	require.Len(t, fake.LastReplacedHistory, 1)
	assert.Equal(t, "new recap for B", fake.LastReplacedHistory[0].Content)
	assert.Equal(t, "new recap for B", w.SummaryCache, "cache updated to new summary")
	assert.Equal(t, "directive B", w.SummaryCacheDirective)
}

func TestInstallChronicle_InvalidatesCacheOnChronicleGrowth(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID: 1, Agent: fake,
		Chronicle: []agent.Message{
			{Role: "user", Content: "prior"},
			{Role: "assistant", Content: "work"},
			{Role: "tool", Content: "result"}, // chronicle is now length 3
		},
		// Cache was built when chronicle length was 2.
		SummaryCache:          "stale recap",
		SummaryCacheDirective: "directive A",
		SummaryCacheChronLen:  2,
	}
	calls := 0
	summarize := func(_ context.Context, _ []agent.Message, _ string, _ int) (string, error) {
		calls++
		return "fresh recap covering new tool result", nil
	}
	installChronicle(t.Context(), w, "directive A", summarize, "mission", nil)
	assert.Equal(t, 1, calls, "chronicle growth forces re-summarize")
	require.Len(t, fake.LastReplacedHistory, 1)
	assert.Equal(t, "fresh recap covering new tool result", fake.LastReplacedHistory[0].Content)
	assert.Equal(t, 3, w.SummaryCacheChronLen, "cache length advanced to current chronicle")
}

func TestInstallChronicle_FallsBackToCachedSummaryOnError(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{}
	w := &WorkerState{
		ID: 1, Agent: fake,
		Chronicle: []agent.Message{
			{Role: "user", Content: "prior"},
			{Role: "assistant", Content: "work"},
			{Role: "tool", Content: "new result"},
		},
		// Stale cache from a prior iter (chronicle has grown since).
		SummaryCache:          "older recap from previous iter",
		SummaryCacheDirective: "directive A",
		SummaryCacheChronLen:  2,
	}
	summarize := func(_ context.Context, _ []agent.Message, _ string, _ int) (string, error) {
		return "", assert.AnError
	}
	installChronicle(t.Context(), w, "directive A", summarize, "mission", nil)
	// Summarize errored; cache exists; fallback installs the stale cached summary.
	require.Len(t, fake.LastReplacedHistory, 1)
	assert.Equal(t, "older recap from previous iter", fake.LastReplacedHistory[0].Content,
		"stale cached summary preserves worker memory when fresh summarize fails")
	require.Len(t, fake.QueriedInputs, 1)
	assert.Equal(t, "directive A", fake.QueriedInputs[0])
	// Cache fields are NOT advanced because no fresh summary was produced.
	assert.Equal(t, 2, w.SummaryCacheChronLen)
}

func TestExtractAndAppend_NewIterContent(t *testing.T) {
	t.Parallel()
	fake := &agent.FakeAgent{
		// Pre-existing chronicle is 2 messages; install marks boundary at 2
		// (BEFORE the directive Query). During drain the agent appended 5
		// more messages (directive + 4 turn elements). After drain, snapshot
		// is 7 messages; boundary is 2; iter content is the trailing 5
		// messages, starting with the directive.
		LastBoundaryIdx: 2,
		SnapshotMessages: []agent.Message{
			{Role: "user", Content: "iter1 directive"},
			{Role: "assistant", Content: "iter1 work"},
			{Role: "user", Content: "iter2 directive"},
			{Role: "assistant", Content: "iter2 thinking", ToolCalls: []agent.ToolCall{{ID: "t1"}}},
			{Role: "tool", Content: "iter2 tool result", ToolCallID: "t1"},
			{Role: "assistant", Content: "iter2 conclusion"},
			{Role: "user", Content: "intra-phase continue"},
		},
	}
	w := &WorkerState{
		ID:    1,
		Agent: fake,
		Chronicle: []agent.Message{
			{Role: "user", Content: "iter1 directive"},
			{Role: "assistant", Content: "iter1 work"},
		},
	}
	extractAndAppend(w)
	require.Len(t, w.Chronicle, 7, "2 existing + 5 new from boundary onward")
	assert.Equal(t, "iter2 directive", w.Chronicle[2].Content,
		"directive is part of iter content (so next iter's chronicle starts with a user message)")
	assert.Equal(t, "intra-phase continue", w.Chronicle[6].Content)
}

func TestExtractAndAppend_BoundaryShiftedBySummarization(t *testing.T) {
	t.Parallel()
	// Simulates the boundary-summarize callback firing mid-drain: the
	// boundary index moves to point past a freshly inserted summary
	// message. Extraction reads from the (smaller) shifted boundary.
	fake := &agent.FakeAgent{
		// Snapshot layout post-summarization:
		// [0] user: <recap>          (the summary that replaced pre-iter chunk)
		// [1] user: iter5 directive  (was after boundary; survives)
		// [2] assistant: iter5 finding
		// [3] tool: iter5 tool result
		// After summarization, boundary points to position 1 (right after the
		// summary message, which is itself the new "pre-iter content"). Iter
		// content is everything from index 1 onward.
		LastBoundaryIdx: 1,
		SnapshotMessages: []agent.Message{
			{Role: "user", Content: "<recap of pre-iter chunk>"},
			{Role: "user", Content: "iter5 directive"},
			{Role: "assistant", Content: "iter5 finding"},
			{Role: "tool", Content: "iter5 tool result"},
		},
	}
	w := &WorkerState{ID: 1, Agent: fake}
	extractAndAppend(w)
	require.Len(t, w.Chronicle, 3, "everything from boundary (1) onward")
	assert.Equal(t, "iter5 directive", w.Chronicle[0].Content)
	assert.Equal(t, "iter5 tool result", w.Chronicle[2].Content)
}

func TestExtractAndAppend_NoNewContent(t *testing.T) {
	t.Parallel()
	// Worker drained but produced nothing past the boundary (silent
	// turn that never produced an assistant response — degenerate case).
	fake := &agent.FakeAgent{
		LastBoundaryIdx: 3,
		SnapshotMessages: []agent.Message{
			{Role: "user", Content: "old"},
			{Role: "user", Content: "new directive"},
			{Role: "assistant", Content: "ack"},
		},
	}
	w := &WorkerState{ID: 1, Agent: fake, Chronicle: nil}
	extractAndAppend(w)
	assert.Empty(t, w.Chronicle, "no append when boundary == len(snapshot)")
}

func TestBoundaryOf_OpenAIAgentImplements(t *testing.T) {
	t.Parallel()
	// *OpenAIAgent must satisfy boundaryReader so chronicle extraction
	// works against real agents.
	oa := agent.NewOpenAIAgent(agent.OpenAIAgentConfig{
		Model: "x", SystemPrompt: "sys",
	})
	br, ok := agent.Agent(oa).(boundaryReader)
	require.True(t, ok, "*OpenAIAgent must implement IterationBoundary()")
	assert.Equal(t, 0, br.IterationBoundary(),
		"fresh agent has boundary 0 (no MarkIterationBoundary call yet)")

	oa.MarkIterationBoundary()
	assert.Equal(t, 1, br.IterationBoundary(),
		"after Mark on a [system]-only history, boundary = 1")
	oa.Query("hello")
	assert.Equal(t, 1, br.IterationBoundary(),
		"Query does not advance the boundary; iter content includes the directive")
}
