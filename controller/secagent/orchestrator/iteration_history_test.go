package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// seedCandidate adds a candidate for workerID and returns its id.
func seedCandidate(pool *CandidatePool, workerID int, title, endpoint string) string {
	return pool.Add(AddInput{
		WorkerID: workerID,
		Title:    title,
		Endpoint: endpoint,
		FlowIDs:  []string{"f1"},
	})
}

func TestDeriveIterationOutcome_Stopped(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: false, EscalationReason: "silent"}
	out := DeriveIterationOutcome(w, nil, NewDecisionQueue(), NewCandidatePool(), nil)
	assert.Equal(t, OutcomeStopped, out)
}

func TestDeriveIterationOutcome_Finding_ViaSupersedes(t *testing.T) {
	t.Parallel()
	pool := NewCandidatePool()
	cid := seedCandidate(pool, 1, "XSS", "GET /x")
	dq := NewDecisionQueue()
	dq.AddFinding(FindingFiled{
		Title:                  "XSS",
		Endpoint:               "GET /x",
		SupersedesCandidateIDs: []string{cid},
	})
	w := &WorkerState{ID: 1, Alive: true}
	out := DeriveIterationOutcome(w, nil, dq, pool, []string{cid})
	assert.Equal(t, OutcomeFinding, out)
}

func TestDeriveIterationOutcome_PossibleFinding_ViaTieredMatch(t *testing.T) {
	t.Parallel()
	// Verifier filed a finding that supersedes nobody explicitly but matches
	// the worker's candidate by title + endpoint. Tier matches are hints, not
	// confirmations — they surface as possible-finding so the director can
	// follow up rather than assume coverage.
	pool := NewCandidatePool()
	cid := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
	dq := NewDecisionQueue()
	dq.AddFinding(FindingFiled{
		Title:    "Reflected XSS in search",
		Endpoint: "GET /search",
	})
	w := &WorkerState{ID: 1, Alive: true}
	out := DeriveIterationOutcome(w, nil, dq, pool, []string{cid})
	assert.Equal(t, OutcomePossibleFinding, out)
}

func TestDeriveIterationOutcome_ExplicitFindingBeatsTierMatch(t *testing.T) {
	t.Parallel()
	// Two candidates from the same worker: one explicitly superseded by a
	// finding, another only tier-matched by a different finding. Explicit
	// link must win — the worker's iteration outcome is "finding", not
	// "possible-finding".
	pool := NewCandidatePool()
	explicit := seedCandidate(pool, 1, "Auth bypass on /admin", "GET /admin")
	tierOnly := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
	dq := NewDecisionQueue()
	dq.AddFinding(FindingFiled{
		Title:                  "Auth bypass on /admin",
		Endpoint:               "GET /admin",
		SupersedesCandidateIDs: []string{explicit},
	})
	dq.AddFinding(FindingFiled{
		Title:    "Reflected XSS in search",
		Endpoint: "GET /search",
	})
	w := &WorkerState{ID: 1, Alive: true}
	out := DeriveIterationOutcome(w, nil, dq, pool, []string{explicit, tierOnly})
	assert.Equal(t, OutcomeFinding, out)
}

func TestDeriveIterationOutcome_Dismissed(t *testing.T) {
	t.Parallel()
	pool := NewCandidatePool()
	cid := seedCandidate(pool, 1, "x", "GET /x")
	dq := NewDecisionQueue()
	dq.AddDismissal(CandidateDismissal{CandidateID: cid, Reason: "noise"})
	w := &WorkerState{ID: 1, Alive: true}
	out := DeriveIterationOutcome(w, nil, dq, pool, []string{cid})
	assert.Equal(t, OutcomeDismissed, out)
}

func TestDeriveIterationOutcome_Candidate_StillPending(t *testing.T) {
	t.Parallel()
	pool := NewCandidatePool()
	cid := seedCandidate(pool, 1, "x", "GET /x")
	// Status remains "pending" — no file_finding or dismiss_candidate.
	c := pool.ByID(cid)
	require.NotNil(t, c)
	require.Equal(t, "pending", c.Status)
	w := &WorkerState{ID: 1, Alive: true}
	out := DeriveIterationOutcome(w, nil, NewDecisionQueue(), pool, []string{cid})
	assert.Equal(t, OutcomeCandidate, out)
}

func TestDeriveIterationOutcome_Silent(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"}
	out := DeriveIterationOutcome(w, nil, NewDecisionQueue(), NewCandidatePool(), nil)
	assert.Equal(t, OutcomeSilent, out)
}

func TestDeriveIterationOutcome_Error(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, EscalationReason: "error"}
	out := DeriveIterationOutcome(w, nil, NewDecisionQueue(), NewCandidatePool(), nil)
	assert.Equal(t, OutcomeError, out)
}

func TestDeriveIterationOutcome_Budget(t *testing.T) {
	t.Parallel()
	w := &WorkerState{ID: 1, Alive: true, EscalationReason: "budget"}
	out := DeriveIterationOutcome(w, nil, NewDecisionQueue(), NewCandidatePool(), nil)
	assert.Equal(t, OutcomeBudget, out)
}

func TestCountToolCallsAndFlows(t *testing.T) {
	t.Parallel()
	runs := []agent.TurnSummary{
		{ToolCalls: []agent.ToolCallRecord{{}, {}}, FlowIDs: []string{"a"}},
		{ToolCalls: []agent.ToolCallRecord{{}}, FlowIDs: []string{"b", "c"}},
	}
	tc, fl := countToolCallsAndFlows(runs)
	assert.Equal(t, 3, tc)
	assert.Equal(t, 3, fl)
}

func TestTruncateAngle(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "short", truncateAngle("short"))
	assert.Equal(t, "compressed whitespace", truncateAngle("  compressed\t  whitespace\n"))
	long := make([]byte, angleMaxLen+50)
	for i := range long {
		long[i] = 'a'
	}
	got := truncateAngle(string(long))
	assert.Len(t, got, angleMaxLen)
	assert.Equal(t, "…", got[len(got)-len("…"):])
}
