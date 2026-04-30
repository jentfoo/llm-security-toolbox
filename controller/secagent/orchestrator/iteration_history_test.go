package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestDeriveIterationOutcome(t *testing.T) {
	t.Parallel()

	type setup struct {
		worker       *WorkerState
		populate     func(pool *CandidatePool, dq *DecisionQueue) []string
		expectedKind IterationOutcome
	}

	tests := []struct {
		name string
		setup
	}{
		{
			name: "stopped_worker_dead",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: false, EscalationReason: "silent"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeStopped,
			},
		},
		{
			name: "finding_via_supersedes",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "XSS", "GET /x")
					dq.AddFinding(FindingFiled{
						Title:                  "XSS",
						Endpoint:               "GET /x",
						SupersedesCandidateIDs: []string{cid},
					})
					return []string{cid}
				},
				expectedKind: OutcomeFinding,
			},
		},
		{
			name: "possible_finding_via_tiered_match",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
					dq.AddFinding(FindingFiled{
						Title:    "Reflected XSS in search",
						Endpoint: "GET /search",
					})
					return []string{cid}
				},
				expectedKind: OutcomePossibleFinding,
			},
		},
		{
			name: "explicit_finding_beats_tier_match",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					explicit := seedCandidate(pool, 1, "Auth bypass on /admin", "GET /admin")
					tierOnly := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
					dq.AddFinding(FindingFiled{
						Title:                  "Auth bypass on /admin",
						Endpoint:               "GET /admin",
						SupersedesCandidateIDs: []string{explicit},
					})
					dq.AddFinding(FindingFiled{
						Title:    "Reflected XSS in search",
						Endpoint: "GET /search",
					})
					return []string{explicit, tierOnly}
				},
				expectedKind: OutcomeFinding,
			},
		},
		{
			name: "candidate_dismissed",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "x", "GET /x")
					dq.AddDismissal(CandidateDismissal{CandidateID: cid, Reason: "noise"})
					return []string{cid}
				},
				expectedKind: OutcomeDismissed,
			},
		},
		{
			name: "candidate_still_pending",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, _ *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "x", "GET /x")
					c := pool.ByID(cid)
					require.NotNil(t, c)
					require.Equal(t, "pending", c.Status)
					return []string{cid}
				},
				expectedKind: OutcomeCandidate,
			},
		},
		{
			name: "silent_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeSilent,
			},
		},
		{
			name: "error_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "error"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeError,
			},
		},
		{
			name: "budget_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "budget"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeBudget,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := NewCandidatePool()
			dq := NewDecisionQueue()
			cids := tc.populate(pool, dq)
			out := DeriveIterationOutcome(tc.worker, nil, dq, pool, cids)
			assert.Equal(t, tc.expectedKind, out)
		})
	}
}

func TestTruncateAngle(t *testing.T) {
	t.Parallel()

	long := make([]byte, angleMaxLen+50)
	for i := range long {
		long[i] = 'a'
	}

	t.Run("whitespace_compressed", func(t *testing.T) {
		assert.Equal(t, "compressed whitespace", truncateAngle("  compressed\t  whitespace\n"))
	})

	t.Run("long_input_truncated", func(t *testing.T) {
		got := truncateAngle(string(long))
		assert.Len(t, got, angleMaxLen)
		assert.Equal(t, "…", got[len(got)-len("…"):])
	})
}
