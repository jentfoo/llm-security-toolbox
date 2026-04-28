package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// TestDumpUnvalidatedCandidates covers the bare dump path: every pending
// candidate gets one unvalidated-NN-*.md file with the UNVALIDATED banner.
func TestDumpUnvalidatedCandidates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writer := NewFindingWriter(dir)
	pending := []FindingCandidate{
		{
			CandidateID: "c001", WorkerID: 2, Title: "Reflected XSS",
			Severity: "high", Endpoint: "GET /search",
			Summary: "q reflects raw", FlowIDs: []string{"f-1"},
		},
		{
			CandidateID: "c002", WorkerID: 3, Title: "SSRF candidate",
			Severity: "critical", Endpoint: "POST /fetch",
		},
	}

	written := DumpUnvalidatedCandidates(pending, writer, nil)
	assert.Equal(t, 2, written)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Name(), "unvalidated-"), e.Name())
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		assert.Contains(t, string(body), "**THIS FINDING IS UNVALIDATED.**")
	}
}

// TestShutdownVerifierCtxCancelMidPhase verifies that a 2nd Ctrl+C arriving
// while the final verifier substep is in progress causes RunVerificationPhase
// to break, leaving the still-pending candidate untouched (so the post-loop
// stage-2 path can dump it).
func TestShutdownVerifierCtxCancelMidPhase(t *testing.T) {
	t.Parallel()

	candidates := NewCandidatePool()
	c1 := candidates.Add(AddInput{
		WorkerID: 1, Title: "candidate one",
		Severity: "med", Endpoint: "GET /x",
	})
	candidates.Add(AddInput{
		WorkerID: 1, Title: "candidate two",
		Severity: "med", Endpoint: "GET /y",
	})

	writer := NewFindingWriter(t.TempDir())
	decisions := NewDecisionQueue()
	sd := NewShutdown(context.Background(), nil)

	// On the first Drain the verifier files candidate one then escalates to
	// stage 2 (operator pressed Ctrl+C again). The cancellation propagates
	// to sd.VerifierCtx, so the next Drain attempt returns context.Canceled
	// and RunVerificationPhase breaks out — candidate two stays pending.
	verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}, {}}}
	verifier.OnDrain = func(_ int) {
		decisions.AddFinding(FindingFiled{
			Title: "candidate one", Severity: "med", Endpoint: "GET /x",
			VerificationNotes:      "ok",
			SupersedesCandidateIDs: []string{c1},
		})
		sd.RequestDumpUnvalidated()
	}

	RunVerificationPhase(sd.VerifierCtx, verifier, decisions, candidates, writer, nil, nil)

	// candidate one was filed and removed from pending; candidate two is
	// still pending because the verifier was cancelled before reaching it.
	assert.Equal(t, CandidateStatusVerified, candidates.ByID(c1).Status)
	pending := candidates.Pending()
	require.Len(t, pending, 1)
	assert.Equal(t, "candidate two", pending[0].Title)

	// Stage 2 dump persists the remaining pending candidate as UNVALIDATED.
	written := DumpUnvalidatedCandidates(pending, writer, nil)
	assert.Equal(t, 1, written)
	assert.Equal(t, 1, writer.UnvalidatedCount)
}

// TestShutdownVerifyOnlyDoesNotCancelVerifier guards the stage-1 invariant:
// requesting verify-only must NOT cancel the verifier ctx so the final
// verification pass can run to completion.
func TestShutdownVerifyOnlyDoesNotCancelVerifier(t *testing.T) {
	t.Parallel()

	sd := NewShutdown(context.Background(), nil)
	sd.RequestVerifyOnly()
	require.NoError(t, sd.VerifierCtx.Err(), "verifier must remain alive at stage 1")
	require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
}
