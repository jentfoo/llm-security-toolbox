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

func TestRunVerificationPhase_FilesAndDismissesThenDone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writer := NewFindingWriter(dir)
	candidates := NewCandidatePool()
	c1 := candidates.Add(AddInput{
		WorkerID: 1, Title: "Reflected XSS in search",
		Severity: "high", Endpoint: "GET /search",
		Summary: "q param reflects without encoding",
	})
	c2 := candidates.Add(AddInput{
		WorkerID: 1, Title: "Leaked stack trace on /debug",
		Severity: "low", Endpoint: "GET /debug",
	})

	decisions := NewDecisionQueue()

	// Substep 1: file for c1, dismiss c2, call verification_done.
	verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "substep 1 done"}}}
	verifier.OnDrain = func(_ int) {
		decisions.AddFinding(FindingFiled{
			Title: "Reflected XSS in search", Severity: "high",
			Endpoint:               "GET /search",
			VerificationNotes:      "Reproduced via replay_send on flow abc12345",
			SupersedesCandidateIDs: []string{c1},
		})
		decisions.AddDismissal(c2, "insufficient impact")
		decisions.SetVerificationDone("filed 1, dismissed 1")
	}

	workers := []*WorkerState{{ID: 1, Alive: true, Agent: verifier}}
	summary := RunVerificationPhase(
		context.Background(), verifier, decisions, candidates, writer,
		map[int][]agent.TurnSummary{1: nil}, workers, 2, 10, nil,
	)

	assert.Equal(t, "filed 1, dismissed 1", summary)
	// Candidate statuses updated.
	assert.Empty(t, candidates.Pending(), "both candidates resolved")
	// Finding file written.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasPrefix(entries[0].Name(), "finding-"))
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	require.NoError(t, err)
	assert.Contains(t, string(body), "Reflected XSS in search")
}

func TestRunVerificationPhase_NoPendingSkips(t *testing.T) {
	t.Parallel()
	writer := NewFindingWriter(t.TempDir())
	candidates := NewCandidatePool()
	decisions := NewDecisionQueue()
	verifier := &agent.FakeAgent{} // no scripted turns, would error if reached
	summary := RunVerificationPhase(
		context.Background(), verifier, decisions, candidates, writer,
		map[int][]agent.TurnSummary{}, nil, 1, 10, nil,
	)
	assert.Contains(t, summary, "No pending candidates")
}

func TestRunVerificationPhase_DuplicateFindingSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writer := NewFindingWriter(dir)
	// Prime the writer with an existing finding so the next is a duplicate.
	_, err := writer.Write(FindingFiled{
		Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
		VerificationNotes: "initial write",
	})
	require.NoError(t, err)

	candidates := NewCandidatePool()
	candidates.Add(AddInput{WorkerID: 1, Title: "Reflected XSS in search", Endpoint: "GET /search"})
	decisions := NewDecisionQueue()
	verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
	verifier.OnDrain = func(_ int) {
		decisions.AddFinding(FindingFiled{
			Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
			VerificationNotes: "dup",
		})
		decisions.SetVerificationDone("done")
	}
	workers := []*WorkerState{{ID: 1, Alive: true, Agent: verifier}}
	RunVerificationPhase(context.Background(), verifier, decisions, candidates, writer,
		nil, workers, 1, 10, nil)

	// Exactly the one pre-primed finding should exist on disk.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
