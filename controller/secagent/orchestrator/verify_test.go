package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRunVerificationPhase(t *testing.T) {
	t.Parallel()

	t.Run("files_and_dismisses", func(t *testing.T) {
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

		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "substep 1 done"}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title: "Reflected XSS in search", Severity: "high",
				Endpoint:               "GET /search",
				VerificationNotes:      "Reproduced via replay_send on flow abc12345",
				SupersedesCandidateIDs: []string{c1},
			})
			decisions.AddDismissal(CandidateDismissal{CandidateID: c2, Reason: "insufficient impact"})
			decisions.SetVerificationDone("filed 1, dismissed 1")
		}

		workers := []*WorkerState{{ID: 1, Alive: true, Agent: verifier}}
		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer,
			map[int][]agent.TurnSummary{1: nil}, workers, 2, 10, nil,
		)

		assert.Equal(t, "filed 1, dismissed 1", summary)
		assert.Empty(t, candidates.Pending())
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, strings.HasPrefix(entries[0].Name(), "finding-"))
		body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
		require.NoError(t, err)
		assert.Contains(t, string(body), "Reflected XSS in search")
	})

	t.Run("no_pending_skips", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{} // no scripted turns, would error if reached
		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer,
			map[int][]agent.TurnSummary{}, nil, 1, 10, nil,
		)
		assert.Contains(t, summary, "No pending candidates")
	})

	t.Run("duplicate_finding_skipped", func(t *testing.T) {
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
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer,
			nil, workers, 1, 10, nil)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	})
}
