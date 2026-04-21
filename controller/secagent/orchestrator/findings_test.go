package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlugify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, out string
	}{
		{"Reflected XSS in /search", "reflected-xss-in-search"},
		{"  Hello   World!  ", "hello-world"},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.out, Slugify(c.in))
	}
}

func TestCanonicalEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, out string
	}{
		{"GET /users/123", "/users/:id"},
		{"POST /api/v1/items/?x=1", "/api/v1/items"},
		{"/Users/42", "/users/:id"},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.out, CanonicalEndpoint(c.in), c.in)
	}
}

func TestTitlesSimilar(t *testing.T) {
	t.Parallel()
	assert.True(t, TitlesSimilar("Reflected XSS in search", "reflected xss in search"))
	assert.True(t, TitlesSimilar("Reflected XSS", "Reflected XSS in login flow"))
	assert.False(t, TitlesSimilar("SQL Injection", "Reflected XSS"))
}

func TestFindingWriter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := NewFindingWriter(dir)
	f := FindingFiled{
		Title:             "Reflected XSS",
		Severity:          "high",
		Endpoint:          "GET /search",
		Description:       "body",
		ReproductionSteps: "steps",
		Evidence:          "evidence",
		Impact:            "impact",
		VerificationNotes: "notes",
	}
	path, err := w.Write(f)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(path) || path != "")
	_, err = os.Stat(path)
	require.NoError(t, err)
	// Duplicate by same title.
	assert.True(t, w.IsDuplicate(f))
	// Different title, same endpoint but not similar.
	other := f
	other.Title = "Completely Different Thing"
	assert.False(t, w.IsDuplicate(other))
}

func TestMatchPendingCandidates(t *testing.T) {
	t.Parallel()
	filed := FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"}
	pending := []FindingCandidate{
		{CandidateID: "c001", Title: "Reflected XSS in search param", Endpoint: "GET /search"},
		{CandidateID: "c002", Title: "SQL Injection", Endpoint: "POST /api/x"},
	}
	got := MatchPendingCandidates(filed, pending)
	assert.Equal(t, []string{"c001"}, got)
}
