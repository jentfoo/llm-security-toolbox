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
		name string
		in   string
		out  string
	}{
		{"path_and_spaces", "Reflected XSS in /search", "reflected-xss-in-search"},
		{"extra_whitespace", "  Hello   World!  ", "hello-world"},
		{"underscore_equals_hyphen", "plaintext client_secret exposure", "plaintext-client-secret-exposure"},
		{"hyphen_equivalence", "plaintext client-secret exposure", "plaintext-client-secret-exposure"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.out, Slugify(c.in))
		})
	}
}

func TestCanonicalEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"method_and_numeric_id", "GET /users/123", "/users/:id"},
		{"trailing_slash_and_query", "POST /api/v1/items/?x=1", "/api/v1/items"},
		{"uppercase_path", "/Users/42", "/users/:id"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.out, CanonicalEndpoint(c.in))
		})
	}
}

func TestTitlesSimilar(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"case_insensitive", "Reflected XSS in search", "reflected xss in search", true},
		{"prefix_substring", "Reflected XSS", "Reflected XSS in login flow", true},
		{"different_vulns", "SQL Injection", "Reflected XSS", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, TitlesSimilar(c.a, c.b))
		})
	}
}

func TestFindingWriter(t *testing.T) {
	t.Parallel()
	finding := FindingFiled{
		Title:             "Reflected XSS",
		Severity:          "high",
		Endpoint:          "GET /search",
		Description:       "body",
		ReproductionSteps: "steps",
		Evidence:          "evidence",
		Impact:            "impact",
		VerificationNotes: "notes",
	}

	t.Run("writes_file", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		path, err := w.Write(finding)
		require.NoError(t, err)
		_, err = os.Stat(path)
		require.NoError(t, err)
	})

	t.Run("detects_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		assert.True(t, w.IsDuplicate(finding))
	})

	t.Run("different_title_not_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := finding
		other.Title = "Completely Different Thing"
		assert.False(t, w.IsDuplicate(other))
	})

	t.Run("underscore_vs_hyphen_client_secret", func(t *testing.T) {
		// Regression: the secagent run at 2026-04-22 produced finding-02
		// "Plaintext client_secret Exposure ..." and finding-03 "Plaintext
		// Client Secret Exposure ..." — same class, different punctuation.
		first := FindingFiled{
			Title:    "Plaintext client_secret Exposure in OAuth2 Registration Response",
			Severity: "high",
			Endpoint: "POST /oauth2/register",
		}
		second := FindingFiled{
			Title:    "Plaintext Client Secret Exposure in OAuth2 Registration Response",
			Severity: "high",
			Endpoint: "POST /oauth2/register",
		}
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(first)
		require.NoError(t, err)
		assert.True(t, w.IsDuplicate(second))
	})

	t.Run("same_title_missing_endpoint_is_duplicate", func(t *testing.T) {
		// Same title regardless of endpoint → exact slug match.
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := finding
		other.Endpoint = ""
		assert.True(t, w.IsDuplicate(other))
	})

	t.Run("similar_title_not_exact_slug_not_duplicate", func(t *testing.T) {
		// Softer match: TitlesSimilar but slug differs — IsDuplicate no
		// longer returns true. Agent-mediated dedup (FindSimilarEntries +
		// reviewer) handles these.
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := FindingFiled{
			Title:    "Reflected XSS in login flow",
			Severity: "high",
			Endpoint: "GET /login",
		}
		assert.False(t, w.IsDuplicate(other))
	})
}

func TestNewFindingWriter(t *testing.T) {
	t.Parallel()

	t.Run("seeds_count_from_existing_files", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"finding-03-foo.md", "finding-07-bar.md", "unrelated.md"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644))
		}
		w := NewFindingWriter(dir)
		assert.Equal(t, 7, w.Count)
		assert.Equal(t, 0, w.RunCount, "RunCount must not be seeded from disk")

		path, err := w.Write(FindingFiled{Title: "New Finding", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, "finding-08-new-finding.md", filepath.Base(path))
		assert.Equal(t, 8, w.Count)
		assert.Equal(t, 1, w.RunCount, "RunCount increments only on in-process Write")
	})

	t.Run("missing_dir_starts_at_zero", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "does-not-exist")
		w := NewFindingWriter(dir)
		assert.Equal(t, 0, w.Count)

		path, err := w.Write(FindingFiled{Title: "First", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, "finding-01-first.md", filepath.Base(path))
	})

	t.Run("ignores_malformed_names", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"finding-ab-x.md", "finding-.md", "other.md"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644))
		}
		assert.Equal(t, 0, NewFindingWriter(dir).Count)
	})
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
