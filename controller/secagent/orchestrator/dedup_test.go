package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDedupReviewer scripts Classify and Merge for tests.
type fakeDedupReviewer struct {
	classifyFn func(existing, incoming FindingFiled) (DedupVerdict, error)
	mergeFn    func(primary, secondary FindingFiled) (FindingFiled, error)
	merged     []FindingFiled // captures each merge call's primary for assertions
}

func (f *fakeDedupReviewer) Classify(_ context.Context, existing, incoming FindingFiled) (DedupVerdict, error) {
	return f.classifyFn(existing, incoming)
}

func (f *fakeDedupReviewer) Merge(_ context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	f.merged = append(f.merged, primary)
	return f.mergeFn(primary, secondary)
}

func TestParseVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		want    DedupVerdict
		wantErr bool
	}{
		{"unique", `{"action":"unique"}`, DedupVerdict{Action: "unique"}, false},
		{"duplicate_keep_existing", `{"action":"duplicate","more_complete":"existing"}`,
			DedupVerdict{Action: "duplicate", MoreComplete: "existing"}, false},
		{"partial_keep_new", `{"action":"partial","more_complete":"new"}`,
			DedupVerdict{Action: "partial", MoreComplete: "new"}, false},
		{"fenced_json", "```json\n{\"action\":\"unique\"}\n```",
			DedupVerdict{Action: "unique"}, false},
		{"leading_prose", "Here's my answer:\n{\"action\":\"unique\"}",
			DedupVerdict{Action: "unique"}, false},
		{"missing_more_complete", `{"action":"duplicate"}`, DedupVerdict{}, true},
		{"unknown_action", `{"action":"maybe"}`, DedupVerdict{}, true},
		{"malformed", `not json`, DedupVerdict{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseVerdict(c.raw)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestParseMerge(t *testing.T) {
	t.Parallel()
	fallback := FindingFiled{
		Title:                  "Original",
		Severity:               "high",
		Endpoint:               "GET /",
		SupersedesCandidateIDs: []string{"c1"},
		FollowUpHint:           "look at logs",
	}
	t.Run("happy_path", func(t *testing.T) {
		raw := `{"title":"Merged","severity":"critical","endpoint":"GET /search","description":"d","reproduction_steps":"s","evidence":"e","impact":"i","verification_notes":"v"}`
		got, err := parseMerge(raw, fallback)
		require.NoError(t, err)
		assert.Equal(t, "Merged", got.Title)
		assert.Equal(t, "critical", got.Severity)
		assert.Equal(t, "d", got.Description)
		assert.Equal(t, []string{"c1"}, got.SupersedesCandidateIDs, "must preserve fallback metadata")
		assert.Equal(t, "look at logs", got.FollowUpHint)
	})
	t.Run("partial_fields_preserve_fallback", func(t *testing.T) {
		raw := `{"title":"","severity":"low"}`
		got, err := parseMerge(raw, fallback)
		require.NoError(t, err)
		assert.Equal(t, "Original", got.Title, "empty field falls back")
		assert.Equal(t, "low", got.Severity)
	})
}

func TestFindSimilarEntries(t *testing.T) {
	t.Parallel()
	w := NewFindingWriter(t.TempDir())
	_, err := w.Write(FindingFiled{
		Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
	})
	require.NoError(t, err)

	t.Run("exact_slug_excluded", func(t *testing.T) {
		// IsDuplicate catches this; FindSimilarEntries must not double-report.
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"})
		assert.Empty(t, got)
	})
	t.Run("similar_title_missing_endpoint", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS", Endpoint: ""})
		require.Len(t, got, 1)
		assert.Equal(t, "Reflected XSS in search", got[0].Filed.Title)
	})
	t.Run("similar_title_explicit_different_endpoint", func(t *testing.T) {
		// Same class, different endpoint → agent review not needed.
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS in login", Endpoint: "GET /login"})
		assert.Empty(t, got)
	})
	t.Run("different_title_no_match", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "SQL Injection", Endpoint: "GET /search"})
		assert.Empty(t, got)
	})
}

func TestFindingWriterReplace(t *testing.T) {
	t.Parallel()
	t.Run("preserves_sequence_renames_on_title_change", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		p1, err := w.Write(FindingFiled{Title: "Original Title", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)

		p2, err := w.Replace(p1, FindingFiled{Title: "Merged Title", Severity: "high", Endpoint: "GET /x"})
		require.NoError(t, err)
		assert.NotEqual(t, p1, p2, "rename on slug change")
		assert.Contains(t, filepath.Base(p2), "finding-01-")
		// old file must be gone
		_, err = os.Stat(p1)
		assert.True(t, os.IsNotExist(err))
		// new file exists with new title
		body, err := os.ReadFile(p2)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Merged Title")
	})
	t.Run("same_title_writes_in_place", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		p1, err := w.Write(FindingFiled{Title: "Same", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		p2, err := w.Replace(p1, FindingFiled{Title: "Same", Severity: "high", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, p1, p2)
	})
	t.Run("untracked_path_errors", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		_, err := w.Replace(filepath.Join(dir, "finding-01-nope.md"), FindingFiled{Title: "x"})
		assert.Error(t, err)
	})
}

func TestReviewAndWrite(t *testing.T) {
	t.Parallel()

	// existing: already-written finding the new one may collide with
	seed := func(t *testing.T) (*FindingWriter, string) {
		t.Helper()
		w := NewFindingWriter(t.TempDir())
		path, err := w.Write(FindingFiled{
			Title: "Reflected XSS in search", Severity: "high",
			Endpoint: "GET /search", Description: "existing desc",
		})
		require.NoError(t, err)
		return w, path
	}

	t.Run("exact_slug_skips_review", func(t *testing.T) {
		w, _ := seed(t)
		// reviewer must not be called; script it to fail if invoked
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				t.Fatal("classify must not be called for exact slug duplicate")
				return DedupVerdict{}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"}, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		assert.Empty(t, path)
	})

	t.Run("no_similar_writes_normally", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				t.Fatal("classify must not be called when no similar entries")
				return DedupVerdict{}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "SQL Injection", Endpoint: "POST /api"}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.NotEmpty(t, path)
	})

	t.Run("nil_reviewer_falls_through_to_write", func(t *testing.T) {
		w, _ := seed(t)
		// Similar title with missing endpoint would formerly auto-dedup.
		// With nil reviewer we now fall through and write both.
		wrote, path, err := ReviewAndWrite(t.Context(), nil, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.NotEmpty(t, path)
	})

	t.Run("verdict_unique_writes_both", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "unique"}, nil
			},
		}
		wrote, _, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS in search v2", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.Equal(t, 2, w.Count)
	})

	t.Run("verdict_duplicate_keep_existing_discards_new", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "duplicate", MoreComplete: "existing"}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: "", Description: "new desc"}, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		assert.Equal(t, existingPath, path, "must point to the kept existing file")
		assert.Equal(t, 1, w.Count)
	})

	t.Run("verdict_duplicate_keep_new_replaces_existing", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "duplicate", MoreComplete: "new"}, nil
			},
		}
		incoming := FindingFiled{
			Title: "Reflected XSS", Severity: "critical",
			Endpoint: "", Description: "more thorough writeup",
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w, incoming, nil)
		require.NoError(t, err)
		assert.False(t, wrote, "wrote=false because we replaced, didn't grow count")
		assert.NotEmpty(t, path)
		// existing path file should be gone or renamed (slug changed from
		// "reflected-xss-in-search" to "reflected-xss")
		_, err = os.Stat(existingPath)
		assert.True(t, os.IsNotExist(err), "original existing file should be renamed away")
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(body), "more thorough writeup")
		assert.Equal(t, 1, w.Count, "count unchanged by replace")
	})

	t.Run("verdict_partial_merges_and_replaces", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "partial", MoreComplete: "existing"}, nil
			},
			mergeFn: func(primary, _ FindingFiled) (FindingFiled, error) {
				out := primary
				out.Description = "merged: " + primary.Description
				return out, nil
			},
		}
		incoming := FindingFiled{
			Title: "Reflected XSS", Endpoint: "", Description: "new pov",
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w, incoming, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		require.Len(t, rev.merged, 1)
		assert.Equal(t, "Reflected XSS in search", rev.merged[0].Title, "existing is primary")
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(body), "merged: existing desc")
		// existingPath stayed (slug preserved because primary.Title preserved)
		assert.Equal(t, existingPath, path)
	})

	t.Run("classifier_error_falls_through_to_write", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{}, errors.New("model down")
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote, "classifier errors must not block legitimate writes")
		assert.NotEmpty(t, path)
	})
}
