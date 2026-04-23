package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var nonSlugChar = regexp.MustCompile(`[^a-z0-9\s-]+`)
var slugDashes = regexp.MustCompile(`[-\s]+`)
var findingIndexRe = regexp.MustCompile(`^finding-(\d+)-.*\.md$`)

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// Slugify produces a URL-safe slug per spec §14.
func Slugify(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	t = nonSlugChar.ReplaceAllString(t, "")
	t = slugDashes.ReplaceAllString(t, "-")
	return strings.Trim(t, "-")
}

// CanonicalEndpoint lowercases, drops method prefix + query, collapses
// numeric path segments to :id.
func CanonicalEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	s := strings.TrimSpace(endpoint)
	fields := strings.SplitN(s, " ", 2)
	if len(fields) == 2 && httpMethods[strings.ToUpper(fields[0])] {
		s = fields[1]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")

	parts := strings.Split(s, "/")
	for i, p := range parts {
		if _, err := strconv.ParseUint(p, 10, 64); err == nil {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

// TitlesSimilar returns true when titles pass the §14 similarity rule.
func TitlesSimilar(a, b string) bool {
	sa, sb := Slugify(a), Slugify(b)
	if sa == "" || sb == "" {
		return false
	}
	if sa == sb || strings.Contains(sa, sb) || strings.Contains(sb, sa) {
		return true
	}
	wa, wb := map[string]bool{}, map[string]bool{}
	for _, w := range strings.Split(sa, "-") {
		if w != "" {
			wa[w] = true
		}
	}
	for _, w := range strings.Split(sb, "-") {
		if w != "" {
			wb[w] = true
		}
	}
	if len(wa) == 0 || len(wb) == 0 {
		return false
	}
	overlap := 0
	for w := range wa {
		if wb[w] {
			overlap++
		}
	}
	denom := len(wa)
	if len(wb) > denom {
		denom = len(wb)
	}
	return float64(overlap)/float64(denom) > 0.8
}

// MatchPendingCandidates returns pending candidate IDs whose title+endpoint match filed.
func MatchPendingCandidates(filed FindingFiled, pending []FindingCandidate) []string {
	filedEP := CanonicalEndpoint(filed.Endpoint)
	if filedEP == "" || filed.Title == "" {
		return nil
	}
	var out []string
	for _, c := range pending {
		if CanonicalEndpoint(c.Endpoint) != filedEP {
			continue
		}
		if !TitlesSimilar(c.Title, filed.Title) {
			continue
		}
		out = append(out, c.CandidateID)
	}
	return out
}

const markdownTemplate = `# %s

- **Severity**: %s
- **Affected Endpoint**: %s

## Description

%s

## Reproduction Steps

%s

## Evidence

%s

## Impact

%s

## Verification

%s
`

// FindingWriter persists verified findings.
type FindingWriter struct {
	mu          sync.Mutex
	findingsDir string
	// Count is the highest finding index on disk (seeded from prior runs) and
	// drives the finding-NN-*.md filename numbering.
	Count int
	// RunCount counts findings filed in this process only; used by the
	// premature-done guard so stale findings left on disk from earlier runs
	// can't bypass it.
	RunCount int
	Paths    []string
	index    []findingIndexEntry
}

type findingIndexEntry struct {
	title     string
	titleSlug string
	endpoint  string
	severity  string
	path      string
}

// NewFindingWriter constructs a FindingWriter for the given output directory.
// Seeds Count from the highest existing finding-NN-*.md file so new findings
// get unique indexes across process restarts.
func NewFindingWriter(findingsDir string) *FindingWriter {
	return &FindingWriter{findingsDir: findingsDir, Count: maxExistingFindingIndex(findingsDir)}
}

func maxExistingFindingIndex(findingsDir string) int {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return 0
	}
	max := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := findingIndexRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max
}

// IsDuplicate returns true when filed matches a previously written finding.
func (w *FindingWriter) IsDuplicate(filed FindingFiled) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(filed.Title)
	ep := CanonicalEndpoint(filed.Endpoint)
	for _, e := range w.index {
		if titleSlug != "" && titleSlug == e.titleSlug {
			return true
		}
		if ep != "" && e.endpoint == ep && TitlesSimilar(filed.Title, e.title) {
			return true
		}
	}
	return false
}

// Write persists the finding to disk and updates the index.
func (w *FindingWriter) Write(filed FindingFiled) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(w.findingsDir, 0o755); err != nil {
		return "", err
	}
	w.Count++
	w.RunCount++
	slug := Slugify(filed.Title)
	if slug == "" {
		slug = "untitled"
	}
	if len(slug) > 60 {
		slug = strings.TrimRight(slug[:60], "-")
	}
	filename := fmt.Sprintf("finding-%02d-%s.md", w.Count, slug)
	filepath := filepath.Join(w.findingsDir, filename)

	endpoint := filed.Endpoint
	if endpoint == "" {
		endpoint = "N/A"
	}
	body := fmt.Sprintf(
		markdownTemplate,
		filed.Title,
		filed.Severity,
		endpoint,
		orDefault(filed.Description, "(none)"),
		orDefault(filed.ReproductionSteps, "(none)"),
		orDefault(filed.Evidence, "(none)"),
		orDefault(filed.Impact, "(none)"),
		orDefault(filed.VerificationNotes, "(none)"),
	)
	if err := os.WriteFile(filepath, []byte(body), 0o644); err != nil {
		return "", err
	}

	w.Paths = append(w.Paths, filepath)
	w.index = append(w.index, findingIndexEntry{
		title:     filed.Title,
		titleSlug: Slugify(filed.Title),
		endpoint:  CanonicalEndpoint(filed.Endpoint),
		severity:  filed.Severity,
		path:      filepath,
	})
	return filepath, nil
}

// SummaryForOrchestrator renders a short listing of all filed findings.
func (w *FindingWriter) SummaryForOrchestrator() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.index) == 0 {
		return "No findings filed yet."
	}
	var sb strings.Builder
	sb.WriteString("**Findings filed so far:**\n")
	for i, e := range w.index {
		fmt.Fprintf(&sb, "%d. [%s] %s — %s\n",
			i+1, orDefault(e.severity, "unknown"), e.title, orDefault(e.endpoint, "N/A"))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
