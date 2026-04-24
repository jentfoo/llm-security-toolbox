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

// Slugify produces a URL-safe slug per spec §14. Underscores normalize to
// spaces first so `client_secret` and `client-secret` yield the same slug.
func Slugify(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	t = strings.ReplaceAll(t, "_", " ")
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

// MatchTier reports which rule matched a pending candidate to a filed finding.
type MatchTier int

const (
	MatchNone MatchTier = iota
	// MatchTitleAndEndpoint: title similar AND endpoint canonical-equal.
	MatchTitleAndEndpoint
	// MatchEndpointOnly: same canonical endpoint, titles diverge.
	MatchEndpointOnly
	// MatchTitleOnly: similar title, endpoints diverge or one is missing.
	MatchTitleOnly
)

// String returns a short label for logging.
func (t MatchTier) String() string {
	switch t {
	case MatchTitleAndEndpoint:
		return "title+endpoint"
	case MatchEndpointOnly:
		return "endpoint-only"
	case MatchTitleOnly:
		return "title-only"
	}
	return "none"
}

// MatchPendingCandidates returns pending candidate IDs whose title+endpoint
// match filed. Kept for compatibility; prefer MatchPendingCandidatesTiered.
func MatchPendingCandidates(filed FindingFiled, pending []FindingCandidate) []string {
	ids, _ := MatchPendingCandidatesTiered(filed, pending)
	return ids
}

// MatchPendingCandidatesTiered resolves pending candidates against a filed
// finding using progressively looser rules, returning the first non-empty
// match along with the tier that matched. Order:
//  1. title similar AND endpoint equal (strictest — no change in semantics
//     for findings that cite both).
//  2. endpoint equal only (the filed title rephrased the candidate's title,
//     e.g. "Admin API Requires JWT Bearer Auth" vs "Standard User Cookie
//     Reuse on Admin API" — same behavior, different wording).
//  3. title similar only (the endpoint was omitted or reworded but the
//     claim is recognizable).
//
// Returns (nil, MatchNone) when no pending candidate matches any tier.
func MatchPendingCandidatesTiered(filed FindingFiled, pending []FindingCandidate) ([]string, MatchTier) {
	if filed.Title == "" && filed.Endpoint == "" {
		return nil, MatchNone
	}
	filedEP := CanonicalEndpoint(filed.Endpoint)

	if filedEP != "" && filed.Title != "" {
		var out []string
		for _, c := range pending {
			if CanonicalEndpoint(c.Endpoint) == filedEP && TitlesSimilar(c.Title, filed.Title) {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchTitleAndEndpoint
		}
	}

	if filedEP != "" {
		var out []string
		for _, c := range pending {
			if CanonicalEndpoint(c.Endpoint) == filedEP {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchEndpointOnly
		}
	}

	if filed.Title != "" {
		var out []string
		for _, c := range pending {
			if TitlesSimilar(c.Title, filed.Title) {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchTitleOnly
		}
	}

	return nil, MatchNone
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

// findingIndexEntry records what a single in-process Write produced. Holds
// the full FindingFiled snapshot so dedup review can compare contents
// without re-reading disk. titleSlug is cached for fast IsDuplicate checks.
type findingIndexEntry struct {
	filed     FindingFiled
	titleSlug string
	endpoint  string
	path      string
}

// SimilarFinding is a snapshot of a previously written finding whose title
// matches closely enough to warrant agent review against a new filing.
type SimilarFinding struct {
	Filed FindingFiled
	Path  string
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

// IsDuplicate returns true when filed matches a previously written finding
// by exact title-slug equality. Softer matches (TitlesSimilar + ambiguous
// endpoints) go through FindSimilarEntries + agent review instead.
func (w *FindingWriter) IsDuplicate(filed FindingFiled) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(filed.Title)
	if titleSlug == "" {
		return false
	}
	for _, e := range w.index {
		if titleSlug == e.titleSlug {
			return true
		}
	}
	return false
}

// FindSimilarEntries returns previously written findings whose titles pass
// TitlesSimilar against filed AND whose endpoints are not explicitly
// different (either side missing, or equal after canonicalization). Exact
// slug matches are excluded — callers should check IsDuplicate first.
// Returned snapshots drive agent-mediated dedup review.
func (w *FindingWriter) FindSimilarEntries(filed FindingFiled) []SimilarFinding {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(filed.Title)
	ep := CanonicalEndpoint(filed.Endpoint)
	var out []SimilarFinding
	for _, e := range w.index {
		if titleSlug != "" && titleSlug == e.titleSlug {
			continue
		}
		if !TitlesSimilar(filed.Title, e.filed.Title) {
			continue
		}
		if ep != "" && e.endpoint != "" && ep != e.endpoint {
			continue
		}
		out = append(out, SimilarFinding{Filed: e.filed, Path: e.path})
	}
	return out
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
	path := filepath.Join(w.findingsDir, findingFilename(w.Count, filed.Title))
	if err := os.WriteFile(path, []byte(renderFinding(filed)), 0o644); err != nil {
		return "", err
	}
	w.Paths = append(w.Paths, path)
	w.index = append(w.index, indexEntry(filed, path))
	return path, nil
}

// Replace overwrites an existing in-process finding with merged content,
// preserving its sequence number. Renames the file if the new title's slug
// differs. Returns the (possibly new) path.
func (w *FindingWriter) Replace(oldPath string, filed FindingFiled) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.indexOfPath(oldPath)
	if idx < 0 {
		return "", fmt.Errorf("replace: path not tracked: %s", oldPath)
	}
	seq := findingSeqFromPath(oldPath)
	if seq <= 0 {
		return "", fmt.Errorf("replace: cannot parse sequence from %s", oldPath)
	}
	newPath := filepath.Join(w.findingsDir, findingFilename(seq, filed.Title))
	if err := os.WriteFile(newPath, []byte(renderFinding(filed)), 0o644); err != nil {
		return "", err
	}
	if newPath != oldPath {
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	w.Paths[idx] = newPath
	w.index[idx] = indexEntry(filed, newPath)
	return newPath, nil
}

func (w *FindingWriter) indexOfPath(path string) int {
	for i, e := range w.index {
		if e.path == path {
			return i
		}
	}
	return -1
}

func findingFilename(seq int, title string) string {
	slug := Slugify(title)
	if slug == "" {
		slug = "untitled"
	}
	if len(slug) > 60 {
		slug = strings.TrimRight(slug[:60], "-")
	}
	return fmt.Sprintf("finding-%02d-%s.md", seq, slug)
}

func findingSeqFromPath(path string) int {
	m := findingIndexRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

func renderFinding(filed FindingFiled) string {
	endpoint := filed.Endpoint
	if endpoint == "" {
		endpoint = "N/A"
	}
	return fmt.Sprintf(
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
}

func indexEntry(filed FindingFiled, path string) findingIndexEntry {
	return findingIndexEntry{
		filed:     filed,
		titleSlug: Slugify(filed.Title),
		endpoint:  CanonicalEndpoint(filed.Endpoint),
		path:      path,
	}
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
			i+1, orDefault(e.filed.Severity, "unknown"), e.filed.Title, orDefault(e.endpoint, "N/A"))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// SummaryForWorker renders a compact title + endpoint listing for workers so
// they can skip re-investigating already-filed vulnerabilities. Deliberately
// omits severity and verifier reasoning (workers shouldn't argue with the
// verifier, only avoid duplicate work).
func (w *FindingWriter) SummaryForWorker() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.index) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("**Findings filed so far — do not re-file:**\n")
	for _, e := range w.index {
		fmt.Fprintf(&sb, "- %s — %s\n", e.filed.Title, orDefault(e.filed.Endpoint, "N/A"))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
