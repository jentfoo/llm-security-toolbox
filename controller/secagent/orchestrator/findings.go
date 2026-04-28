package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var nonSlugChar = regexp.MustCompile(`[^a-z0-9\s-]+`)
var slugDashes = regexp.MustCompile(`[-\s]+`)
var findingIndexRe = regexp.MustCompile(`^finding-(\d+)-.*\.md$`)
var unvalidatedIndexRe = regexp.MustCompile(`^unvalidated-(\d+)-.*\.md$`)

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
	return float64(overlap)/float64(denom) > 0.5
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
	// UnvalidatedCount is the highest unvalidated index on disk, seeded from
	// prior runs so unvalidated-NN-*.md files don't collide across runs.
	UnvalidatedCount int
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
	index, count := loadExistingFindingIndex(findingsDir)
	unvalidated := loadExistingUnvalidatedMax(findingsDir)
	return &FindingWriter{
		findingsDir:      findingsDir,
		Count:            count,
		UnvalidatedCount: unvalidated,
		index:            index,
	}
}

// loadExistingUnvalidatedMax returns the highest unvalidated-NN-*.md sequence
// found in findingsDir, or 0 if none / dir missing.
func loadExistingUnvalidatedMax(findingsDir string) int {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return 0
	}
	max := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := unvalidatedIndexRe.FindStringSubmatch(e.Name())
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

func loadExistingFindingIndex(findingsDir string) ([]findingIndexEntry, int) {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return nil, 0
	}
	type diskFinding struct {
		seq   int
		entry findingIndexEntry
	}

	max := 0
	var loaded []diskFinding
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
		path := filepath.Join(findingsDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		filed, ok := parseFindingMarkdown(string(raw))
		if !ok {
			continue
		}
		loaded = append(loaded, diskFinding{
			seq:   n,
			entry: indexEntry(filed, path),
		})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].seq < loaded[j].seq })

	index := make([]findingIndexEntry, 0, len(loaded))
	for _, item := range loaded {
		index = append(index, item.entry)
	}
	return index, max
}

func parseFindingMarkdown(raw string) (FindingFiled, bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "# ") {
		return FindingFiled{}, false
	}
	filed := FindingFiled{
		Title:    strings.TrimSpace(strings.TrimPrefix(lines[0], "# ")),
		Severity: findMarkdownField(lines, "- **Severity**: "),
		Endpoint: normalizeStoredEndpoint(findMarkdownField(lines, "- **Affected Endpoint**: ")),
	}
	filed.Description = findingSection(raw, "Description", "Reproduction Steps")
	filed.ReproductionSteps = findingSection(raw, "Reproduction Steps", "Evidence")
	filed.Evidence = findingSection(raw, "Evidence", "Impact")
	filed.Impact = findingSection(raw, "Impact", "Verification")
	filed.VerificationNotes = findingSection(raw, "Verification", "")
	if filed.Title == "" {
		return FindingFiled{}, false
	}
	return filed, true
}

func findMarkdownField(lines []string, prefix string) string {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func findingSection(raw, heading, next string) string {
	marker := "## " + heading + "\n\n"
	start := strings.Index(raw, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := len(raw)
	if next != "" {
		nextMarker := "\n\n## " + next + "\n\n"
		if idx := strings.Index(raw[start:], nextMarker); idx >= 0 {
			end = start + idx
		}
	}
	return strings.TrimSpace(raw[start:end])
}

func normalizeStoredEndpoint(endpoint string) string {
	if endpoint == "N/A" {
		return ""
	}
	return endpoint
}

// IsDuplicate returns true when filed matches a previously written finding
// on exact title-slug AND exact canonical-endpoint equality. Anything
// fuzzier (slug match with endpoint divergence, similar title) falls
// through to FindSimilarEntries so the LLM dedup reviewer can adjudicate
// with both endpoints in view.
func (w *FindingWriter) IsDuplicate(filed FindingFiled) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(filed.Title)
	canonEP := CanonicalEndpoint(filed.Endpoint)
	if titleSlug == "" {
		return false
	}
	for _, e := range w.index {
		if titleSlug == e.titleSlug && canonEP == e.endpoint {
			return true
		}
	}
	return false
}

// MatchesFiled reports whether (title, endpoint) matches an already-filed
// finding on exact title-slug AND exact canonical-endpoint equality.
// Returns the matched finding's title and path so the caller can cite it.
// Intended for the worker hot path as the deterministic fallback when the
// LLM CandidateDedupReviewer is not configured; anything fuzzier should go
// through that reviewer rather than getting suppressed here.
func (w *FindingWriter) MatchesFiled(title, endpoint string) (matchedTitle, path string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(title)
	canonEP := CanonicalEndpoint(endpoint)
	if titleSlug == "" {
		return "", "", false
	}
	for _, e := range w.index {
		if titleSlug == e.titleSlug && canonEP == e.endpoint {
			return e.filed.Title, e.path, true
		}
	}
	return "", "", false
}

// FindSimilarEntries returns previously written findings whose titles
// match the filed entry closely enough to warrant LLM dedup review. Slug
// matches with a divergent endpoint surface here (the LLM gets both
// endpoints in its prompt and decides unique / duplicate / partial-merge);
// title-similar (non-slug-equal) entries surface regardless of endpoint
// for the same reason. Exact title-slug + canonical-endpoint matches are
// already filtered upstream by IsDuplicate.
func (w *FindingWriter) FindSimilarEntries(filed FindingFiled) []SimilarFinding {
	w.mu.Lock()
	defer w.mu.Unlock()
	titleSlug := Slugify(filed.Title)
	var out []SimilarFinding
	for _, e := range w.index {
		if titleSlug != "" && titleSlug == e.titleSlug {
			out = append(out, SimilarFinding{Filed: e.filed, Path: e.path})
			continue
		}
		if TitlesSimilar(filed.Title, e.filed.Title) {
			out = append(out, SimilarFinding{Filed: e.filed, Path: e.path})
		}
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
	nextCount := w.Count + 1
	path := filepath.Join(w.findingsDir, findingFilename(nextCount, filed.Title))
	if err := os.WriteFile(path, []byte(renderFinding(filed)), 0o644); err != nil {
		return "", err
	}
	w.Count = nextCount
	w.RunCount++
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
	w.index[idx] = indexEntry(filed, newPath)
	for i := range w.Paths {
		if w.Paths[i] == oldPath {
			w.Paths[i] = newPath
			break
		}
	}
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
		orDefault(filed.Description, noneSentinel),
		orDefault(filed.ReproductionSteps, noneSentinel),
		orDefault(filed.Evidence, noneSentinel),
		orDefault(filed.Impact, noneSentinel),
		orDefault(filed.VerificationNotes, noneSentinel),
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

// LookupByFilename returns the in-memory FindingFiled snapshot and full
// path for the finding whose file basename matches name, or ("",false) if
// nothing matches. Used by the async merge path to fetch the existing
// finding before reviewer.Merge.
func (w *FindingWriter) LookupByFilename(name string) (FindingFiled, string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.index {
		if filepath.Base(e.path) == name {
			return e.filed, e.path, true
		}
	}
	return FindingFiled{}, "", false
}

// FindingDigest is a compact, LLM-classifier-friendly summary of an
// already-filed finding: filename + a few load-bearing fields. Built from
// the in-memory FindingWriter index — no disk reads.
type FindingDigest struct {
	Filename   string
	Title      string
	Severity   string
	Endpoint   string
	FirstLines string // a few lines of description for context
}

// findingDigestDescriptionLines caps the description excerpt embedded in
// each digest. Keeps the classifier prompt bounded as the index grows.
const findingDigestDescriptionLines = 6

// Digests returns one FindingDigest per finding in the in-memory index.
// Safe to call concurrently with Write/Replace.
func (w *FindingWriter) Digests() []FindingDigest {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]FindingDigest, 0, len(w.index))
	for _, e := range w.index {
		out = append(out, FindingDigest{
			Filename:   filepath.Base(e.path),
			Title:      e.filed.Title,
			Severity:   e.filed.Severity,
			Endpoint:   orDefault(e.filed.Endpoint, "N/A"),
			FirstLines: firstNLines(e.filed.Description, findingDigestDescriptionLines),
		})
	}
	return out
}

// firstNLines returns the first n lines of s.
func firstNLines(s string, n int) string {
	if s == "" || n <= 0 {
		return ""
	}
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
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

// unvalidatedTemplate renders a worker-reported candidate that the verifier
// never confirmed. Operator must treat the contents as an investigative tip,
// not a confirmed vulnerability.
const unvalidatedTemplate = `# UNVALIDATED — %s

> ⚠ **THIS FINDING IS UNVALIDATED.** A worker reported it during the run, but
> the verifier never independently reproduced it because the operator
> interrupted the run before validation completed. The reported issue may be
> a false positive, already-known behavior, or unreachable in practice.
> **Do not rely on this as a confirmed finding.**

- **Severity (claimed)**: %s
- **Affected Endpoint (claimed)**: %s
- **Originating Worker**: %d
- **Candidate ID**: %s

## Worker Summary

%s

## Evidence Notes (worker-reported)

%s

## Reproduction Hint (worker-reported)

%s

## Flow IDs Touched

%s
`

// WriteUnvalidated persists a still-pending candidate to disk under an
// UNVALIDATED banner. Uses an `unvalidated-NN-slug.md` filename so the
// regular findings index doesn't pick these up on the next run.
func (w *FindingWriter) WriteUnvalidated(c FindingCandidate) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(w.findingsDir, 0o755); err != nil {
		return "", err
	}
	next := w.UnvalidatedCount + 1
	slug := Slugify(c.Title)
	if slug == "" {
		slug = "untitled"
	}
	if len(slug) > 60 {
		slug = strings.TrimRight(slug[:60], "-")
	}
	name := fmt.Sprintf("unvalidated-%02d-%s.md", next, slug)
	path := filepath.Join(w.findingsDir, name)
	body := fmt.Sprintf(unvalidatedTemplate,
		c.Title,
		orDefault(c.Severity, "unknown"),
		orDefault(c.Endpoint, "N/A"),
		c.WorkerID,
		c.CandidateID,
		orDefault(c.Summary, noneSentinel),
		orDefault(c.EvidenceNotes, noneSentinel),
		orDefault(c.ReproductionHint, noneSentinel),
		formatFlowIDList(c.FlowIDs),
	)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	w.UnvalidatedCount = next
	w.Paths = append(w.Paths, path)
	return path, nil
}

func formatFlowIDList(ids []string) string {
	if len(ids) == 0 {
		return noneSentinel
	}
	var b strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&b, "- %s\n", id)
	}
	return strings.TrimRight(b.String(), "\n")
}
