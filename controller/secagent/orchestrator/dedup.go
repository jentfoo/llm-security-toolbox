package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// Dedup verdict actions. Pair-wise (DedupVerdict) uses unique / duplicate /
// partial; multi-existing (CandidateDedupVerdict) uses unique / duplicate /
// merge. The "merge" action is only emitted by the candidate classifier
// because the per-pair classifier was originally designed to compare two
// finished findings, not a candidate-to-finding match where the candidate
// is naturally less complete.
const (
	dedupActionUnique    = "unique"
	dedupActionDuplicate = "duplicate"
	dedupActionPartial   = "partial"
	dedupActionMerge     = "merge"
)

// DedupVerdict classifies the relationship between two candidate-duplicate
// findings. MoreComplete is populated for "duplicate" and "partial" to tell
// the writer which side to preserve; it's ignored for "unique".
type DedupVerdict struct {
	Action       string // "unique" | "duplicate" | "partial"
	MoreComplete string // "existing" | "new"
}

// DedupReviewer arbitrates ambiguous dedup cases that TitlesSimilar flagged.
// Classify decides the relationship; Merge combines two findings when the
// verdict is "partial" (or when "duplicate" but the caller still wants a
// coalesced version).
type DedupReviewer interface {
	Classify(ctx context.Context, existing, incoming FindingFiled) (DedupVerdict, error)
	Merge(ctx context.Context, primary, secondary FindingFiled) (FindingFiled, error)
}

// OpenAIDedupReviewer calls an OpenAI-compatible chat-completion endpoint
// to classify and merge candidate-duplicate findings. Uses a pooled client
// (shared with the verifier/director) for one-shot completions — no agent
// state, no tools, structured JSON in/out.
type OpenAIDedupReviewer struct {
	Pool      *agent.ClientPool
	Model     string
	MaxTokens int
	Log       *Logger
}

// Classify asks the model for a verdict on the two findings.
func (r *OpenAIDedupReviewer) Classify(ctx context.Context, existing, incoming FindingFiled) (DedupVerdict, error) {
	prompt := classifyPrompt(existing, incoming)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return DedupVerdict{}, fmt.Errorf("dedup classify: %w", err)
	}
	return parseVerdict(raw)
}

// CandidateDedupVerdict is the multi-existing classifier's response: the
// disposition for the incoming candidate and (for non-unique outcomes) the
// filename of the existing finding that matched.
type CandidateDedupVerdict struct {
	Action          string // "unique" | "duplicate" | "merge"
	MatchedFilename string // populated for "duplicate" and "merge"
	Reason          string // optional one-liner from the classifier
}

// CandidateDedupReviewer classifies a worker-reported candidate against the
// set of existing finding digests. Returns a single verdict identifying
// which existing finding (if any) covers it. Implemented by
// OpenAIDedupReviewer; tests can substitute a fake.
type CandidateDedupReviewer interface {
	ClassifyCandidate(ctx context.Context, incoming AddInput, digests []FindingDigest) (CandidateDedupVerdict, error)
}

// ClassifyCandidate runs a single LLM call comparing one incoming worker
// candidate against every existing finding digest. Cheaper than the
// pair-wise per-similar Classify path because it folds the whole comparison
// into one prompt; suited to the worker hot path where latency on every
// report_finding_candidate matters.
func (r *OpenAIDedupReviewer) ClassifyCandidate(ctx context.Context, incoming AddInput, digests []FindingDigest) (CandidateDedupVerdict, error) {
	if len(digests) == 0 {
		return CandidateDedupVerdict{Action: dedupActionUnique}, nil
	}
	prompt := candidateClassifyPrompt(incoming, digests)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return CandidateDedupVerdict{}, fmt.Errorf("dedup classify candidate: %w", err)
	}
	return parseCandidateVerdict(raw, digests)
}

// Merge asks the model to coalesce primary and secondary into one finding.
// Primary is the more-complete side; its structure leads and secondary's
// unique details get folded in.
func (r *OpenAIDedupReviewer) Merge(ctx context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	prompt := mergePrompt(primary, secondary)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return FindingFiled{}, fmt.Errorf("dedup merge: %w", err)
	}
	return parseMerge(raw, primary)
}

// oneShot runs a single classify/merge completion with no ReasoningEffort
// set. Dedup verdicts and merges benefit from full reasoning and emit JSON
// that extractJSONObject already tolerates fenced/wrapped output for, so
// capping reasoning here would degrade quality for marginal token savings.
// MaxTokens defaults high so a thinking model has room to reason before
// emitting the verdict JSON.
func (r *OpenAIDedupReviewer) oneShot(ctx context.Context, system, user string) (string, error) {
	maxTokens := r.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 20000
	}
	return runOneShot(ctx, r.Pool, r.Model, system, user, maxTokens, "")
}

// runOneShot executes a single non-streaming chat completion against a
// pooled client and returns the trimmed response content. Shared by
// OpenAIDedupReviewer and HistoryCompressor — both perform stateless
// system+user → text completions with no tool dispatch and no agent state.
//
// reasoningEffort is forwarded as ChatRequest.ReasoningEffort; pass "" to
// inherit the model's default and let the backend ignore the field.
func runOneShot(
	ctx context.Context,
	pool *agent.ClientPool,
	model, system, user string,
	maxTokens int,
	reasoningEffort string,
) (string, error) {
	client, err := pool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer pool.Release(client)
	resp, err := client.CreateChatCompletion(ctx, agent.ChatRequest{
		Model: model,
		Messages: []agent.ChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens:       maxTokens,
		ReasoningEffort: reasoningEffort,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Content), nil
}

const dedupSystemPrompt = `You review security findings for duplication. Respond with JSON only — no prose, no markdown fences. Your output must parse as a single JSON object.`

func classifyPrompt(existing, incoming FindingFiled) string {
	var b strings.Builder
	b.WriteString("Compare two security findings. Decide whether they describe the same vulnerability.\n\n")
	b.WriteString("## Existing finding (already written to disk)\n")
	writeFindingBlock(&b, existing)
	b.WriteString("\n## New finding (just reported)\n")
	writeFindingBlock(&b, incoming)
	b.WriteString(`
## Response

Respond with exactly one JSON object:

  {"action": "unique"}
  {"action": "duplicate", "more_complete": "existing"}
  {"action": "duplicate", "more_complete": "new"}
  {"action": "partial", "more_complete": "existing"}
  {"action": "partial", "more_complete": "new"}

Meaning:
- "unique": different vulnerabilities that happen to share words; keep both.
- "duplicate": same vulnerability; pick which write-up is more thorough.
- "partial": same vulnerability class but each has unique details worth merging; pick which is the stronger base.

Return only the JSON object. No explanation.
`)
	return b.String()
}

func mergePrompt(primary, secondary FindingFiled) string {
	var b strings.Builder
	b.WriteString("Merge two security findings that describe the same vulnerability. Keep the primary's structure and voice; fold in unique details from the secondary. Do not drop reproduction steps or evidence from either side.\n\n")
	b.WriteString("## Primary (base to keep)\n")
	writeFindingBlock(&b, primary)
	b.WriteString("\n## Secondary (fold in unique details)\n")
	writeFindingBlock(&b, secondary)
	b.WriteString(`
## Response

Respond with a single JSON object containing the merged finding:

  {
    "title": "...",
    "severity": "low|medium|high|critical",
    "endpoint": "METHOD /path",
    "description": "...",
    "reproduction_steps": "...",
    "evidence": "...",
    "impact": "...",
    "verification_notes": "..."
  }

Return only the JSON object. No explanation.
`)
	return b.String()
}

// candidateClassifyPrompt renders the multi-existing classify request.
// Existing findings are presented as compact digests; the model picks one
// of three actions and (for duplicate/merge) names the existing filename.
func candidateClassifyPrompt(incoming AddInput, digests []FindingDigest) string {
	var b strings.Builder
	b.WriteString("A worker reported a candidate security finding. Decide whether it is genuinely new or already covered by an existing finding.\n\n")
	b.WriteString("## Existing findings\n\n")
	for i, d := range digests {
		fmt.Fprintf(&b, "[%d] file: %s\n", i+1, d.Filename)
		fmt.Fprintf(&b, "    title: %s\n", d.Title)
		fmt.Fprintf(&b, "    severity: %s\n", d.Severity)
		fmt.Fprintf(&b, "    endpoint: %s\n", d.Endpoint)
		if d.FirstLines != "" {
			fmt.Fprintf(&b, "    excerpt:\n      %s\n", strings.ReplaceAll(d.FirstLines, "\n", "\n      "))
		}
		b.WriteString("\n")
	}
	b.WriteString("## New candidate\n\n")
	fmt.Fprintf(&b, "Title: %s\n", incoming.Title)
	fmt.Fprintf(&b, "Severity: %s\n", incoming.Severity)
	fmt.Fprintf(&b, "Endpoint: %s\n", incoming.Endpoint)
	fmt.Fprintf(&b, "Summary: %s\n", orDefault(incoming.Summary, noneSentinel))
	fmt.Fprintf(&b, "Evidence notes: %s\n", orDefault(incoming.EvidenceNotes, noneSentinel))
	fmt.Fprintf(&b, "Reproduction hint: %s\n", orDefault(incoming.ReproductionHint, noneSentinel))
	b.WriteString(`
## Response

Respond with exactly one JSON object:

  {"action": "unique"}
  {"action": "duplicate", "matched_filename": "finding-NN-...md", "reason": "short reason"}
  {"action": "merge", "matched_filename": "finding-NN-...md", "reason": "short reason"}

Meaning:
- "unique": this candidate describes a vulnerability not covered by any existing finding.
- "duplicate": an existing finding already covers this candidate fully — nothing new to add.
- "merge": same vulnerability as an existing finding, but the candidate has unique evidence or details worth folding in.

Return only the JSON object. No prose, no markdown fences.
`)
	return b.String()
}

func parseCandidateVerdict(raw string, digests []FindingDigest) (CandidateDedupVerdict, error) {
	body := extractJSONObject(raw)
	var v struct {
		Action          string `json:"action"`
		MatchedFilename string `json:"matched_filename"`
		Reason          string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return CandidateDedupVerdict{}, fmt.Errorf("parse candidate verdict: %w (raw: %q)", err, raw)
	}
	switch v.Action {
	case dedupActionUnique:
		return CandidateDedupVerdict{Action: dedupActionUnique}, nil
	case dedupActionDuplicate, dedupActionMerge:
		if v.MatchedFilename == "" {
			return CandidateDedupVerdict{}, fmt.Errorf("verdict %q missing matched_filename (raw: %q)", v.Action, raw)
		}
		known := false
		for _, d := range digests {
			if d.Filename == v.MatchedFilename {
				known = true
				break
			}
		}
		if !known {
			return CandidateDedupVerdict{}, fmt.Errorf("verdict references unknown filename %q (raw: %q)", v.MatchedFilename, raw)
		}
		return CandidateDedupVerdict{
			Action:          v.Action,
			MatchedFilename: v.MatchedFilename,
			Reason:          v.Reason,
		}, nil
	default:
		return CandidateDedupVerdict{}, fmt.Errorf("unknown action %q (raw: %q)", v.Action, raw)
	}
}

func writeFindingBlock(b *strings.Builder, f FindingFiled) {
	fmt.Fprintf(b, "Title: %s\n", f.Title)
	fmt.Fprintf(b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(b, "Endpoint: %s\n", f.Endpoint)
	fmt.Fprintf(b, "\nDescription:\n%s\n", orDefault(f.Description, noneSentinel))
	fmt.Fprintf(b, "\nReproduction:\n%s\n", orDefault(f.ReproductionSteps, noneSentinel))
	fmt.Fprintf(b, "\nEvidence:\n%s\n", orDefault(f.Evidence, noneSentinel))
	fmt.Fprintf(b, "\nImpact:\n%s\n", orDefault(f.Impact, noneSentinel))
	fmt.Fprintf(b, "\nVerification:\n%s\n", orDefault(f.VerificationNotes, noneSentinel))
}

func parseVerdict(raw string) (DedupVerdict, error) {
	body := extractJSONObject(raw)
	var v struct {
		Action       string `json:"action"`
		MoreComplete string `json:"more_complete"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return DedupVerdict{}, fmt.Errorf("parse verdict: %w (raw: %q)", err, raw)
	}
	switch v.Action {
	case dedupActionUnique:
		return DedupVerdict{Action: dedupActionUnique}, nil
	case dedupActionDuplicate, dedupActionPartial:
		if v.MoreComplete != "existing" && v.MoreComplete != "new" {
			return DedupVerdict{}, fmt.Errorf("verdict %q missing more_complete in/out (raw: %q)", v.Action, raw)
		}
		return DedupVerdict{Action: v.Action, MoreComplete: v.MoreComplete}, nil
	default:
		return DedupVerdict{}, fmt.Errorf("unknown action %q (raw: %q)", v.Action, raw)
	}
}

func parseMerge(raw string, fallback FindingFiled) (FindingFiled, error) {
	body := extractJSONObject(raw)
	var m struct {
		Title             string `json:"title"`
		Severity          string `json:"severity"`
		Endpoint          string `json:"endpoint"`
		Description       string `json:"description"`
		ReproductionSteps string `json:"reproduction_steps"`
		Evidence          string `json:"evidence"`
		Impact            string `json:"impact"`
		VerificationNotes string `json:"verification_notes"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return FindingFiled{}, fmt.Errorf("parse merge: %w (raw: %q)", err, raw)
	}
	out := fallback // preserve SupersedesCandidateIDs / FollowUpHint from primary
	if m.Title != "" {
		out.Title = m.Title
	}
	if m.Severity != "" {
		out.Severity = m.Severity
	}
	if m.Endpoint != "" {
		out.Endpoint = m.Endpoint
	}
	if m.Description != "" {
		out.Description = m.Description
	}
	if m.ReproductionSteps != "" {
		out.ReproductionSteps = m.ReproductionSteps
	}
	if m.Evidence != "" {
		out.Evidence = m.Evidence
	}
	if m.Impact != "" {
		out.Impact = m.Impact
	}
	if m.VerificationNotes != "" {
		out.VerificationNotes = m.VerificationNotes
	}
	return out, nil
}

// extractJSONObject scrapes the first {..} block from raw. Models sometimes
// wrap JSON in ```json fences or add a leading sentence despite instructions;
// this tolerates both.
func extractJSONObject(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end < 0 || end < start {
		return s
	}
	return s[start : end+1]
}

// ReviewAndWrite persists a filed finding after dedup: exact-duplicate check,
// similarity review, and optional merge. Returns (wrote, path, err) where
// wrote is true when a new file was persisted; path is "" only when incoming
// was an exact duplicate.
func ReviewAndWrite(
	ctx context.Context,
	reviewer DedupReviewer,
	writer *FindingWriter,
	incoming FindingFiled,
	log *Logger,
) (bool, string, error) {
	if writer.IsDuplicate(incoming) {
		if log != nil {
			log.Log("finding", "duplicate skipped", map[string]any{"title": incoming.Title})
		}
		return false, "", nil
	}
	similars := writer.FindSimilarEntries(incoming)
	if len(similars) == 0 || reviewer == nil {
		path, err := writer.Write(incoming)
		return err == nil, path, err
	}
	for _, s := range similars {
		verdict, err := reviewer.Classify(ctx, s.Filed, incoming)
		if err != nil {
			if log != nil {
				log.Log("finding", "dedup classify error", map[string]any{
					"err": err.Error(), "similar": s.Path,
				})
			}
			continue
		}
		if verdict.Action == "unique" {
			continue
		}
		return ApplyDedupVerdict(ctx, reviewer, writer, incoming, s, verdict, log)
	}
	path, err := writer.Write(incoming)
	return err == nil, path, err
}

// ApplyDedupVerdict routes a verdict to the appropriate writer action.
// Returns (wrote, resolvedPath, err). "wrote" is true when a new finding was
// persisted (unique branch, or a merge that produced a new tail file). When
// false the existing finding remained (possibly overwritten in place) and
// the new filing was absorbed.
func ApplyDedupVerdict(
	ctx context.Context,
	reviewer DedupReviewer,
	writer *FindingWriter,
	incoming FindingFiled,
	similar SimilarFinding,
	verdict DedupVerdict,
	log *Logger,
) (wrote bool, resolvedPath string, err error) {
	switch verdict.Action {
	case dedupActionUnique:
		path, werr := writer.Write(incoming)
		if werr != nil {
			return false, "", werr
		}
		if log != nil {
			log.Log("finding", "dedup-unique", map[string]any{"path": path, "similar_to": similar.Path})
		}
		return true, path, nil

	case dedupActionDuplicate:
		if verdict.MoreComplete == "new" {
			// replace existing file's content with incoming, keep its sequence
			newPath, rerr := writer.Replace(similar.Path, incoming)
			if rerr != nil {
				return false, "", rerr
			}
			if log != nil {
				log.Log("finding", "dedup-duplicate-replace", map[string]any{
					"path": newPath, "replaced": similar.Path,
				})
			}
			return false, newPath, nil
		}
		// keep existing, discard incoming
		if log != nil {
			log.Log("finding", "dedup-duplicate-skip", map[string]any{
				"kept": similar.Path, "discarded_title": incoming.Title,
			})
		}
		return false, similar.Path, nil

	case dedupActionPartial:
		primary, secondary := similar.Filed, incoming
		if verdict.MoreComplete == "new" {
			primary, secondary = incoming, similar.Filed
		}
		merged, merr := reviewer.Merge(ctx, primary, secondary)
		if merr != nil {
			return false, "", merr
		}
		newPath, rerr := writer.Replace(similar.Path, merged)
		if rerr != nil {
			return false, "", rerr
		}
		if log != nil {
			log.Log("finding", "dedup-partial-merge", map[string]any{
				"path": newPath, "merged_into": similar.Path, "more_complete": verdict.MoreComplete,
			})
		}
		return false, newPath, nil

	default:
		return false, "", fmt.Errorf("apply dedup: unknown action %q", verdict.Action)
	}
}
