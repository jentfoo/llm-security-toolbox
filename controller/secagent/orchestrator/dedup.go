package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-appsec/secagent/agent"
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

func (r *OpenAIDedupReviewer) oneShot(ctx context.Context, system, user string) (string, error) {
	client, err := r.Pool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer r.Pool.Release(client)
	maxTokens := r.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	resp, err := client.CreateChatCompletion(ctx, agent.ChatRequest{
		Model: r.Model,
		Messages: []agent.ChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens: maxTokens,
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

func writeFindingBlock(b *strings.Builder, f FindingFiled) {
	fmt.Fprintf(b, "Title: %s\n", f.Title)
	fmt.Fprintf(b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(b, "Endpoint: %s\n", f.Endpoint)
	fmt.Fprintf(b, "\nDescription:\n%s\n", orDefault(f.Description, "(none)"))
	fmt.Fprintf(b, "\nReproduction:\n%s\n", orDefault(f.ReproductionSteps, "(none)"))
	fmt.Fprintf(b, "\nEvidence:\n%s\n", orDefault(f.Evidence, "(none)"))
	fmt.Fprintf(b, "\nImpact:\n%s\n", orDefault(f.Impact, "(none)"))
	fmt.Fprintf(b, "\nVerification:\n%s\n", orDefault(f.VerificationNotes, "(none)"))
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
	case "unique":
		return DedupVerdict{Action: "unique"}, nil
	case "duplicate", "partial":
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

// ReviewAndWrite runs the full dedup pipeline for one filed finding:
//  1. IsDuplicate (exact-slug) — skip.
//  2. FindSimilarEntries — if empty or reviewer is nil, write as-is.
//  3. Classify each similar entry; first non-"unique" verdict wins and is
//     applied via ApplyDedupVerdict. Classifier errors fail open (skip that
//     entry and continue).
//  4. If all similar entries classify "unique", write incoming as a new file.
//
// Returns (wrote, path, err). "wrote" is true when a new finding was
// persisted (either a fresh file or an overwrite that introduced new
// content). "path" is the resulting file path, or "" when incoming was
// dropped as an exact duplicate.
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
	case "unique":
		path, werr := writer.Write(incoming)
		if werr != nil {
			return false, "", werr
		}
		if log != nil {
			log.Log("finding", "dedup-unique", map[string]any{"path": path, "similar_to": similar.Path})
		}
		return true, path, nil

	case "duplicate":
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

	case "partial":
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
