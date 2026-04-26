package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-appsec/secagent/agent"
)

// Summarizer produces on-demand recaps. All variants are stateless
// one-shot LLM calls routed through the shared pool with the main model —
// expensive enough that we use the main model, not the cheap log model,
// because these recaps drive what agents remember across long runs.
//
// Three prompt variants:
//
//   - SummarizeWorkerFromChronicle is fired every iter for every alive
//     worker. Input is the worker's full canonical chronicle (raw
//     messages from prior iters); output is a first-person recap installed
//     as the worker's pre-iter context. Always summarized from raw — never
//     from a prior summary — so worker focus doesn't drift across iters.
//
//   - SummarizeCompletedWorker fires once per worker at retire time. Input
//     is the worker's full chronicle; output is a detailed third-person
//     recap rendered into every subsequent director prompt as the
//     canonical reference for that retired worker.
//
//   - SummarizeDirectorOldest fires only when the director's
//     boundary-summarize watermark trips. A contiguous chunk of the
//     director's oldest iterations is condensed into a concise
//     third-person recap.
type Summarizer struct {
	Pool      *agent.ClientPool
	Model     string
	MaxTokens int
	Timeout   time.Duration
	Log       *Logger
}

const (
	summarizeMaxTokens = 12000
	summarizeTimeout   = 30 * time.Second
)

// SummarizeWorkerFromChronicle condenses a worker's canonical chronicle
// (raw messages accumulated across prior iterations) into a first-person
// recap that the worker reads as its pre-iter context. Always summarizes
// from the raw record, never from a prior summary — workers never see
// their own summaries as input, only the canonical chronicle, which
// preserves focus across long runs.
func (s *Summarizer) SummarizeWorkerFromChronicle(
	ctx context.Context,
	chronicle []agent.Message,
	mission string,
	workerID int,
) (string, error) {
	if s == nil || s.Pool == nil || s.Model == "" {
		return "", errors.New("summarizer: not configured")
	}
	if len(chronicle) == 0 {
		return "", errors.New("summarizer: empty chronicle")
	}
	user := buildWorkerChroniclePrompt(chronicle, mission, workerID)
	out, err := s.oneShot(ctx, workerChronicleSystemPrompt, user)
	if err != nil {
		if s.Log != nil {
			s.Log.Log("summarize", "worker error", map[string]any{
				"err": err.Error(), "worker_id": workerID,
			})
		}
		return "", err
	}
	out = strings.TrimSpace(agent.StripThinkBlocks(out))
	if out == "" {
		return "", errors.New("summarizer: empty output")
	}
	return out, nil
}

// SummarizeDirectorOldest condenses a contiguous slice of the director's
// oldest iterations into a single concise third-person recap. The
// director's mission lives in its system prompt and survives this pass
// automatically — no need to pass it explicitly.
func (s *Summarizer) SummarizeDirectorOldest(
	ctx context.Context,
	snapshot []agent.Message,
) (string, error) {
	if s == nil || s.Pool == nil || s.Model == "" {
		return "", errors.New("summarizer: not configured")
	}
	if len(snapshot) == 0 {
		return "", errors.New("summarizer: empty snapshot")
	}
	user := buildDirectorOldestPrompt(snapshot)
	out, err := s.oneShot(ctx, directorOldestSystemPrompt, user)
	if err != nil {
		if s.Log != nil {
			s.Log.Log("summarize", "director error", map[string]any{"err": err.Error()})
		}
		return "", err
	}
	out = strings.TrimSpace(agent.StripThinkBlocks(out))
	if out == "" {
		return "", errors.New("summarizer: empty output")
	}
	return out, nil
}

// SummarizeCompletedWorker writes a detailed third-person recap of a worker
// that has just been retired. The director will read this as the canonical
// reference for what the worker investigated; the worker's ID is gone after
// this and the summary stands in for it across all subsequent director
// prompts.
//
// transcript is the worker agent's full history at retire time (typically
// from agent.Snapshot()). mission anchors the run-wide goal. reason is the
// retirement reason ("stall-force-stop" or the director's stop reason).
func (s *Summarizer) SummarizeCompletedWorker(
	ctx context.Context,
	transcript []agent.Message,
	mission, reason string,
	workerID int,
) (string, error) {
	if s == nil || s.Pool == nil || s.Model == "" {
		return "", errors.New("summarizer: not configured")
	}
	if len(transcript) == 0 {
		return "", errors.New("summarizer: empty transcript")
	}
	user := buildCompletedWorkerPrompt(transcript, mission, reason, workerID)
	out, err := s.oneShot(ctx, completedWorkerSystemPrompt, user)
	if err != nil {
		if s.Log != nil {
			s.Log.Log("summarize", "completed-worker error", map[string]any{
				"err": err.Error(), "worker_id": workerID,
			})
		}
		return "", err
	}
	out = strings.TrimSpace(agent.StripThinkBlocks(out))
	if out == "" {
		return "", errors.New("summarizer: empty output")
	}
	return out, nil
}

func (s *Summarizer) oneShot(ctx context.Context, system, user string) (string, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = summarizeTimeout
	}
	maxTokens := s.MaxTokens
	if maxTokens <= 0 {
		maxTokens = summarizeMaxTokens
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runOneShot(cctx, s.Pool, s.Model, system, user, maxTokens, agent.CompressionReasoningEffort)
}

// summarizeMsgRoleTool is the message-role string for tool-result entries.
// Extracted as a named constant so goconst doesn't flag the repeated
// literal across summarize.go's switch arms.
const summarizeMsgRoleTool = "tool"

// renderSnapshotForSummary serializes a chat-message slice into a readable
// transcript for the summarizer. Tool results and tool calls are inlined
// because they carry the byte-level texture (server responses, error
// strings) that distinguishes a near-miss from a clean failure.
func renderSnapshotForSummary(snapshot []agent.Message) string {
	var b strings.Builder
	for i, m := range snapshot {
		fmt.Fprintf(&b, "[%d] ", i)
		switch m.Role {
		case "user":
			fmt.Fprintf(&b, "USER: %s\n", short(m.Content, 4000))
		case "assistant":
			text := strings.TrimSpace(agent.StripThinkBlocks(m.Content))
			if text != "" {
				fmt.Fprintf(&b, "ASSISTANT: %s\n", short(text, 4000))
			}
			for j, tc := range m.ToolCalls {
				name := tc.Function.Name
				if name == "" {
					name = "?"
				}
				fmt.Fprintf(&b, "    call %d: %s(%s)\n", j+1, name,
					short(tc.Function.Arguments, 600))
			}
			if text == "" && len(m.ToolCalls) == 0 {
				b.WriteString("ASSISTANT: (empty)\n")
			}
		case summarizeMsgRoleTool:
			name := m.ToolName
			if name == "" {
				name = "?"
			}
			fmt.Fprintf(&b, "TOOL [%s]: %s\n", name, short(m.Content, 2400))
		case "system":
			// Skipped — the agent already has the system prompt; summary
			// input shouldn't repeat it.
			continue
		default:
			fmt.Fprintf(&b, "%s: %s\n", m.Role, short(m.Content, 2000))
		}
	}
	return b.String()
}

func buildWorkerChroniclePrompt(chronicle []agent.Message, mission string, workerID int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are summarizing security-testing worker %d's full canonical chronicle — every directive, tool call, tool result, and assistant turn the worker has produced so far across all iterations. Your output is a first-person recap that the worker itself will read at the start of its NEXT iteration as the only memory of its own prior work.\n\n", workerID)
	if mission != "" {
		b.WriteString("## Run mission (anchored across all iterations)\n\n")
		b.WriteString(strings.TrimSpace(mission))
		b.WriteString("\n\n")
	}
	b.WriteString("## Worker chronicle (raw record — every iteration's directive and turns, in order)\n\n")
	b.WriteString(renderSnapshotForSummary(chronicle))
	b.WriteString(`

Write the recap now, in first person, as the worker. The next directive is NOT yet known to you — do not invent or restate one. Preserve verbatim:
- Flow IDs, candidate IDs, endpoint paths, status codes from tool results.
- Tool error signatures (what failed and why) so I don't repeat the same mistakes.
- Hypotheses I tried with their actual outcomes (confirmed / refuted / inconclusive).
- Partial-success evidence and near-misses worth re-investigating.
- Filed candidates I reported, including their candidate IDs.

Drop:
- Verbose tool-result internals beyond the load-bearing bytes (e.g. full HTML pages — keep the status code and a short snippet).
- Repeated narration of obvious actions.
- Assistant self-talk that did not lead to a tool call or a finding.

No preamble, no headings, no fences. A few short paragraphs is fine. End with one short line summarizing what state I am in (e.g. "Currently waiting on next directive after dismissed candidate c004.").`)
	return b.String()
}

func buildDirectorOldestPrompt(snapshot []agent.Message) string {
	var b strings.Builder
	b.WriteString("You are condensing a contiguous chunk of the security-testing director's earliest iterations into a single concise third-person recap. The director will read this much later as its long-term record of how the run started.\n\n")
	b.WriteString("## Director transcript (oldest iterations to summarize)\n\n")
	b.WriteString(renderSnapshotForSummary(snapshot))
	b.WriteString(`

Write the recap now, in third person. Be concise — aim for around 300-500 words. Preserve:
- Each iteration's number and the angle assigned to each worker.
- Findings filed (title + severity + endpoint) and candidates dismissed (id + reason).
- Director decisions per iteration: plan_workers, continue, expand, stop — with the gist of each instruction.
- Verifier dispositions (filed, dismissed, still-pending counts).
- Vectors that were tried and ruled out, so the director doesn't re-suggest them.

Drop:
- Verbose substep-by-substep narration.
- Restated mission text (the director already has the mission in its system prompt).
- Tool-call internals that aren't load-bearing for future planning.

No preamble, no headings beyond the natural per-iteration structure if useful. No fences.`)
	return b.String()
}

const workerChronicleSystemPrompt = `You write first-person recaps that an autonomous security-testing worker will read as its only memory of its own prior session work. The input is the worker's full canonical chronicle (raw messages from every iteration so far) — always summarize from this raw record. Write strictly in first person ("I tested...", "I confirmed...") — never in third person. Output is consumed verbatim as a single user-role message in the worker's next chat turn, so be the recap; do not describe it.`

const directorOldestSystemPrompt = `You write concise third-person recaps of an autonomous security-testing director's prior planning iterations. The director will read this as its long-term record of how the run progressed. Be specific and preserve every load-bearing detail (decisions, dispositions, vectors ruled out). Never first-person.`

const completedWorkerSystemPrompt = `You write detailed third-person recaps of a single completed (retired) security-testing worker. The director will read this as the canonical reference for what the worker investigated and use it to choose how to explore the target further; the worker's ID is gone and the summary stands in for it. Be EXHAUSTIVE on the process, findings, and all other details so the director can make precise re-exploration decisions — do not omit substance to save space. Use clear, concise wording and do not excessively repeat details (every point appears once, in the most useful place). Always third-person ("the worker tested...", "the worker confirmed..."). No Markdown headings or fences (the summary is rendered as a bullet body inside another prompt).`

func buildCompletedWorkerPrompt(transcript []agent.Message, mission, reason string, workerID int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are summarizing the entire investigation of a completed security-testing worker (worker_id=%d) that has just been retired. The director will read this as historical reference — the worker's ID is gone and will not be reassigned, forked, or narrated.\n\n", workerID)
	if mission != "" {
		b.WriteString("## Run mission\n\n")
		b.WriteString(strings.TrimSpace(mission))
		b.WriteString("\n\n")
	}
	if reason != "" {
		b.WriteString("## Retirement reason\n\n")
		b.WriteString(strings.TrimSpace(reason))
		b.WriteString("\n\n")
	}
	b.WriteString("## Worker transcript (full history at retire time)\n\n")
	b.WriteString(renderSnapshotForSummary(transcript))
	b.WriteString(`

Write the recap now, in third person, framing this as "the worker". Be EXHAUSTIVE on the process, findings, and all other details — the director uses this to decide how to explore further, so missing detail directly costs coverage. Use clear, concise wording and don't excessively repeat details (every point appears once, in the most useful place). Length should be driven by content, not compressed for context.

Preserve:
- Every distinct angle and permutation the worker tested, with how it was probed.
- Endpoints, methods, payloads, and the actual outcomes (status codes, response shape, errors).
- Partial findings, near-misses, and unique observations worth other workers' attention.
- Tool errors that proved structural (vs transient typos).
- Reported finding candidates, including their candidate IDs and disposition (filed / dismissed / pending) when known.
- Final disposition: what is confirmed, what is ruled out, what remains uncertain and worth further work.

Drop:
- Restated mission text.
- Iteration-by-iteration narration when the work converged on the same angle (collapse to one statement).
- Verbose tool-result internals beyond the load-bearing bytes.

No preamble. No Markdown headings or fences. Plain prose paragraphs are best.`)
	return b.String()
}
