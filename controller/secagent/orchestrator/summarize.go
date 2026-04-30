package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-appsec/secagent/agent"
)

// Summarizer produces on-demand recaps. The single remaining variant —
// SummarizeCompletedWorker — runs once per worker at retire time. Workers
// no longer summarize themselves while alive (chronicle stays raw,
// compacted in place), and the director chat is canonical at the
// controller (no boundary-summarize callback).
//
// Routed through the shared pool with the main model — the recap drives
// the only memory the director keeps of a retired worker, so it gets the
// main model, not the cheap log model.
type Summarizer struct {
	Pool      *agent.ClientPool
	Model     string
	MaxTokens int
	Timeout   time.Duration
	Log       *Logger
}

const (
	summarizeMaxTokens = 20000
	summarizeTimeout   = 20 * time.Minute
)

// SummarizeReconMission converts a mission prompt into a recon-scoped goal,
// stripping testing/exploitation language so the recon worker focuses on
// surface mapping.
func (s *Summarizer) SummarizeReconMission(ctx context.Context, mission string) (string, error) {
	if s == nil || s.Pool == nil || s.Model == "" {
		return "", errors.New("summarizer: not configured")
	}
	mission = strings.TrimSpace(mission)
	if mission == "" {
		return "", errors.New("summarizer: empty mission")
	}
	user := "Mission:\n" + mission + "\n\nRecon goal:"
	out, err := s.oneShot(ctx, reconMissionSystemPrompt, user)
	if err != nil {
		if s.Log != nil {
			s.Log.Log("summarize", "recon-mission error", map[string]any{"err": err.Error()})
		}
		return "", err
	}
	out = strings.TrimSpace(agent.StripThinkBlocks(out))
	if out == "" {
		return "", errors.New("summarizer: empty output")
	}
	return out, nil
}

const reconMissionSystemPrompt = `Convert a security-testing mission into a focused reconnaissance goal for an agent whose ONLY job is mapping the target's surface (endpoints, technologies, authentication boundaries, public/private boundaries, observable configuration) — not testing, not exploitation, not finding-filing.

Strip any motivation-to-test language, any vulnerability classes named, any exploitation hints. Describe WHAT the target is and WHICH surface needs mapping in 2-4 plain sentences. Output prose only — no headings, no lists, no preamble.`

// SummarizeCompletedWorker writes a third-person recap of a retired worker's
// investigation. transcript is the worker's full chat history; mission and
// reason are context for the summary.
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
	// Tool errors (unknown-tool synthetics, MCP failures, malformed-arg
	// repair stubs) are noise to the summarizer — the recap describes what
	// the worker LEARNED, not what it bumbled. Stripping them reclaims a
	// large slice of context on noisy runs.
	transcript = agent.FilterErrorMessages(transcript)
	if !agent.HasSubstantiveMessages(transcript) {
		// Filtered transcript is system/user only — nothing happened
		// worth summarizing. Skip the LLM call rather than spend budget
		// recapping noise. retire.go's empty-summary path keeps raw
		// worker activity in dirChat as the existing fall-through.
		if s.Log != nil {
			s.Log.Log("summarize", "completed-worker skip-noise-only", map[string]any{
				"worker_id": workerID,
			})
		}
		return "", nil
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

// summarizeMsgRoleTool / summarizeMsgRoleAssistant are message-role strings
// for the matching entries. Extracted as named constants so goconst doesn't
// flag the repeated literals across the orchestrator package.
const (
	summarizeMsgRoleTool      = "tool"
	summarizeMsgRoleAssistant = "assistant"
)

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
