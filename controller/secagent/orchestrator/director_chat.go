package orchestrator

// DirectorChat is the controller-owned canonical chat history for the
// director. Workers' iter activity, the director's own decisions, the
// recon summary, retired-worker summaries, and verifier reports all live
// here as raw chat messages tagged with (WorkerID, Iter) metadata.
//
// The director agent itself is a stateless one-shot per call: each
// per-worker decision call and each synthesis call uses
// agent.ReplaceHistory(<rendered view>) so the agent's own chat history
// is wiped between calls. The canonical record stays here at the
// controller and survives across iterations and across worker retirements.
//
// Why a canonical chat instead of a long-lived agent chat:
//
//   - Workers retire over time; their messages need to be replaced with a
//     summary in place. That's a structural slice op against the canonical
//     record — easy. Doing it inside an opaque agent's history is awkward.
//
//   - Each per-worker decision call needs a *different* selectively-compacted
//     view: the current worker's messages stay raw, every other worker's
//     messages get think-stripped + tool-stubbed. The director-thinking
//     stays raw regardless. Selective compaction is a render-time decision
//     against tagged messages.
//
//   - Re-installing per call costs a chat round-trip but no LLM call beyond
//     the decision itself, and selective compaction means each call's
//     payload is a *different* shape anyway, so prompt caching wouldn't
//     help.

import (
	"github.com/go-appsec/secagent/agent"
)

// DirectorMsgMeta tags one DirectorChat message with the worker it
// belongs to and the iteration in which it was added.
//
//   - WorkerID == 0 means "director-owned" — the mission anchor, synthesis
//     prompts, recon summary, retired-worker summaries, verifier reports.
//     These messages are NEVER compacted by RenderForWorker because the
//     director's own thinking and run-wide context must always be visible.
//   - WorkerID > 0 means "scoped to this worker" — that worker's iter
//     activity (assistant turns + tool calls + tool results) AND the
//     director's per-worker decision messages about it (the assistant
//     message issuing decide_worker + the resulting tool result). When
//     RenderForWorker(N) is called, only messages where WorkerID == N
//     stay raw; messages where WorkerID is some other positive value get
//     think-stripped + tool-stubbed.
type DirectorMsgMeta struct {
	WorkerID int
	Iter     int
}

// DirectorChat is the canonical record. Messages and Meta are kept in
// lockstep — len(Messages) == len(Meta) always.
type DirectorChat struct {
	Messages []agent.Message
	Meta     []DirectorMsgMeta
}

// NewDirectorChat constructs an empty chat.
func NewDirectorChat() *DirectorChat {
	return &DirectorChat{}
}

// Append adds one message tagged with workerID + iter. workerID=0 marks
// the message as director-owned (mission, synthesis, recon summary,
// verifier report, retired-worker summary).
func (c *DirectorChat) Append(msg agent.Message, workerID, iter int) {
	c.Messages = append(c.Messages, msg)
	c.Meta = append(c.Meta, DirectorMsgMeta{WorkerID: workerID, Iter: iter})
}

// AppendWorkerActivity adds a slice of worker-produced messages (assistant
// turns + tool results from the worker's iter run), each tagged with the
// worker's id and the iteration. Order is preserved.
func (c *DirectorChat) AppendWorkerActivity(workerID, iter int, msgs []agent.Message) {
	for _, m := range msgs {
		c.Append(m, workerID, iter)
	}
}

// ReplaceWorkerWithSummary replaces every message tagged with workerID with
// one user-role summary inserted at the first removed message's position.
// The replacement is tagged as director-owned (WorkerID=0) and idempotent.
func (c *DirectorChat) ReplaceWorkerWithSummary(workerID int, summary string, iter int) {
	if workerID <= 0 {
		return
	}
	firstIdx := -1
	keptMsgs := make([]agent.Message, 0, len(c.Messages))
	keptMeta := make([]DirectorMsgMeta, 0, len(c.Meta))
	for i := range c.Messages {
		if c.Meta[i].WorkerID == workerID {
			if firstIdx < 0 {
				firstIdx = len(keptMsgs)
			}
			continue
		}
		keptMsgs = append(keptMsgs, c.Messages[i])
		keptMeta = append(keptMeta, c.Meta[i])
	}
	if firstIdx < 0 {
		// No messages for this worker; nothing to replace.
		return
	}
	summaryMsg := agent.Message{Role: "user", Content: summary}
	summaryMeta := DirectorMsgMeta{WorkerID: 0, Iter: iter}
	// Insert the summary at firstIdx (the position the first removed
	// message occupied in the kept slice — which is now slightly different
	// from the original index because everything between has shifted left).
	c.Messages = append(keptMsgs[:firstIdx],
		append([]agent.Message{summaryMsg}, keptMsgs[firstIdx:]...)...)
	c.Meta = append(keptMeta[:firstIdx],
		append([]DirectorMsgMeta{summaryMeta}, keptMeta[firstIdx:]...)...)
}

// RenderForWorker produces a deep-copied selectively-compacted view of
// the canonical chat for a per-worker decision call about currentWorkerID.
//
// Compaction rules:
//   - WorkerID == 0 (director-owned): always raw. Mission anchor,
//     synthesis prompts and decisions, recon summary, retired-worker
//     summaries, verifier reports — all preserved verbatim because the
//     director needs its own reasoning trail and run-wide context.
//   - WorkerID == currentWorkerID: raw. The current decision call needs
//     full byte-level evidence about the worker we're evaluating.
//   - Other WorkerID > 0: think-strip assistant content + stub tool
//     results. Other workers' activity stays present so the director
//     knows what's in flight (peer-state context for coordination), but
//     bulk text and tool-result bodies fold into compact stubs.
//
// Length-preserving by design: callers that need exact index alignment
// with the canonical record can rely on len(rendered) == len(c.Messages).
//
// Defense-in-depth: empty Content on user/system/tool messages is
// replaced with a descriptive placeholder before return. Some endpoints
// reject `messages[]` entries whose content is missing on the wire, and
// the rendered slice is what the director agent ultimately sends.
func (c *DirectorChat) RenderForWorker(currentWorkerID int) []agent.Message {
	out := make([]agent.Message, len(c.Messages))
	for i, m := range c.Messages {
		out[i] = m
		w := c.Meta[i].WorkerID
		if w == 0 || w == currentWorkerID {
			continue
		}
		agent.StripAssistantThink(&out[i])
		agent.StubToolResult(&out[i])
	}
	NormalizeEmptyContent(out)
	return out
}

// RenderForSynthesis produces a deep-copied uniformly-compacted view for
// the synthesis call (plan_workers / direction_done / end_run).
//
// Compaction rules:
//   - WorkerID == 0 (director-owned): raw. Director's own decisions,
//     verifier reports, recon summary, retired-worker summaries.
//   - Any WorkerID > 0: think-strip + tool-stub. Synthesis decides
//     run-wide direction; granular per-worker turns aren't needed.
//
// Empty Content is normalized at return — see RenderForWorker.
func (c *DirectorChat) RenderForSynthesis() []agent.Message {
	out := make([]agent.Message, len(c.Messages))
	for i, m := range c.Messages {
		out[i] = m
		if c.Meta[i].WorkerID == 0 {
			continue
		}
		agent.StripAssistantThink(&out[i])
		agent.StubToolResult(&out[i])
	}
	NormalizeEmptyContent(out)
	return out
}

// NormalizeEmptyContent rewrites any user / system / tool message whose
// Content is empty into a descriptive placeholder. Walks msgs in place.
//
// Why: some OpenAI-compatible endpoints reject messages whose `content`
// field is missing on the wire ("Messages from roles [user, system,
// tool] must contain a 'content' field. Got 'undefined'."). Empty
// Content is the upstream cause — it serializes as an omitted field via
// the go-openai library's `omitempty` tag.
//
// This is a render-boundary safety net layered on top of the
// transport-layer single-space fallback in agent.OpenAIChatClient. The
// placeholder is more informative than a single space when the message
// reaches the model, and removes the ambiguity of "did the tool return
// nothing or did rendering produce nothing".
//
// Assistant messages are left alone — they may legitimately carry no
// content when accompanied by tool_calls.
func NormalizeEmptyContent(msgs []agent.Message) {
	for i := range msgs {
		if msgs[i].Content != "" || msgs[i].Role == summarizeMsgRoleAssistant {
			continue
		}
		switch msgs[i].Role {
		case summarizeMsgRoleTool:
			msgs[i].Content = "(tool returned no output)"
		default:
			msgs[i].Content = "(no content)"
		}
	}
}
