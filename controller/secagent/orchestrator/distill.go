package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// distillMaxTokens caps each per-batch model response.
const distillMaxTokens = 4000

const distillSystemPrompt = `You compress one or more tool-call results from a security-testing agent's history into 1-3 sentences of plain prose. Capture status codes, key fields, observed behavior, and cross-call patterns — anything the agent might need to reference later. Drop boilerplate, byte-level minutiae, and anything already obvious from the tool name. Return prose only — no preamble, no markdown headings or fences.`

// TODO: tune distill batch sizing once OnCompact telemetry is available.
const (
	distillMinBatchEvents = 3
	distillMaxBatchEvents = 6
	distillMinBatchBytes  = 2048
)

// DistillCallback returns an OnDistillResults callback that replaces
// eligible tool-result content with model-generated prose summaries.
// Returns nil when s is nil or unconfigured.
func DistillCallback(s *Summarizer) func(ctx context.Context, snapshot []agent.Message) ([]agent.Message, error) {
	return func(ctx context.Context, snapshot []agent.Message) ([]agent.Message, error) {
		if s == nil || s.Pool == nil || s.Model == "" {
			return nil, nil
		}
		batches := buildDistillBatches(snapshot)
		if len(batches) == 0 {
			return nil, nil
		}
		out := make([]agent.Message, len(snapshot))
		copy(out, snapshot)
		distilledBatches := 0
		distilledMsgs := 0
		for batchIdx, b := range batches {
			prose, err := runDistillBatch(ctx, s, b)
			if err != nil {
				if s.Log != nil {
					s.Log.Log("compact", "distill batch error", map[string]any{
						"batch_idx": batchIdx, "events": len(b.indices),
						"err": err.Error(),
					})
				}
				continue // fail-open: leave this batch alone
			}
			if strings.TrimSpace(prose) == "" {
				continue
			}
			content := fmt.Sprintf("%s%d: %s)", agent.DistillPrefix, batchIdx+1, strings.TrimSpace(prose))
			for _, idx := range b.indices {
				out[idx].Content = content
				distilledMsgs++
			}
			distilledBatches++
		}
		if distilledBatches == 0 {
			return nil, nil
		}
		if s.Log != nil {
			s.Log.Log("compact", "distill apply", map[string]any{
				"batches":  distilledBatches,
				"messages": distilledMsgs,
			})
		}
		return out, nil
	}
}

// distillBatch groups snapshot indices and rendered calls summarized together.
type distillBatch struct {
	indices []int
	calls   []distillCall
}

// distillCall is one tool-call/result pair for the distill prompt.
type distillCall struct {
	Name    string
	Args    string
	Content string
	IsError bool
}

// buildDistillBatches groups eligible old tool-result messages into batches.
func buildDistillBatches(snapshot []agent.Message) []distillBatch {
	const keepWindow = 8 // mirrors KeepTurns*2 trailing window
	cutoff := len(snapshot) - keepWindow
	if cutoff <= 1 {
		return nil
	}

	parentCall := map[string]agent.ToolCall{}
	for _, m := range snapshot {
		if m.Role == summarizeMsgRoleAssistant {
			for _, tc := range m.ToolCalls {
				parentCall[tc.ID] = tc
			}
		}
	}

	var batches []distillBatch
	var current distillBatch
	flush := func() {
		if len(current.indices) >= distillMinBatchEvents && batchByteLen(current) >= distillMinBatchBytes {
			batches = append(batches, current)
		}
		current = distillBatch{}
	}
	for i := 0; i < cutoff; i++ {
		m := snapshot[i]
		if m.Role == "user" {
			// User messages can mark a directive boundary — don't merge across them.
			flush()
			continue
		}
		if m.Role != summarizeMsgRoleTool {
			continue
		}
		if !isDistillEligible(m) {
			flush()
			continue
		}
		tc := parentCall[m.ToolCallID]
		current.indices = append(current.indices, i)
		current.calls = append(current.calls, distillCall{
			Name:    tc.Function.Name,
			Args:    short(tc.Function.Arguments, 240),
			Content: m.Content,
			IsError: m.IsRepairError || strings.HasPrefix(m.Content, "ERROR:"),
		})
		if len(current.indices) >= distillMaxBatchEvents {
			flush()
		}
	}
	flush()
	return batches
}

func isDistillEligible(m agent.Message) bool {
	if m.Role != summarizeMsgRoleTool {
		return false
	}
	if m.IsRepairError {
		return false
	}
	if agent.IsCompactionStub(m.Content) {
		return false
	}
	return true
}

func batchByteLen(b distillBatch) int {
	total := 0
	for _, c := range b.calls {
		total += len(c.Content)
	}
	return total
}

// runDistillBatch returns the prose summary for one batch.
func runDistillBatch(
	ctx context.Context,
	s *Summarizer,
	b distillBatch,
) (string, error) {
	prompt := buildDistillPrompt(b)
	raw, err := runOneShot(ctx, s.Pool, s.Model, distillSystemPrompt, prompt,
		distillMaxTokens, agent.CompressionReasoningEffort)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(agent.StripThinkBlocks(raw)), nil
}

func buildDistillPrompt(b distillBatch) string {
	var sb strings.Builder
	sb.WriteString("Summarize the following ")
	fmt.Fprintf(&sb, "%d tool-call results", len(b.calls))
	sb.WriteString(" into 1-3 sentences of prose. Preserve status codes, key field values, observed behavior, and cross-call patterns; drop boilerplate. Plain prose only — no headings, no fences, no preamble.\n\n")
	for i, c := range b.calls {
		fmt.Fprintf(&sb, "## Call %d: %s(%s)\n", i+1, fallbackName(c.Name), fallbackArgs(c.Args))
		if c.IsError {
			sb.WriteString("(error result)\n")
		}
		sb.WriteString(short(c.Content, 4000))
		sb.WriteString("\n\n")
	}
	return sb.String()
}
