package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// buildDistillSnapshot seeds a snapshot with eligibleEvents fat tool-result
// pairs followed by trailingEvents small ones. distillBatches uses a fixed
// keepWindow of 8 messages (= 4 trailing events × 2 messages each). When
// trailingEvents == 4 the trailing block exactly fills the keepWindow,
// leaving only the eligible block in the loop's cutoff range. When
// trailingEvents > 4, some "trailing" events spill into the eligible
// range too; tests use that to drive different shape scenarios.
func buildDistillSnapshot(eligibleEvents int, eligibleBodyBytes int, trailingEvents int) []agent.Message {
	out := []agent.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
	}
	body := strings.Repeat("x", eligibleBodyBytes)
	for i := 0; i < eligibleEvents; i++ {
		id := "old" + string(rune('A'+i))
		out = append(out,
			agent.Message{
				Role:    "assistant",
				Content: "calling",
				ToolCalls: []agent.ToolCall{{
					ID: id,
					Function: agent.ToolFunction{
						Name:      "proxy_poll",
						Arguments: `{"summary":true}`,
					},
				}},
			},
			agent.Message{
				Role: summarizeMsgRoleTool, ToolCallID: id, ToolName: "proxy_poll",
				Content: body,
			},
		)
	}
	for i := 0; i < trailingEvents; i++ {
		id := "new" + string(rune('A'+i))
		out = append(out,
			agent.Message{
				Role:    "assistant",
				Content: "calling",
				ToolCalls: []agent.ToolCall{{
					ID: id,
					Function: agent.ToolFunction{
						Name:      "flow_get",
						Arguments: `{}`,
					},
				}},
			},
			agent.Message{
				Role: summarizeMsgRoleTool, ToolCallID: id, ToolName: "flow_get",
				Content: "small recent",
			},
		)
	}
	return out
}

func TestDistillCallback_RewritesEligibleBatches(t *testing.T) {
	t.Parallel()
	client := &sequenceClient{
		responses: []agent.ChatResponse{
			{Content: "GET /api/v1 → 200 with 12 entries summarizing user activity."},
		},
	}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	// 6 eligible events × 1KB each, trailing=4 fills keepWindow exactly.
	snap := buildDistillSnapshot(6, 1024, 4)

	out, err := cb(t.Context(), snap)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Len(t, out, len(snap), "snapshot shape preserved (pairing intact)")

	rewritten := 0
	for i := range out {
		if out[i].Role == summarizeMsgRoleTool && snap[i].Content != out[i].Content {
			rewritten++
			assert.True(t, strings.HasPrefix(out[i].Content, agent.DistillPrefix))
		}
	}
	assert.Equal(t, 6, rewritten, "all 6 eligible tool results rewritten")
	assert.Equal(t, 1, client.callCount(), "one LLM call for the single batch")
}

func TestDistillCallback_BelowMinEventsNoBatch(t *testing.T) {
	t.Parallel()
	client := &sequenceClient{}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	// 2 eligible events < distillMinBatchEvents (3); trailing=4 keeps the
	// keepWindow tight so trailing events don't bleed into the eligible
	// range.
	snap := buildDistillSnapshot(2, 4096, 4)

	out, err := cb(t.Context(), snap)
	require.NoError(t, err)
	assert.Nil(t, out, "no replacement when batch is below the event floor")
	assert.Equal(t, 0, client.callCount())
}

func TestDistillCallback_BelowMinBytesNoBatch(t *testing.T) {
	t.Parallel()
	client := &sequenceClient{}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	// 4 eligible events × 50 bytes = 200 bytes < distillMinBatchBytes (2048).
	snap := buildDistillSnapshot(4, 50, 4)

	out, err := cb(t.Context(), snap)
	require.NoError(t, err)
	assert.Nil(t, out, "skip LLM call when batch is too small to justify it")
	assert.Equal(t, 0, client.callCount())
}

func TestDistillCallback_LLMErrorFailsOpen(t *testing.T) {
	t.Parallel()
	client := &sequenceClient{
		responses: []agent.ChatResponse{{}},
		errors:    []error{errMsg("upstream")},
	}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	snap := buildDistillSnapshot(6, 1024, 4)

	out, err := cb(t.Context(), snap)
	// Callback errors are absorbed per the contract — batches that fail
	// stay raw. With only one batch and it failed, no successful batches
	// → nil replacement so maybeCompact knows nothing changed.
	require.NoError(t, err)
	assert.Nil(t, out, "fail-open: nil replacement when no batch succeeded")
}

func TestDistillCallback_NilSummarizerNoCalls(t *testing.T) {
	t.Parallel()
	cb := DistillCallback(nil)
	out, err := cb(t.Context(), buildDistillSnapshot(6, 1024, 4))
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestDistillCallback_AlreadyDistilledIsIdempotent(t *testing.T) {
	t.Parallel()
	client := &sequenceClient{}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	snap := buildDistillSnapshot(6, 1024, 4)
	// Pre-mark every eligible tool message as already distilled.
	for i := range snap {
		if snap[i].Role == summarizeMsgRoleTool {
			snap[i].Content = agent.DistillPrefix + "1: prior summary)"
		}
	}
	out, err := cb(t.Context(), snap)
	require.NoError(t, err)
	assert.Nil(t, out, "already-distilled messages are skipped — no LLM call")
	assert.Equal(t, 0, client.callCount())
}

func TestDistillCallback_MultipleBatches(t *testing.T) {
	t.Parallel()
	// 12 eligible events at distillMaxBatchEvents=6 each → 2 batches.
	client := &sequenceClient{
		responses: []agent.ChatResponse{
			{Content: "Batch 1 prose."},
			{Content: "Batch 2 prose."},
		},
	}
	s := &Summarizer{Pool: poolOf(client), Model: "m"}
	cb := DistillCallback(s)
	snap := buildDistillSnapshot(12, 1024, 4)

	out, err := cb(t.Context(), snap)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, 2, client.callCount(), "one LLM call per batch")

	var joined strings.Builder
	for _, m := range out {
		if m.Role == summarizeMsgRoleTool && strings.HasPrefix(m.Content, agent.DistillPrefix) {
			joined.WriteString(m.Content)
			joined.WriteString("\n")
		}
	}
	assert.Contains(t, joined.String(), "Batch 1 prose.")
	assert.Contains(t, joined.String(), "Batch 2 prose.")
}

func TestBuildDistillBatches_ExcludesRepairErrors(t *testing.T) {
	t.Parallel()
	snap := []agent.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
	}
	body := strings.Repeat("x", 1024)
	for i := 0; i < 3; i++ {
		id := "id" + string(rune('A'+i))
		snap = append(snap,
			agent.Message{
				Role: "assistant", Content: "go",
				ToolCalls: []agent.ToolCall{{ID: id, Function: agent.ToolFunction{Name: "t"}}},
			},
			agent.Message{
				Role: summarizeMsgRoleTool, ToolCallID: id, ToolName: "t",
				Content:       body,
				IsRepairError: i == 1,
			},
		)
	}
	for i := 0; i < 4; i++ {
		snap = append(snap, agent.Message{Role: "assistant", Content: "trail"})
	}
	batches := buildDistillBatches(snap)
	// Repair error at the middle event breaks the batch into two single-
	// event runs; each is below distillMinBatchEvents so neither qualifies.
	assert.Empty(t, batches)
}

// errMsg is a string-typed sentinel error used to drive scripted error paths.
type errMsg string

func (e errMsg) Error() string { return string(e) }
