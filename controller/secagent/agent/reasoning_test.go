package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReasoningFormat_String(t *testing.T) {
	t.Parallel()
	cases := map[ReasoningFormat]string{
		ReasoningFormatUnknown:    "unknown",
		ReasoningFormatNone:       "none",
		ReasoningFormatInline:     "inline",
		ReasoningFormatStructured: "structured",
	}
	for f, want := range cases {
		assert.Equal(t, want, f.String())
	}
}

func TestDetectReasoningFormat_Structured(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{
		Content:          "",
		ReasoningContent: "working through it",
	}}}
	f, err := DetectReasoningFormat(context.Background(), client, "m")
	require.NoError(t, err)
	assert.Equal(t, ReasoningFormatStructured, f)
	require.Len(t, client.calls, 1)
	assert.Contains(t, client.calls[0].Messages[0].Content, "sky is blue")
}

func TestDetectReasoningFormat_Inline(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{
		Content: "<think>reasoning here</think>final answer",
	}}}
	f, err := DetectReasoningFormat(context.Background(), client, "m")
	require.NoError(t, err)
	assert.Equal(t, ReasoningFormatInline, f)
}

func TestDetectReasoningFormat_None(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{{
		Content: "plain prose answer — no thinking shown.",
	}}}
	f, err := DetectReasoningFormat(context.Background(), client, "m")
	require.NoError(t, err)
	assert.Equal(t, ReasoningFormatNone, f)
}

func TestDetectReasoningFormat_ErrorFallsBackToUnknown(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{
		responses: []ChatResponse{{}},
		errors:    []error{errors.New("probe failed")},
	}
	f, err := DetectReasoningFormat(context.Background(), client, "m")
	require.Error(t, err)
	assert.Equal(t, ReasoningFormatUnknown, f)
}

func TestReasoningFormatCache_Dedups(t *testing.T) {
	t.Parallel()
	client := &fakeChatClient{responses: []ChatResponse{
		{ReasoningContent: "x"},
		{ReasoningContent: "x"}, // should never be reached — dedup from cache
	}}
	cache := NewReasoningFormatCache()
	var detectCount int
	onDetect := func(ReasoningFormat, time.Duration, error) { detectCount++ }

	f1 := cache.Resolve(context.Background(), client, "u1", "m", onDetect)
	f2 := cache.Resolve(context.Background(), client, "u1", "m", onDetect)
	f3 := cache.Resolve(context.Background(), client, "u2", "m", onDetect) // different URL → probe again

	assert.Equal(t, ReasoningFormatStructured, f1)
	assert.Equal(t, ReasoningFormatStructured, f2)
	assert.Equal(t, ReasoningFormatStructured, f3)
	assert.Equal(t, 2, detectCount, "same (url,model) dedup; different url re-probes")
	assert.Equal(t, int32(2), client.idx, "exactly two probes hit the client")
}

func TestNewReasoningHandler_UnknownFallsBackToInline(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatUnknown)
	assert.Equal(t, ReasoningFormatInline, h.Format(), "unknown maps to inline for back-compat")
}

func TestInlineHandler_IngestPassesContentThrough(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatInline)
	content, reasoning := h.Ingest(ChatResponse{
		Content:          "<think>x</think>answer",
		ReasoningContent: "ignored-if-present-on-inline-model",
	})
	assert.Equal(t, "<think>x</think>answer", content)
	assert.Empty(t, reasoning, "inline handler stores reasoning only in Content")
}

func TestInlineHandler_ReplayPreservesLastN(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatInline)
	msgs := []Message{
		{Role: roleSystem, Content: "sys"},
		{Role: roleAssistant, Content: "<think>turn1</think>done1"},
		{Role: roleAssistant, Content: "<think>turn2</think>done2"},
		{Role: roleAssistant, Content: "<think>turn3</think>done3"},
	}
	out := h.Replay(msgs, 1)
	assert.Equal(t, "done1", out[1].Content, "older stripped")
	assert.Equal(t, "done2", out[2].Content, "older stripped")
	assert.Contains(t, out[3].Content, "<think>turn3</think>", "newest preserved")
}

func TestInlineHandler_ForSummaryIsPassThrough(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatInline)
	msgs := []Message{{Role: roleAssistant, Content: "<think>x</think>y"}}
	out := h.ForSummary(msgs)
	assert.Equal(t, msgs[0].Content, out[0].Content)
}

func TestInlineHandler_TailUsesContentTruncation(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatInline)
	tail := h.Tail(ChatResponse{Content: "<think>I was investigating OAuth"})
	assert.Equal(t, "I was investigating OAuth", tail)
}

func TestStructuredHandler_IngestSplitsFields(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatStructured)
	content, reasoning := h.Ingest(ChatResponse{
		Content:          "final",
		ReasoningContent: "my reasoning",
	})
	assert.Equal(t, "final", content)
	assert.Equal(t, "my reasoning", reasoning)
}

func TestStructuredHandler_ReplayBlanksReasoningRegardlessOfKeepN(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatStructured)
	msgs := []Message{
		{Role: roleAssistant, Content: "a1", ReasoningContent: "r1"},
		{Role: roleAssistant, Content: "a2", ReasoningContent: "r2"},
		{Role: roleAssistant, Content: "a3", ReasoningContent: "r3"},
	}
	for _, keep := range []int{0, 1, 5} {
		out := h.Replay(msgs, keep)
		for i, m := range out {
			assert.Emptyf(t, m.ReasoningContent, "keep=%d msg=%d: reasoning must be blanked", keep, i)
			assert.Equal(t, msgs[i].Content, m.Content, "content passes through")
		}
	}
	// Original not mutated.
	assert.Equal(t, "r1", msgs[0].ReasoningContent)
}

func TestStructuredHandler_ForSummaryWrapsAsInlineThink(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatStructured)
	msgs := []Message{
		{Role: roleSystem, Content: "sys"},
		{Role: roleUser, Content: "assignment"},
		{Role: roleAssistant, Content: "", ReasoningContent: "probing JWT"},
		{Role: roleAssistant, Content: "final answer", ReasoningContent: "more reasoning"},
	}
	out := h.ForSummary(msgs)
	assert.Equal(t, "sys", out[0].Content)
	assert.Equal(t, "<think>probing JWT</think>", out[2].Content)
	assert.Empty(t, out[2].ReasoningContent, "reasoning moved into Content")
	assert.True(t, strings.HasPrefix(out[3].Content, "<think>more reasoning</think>"))
	assert.Contains(t, out[3].Content, "final answer", "original content preserved after wrapper")
}

func TestInlineHandler_ExtractUsesExtractProse(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatInline)
	line := h.Extract(ChatResponse{
		Content: "<think>planning</think>```\nworker is scanning OAuth endpoints\n```",
	})
	assert.Equal(t, "worker is scanning OAuth endpoints", line)
}

func TestStructuredHandler_ExtractSalvagesMarkerInReasoning(t *testing.T) {
	t.Parallel()
	// Real-world failure: reasoning ends with "…Final: <actual summary>."
	// Extract must surface the sentence after Final: as the confident line
	// so narrator logs it without the "…thinking:" prefix.
	h := NewReasoningHandler(ReasoningFormatStructured)
	line := h.Extract(ChatResponse{
		Content: "",
		ReasoningContent: "(14) -> 14 words. Matches all constraints. Output matches.✅ " +
			"Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->",
	})
	assert.Equal(t, "The agent just dispatched another test request and is currently evaluating the network response for security analysis.", line)
}

func TestStructuredHandler_ExtractPrefersContentWhenBothPresent(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatStructured)
	line := h.Extract(ChatResponse{
		Content:          "the clean final answer.",
		ReasoningContent: "Final: something else",
	})
	assert.Equal(t, "the clean final answer.", line, "Content wins when both are populated")
}

func TestStructuredHandler_ExtractReturnsEmptyWhenNoMarker(t *testing.T) {
	t.Parallel()
	// Reasoning with no Final:/Output: marker — Extract returns "", Tail
	// will produce the "…thinking:" fallback.
	h := NewReasoningHandler(ReasoningFormatStructured)
	line := h.Extract(ChatResponse{
		Content:          "",
		ReasoningContent: "just meandering thoughts with no output marker",
	})
	assert.Empty(t, line)
}

func TestNoReasoningHandler_ExtractRunsExtractProse(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatNone)
	line := h.Extract(ChatResponse{Content: `{"summary": "plain answer"}`})
	assert.Equal(t, "plain answer", line)
}

func TestStructuredHandler_TailPrefersStructuredWhenInlineEmpty(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatStructured)
	tail := h.Tail(ChatResponse{
		Content:          "",
		ReasoningContent: "planning to probe OAuth redirect validation next",
	})
	assert.Contains(t, tail, "OAuth redirect validation next")
}

func TestNoReasoningHandler_PassesEverythingThrough(t *testing.T) {
	t.Parallel()
	h := NewReasoningHandler(ReasoningFormatNone)
	assert.Equal(t, ReasoningFormatNone, h.Format())
	content, reasoning := h.Ingest(ChatResponse{Content: "hi"})
	assert.Equal(t, "hi", content)
	assert.Empty(t, reasoning)
	msgs := []Message{{Role: roleAssistant, Content: "x"}}
	assert.Equal(t, msgs, h.Replay(msgs, 4))
	assert.Equal(t, msgs, h.ForSummary(msgs))
	assert.Empty(t, h.Tail(ChatResponse{Content: "nothing"}))
}
