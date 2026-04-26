package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectReasoningFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		resp    ChatResponse
		err     error
		want    ReasoningFormat
		wantErr bool
	}{
		{
			name: "structured",
			resp: ChatResponse{ReasoningContent: "working through it"},
			want: ReasoningFormatStructured,
		},
		{
			name: "inline",
			resp: ChatResponse{Content: "<think>reasoning here</think>final answer"},
			want: ReasoningFormatInline,
		},
		{
			name: "none",
			resp: ChatResponse{Content: "plain prose answer — no thinking shown."},
			want: ReasoningFormatNone,
		},
		{
			name:    "error_falls_back_to_unknown",
			resp:    ChatResponse{},
			err:     errors.New("probe failed"),
			want:    ReasoningFormatUnknown,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeChatClient{responses: []ChatResponse{tc.resp}}
			if tc.err != nil {
				client.errors = []error{tc.err}
			}
			f, err := DetectReasoningFormat(t.Context(), client, "m")
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, tc.want, f)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, f)
			require.Len(t, client.calls, 1)
			assert.Contains(t, client.calls[0].Messages[0].Content, "sky is blue")
		})
	}
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

	f1 := cache.Resolve(t.Context(), client, "u1", "m", onDetect)
	f2 := cache.Resolve(t.Context(), client, "u1", "m", onDetect)
	f3 := cache.Resolve(t.Context(), client, "u2", "m", onDetect) // different URL → probe again

	assert.Equal(t, ReasoningFormatStructured, f1)
	assert.Equal(t, ReasoningFormatStructured, f2)
	assert.Equal(t, ReasoningFormatStructured, f3)
	assert.Equal(t, 2, detectCount)
}

func TestReasoningHandler_Ingest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		format        ReasoningFormat
		resp          ChatResponse
		wantContent   string
		wantReasoning string
	}{
		{
			name:        "inline_passes_content_through",
			format:      ReasoningFormatInline,
			resp:        ChatResponse{Content: "<think>x</think>answer", ReasoningContent: "ignored"},
			wantContent: "<think>x</think>answer",
		},
		{
			name:          "structured_splits_fields",
			format:        ReasoningFormatStructured,
			resp:          ChatResponse{Content: "final", ReasoningContent: "my reasoning"},
			wantContent:   "final",
			wantReasoning: "my reasoning",
		},
		{
			name:        "none_drops_reasoning",
			format:      ReasoningFormatNone,
			resp:        ChatResponse{Content: "hi", ReasoningContent: "ignored"},
			wantContent: "hi",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewReasoningHandler(tc.format)
			content, reasoning := h.Ingest(tc.resp)
			assert.Equal(t, tc.wantContent, content)
			assert.Equal(t, tc.wantReasoning, reasoning)
		})
	}
}

func TestReasoningHandler_Replay(t *testing.T) {
	t.Parallel()

	t.Run("inline_keeps_last_n_think_blocks", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		msgs := []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleAssistant, Content: "<think>turn1</think>done1"},
			{Role: roleAssistant, Content: "<think>turn2</think>done2"},
			{Role: roleAssistant, Content: "<think>turn3</think>done3"},
		}
		out := h.Replay(msgs, 1)
		assert.Equal(t, "done1", out[1].Content)
		assert.Equal(t, "done2", out[2].Content)
		assert.Contains(t, out[3].Content, "<think>turn3</think>")
	})

	t.Run("structured_blanks_reasoning_for_any_keep_n", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		msgs := []Message{
			{Role: roleAssistant, Content: "a1", ReasoningContent: "r1"},
			{Role: roleAssistant, Content: "a2", ReasoningContent: "r2"},
			{Role: roleAssistant, Content: "a3", ReasoningContent: "r3"},
		}
		for _, keep := range []int{0, 1, 5} {
			out := h.Replay(msgs, keep)
			for i, m := range out {
				assert.Empty(t, m.ReasoningContent)
				assert.Equal(t, msgs[i].Content, m.Content)
			}
		}
		assert.Equal(t, "r1", msgs[0].ReasoningContent)
	})

	t.Run("none_returns_input_unchanged", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatNone)
		msgs := []Message{{Role: roleAssistant, Content: "x"}}
		assert.Equal(t, msgs, h.Replay(msgs, 4))
	})
}

func TestReasoningHandler_ForSummary(t *testing.T) {
	t.Parallel()

	t.Run("inline_passes_through", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		msgs := []Message{{Role: roleAssistant, Content: "<think>x</think>y"}}
		out := h.ForSummary(msgs)
		assert.Equal(t, msgs[0].Content, out[0].Content)
	})

	t.Run("structured_wraps_reasoning_as_think", func(t *testing.T) {
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
		assert.Empty(t, out[2].ReasoningContent)
		assert.True(t, strings.HasPrefix(out[3].Content, "<think>more reasoning</think>"))
		assert.Contains(t, out[3].Content, "final answer")
	})
}

func TestReasoningHandler_Extract(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format ReasoningFormat
		resp   ChatResponse
		want   string
	}{
		{
			name:   "inline_strips_think_and_fence",
			format: ReasoningFormatInline,
			resp:   ChatResponse{Content: "<think>planning</think>```\nworker is scanning OAuth endpoints\n```"},
			want:   "worker is scanning OAuth endpoints",
		},
		{
			name:   "structured_prefers_content_when_both_present",
			format: ReasoningFormatStructured,
			resp:   ChatResponse{Content: "the clean final answer.", ReasoningContent: "Final: something else"},
			want:   "the clean final answer.",
		},
		{
			name:   "structured_salvages_marker_in_reasoning",
			format: ReasoningFormatStructured,
			// Real-world: reasoning ends with "…Final: <actual summary>." and Extract
			// must surface the sentence after Final: as the confident line.
			resp: ChatResponse{
				ReasoningContent: "(14) -> 14 words. Matches all constraints. Output matches.✅ " +
					"Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->",
			},
			want: "The agent just dispatched another test request and is currently evaluating the network response for security analysis.",
		},
		{
			name:   "structured_returns_empty_without_marker",
			format: ReasoningFormatStructured,
			resp:   ChatResponse{ReasoningContent: "just meandering thoughts with no output marker"},
			want:   "",
		},
		{
			name:   "none_runs_extract_prose",
			format: ReasoningFormatNone,
			resp:   ChatResponse{Content: `{"summary": "plain answer"}`},
			want:   "plain answer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewReasoningHandler(tc.format)
			assert.Equal(t, tc.want, h.Extract(tc.resp))
		})
	}
}

func TestReasoningHandler_Tail(t *testing.T) {
	t.Parallel()

	t.Run("inline_truncates_unclosed_think_content", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		tail := h.Tail(ChatResponse{Content: "<think>I was investigating OAuth"})
		assert.Equal(t, "I was investigating OAuth", tail)
	})

	t.Run("structured_prefers_reasoning_when_content_empty", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		tail := h.Tail(ChatResponse{ReasoningContent: "planning to probe OAuth redirect validation next"})
		assert.Contains(t, tail, "OAuth redirect validation next")
	})
}
