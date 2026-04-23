package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripThinkBlocks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no_think", "hello", "hello"},
		{"think_lower", "a<think>hidden</think>b", "ab"},
		{"think_upper", "a<THINK>hidden</THINK>b", "ab"},
		{"multiline", "a<think>line1\nline2</think>b", "ab"},
		{"thinking_tag", "a<thinking>x</thinking>b", "ab"},
		{"reasoning_tag", "a<reasoning>x</reasoning>b", "ab"},
		{"pipe_tag", "a<|thinking|>x<|/thinking|>b", "ab"},
		{"two_blocks", "a<think>x</think>b<think>y</think>c", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripThinkBlocks(tc.in))
		})
	}
}

func TestStripCodeFences(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no_fence", "hello world", "hello world"},
		{"bare_fence_pair", "```\nhello\n```", "hello"},
		{"language_tag", "```json\n{\"foo\":\"bar\"}\n```", `{"foo":"bar"}`},
		{"leading_blanks_and_fence", "\n\n```\nline one\nline two\n```\n", "line one\nline two"},
		{"leading_only", "```md\nprose", "prose"},
		{"trailing_only", "prose\n```", "prose"},
		{"fence_only", "```", ""},
		{"two_fences_only", "```\n```", ""},
		{"inline_backticks_untouched", "the `foo` bar", "the `foo` bar"},
		{"trailing_fence_exact_only", "prose\n```json", "prose\n```json"}, // opener-style trailer not stripped
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripCodeFences(tc.in))
		})
	}
}

func TestFilterThinkBlocks(t *testing.T) {
	t.Parallel()
	build := func() []Message {
		return []Message{
			{Role: roleSystem, Content: "sys"},
			{Role: roleUser, Content: "assignment"},
			{Role: roleAssistant, Content: "<think>turn1</think>done1"},
			{Role: roleTool, Content: "<think>not-stripped-in-tools</think>payload", ToolCallID: "c1"},
			{Role: roleAssistant, Content: "<think>turn2</think>done2"},
			{Role: roleAssistant, Content: "<think>turn3</think>done3"},
		}
	}

	t.Run("keep_all_when_n_exceeds", func(t *testing.T) {
		msgs := FilterThinkBlocks(build(), 10)
		for _, m := range msgs {
			if m.Role == roleAssistant {
				assert.Contains(t, m.Content, "<think>", "n=10 covers all 3 assistants")
			}
		}
	})

	t.Run("keep_two_preserves_last_two", func(t *testing.T) {
		msgs := FilterThinkBlocks(build(), 2)
		assert.NotContains(t, msgs[2].Content, "<think>", "oldest assistant should be stripped")
		assert.Equal(t, "done1", msgs[2].Content)
		assert.Contains(t, msgs[4].Content, "<think>turn2</think>")
		assert.Contains(t, msgs[5].Content, "<think>turn3</think>")
	})

	t.Run("keep_zero_strips_all_assistants", func(t *testing.T) {
		msgs := FilterThinkBlocks(build(), 0)
		for i, m := range msgs {
			if m.Role == roleAssistant {
				assert.NotContainsf(t, m.Content, "<think>", "assistant at %d should have think stripped", i)
			}
		}
	})

	t.Run("non_assistant_roles_untouched", func(t *testing.T) {
		msgs := FilterThinkBlocks(build(), 0)
		assert.Equal(t, "sys", msgs[0].Content)
		assert.Equal(t, "assignment", msgs[1].Content)
		// Tool content is left alone — it's not part of the think-retention
		// bargain and shouldn't be modified here.
		assert.Contains(t, msgs[3].Content, "<think>not-stripped-in-tools</think>payload")
	})

	t.Run("nil_and_empty_safe", func(t *testing.T) {
		assert.Nil(t, FilterThinkBlocks(nil, 2))
		assert.Empty(t, FilterThinkBlocks([]Message{}, 2))
	})

	t.Run("returns_copy_not_mutation", func(t *testing.T) {
		orig := build()
		_ = FilterThinkBlocks(orig, 0)
		assert.Contains(t, orig[2].Content, "<think>turn1</think>")
	})
}

func TestTruncatedThinkTail(t *testing.T) {
	t.Parallel()

	t.Run("closed_block_returns_empty", func(t *testing.T) {
		assert.Empty(t, TruncatedThinkTail("<think>planning</think>done"))
	})

	t.Run("no_think_tag_returns_empty", func(t *testing.T) {
		assert.Empty(t, TruncatedThinkTail("just a normal response"))
	})

	t.Run("empty_returns_empty", func(t *testing.T) {
		assert.Empty(t, TruncatedThinkTail(""))
	})

	t.Run("unclosed_think_returns_content", func(t *testing.T) {
		got := TruncatedThinkTail("<think>I am investigating the login flow")
		assert.Equal(t, "I am investigating the login flow", got)
	})

	t.Run("unclosed_thinking_variant", func(t *testing.T) {
		got := TruncatedThinkTail("<thinking>checking JWT kid confusion")
		assert.Equal(t, "checking JWT kid confusion", got)
	})

	t.Run("case_insensitive_open_tag", func(t *testing.T) {
		got := TruncatedThinkTail("<THINK>reviewing endpoints")
		assert.Equal(t, "reviewing endpoints", got)
	})

	t.Run("long_tail_truncated_with_ellipsis", func(t *testing.T) {
		long := strings.Repeat("word ", 200)
		got := TruncatedThinkTail("<think>" + long)
		assert.Truef(t, strings.HasPrefix(got, "…"), "long tail should be prefixed with ellipsis, got %q", got)
		assert.Less(t, len(got), len(long))
	})

	t.Run("collapses_newlines", func(t *testing.T) {
		got := TruncatedThinkTail("<think>line one\n\nline two\n  line three")
		assert.NotContains(t, got, "\n")
		assert.Contains(t, got, "line one")
		assert.Contains(t, got, "line three")
	})

	t.Run("prefers_later_sentence_start", func(t *testing.T) {
		// Build a tail where the middle contains a sentence boundary; result
		// should start on a clean sentence rather than mid-word.
		prefix := strings.Repeat("a ", 200)
		got := TruncatedThinkTail("<think>" + prefix + "An earlier sentence. The latest thought is about OAuth.")
		assert.Contains(t, got, "The latest thought is about OAuth.")
	})

	t.Run("multiple_opens_only_last_counts", func(t *testing.T) {
		// Earlier closed block + later unclosed block → use the later tail.
		got := TruncatedThinkTail("<think>first closed thought</think>some text<think>second unclosed thought")
		assert.Equal(t, "second unclosed thought", got)
	})
}
