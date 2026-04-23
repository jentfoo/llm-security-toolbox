package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractMarkedOutput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no_marker", "just plain prose without markers", ""},
		{"empty", "", ""},
		{
			name: "final_marker_picks_sentence_after",
			in:   "thinking about it... Final: The worker scanned endpoints.",
			want: "The worker scanned endpoints.",
		},
		{
			name: "output_marker_case_insensitive",
			in:   "Done. OUTPUT: Investigating OAuth scopes.",
			want: "Investigating OAuth scopes.",
		},
		{
			name: "stops_at_newline_before_period",
			in:   "Answer: One line of output\n(meta noise)",
			want: "One line of output",
		},
		{
			name: "takes_last_marker_when_multiple",
			in:   "Output: first thought.\nFinal: real answer.",
			want: "real answer.",
		},
		{
			name: "drops_trailing_parenthetical_noise",
			in:   "Final: The agent just dispatched a request. (16 words) -> foo",
			want: "The agent just dispatched a request.",
		},
		{
			name: "response_marker",
			in:   "Let me think... Response: scanning now.",
			want: "scanning now.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractMarkedOutput(tc.in))
		})
	}
}

func TestExtractProse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    string
		wantAny bool // when true, assert NotEmpty rather than matching want
	}{
		{name: "plain_prose", in: "The worker is scanning OAuth endpoints.", want: "The worker is scanning OAuth endpoints."},
		{
			name: "strips_think_and_fences",
			in:   "<think>planning</think>```\nworker is scanning OAuth endpoints\n```",
			want: "worker is scanning OAuth endpoints",
		},
		// Unclosed think survives the stripper; caller must fall back to Tail.
		{name: "unclosed_think_returns_empty", in: "<think>I was planning to test the OAuth redirect next", want: ""},
		{name: "summary_field", in: `{"summary": "running replay_send"}`, want: "running replay_send"},
		{name: "text_field", in: `{"text": "analyzing response."}`, want: "analyzing response."},
		{
			name: "multiple_fields_summary_wins",
			in:   `{"status": "ok", "summary": "probing OAuth scopes"}`,
			want: "probing OAuth scopes",
		},
		{name: "falls_back_to_first_string", in: `{"z_other": "last-resort value"}`, want: "last-resort value"},
		{name: "empty_object_returns_empty", in: `{}`, want: ""},
		{
			name: "with_whitespace_and_newlines",
			in:   "\n{\n  \"summary\": \"the worker tried X\"\n}\n",
			want: "the worker tried X",
		},
		{
			name: "malformed_json_falls_back",
			in:   "{\nunterminated json is noise\nbut this line is prose",
			want: "unterminated json is noise",
		},
		{
			name: "prefers_marker_over_first_line",
			in:   "Thinking about it.\nMatches constraints.\nFinal: The worker just probed /admin/api/clients.",
			want: "The worker just probed /admin/api/clients.",
		},
		{name: "skips_leading_brace", in: "{\n\"summary\": real answer", want: `"summary": real answer`},
		{name: "skips_leading_quote", in: "\"\nactual prose", want: "actual prose"},
		{name: "skips_leading_fences", in: "```\n```\nbare prose after fences", want: "bare prose after fences"},
		{
			// Marker "[Output]" is not in our list; falls back to first-line. Input is one line
			// so it returns as-is — not ideal, but we just assert we did not drop the sentence.
			name:    "unknown_marker_preserves_line",
			in:      `"just switched from idle to autonomous" covers just did. Perfect. Output matches.✅ [Output] The agent just switched from idle to autonomous and is now executing its first security test iteration with one active worker.`,
			wantAny: true,
		},
		{
			name: "final_colon_marker_after_meta",
			in:   `(14) -> 14 words. Very concise. Matches all constraints. Output matches.✅ Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->`,
			want: "The agent just dispatched another test request and is currently evaluating the network response for security analysis.",
		},
		{
			name: "bare_json_brace_fallback",
			in:   "{\n  \"summary\": \"Currently investigating residual OIDC state-machines\"\n}",
			want: "Currently investigating residual OIDC state-machines",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractProse(tc.in)
			if tc.wantAny {
				assert.NotEmpty(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestFirstSentenceOrLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sentence_terminator", "one sentence. second sentence.", "one sentence."},
		{"newline_split", "first line\nsecond line", "first line"},
		{"no_terminator", "no terminator", "no terminator"},
		{"trim_whitespace", "   trim whitespace.   ", "trim whitespace."},
		{"empty", "", ""},
		{"whitespace_only", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firstSentenceOrLine(tc.in))
		})
	}
}

func TestFirstMeaningfulLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain_line", "plain line", "plain line"},
		{"brace_skipped", "{\nreal content", "real content"},
		{"punctuation_skipped", "\"\n'\n`\n,\nprose", "prose"},
		{"blanks_only", "\n\n\n", ""},
		{"structural_only", strings.Join([]string{"{", "}", "[", "]"}, "\n"), ""},
		{"fence_skipped", "```\nprose inside fence", "prose inside fence"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firstMeaningfulLine(tc.in))
		})
	}
}
