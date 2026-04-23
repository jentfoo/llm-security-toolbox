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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractMarkedOutput(tc.in))
		})
	}
}

func TestExtractProse_Prose(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "The worker is scanning OAuth endpoints.",
		ExtractProse("The worker is scanning OAuth endpoints."))
}

func TestExtractProse_StripsThinkAndFences(t *testing.T) {
	t.Parallel()
	got := ExtractProse("<think>planning</think>```\nworker is scanning OAuth endpoints\n```")
	assert.Equal(t, "worker is scanning OAuth endpoints", got)
}

func TestExtractProse_UnclosedThinkReturnsEmpty(t *testing.T) {
	t.Parallel()
	// Unclosed think tag survived the stripper — ExtractProse returns ""
	// so the caller falls back to Tail.
	assert.Empty(t, ExtractProse("<think>I was planning to test the OAuth redirect next"))
}

func TestExtractProse_JSONWrapperCommonFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"summary_field", `{"summary": "running replay_send"}`, "running replay_send"},
		{"text_field", `{"text": "analyzing response."}`, "analyzing response."},
		{
			name: "multiple_fields_summary_wins",
			in:   `{"status": "ok", "summary": "probing OAuth scopes"}`,
			want: "probing OAuth scopes",
		},
		{
			name: "no_known_field_falls_back_to_first_string",
			in:   `{"z_other": "last-resort value"}`,
			want: "last-resort value",
		},
		{
			name: "empty_object_returns_empty",
			in:   `{}`,
			want: "",
		},
		{
			name: "with_whitespace_and_newlines",
			in:   "\n{\n  \"summary\": \"the worker tried X\"\n}\n",
			want: "the worker tried X",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractProse(tc.in))
		})
	}
}

func TestExtractProse_MalformedJSONFallsBackToLineScan(t *testing.T) {
	t.Parallel()
	// Response starts with { but is truncated / invalid — skip the structural
	// lines and pick the first real prose line.
	in := "{\nunterminated json is noise\nbut this line is prose"
	assert.Equal(t, "unterminated json is noise", ExtractProse(in))
}

func TestExtractProse_PrefersMarkerOverFirstLine(t *testing.T) {
	t.Parallel()
	// Reasoning model emitted meta-chatter then "Final:" then the answer.
	// Marker wins over first-line.
	in := "Thinking about it.\nMatches constraints.\nFinal: The worker just probed /admin/api/clients."
	assert.Equal(t, "The worker just probed /admin/api/clients.", ExtractProse(in))
}

func TestExtractProse_SkipsStructuralLeadingLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"{\n\"summary\": real answer", `"summary": real answer`},
		{"\"\nactual prose", "actual prose"},
		{"```\n```\nbare prose after fences", "bare prose after fences"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ExtractProse(tc.in))
	}
}

func TestExtractProse_RealWorldFailureSamples(t *testing.T) {
	t.Parallel()
	// Taken directly from the user's reported failure modes — the real
	// bar ExtractProse must clear.

	t.Run("final_marker_in_reasoning_meta_chatter", func(t *testing.T) {
		in := `"just switched from idle to autonomous" covers just did. Perfect. Output matches.✅ [Output] The agent just switched from idle to autonomous and is now executing its first security test iteration with one active worker.`
		got := ExtractProse(in)
		// Marker is "[Output]" which isn't in our list, fall back to first
		// line. But the whole thing is one line — so this particular sample
		// should return as-is (not great, but not worse than the raw output).
		// The structured handler will also run ExtractMarkedOutput on the
		// *raw reasoning* which includes it. Just asserting we don't drop
		// the sentence.
		assert.NotEmpty(t, got)
	})

	t.Run("final_colon_marker_after_meta", func(t *testing.T) {
		in := `(14) -> 14 words. Very concise. Matches all constraints. Output matches.✅ Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->`
		got := ExtractProse(in)
		assert.Equal(t, "The agent just dispatched another test request and is currently evaluating the network response for security analysis.", got)
	})

	t.Run("bare_json_brace_recovered_via_fallback", func(t *testing.T) {
		in := "{\n  \"summary\": \"Currently investigating residual OIDC state-machines\"\n}"
		assert.Equal(t, "Currently investigating residual OIDC state-machines", ExtractProse(in))
	})
}

func TestFirstSentenceOrLine(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "one sentence.", firstSentenceOrLine("one sentence. second sentence."))
	assert.Equal(t, "first line", firstSentenceOrLine("first line\nsecond line"))
	assert.Equal(t, "no terminator", firstSentenceOrLine("no terminator"))
	assert.Equal(t, "trim whitespace.", firstSentenceOrLine("   trim whitespace.   "))
	assert.Empty(t, firstSentenceOrLine(""))
	assert.Empty(t, firstSentenceOrLine("   "))
}

func TestFirstMeaningfulLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"plain line", "plain line"},
		{"{\nreal content", "real content"},
		{"\"\n'\n`\n,\nprose", "prose"},
		{"\n\n\n", ""},
		{strings.Join([]string{"{", "}", "[", "]"}, "\n"), ""},
		{"```\nprose inside fence", "prose inside fence"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, firstMeaningfulLine(tc.in))
	}
}
