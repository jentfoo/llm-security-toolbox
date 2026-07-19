package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testHeader struct {
	Name  string
	Value string
	Raw   []byte
}

func TestReplaceCaseInsensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		match   string
		replace string
		want    string
	}{
		{name: "empty_match", input: "abc", match: "", replace: "x", want: "abc"},
		{name: "ascii_fold", input: "Foo FOO foo", match: "foo", replace: "bar", want: "bar bar bar"},
		{name: "multi_occurrence_grow", input: "AaAa", match: "a", replace: "bb", want: "bbbbbbbb"},
		{name: "kelvin_before_match", input: "K foo", match: "foo", replace: "x", want: "K x"},
		{name: "latin_a_stroke_before_match", input: "Ⱥ foo", match: "foo", replace: "x", want: "Ⱥ x"},
		{name: "nonascii_case_sensitive", input: "ⱥ", match: "Ⱥ", replace: "x", want: "ⱥ"},
		{name: "no_match", input: "hello", match: "xyz", replace: "q", want: "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(ReplaceCaseInsensitive([]byte(tt.input), tt.match, tt.replace)))
		})
	}
}

func TestRenderHeaders(t *testing.T) {
	t.Parallel()

	hs := []testHeader{{Name: "Host", Value: "example.com"}, {Name: "X-Empty", Value: ""}}
	got := RenderHeaders(hs, func(h testHeader) string { return h.Name }, func(h testHeader) string { return h.Value })
	assert.Equal(t, "Host: example.com\r\nX-Empty: \r\n", string(got))
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	mk := func(name, value string, raw []byte) testHeader {
		return testHeader{Name: name, Value: value, Raw: raw}
	}

	tests := []struct {
		name  string
		input string
		want  []testHeader
	}{
		{
			name:  "single_header",
			input: "Content-Type: text/plain\r\n",
			want:  []testHeader{{Name: "Content-Type", Value: "text/plain", Raw: []byte("Content-Type: text/plain")}},
		},
		{
			name:  "value_whitespace_verbatim",
			input: "X-Test:   spaced   \r\n",
			want:  []testHeader{{Name: "X-Test", Value: "  spaced   ", Raw: []byte("X-Test:   spaced   ")}},
		},
		{
			name:  "colon_less_line_kept",
			input: "Malformed\r\nValid: v\r\n",
			want: []testHeader{
				{Name: "Malformed", Value: "", Raw: []byte("Malformed")},
				{Name: "Valid", Value: "v", Raw: []byte("Valid: v")},
			},
		},
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseHeaders([]byte(tt.input), mk))
		})
	}
}
