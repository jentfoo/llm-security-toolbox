package service

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileSearchPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pattern   string
		input     string
		wantMatch bool
		wantNote  string
	}{
		{
			name:      "valid_regex",
			pattern:   `token=[a-f0-9]+`,
			input:     "token=abc123",
			wantMatch: true,
		},
		{
			name:      "valid_regex_no_match",
			pattern:   `token=[a-f0-9]+`,
			input:     "nothing here",
			wantMatch: false,
		},
		{
			name:      "invalid_regex_fallback",
			pattern:   `[invalid`,
			input:     "text with [invalid inside",
			wantMatch: true,
			wantNote:  `invalid regex "[invalid", treated as literal`,
		},
		{
			name:      "literal_string",
			pattern:   "plain text",
			input:     "some plain text here",
			wantMatch: true,
		},
		// Double-escaped patterns: LLM agents often over-escape
		{
			name:      "double_escaped_dot",
			pattern:   `www\\.google\\.com`,
			input:     "https://www.google.com/",
			wantMatch: true,
			wantNote:  `pattern had double-escaped regex metacharacters, auto-corrected to "www\\.google\\.com"`,
		},
		{
			name:      "double_escaped_star",
			pattern:   `Accept: \\*/\\*`,
			input:     "Accept: */*",
			wantMatch: true,
			wantNote:  `pattern had double-escaped regex metacharacters, auto-corrected to "Accept: \\*/\\*"`,
		},
		{
			name:      "double_escaped_shorthand",
			pattern:   `\\d+\\.\\d+`,
			input:     "version 1.23",
			wantMatch: true,
			wantNote:  `pattern had double-escaped regex metacharacters, auto-corrected to "\\d+\\.\\d+"`,
		},
		{
			name:      "correct_single_escape",
			pattern:   `www\.google\.com`,
			input:     "https://www.google.com/",
			wantMatch: true,
		},
		{
			name:      "mixed_correct_and_double",
			pattern:   `www\\.google\.com`,
			input:     "https://www.google.com/",
			wantMatch: true,
			wantNote:  `pattern had double-escaped regex metacharacters, auto-corrected to "www\\.google\\.com"`,
		},
		{
			name:      "unescaped_dot_wildcard",
			pattern:   `www.google.com`,
			input:     "https://www.google.com/",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, note := compileSearchPattern(tt.pattern, false)
			require.NotNil(t, re)
			assert.Equal(t, tt.wantNote, note)
			assert.Equal(t, tt.wantMatch, re.MatchString(tt.input))
		})
	}

	t.Run("case_insensitive", func(t *testing.T) {
		re, note := compileSearchPattern(`Set-Cookie`, true)
		require.NotNil(t, re)
		assert.Empty(t, note)
		assert.True(t, re.MatchString("set-cookie: session=abc"))
		assert.True(t, re.MatchString("SET-COOKIE: session=abc"))
		assert.True(t, re.MatchString("Set-Cookie: session=abc"))
	})

	t.Run("case_insensitive_invalid_regex", func(t *testing.T) {
		re, note := compileSearchPattern(`[invalid`, true)
		require.NotNil(t, re)
		assert.Equal(t, `invalid regex "[invalid", treated as literal`, note)
		assert.True(t, re.MatchString("text with [INVALID inside"))
	})

	t.Run("user_provided_case_insensitive", func(t *testing.T) {
		// User already provides (?i) and caseInsensitive=true; double prefix is harmless
		re, note := compileSearchPattern(`(?i)Set-Cookie`, true)
		require.NotNil(t, re)
		assert.Empty(t, note)
		assert.True(t, re.MatchString("set-cookie: session=abc"))
		assert.True(t, re.MatchString("SET-COOKIE: session=abc"))
	})

	t.Run("user_provided_case_insensitive_body", func(t *testing.T) {
		// User provides (?i) for body search where caseInsensitive=false
		re, note := compileSearchPattern(`(?i)password`, false)
		require.NotNil(t, re)
		assert.Empty(t, note)
		assert.True(t, re.MatchString("PASSWORD"))
		assert.True(t, re.MatchString("password"))
	})
}

func TestExtractMatchContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		pattern      string
		data         string
		maxMatches   int
		want         string // exact expected output for deterministic cases
		wantContains string // used when exact output is too noisy to pin
		wantEmpty    bool
	}{
		{
			name:    "single_match",
			pattern: "needle",
			data:    "haystack needle haystack",
			want:    "haystack needle haystack",
		},
		{
			name:    "multiple_matches",
			pattern: "find",
			data:    "find me once and find me twice",
			want:    "find me once and find me twice\n----\nfind me once and find me twice",
		},
		{
			name:         "truncation",
			pattern:      "x",
			data:         strings.Repeat("x ", 20),
			maxMatches:   3,
			wantContains: "[truncated: more matches]",
		},
		{
			name:      "no_match",
			pattern:   "missing",
			data:      "nothing here",
			wantEmpty: true,
		},
		{
			name:      "binary_data",
			pattern:   "test",
			data:      string([]byte{0xff, 0xfe, 't', 'e', 's', 't'}),
			wantEmpty: true,
		},
		{
			name:    "context_ellipsis",
			pattern: "TARGET",
			data:    strings.Repeat("a", 100) + "TARGET" + strings.Repeat("b", 100),
			want:    "..." + strings.Repeat("a", 80) + "TARGET" + strings.Repeat("b", 80) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, _ := compileSearchPattern(tt.pattern, false)
			maxM := tt.maxMatches
			if maxM == 0 {
				maxM = maxMatchesPerSection
			}
			result := extractMatchContext(re, []byte(tt.data), maxM)
			switch {
			case tt.wantEmpty:
				assert.Empty(t, result)
			case tt.wantContains != "":
				assert.Contains(t, result, tt.wantContains)
			default:
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestUnescapeLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "no_backslash", in: "hello world", want: "hello world"},
		{name: "carriage_return_newline", in: "a\\r\\nb", want: "a\r\nb"},
		{name: "tab", in: "x\\ty", want: "x\ty"},
		{name: "unknown_escape_kept", in: "a\\zb", want: "a\\zb"},
		{name: "trailing_backslash", in: "end\\", want: "end\\"},
		{name: "mixed", in: "\\tvalue\\r", want: "\tvalue\r"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, unescapeLiteral(tt.in))
		})
	}
}

func TestMatchesFlowSearch(t *testing.T) {
	t.Parallel()

	makeHTTP := func(headers, body string) []byte {
		return []byte(headers + "\r\n\r\n" + body)
	}

	req := makeHTTP("GET / HTTP/1.1\r\nHost: example.com\r\nX-Token: secret123", "request body here")
	resp := makeHTTP("HTTP/1.1 200 OK\r\nContent-Type: text/html", "response body here")

	tests := []struct {
		name     string
		request  []byte
		response []byte
		headerRe *regexp.Regexp
		bodyRe   *regexp.Regexp
		want     bool
	}{
		{
			name:     "nil_regexes",
			request:  req,
			response: resp,
			want:     true,
		},
		{
			name:     "header_match_request",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`secret123`),
			want:     true,
		},
		{
			name:     "header_match_response",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`text/html`),
			want:     true,
		},
		{
			name:     "header_no_match",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`missing-header`),
			want:     false,
		},
		{
			name:     "body_match_request",
			request:  req,
			response: resp,
			bodyRe:   regexp.MustCompile(`request body`),
			want:     true,
		},
		{
			name:     "body_match_response",
			request:  req,
			response: resp,
			bodyRe:   regexp.MustCompile(`response body`),
			want:     true,
		},
		{
			name:     "body_no_match",
			request:  req,
			response: resp,
			bodyRe:   regexp.MustCompile(`not found anywhere`),
			want:     false,
		},
		{
			name:     "header_and_body_both_match",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`example\.com`),
			bodyRe:   regexp.MustCompile(`response body`),
			want:     true,
		},
		{
			name:     "header_matches_body_does_not",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`example\.com`),
			bodyRe:   regexp.MustCompile(`missing`),
			want:     true, // OR semantics: header match suffices
		},
		{
			name:     "binary_body_skipped",
			request:  makeHTTP("GET / HTTP/1.1\r\nHost: test", string([]byte{0xff, 0xfe, 0x00})),
			response: makeHTTP("HTTP/1.1 200 OK", string([]byte{0xff, 0xfe, 0x00})),
			bodyRe:   regexp.MustCompile(`anything`),
			want:     false,
		},
		{
			name:     "empty_request_response",
			request:  nil,
			response: nil,
			headerRe: regexp.MustCompile(`test`),
			want:     false,
		},
		{
			name:     "case_insensitive_header",
			request:  req,
			response: resp,
			headerRe: regexp.MustCompile(`(?i)content-type`),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchesFlowSearch(tt.request, tt.response, tt.headerRe, tt.bodyRe))
		})
	}
}

func TestParseScopeSet(t *testing.T) {
	t.Parallel()

	allScopes := map[string]bool{
		"request_headers":  true,
		"request_body":     true,
		"response_headers": true,
		"response_body":    true,
	}

	tests := []struct {
		name    string
		scope   string
		want    map[string]bool
		wantErr bool
	}{
		{
			name:  "empty_returns_all",
			scope: "",
			want:  allScopes,
		},
		{
			name:  "all_keyword",
			scope: "all",
			want:  allScopes,
		},
		{
			name:  "single_scope",
			scope: "response_body",
			want:  map[string]bool{"response_body": true},
		},
		{
			name:  "multiple_scopes",
			scope: "request_headers,response_body",
			want:  map[string]bool{"request_headers": true, "response_body": true},
		},
		{
			name:  "whitespace_trimmed",
			scope: " response_body , request_body ",
			want:  map[string]bool{"response_body": true, "request_body": true},
		},
		{
			name:    "invalid_value",
			scope:   "invalid",
			wantErr: true,
		},
		{
			name:    "mixed_valid_invalid",
			scope:   "response_body,bogus",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseScopeSet(tt.scope)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestUnDoubleEscapeRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no_escapes", "Accept: text/html", "Accept: text/html"},
		{"single_escape_preserved", `Accept: \*/\*`, `Accept: \*/\*`},
		{"double_escape_collapsed", `Accept: \\*/\\*`, `Accept: \*/\*`},
		{"double_escape_dot", `Host: example\\.com`, `Host: example\.com`},
		{"double_escape_plus", `count: \\d\\+`, `count: \d\+`},
		{"shorthand_classes", `\\d{3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}`, `\d{3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`},
		{"word_whitespace", `\\w+\\s+\\b`, `\w+\s+\b`},
		{"literal_backslash_kept", `path: \\\\server`, `path: \\\\server`},
		{"mixed", `\\. and \. ok`, `\. and \. ok`},
		{"empty", "", ""},
		{"trailing_backslash", `test\\`, `test\\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, unDoubleEscapeRegex(tt.in))
		})
	}
}
