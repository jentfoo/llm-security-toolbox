package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *RawHTTP1Request
		wantErr string
	}{
		{
			name: "valid_get",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "valid_post",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/users",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
				},
				Body: []byte(`{"name":"test"}`),
			},
			wantErr: "",
		},
		{
			name:    "nil_request",
			req:     nil,
			wantErr: "nil request",
		},
		{
			name: "empty_method",
			req: &RawHTTP1Request{
				Method:  "",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "empty method",
		},
		{
			name: "method_with_space",
			req: &RawHTTP1Request{
				Method:  "GET POST",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "invalid method characters",
		},
		{
			name: "method_with_control",
			req: &RawHTTP1Request{
				Method:  "GET\x00",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "invalid method characters",
		},
		{
			name: "empty_path",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "",
				Version: "HTTP/1.1",
			},
			wantErr: "empty path",
		},
		{
			name: "invalid_version",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/2.0",
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "http_1_0_valid",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.0",
			},
			wantErr: "",
		},
		{
			name: "nul_in_header_name",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "X-Bad\x00Header", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "nul_in_header_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "X-Header", Value: "bad\x00value"},
				},
			},
			wantErr: "NUL byte in header value",
		},
		{
			name: "path_with_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users?id=123",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "custom_method",
			req: &RawHTTP1Request{
				Method:  "CUSTOMMETHOD",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "method_with_tab",
			req: &RawHTTP1Request{
				Method:  "GET\t",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "invalid method characters",
		},
		{
			name: "path_with_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\x00inject",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "multiple_headers",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Accept", Value: "*/*"},
					{Name: "User-Agent", Value: "test"},
				},
			},
			wantErr: "",
		},
		{
			name: "empty_headers_slice",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{},
			},
			wantErr: "",
		},
		{
			name: "lowercase_method_valid",
			req: &RawHTTP1Request{
				Method:  "get",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "method_special_chars_only",
			req: &RawHTTP1Request{
				Method:  "!#$%",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "path_query_and_fragment",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users?id=1#section",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "path_only_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "?query=1",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "path_encoded_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path%00inject",
				Version: "HTTP/1.1",
			},
			wantErr: "",
		},
		{
			name: "header_value_with_tab",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "X-Header", Value: "value\twith\ttabs"},
				},
			},
			wantErr: "",
		},
		{
			name: "header_name_only_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "\x00", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "http_2_invalid_for_request",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/2",
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "http_version_with_spaces",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/ 1.1",
			},
			wantErr: "invalid HTTP version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		resp    *RawHTTP1Response
		wantErr string
	}{
		{
			name: "valid_response",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
			},
			wantErr: "",
		},
		{
			name:    "nil_response",
			resp:    nil,
			wantErr: "nil response",
		},
		{
			name: "invalid_version",
			resp: &RawHTTP1Response{
				Version:    "INVALID",
				StatusCode: 200,
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "status_code_too_low",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 99,
			},
			wantErr: "invalid status code",
		},
		{
			name: "status_code_too_high",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 600,
			},
			wantErr: "invalid status code",
		},
		{
			name: "nul_in_header_name",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "X-Bad\x00", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "nul_in_header_value",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "X-Header", Value: "bad\x00value"},
				},
			},
			wantErr: "NUL byte in header value",
		},
		{
			name: "lowercase_http_version",
			resp: &RawHTTP1Response{
				Version:    "http/1.1",
				StatusCode: 200,
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "status_101_switching_protocols",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 101,
				StatusText: "Switching Protocols",
			},
			wantErr: "",
		},
		{
			name: "status_301_redirect",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 301,
				StatusText: "Moved Permanently",
			},
			wantErr: "",
		},
		{
			name: "status_500_error",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 500,
				StatusText: "Internal Server Error",
			},
			wantErr: "",
		},
		{
			name: "empty_status_text",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "",
			},
			wantErr: "",
		},
		{
			name: "http_1_0_response",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.0",
				StatusCode: 200,
				StatusText: "OK",
			},
			wantErr: "",
		},
		{
			name: "http_2_valid_for_response",
			resp: &RawHTTP1Response{
				Version:    "HTTP/2",
				StatusCode: 200,
				StatusText: "OK",
			},
			wantErr: "",
		},
		{
			name: "http_2_0_valid_for_response",
			resp: &RawHTTP1Response{
				Version:    "HTTP/2.0",
				StatusCode: 200,
				StatusText: "OK",
			},
			wantErr: "",
		},
		{
			name: "empty_headers_slice",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers:    []Header{},
			},
			wantErr: "",
		},
		{
			name: "nil_headers_slice",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers:    nil,
			},
			wantErr: "",
		},
		{
			name: "status_code_zero",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 0,
			},
			wantErr: "invalid status code",
		},
		{
			name: "status_code_negative",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: -1,
			},
			wantErr: "invalid status code",
		},
		{
			name: "status_text_with_numbers",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 404,
				StatusText: "Not Found 2024",
			},
			wantErr: "",
		},
		{
			name: "status_text_with_tabs",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK\tSuccess",
			},
			wantErr: "",
		},
		{
			name: "header_name_mixed_case",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "CoNtEnT-TyPe", Value: "text/html"},
					{Name: "x-custom-header", Value: "value"},
					{Name: "X-UPPERCASE", Value: "value"},
				},
			},
			wantErr: "",
		},
		{
			name: "header_name_only_nul",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "\x00", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "header_value_empty",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "X-Empty", Value: ""},
				},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResponse(tt.resp)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCheckLineEndings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantMsg string
	}{
		{
			name:    "crlf_only",
			input:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMsg: "",
		},
		{
			name:    "bare_lf_only",
			input:   "GET / HTTP/1.1\nHost: example.com\n\n",
			wantMsg: "using LF instead of CRLF",
		},
		{
			name:    "mixed_endings",
			input:   "GET / HTTP/1.1\r\nHost: example.com\n\r\n",
			wantMsg: "mixed line endings",
		},
		{
			name:    "bare_cr",
			input:   "GET / HTTP/1.1\rHost: example.com\r\n\r\n",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "empty_input",
			input:   "",
			wantMsg: "",
		},
		{
			name:    "no_newlines",
			input:   "GET / HTTP/1.1",
			wantMsg: "",
		},
		{
			name:    "crlf_at_end_only",
			input:   "GET / HTTP/1.1\r\n",
			wantMsg: "",
		},
		{
			name:    "multiple_crlf",
			input:   "\r\n\r\n\r\n",
			wantMsg: "",
		},
		{
			name:    "only_cr",
			input:   "\r",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "cr_not_followed_by_lf",
			input:   "GET / HTTP/1.1\r Host: example.com\r\n",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "alternating_crlf_lf",
			input:   "Line1\r\nLine2\nLine3\r\n",
			wantMsg: "mixed line endings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckLineEndings([]byte(tt.input))

			if tt.wantMsg == "" {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, tt.wantMsg)
			}
		})
	}
}

func TestIsValidToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid_method",
			input: "GET",
			want:  true,
		},
		{
			name:  "valid_custom_header",
			input: "X-CUSTOM",
			want:  true,
		},
		{
			name:  "with_numbers",
			input: "HTTP2",
			want:  true,
		},
		{
			name:  "special_chars",
			input: "!#$%&'*+-.^_`|~",
			want:  true,
		},
		{
			name:  "empty_string",
			input: "",
			want:  false,
		},
		{
			name:  "with_space",
			input: "GET POST",
			want:  false,
		},
		{
			name:  "with_colon",
			input: "Content-Type:",
			want:  false,
		},
		{
			name:  "with_slash",
			input: "HTTP/1.1",
			want:  false,
		},
		{
			name:  "with_nul",
			input: "GET\x00",
			want:  false,
		},
		{
			name:  "with_tab",
			input: "GET\t",
			want:  false,
		},
		{
			name:  "tilde_allowed",
			input: "X-Custom~Header",
			want:  true,
		},
		{
			name:  "caret_allowed",
			input: "X^Custom",
			want:  true,
		},
		{
			name:  "backtick_allowed",
			input: "X`Custom",
			want:  true,
		},
		{
			name:  "at_sign_not_allowed",
			input: "X@Custom",
			want:  false,
		},
		{
			name:  "brackets_not_allowed",
			input: "X[Custom]",
			want:  false,
		},
		{
			name:  "quotes_not_allowed",
			input: "X\"Custom\"",
			want:  false,
		},
		{
			name:  "parentheses_not_allowed",
			input: "X(Custom)",
			want:  false,
		},
		{
			name:  "single_char",
			input: "X",
			want:  true,
		},
		{
			name:  "all_digits",
			input: "12345",
			want:  true,
		},
		{
			name:  "del_char_not_allowed",
			input: "X\x7FCustom",
			want:  false,
		},
		{
			name:  "high_ascii_not_allowed",
			input: "X\x80Custom",
			want:  false,
		},
		{
			name:  "newline_not_allowed",
			input: "X\nCustom",
			want:  false,
		},
		{
			name:  "carriage_return_not_allowed",
			input: "X\rCustom",
			want:  false,
		},
		{
			name:  "form_feed_not_allowed",
			input: "X\fCustom",
			want:  false,
		},
		{
			name:  "hyphen_allowed_middle",
			input: "Content-Type",
			want:  true,
		},
		{
			name:  "underscore_allowed",
			input: "Content_Type",
			want:  true,
		},
		{
			name:  "period_allowed",
			input: "X.Custom",
			want:  true,
		},
		{
			name:  "semicolon_not_allowed",
			input: "X;Custom",
			want:  false,
		},
		{
			name:  "equals_not_allowed",
			input: "X=Custom",
			want:  false,
		},
		{
			name:  "comma_not_allowed",
			input: "X,Custom",
			want:  false,
		},
		{
			name:  "brace_not_allowed",
			input: "X{Custom}",
			want:  false,
		},
		{
			name:  "backslash_not_allowed",
			input: "X\\Custom",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidToken(tt.input))
		})
	}
}

func TestValidateRequestCRLFInjection(t *testing.T) {
	t.Parallel()

	// CRLF injection tests - these should parse but may be flagged by validation
	tests := []struct {
		name    string
		req     *RawHTTP1Request
		wantErr string
	}{
		{
			name: "method_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET\r\nX-Injected: true",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "invalid method characters",
		},
		{
			name: "path_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\r\nX-Inject: val",
				Version: "HTTP/1.1",
			},
			wantErr: "", // paths are allowed to contain unusual characters for testing
		},
		{
			name: "version_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1\r\nX-Inject: val",
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "header_value_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "X-Header", Value: "value\r\nX-Inject: evil"},
				},
			},
			wantErr: "", // header values can contain unusual chars for testing
		},
		{
			name: "multiple_nul_in_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "X-Header", Value: "a\x00b\x00c"},
				},
			},
			wantErr: "NUL byte in header value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateResponseCRLFInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		resp    *RawHTTP1Response
		wantErr string
	}{
		{
			name: "version_without_http_prefix",
			resp: &RawHTTP1Response{
				Version:    "XTTP/1.1",
				StatusCode: 200,
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "multiple_nul_in_header",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				Headers: []Header{
					{Name: "X-Header", Value: "a\x00b\x00c"},
				},
			},
			wantErr: "NUL byte in header value",
		},
		{
			name: "version_with_crlf_passes",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1\r\nX-Inject: val",
				StatusCode: 200,
			},
			wantErr: "", // Version validation only checks HTTP/ prefix for responses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResponse(tt.resp)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseValidationIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantParse bool
		wantValid bool
	}{
		{
			name:      "invalid_method_chars",
			input:     "GET<inject> / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantParse: true,
			wantValid: false,
		},
		{
			name:      "nul_in_header",
			input:     "GET / HTTP/1.1\r\nX-Header: val\x00ue\r\n\r\n",
			wantParse: true,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parseRequest(strings.NewReader(tt.input))

			if tt.wantParse {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}

			err = validateRequest(req)
			if tt.wantValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
