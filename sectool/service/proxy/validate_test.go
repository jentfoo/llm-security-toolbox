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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidToken(tt.input))
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
