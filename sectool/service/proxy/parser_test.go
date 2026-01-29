package proxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    *RawHTTP1Request
		wantErr bool
	}{
		{
			name:  "simple_get",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Query:    "",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "path_with_query",
			input: "GET /api/users?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/api/users",
				Query:    "id=123&name=test",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "post_with_body",
			input: "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!",
			want: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/api/data",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Length", Value: "13"},
				},
				Body: []byte("Hello, World!"),
			},
		},
		{
			name:  "header_order_preserved",
			input: "GET / HTTP/1.1\r\nZebra: 1\r\nAlpha: 2\r\nMiddle: 3\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Zebra", Value: "1"},
					{Name: "Alpha", Value: "2"},
					{Name: "Middle", Value: "3"},
				},
			},
		},
		{
			name:  "casing_preserved",
			input: "GET / HTTP/1.1\r\ncontent-type: text/plain\r\nCONTENT-LENGTH: 0\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "CONTENT-LENGTH", Value: "0"},
				},
			},
		},
		{
			name:  "duplicate_headers",
			input: "GET / HTTP/1.1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nSet-Cookie: c=3\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Set-Cookie", Value: "a=1"},
					{Name: "Set-Cookie", Value: "b=2"},
					{Name: "Set-Cookie", Value: "c=3"},
				},
			},
		},
		{
			name:  "bare_lf_accepted",
			input: "GET / HTTP/1.1\nHost: example.com\n\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "whitespace_in_header_name",
			input: "GET / HTTP/1.1\r\nHeader : value\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Header ", Value: "value"},
				},
			},
		},
		{
			name:  "no_space_after_colon",
			input: "GET / HTTP/1.1\r\nHeader:value\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Header", Value: "value"},
				},
			},
		},
		{
			name:  "empty_header_value",
			input: "GET / HTTP/1.1\r\nEmpty: \r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Empty", Value: ""},
				},
			},
		},
		{
			name:  "obs_fold_continuation",
			input: "GET / HTTP/1.1\r\nLong-Header: first\r\n second\r\n\tthird\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Long-Header", Value: "first second third"},
				},
			},
		},
		{
			name:  "http_1_0",
			input: "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.0",
				Protocol: "http/1.0",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "proxy_form_url",
			input: "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "http://example.com/path",
				Query:    "q=1",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "proxy.local"},
				},
			},
		},
		{
			name:  "cl_te_conflict",
			input: "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nHello",
			want: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Length", Value: "5"},
					{Name: "Transfer-Encoding", Value: "chunked"},
				},
				Body: []byte{}, // chunked takes precedence but "Hello" isn't valid chunked
			},
		},
		{
			name:  "multiple_content_length",
			input: "GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Length", Value: "0"},
					{Name: "Content-Length", Value: "5"},
				},
			},
		},
		{
			name:    "empty_request",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid_request_line",
			input:   "INVALID\r\n\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRequest(strings.NewReader(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Method, got.Method)
			assert.Equal(t, tt.want.Path, got.Path)
			assert.Equal(t, tt.want.Query, got.Query)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assert.Equal(t, tt.want.Headers, got.Headers)
			// Handle nil vs empty slice for body
			if len(tt.want.Body) == 0 {
				assert.Empty(t, got.Body)
			} else {
				assert.Equal(t, tt.want.Body, got.Body)
			}
		})
	}
}

func TestParseRequest_ChunkedBody(t *testing.T) {
	t.Parallel()

	input := "POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\n" +
		"Hello\r\n" +
		"6\r\n" +
		"World!\r\n" +
		"0\r\n" +
		"\r\n"

	req, err := ParseRequest(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "/upload", req.Path)
	assert.Equal(t, []byte("HelloWorld!"), req.Body)
}

func TestParseRequest_ChunkedWithTrailers(t *testing.T) {
	t.Parallel()

	input := "POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Trailer: Checksum\r\n" +
		"\r\n" +
		"5\r\n" +
		"Hello\r\n" +
		"0\r\n" +
		"Checksum: abc123\r\n" +
		"\r\n"

	req, err := ParseRequest(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, []byte("Hello"), req.Body)
	assert.Contains(t, string(req.Trailers), "Checksum: abc123")
}

func TestParseResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		requestMethod string
		want          *RawHTTP1Response
		wantErr       bool
	}{
		{
			name:          "simple_200",
			input:         "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Length", Value: "5"},
				},
				Body: []byte("Hello"),
			},
		},
		{
			name:          "head_no_body",
			input:         "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
			requestMethod: "HEAD",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Length", Value: "1000"},
				},
			},
		},
		{
			name:          "204_no_body",
			input:         "HTTP/1.1 204 No Content\r\n\r\n",
			requestMethod: "DELETE",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 204,
				StatusText: "No Content",
				Headers:    []Header{},
			},
		},
		{
			name:          "304_no_body",
			input:         "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 304,
				StatusText: "Not Modified",
				Headers: []Header{
					{Name: "ETag", Value: "\"abc\""},
				},
			},
		},
		{
			name:          "header_casing_preserved",
			input:         "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nX-CUSTOM: value\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM", Value: "value"},
				},
			},
		},
		{
			name:          "empty_status_text",
			input:         "HTTP/1.1 200\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "",
				Headers:    []Header{},
			},
		},
		{
			name:          "http_1_0",
			input:         "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nBody",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.0",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Connection", Value: "close"},
				},
				Body: []byte("Body"),
			},
		},
		{
			name:          "chunked_response",
			input:         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Transfer-Encoding", Value: "chunked"},
				},
				Body: []byte("Hello"),
			},
		},
		{
			name:          "empty_response",
			input:         "",
			requestMethod: "GET",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseResponse(strings.NewReader(tt.input), tt.requestMethod)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.StatusCode, got.StatusCode)
			assert.Equal(t, tt.want.StatusText, got.StatusText)
			// Handle nil vs empty slice for headers
			if len(tt.want.Headers) == 0 {
				assert.Empty(t, got.Headers)
			} else {
				assert.Equal(t, tt.want.Headers, got.Headers)
			}
			// Handle nil vs empty slice for body
			if len(tt.want.Body) == 0 {
				assert.Empty(t, got.Body)
			} else {
				assert.Equal(t, tt.want.Body, got.Body)
			}
		})
	}
}

func TestSerialize_Request(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *RawHTTP1Request
		want string
	}{
		{
			name: "simple_get",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			want: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "with_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users",
				Query:   "id=123",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			want: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "with_body",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/data",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
			want: "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello",
		},
		{
			name: "preserves_casing",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM-HEADER", Value: "value"},
				},
			},
			want: "GET / HTTP/1.1\r\ncontent-type: text/plain\r\nX-CUSTOM-HEADER: value\r\n\r\n",
		},
		{
			name: "preserves_order",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Zebra", Value: "last"},
					{Name: "Alpha", Value: "first"},
					{Name: "Middle", Value: "middle"},
				},
			},
			want: "GET / HTTP/1.1\r\nZebra: last\r\nAlpha: first\r\nMiddle: middle\r\n\r\n",
		},
	}

	var buf bytes.Buffer // reuse to verify reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.req.Serialize(&buf)))
		})
	}
}

func TestSerialize_Response(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		resp *RawHTTP1Response
		want string
	}{
		{
			name: "simple_200",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
			want: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello",
		},
		{
			name: "no_status_text",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 204,
				Headers:    []Header{},
			},
			want: "HTTP/1.1 204\r\n\r\n",
		},
		{
			name: "preserves_header_casing",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM", Value: "value"},
				},
			},
			want: "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nX-CUSTOM: value\r\n\r\n",
		},
	}

	var buf bytes.Buffer // reuse to verify reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.resp.Serialize(&buf)))
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple_get",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:  "with_body",
			input: "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHello",
		},
		{
			name:  "multiple_headers",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: test\r\n\r\n",
		},
	}

	var buf bytes.Buffer // reuse to verify reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest(strings.NewReader(tt.input))
			require.NoError(t, err)

			assert.Equal(t, tt.input, string(req.Serialize(&buf)))
		})
	}
}

func TestParseRequest_LargeHeaderValue(t *testing.T) {
	t.Parallel()

	// Header value > 8KB
	largeValue := strings.Repeat("x", 10000)
	input := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: " + largeValue + "\r\n\r\n"

	req, err := ParseRequest(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, largeValue, req.GetHeader("X-Large"))
}

func TestParseRequest_InvalidHeaderName(t *testing.T) {
	t.Parallel()

	// Invalid characters in header name should be accepted (tolerant parsing)
	input := "GET / HTTP/1.1\r\nInvalid<Header>: value\r\n\r\n"

	req, err := ParseRequest(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "Invalid<Header>", req.Headers[0].Name)
	assert.Equal(t, "value", req.Headers[0].Value)
}

func TestParseRequest_ControlCharacters(t *testing.T) {
	t.Parallel()

	// Control characters in value should be preserved
	input := "GET / HTTP/1.1\r\nX-Test: value\twith\ttabs\r\n\r\n"

	req, err := ParseRequest(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "value\twith\ttabs", req.GetHeader("X-Test"))
}

func TestGetHeader(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "X-Custom", Value: "value1"},
			{Name: "x-custom", Value: "value2"},
		},
	}

	assert.Equal(t, "text/plain", req.GetHeader("content-type"))
	assert.Equal(t, "text/plain", req.GetHeader("Content-Type"))
	assert.Equal(t, "value1", req.GetHeader("X-Custom"))
	assert.Equal(t, "value1", req.GetHeader("x-custom"))
	assert.Empty(t, req.GetHeader("Missing"))
}

func TestSetHeader(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
		},
	}

	// Update existing
	req.SetHeader("Content-Type", "application/json")
	assert.Equal(t, "application/json", req.GetHeader("Content-Type"))

	// Add new
	req.SetHeader("X-New", "value")
	assert.Equal(t, "value", req.GetHeader("X-New"))
}

func TestRemoveHeader(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "X-Remove", Value: "value1"},
			{Name: "x-remove", Value: "value2"},
			{Name: "Keep", Value: "keep"},
		},
	}

	req.RemoveHeader("X-Remove")

	assert.Empty(t, req.GetHeader("X-Remove"))
	assert.Equal(t, "text/plain", req.GetHeader("Content-Type"))
	assert.Equal(t, "keep", req.GetHeader("Keep"))
	assert.Len(t, req.Headers, 2)
}

func TestSerialize_RemovesChunked(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
		Body: []byte("Hello"),
	}

	serialized := string(req.Serialize(bytes.NewBuffer(nil)))

	assert.NotContains(t, serialized, "Transfer-Encoding")
	assert.Contains(t, serialized, "Content-Length: 5")
}

func TestSerialize_Idempotent(t *testing.T) {
	t.Parallel()

	t.Run("request_with_chunked", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("test"),
		}

		first := req.Serialize(bytes.NewBuffer(nil))
		second := req.Serialize(bytes.NewBuffer(nil))
		third := req.Serialize(bytes.NewBuffer(nil))

		assert.Equal(t, first, second)
		assert.Equal(t, second, third)
		// Original headers should be unchanged
		assert.Len(t, req.Headers, 2)
		assert.Equal(t, "Transfer-Encoding", req.Headers[1].Name)
	})

	t.Run("response_with_chunked", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("test"),
		}

		first := resp.Serialize(bytes.NewBuffer(nil))
		second := resp.Serialize(bytes.NewBuffer(nil))

		assert.Equal(t, first, second)
		// Original headers should be unchanged
		assert.Len(t, resp.Headers, 1)
		assert.Equal(t, "Transfer-Encoding", resp.Headers[0].Name)
	})
}

func TestParseRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantMethod  string
		wantPath    string
		wantQuery   string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "standard",
			input:       "GET /path HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/path",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "with_query",
			input:       "POST /api?foo=bar HTTP/1.1",
			wantMethod:  "POST",
			wantPath:    "/api",
			wantQuery:   "foo=bar",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "proxy_form",
			input:       "GET http://example.com/path?q=1 HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "http://example.com/path",
			wantQuery:   "q=1",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "no_version",
			input:       "GET /",
			wantMethod:  "GET",
			wantPath:    "/",
			wantVersion: "HTTP/1.1",
		},
		{
			name:    "invalid",
			input:   "INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path, query, version, err := parseRequestLine([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantPath, path)
			assert.Equal(t, tt.wantQuery, query)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestParseStatusLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantCode    int
		wantText    string
		wantErr     bool
	}{
		{
			name:        "standard",
			input:       "HTTP/1.1 200 OK",
			wantVersion: "HTTP/1.1",
			wantCode:    200,
			wantText:    "OK",
		},
		{
			name:        "no_reason",
			input:       "HTTP/1.1 204",
			wantVersion: "HTTP/1.1",
			wantCode:    204,
			wantText:    "",
		},
		{
			name:        "multi_word_reason",
			input:       "HTTP/1.1 404 Not Found",
			wantVersion: "HTTP/1.1",
			wantCode:    404,
			wantText:    "Not Found",
		},
		{
			name:    "invalid_code",
			input:   "HTTP/1.1 ABC",
			wantErr: true,
		},
		{
			name:    "too_short",
			input:   "HTTP/1.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, code, text, err := parseStatusLine([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantText, text)
		})
	}
}

func TestReadChunkedBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantBody     string
		wantTrailers string
	}{
		{
			name:     "simple",
			input:    "5\r\nHello\r\n0\r\n\r\n",
			wantBody: "Hello",
		},
		{
			name:     "multiple_chunks",
			input:    "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n",
			wantBody: "Hello World",
		},
		{
			name:         "with_trailers",
			input:        "5\r\nHello\r\n0\r\nChecksum: abc\r\n\r\n",
			wantBody:     "Hello",
			wantTrailers: "Checksum: abc\r\n",
		},
		{
			name:     "chunk_extensions",
			input:    "5;ext=val\r\nHello\r\n0\r\n\r\n",
			wantBody: "Hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader([]byte(tt.input)))
			body, trailers, err := readChunkedBody(br)
			require.NoError(t, err)

			assert.Equal(t, tt.wantBody, string(body))
			assert.Equal(t, tt.wantTrailers, string(trailers))
		})
	}
}
