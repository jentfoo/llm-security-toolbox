package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "standard_request",
			raw:  []byte("POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "POST",
		},
		{
			name: "bare_lf",
			raw:  []byte("PUT /path HTTP/1.1\nHost: example.com\n\n"),
			want: "PUT",
		},
		{
			name: "empty_input",
			raw:  nil,
			want: "GET",
		},
		{
			name: "no_space_in_line",
			raw:  []byte("INVALID\r\n"),
			want: "INVALID",
		},
		{
			name: "method_only",
			raw:  []byte("DELETE"),
			want: "DELETE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExtractMethod(tt.raw))
		})
	}
}

func TestGroupHeaderEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []string
		want    []HeaderGroup
	}{
		{
			name:    "single_entry",
			entries: []string{"Host: example.com"},
			want:    []HeaderGroup{{Key: "host", Entries: []string{"Host: example.com"}}},
		},
		{
			name:    "duplicate_name",
			entries: []string{"TE: chunked", "TE: identity"},
			want:    []HeaderGroup{{Key: "te", Entries: []string{"TE: chunked", "TE: identity"}}},
		},
		{
			name:    "mixed",
			entries: []string{"Host: new.com", "TE: chunked", "TE: identity", "X-Custom: val"},
			want: []HeaderGroup{
				{Key: "host", Entries: []string{"Host: new.com"}},
				{Key: "te", Entries: []string{"TE: chunked", "TE: identity"}},
				{Key: "x-custom", Entries: []string{"X-Custom: val"}},
			},
		},
		{
			name:    "case_insensitive",
			entries: []string{"host: a", "HOST: b"},
			want:    []HeaderGroup{{Key: "host", Entries: []string{"host: a", "HOST: b"}}},
		},
		{
			name:    "invalid_skipped",
			entries: []string{"no-colon", "Valid: yes"},
			want:    []HeaderGroup{{Key: "valid", Entries: []string{"Valid: yes"}}},
		},
		{
			name:    "empty",
			entries: nil,
			want:    []HeaderGroup{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GroupHeaderEntries(tt.entries)
			if len(tt.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsHeader(t *testing.T) {
	t.Parallel()

	entries := []string{"Content-Type: text/html", "Authorization: Bearer tok"}

	assert.True(t, ContainsHeader(entries, "Content-Type"))
	assert.True(t, ContainsHeader(entries, "content-type"))
	assert.True(t, ContainsHeader(entries, "AUTHORIZATION"))
	assert.False(t, ContainsHeader(entries, "Content-Length"))
	assert.False(t, ContainsHeader(nil, "anything"))
}

func TestSendError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       int
		message    string
		wantStatus string
		wantBody   string
	}{
		{"bad_request", 400, "Bad Request", "400 Bad Request", "Bad Request\n"},
		{"bad_gateway", 502, "Bad Gateway", "502 Bad Gateway", "Bad Gateway\n"},
		{"internal_error", 500, "Internal Server Error", "500 Internal Server Error", "Internal Server Error\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			go sendError(serverConn, tt.code, tt.message)

			buf := make([]byte, 1024)
			n, err := clientConn.Read(buf)
			require.NoError(t, err)

			response := string(buf[:n])
			assert.Contains(t, response, "HTTP/1.1 "+tt.wantStatus)
			assert.Contains(t, response, "Content-Type: text/plain")
			assert.Contains(t, response, "Connection: close")
			assert.Contains(t, response, tt.wantBody)
		})
	}
}
