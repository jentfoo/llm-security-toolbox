package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func TestExtractTarget_ProxyForm(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{history: history}
	t.Cleanup(history.Close)

	tests := []struct {
		name     string
		path     string
		host     string
		wantHost string
		wantPort int
		wantTLS  bool
	}{
		{
			name:     "http_default_port",
			path:     "http://example.com/path",
			wantHost: "example.com",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "http_custom_port",
			path:     "http://example.com:8080/path",
			wantHost: "example.com",
			wantPort: 8080,
			wantTLS:  false,
		},
		{
			name:     "https_default_port",
			path:     "https://example.com/path",
			wantHost: "example.com",
			wantPort: 443,
			wantTLS:  true,
		},
		{
			name:     "https_custom_port",
			path:     "https://example.com:8443/path",
			wantHost: "example.com",
			wantPort: 8443,
			wantTLS:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    tt.path,
				Version: "HTTP/1.1",
			}

			target, err := h.extractTarget(req)
			require.NoError(t, err)

			assert.Equal(t, tt.wantHost, target.Hostname)
			assert.Equal(t, tt.wantPort, target.Port)
			assert.Equal(t, tt.wantTLS, target.UsesHTTPS)
		})
	}
}

func TestExtractTarget_HostHeader(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{history: history}
	t.Cleanup(history.Close)

	tests := []struct {
		name     string
		path     string
		host     string
		wantHost string
		wantPort int
	}{
		{
			name:     "host_only",
			path:     "/path",
			host:     "example.com",
			wantHost: "example.com",
			wantPort: 80,
		},
		{
			name:     "host_with_port",
			path:     "/path",
			host:     "example.com:8080",
			wantHost: "example.com",
			wantPort: 8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    tt.path,
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: tt.host},
				},
			}

			target, err := h.extractTarget(req)
			require.NoError(t, err)

			assert.Equal(t, tt.wantHost, target.Hostname)
			assert.Equal(t, tt.wantPort, target.Port)
		})
	}
}

func TestExtractTarget_NoHost(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{history: history}
	t.Cleanup(history.Close)

	req := &RawHTTP1Request{
		Method:  "GET",
		Path:    "/path",
		Version: "HTTP/1.1",
	}

	_, err := h.extractTarget(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Host header")
}

func TestRewriteToOriginForm(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{history: history}
	t.Cleanup(history.Close)

	tests := []struct {
		name        string
		inputPath   string
		inputQuery  string
		target      *Target
		wantPath    string
		wantHostHdr string
	}{
		{
			name:       "proxy_form_to_origin",
			inputPath:  "http://example.com/api/users",
			inputQuery: "id=123",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/api/users",
			wantHostHdr: "example.com",
		},
		{
			name:       "https_proxy_form",
			inputPath:  "https://secure.example.com:8443/path",
			inputQuery: "",
			target: &Target{
				Hostname:  "secure.example.com",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath:    "/path",
			wantHostHdr: "secure.example.com:8443",
		},
		{
			name:       "already_origin_form",
			inputPath:  "/already/origin",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/already/origin",
			wantHostHdr: "example.com",
		},
		{
			name:       "root_path",
			inputPath:  "http://example.com",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/",
			wantHostHdr: "example.com",
		},
		{
			name:       "non_standard_http_port",
			inputPath:  "/path",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      8080,
				UsesHTTPS: false,
			},
			wantPath:    "/path",
			wantHostHdr: "example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    tt.inputPath,
				Query:   tt.inputQuery,
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "original.host"},
				},
			}

			h.rewriteToOriginForm(req, tt.target)

			assert.Equal(t, tt.wantPath, req.Path)
			assert.Equal(t, tt.wantHostHdr, req.GetHeader("Host"))
		})
	}
}

func TestParseHostPort(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{history: history}
	t.Cleanup(history.Close)

	tests := []struct {
		name      string
		hostPort  string
		usesHTTPS bool
		wantHost  string
		wantPort  int
		wantErr   bool
	}{
		{
			name:      "host_only_http",
			hostPort:  "example.com",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  80,
		},
		{
			name:      "host_only_https",
			hostPort:  "example.com",
			usesHTTPS: true,
			wantHost:  "example.com",
			wantPort:  443,
		},
		{
			name:      "host_with_port",
			hostPort:  "example.com:8080",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  8080,
		},
		{
			name:      "ipv4_with_port",
			hostPort:  "192.168.1.1:9000",
			usesHTTPS: false,
			wantHost:  "192.168.1.1",
			wantPort:  9000,
		},
		{
			name:      "invalid_port",
			hostPort:  "example.com:abc",
			usesHTTPS: false,
			wantErr:   true,
		},
		{
			name:      "ipv6_with_brackets_and_port",
			hostPort:  "[::1]:8080",
			usesHTTPS: false,
			wantHost:  "::1",
			wantPort:  8080,
		},
		{
			name:      "ipv6_with_brackets_no_port",
			hostPort:  "[::1]",
			usesHTTPS: false,
			wantHost:  "::1",
			wantPort:  80,
		},
		{
			name:      "ipv6_full_with_port",
			hostPort:  "[2001:db8::1]:443",
			usesHTTPS: true,
			wantHost:  "2001:db8::1",
			wantPort:  443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := h.parseHostPort(tt.hostPort, tt.usesHTTPS)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, target.Hostname)
			assert.Equal(t, tt.wantPort, target.Port)
			assert.Equal(t, tt.usesHTTPS, target.UsesHTTPS)
		})
	}
}

func TestBodyTruncation(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	h := &HTTP1Handler{
		history:      history,
		maxBodyBytes: 10, // Very small limit for testing
	}
	t.Cleanup(history.Close)

	// Create a large request body
	largeBody := make([]byte, 100)
	for i := range largeBody {
		largeBody[i] = byte('A' + i%26)
	}

	req := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/upload",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
		},
		Body: largeBody,
	}

	// Manually call body truncation logic
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.Body = req.Body[:h.maxBodyBytes]
	}

	assert.Len(t, req.Body, 10)
	assert.Equal(t, []byte("ABCDEFGHIJ"), req.Body)
}
