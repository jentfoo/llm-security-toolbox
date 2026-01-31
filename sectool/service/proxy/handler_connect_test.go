package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func TestParseConnectRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "standard_with_port",
			input:    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:     "custom_port",
			input:    "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 8443,
		},
		{
			name:     "no_port_defaults_443",
			input:    "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:     "with_extra_headers",
			input:    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:    "invalid_not_connect",
			input:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "empty_line",
			input:   "\r\n",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &ConnectHandler{}
			reader := bufio.NewReader(strings.NewReader(tc.input))

			target, err := h.parseConnectRequest(reader)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, target)
			assert.Equal(t, tc.wantHost, target.Hostname)
			assert.Equal(t, tc.wantPort, target.Port)
			assert.True(t, target.UsesHTTPS)
		})
	}
}

func TestConnectHandler_Handle_Response(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(t.Context()) })

	// Connect to proxy
	conn, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Send CONNECT request
	_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	// Read response
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)

	assert.Contains(t, line, "200 Connection Established")
}

func TestHTTPSProxy_EndToEnd(t *testing.T) {
	t.Parallel()

	// Start HTTPS test server
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Response", "success")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from HTTPS server"))
	}))
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(t.Context()) })

	// Create CA cert pool with proxy's CA
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	// Create HTTP client with proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, // Test server uses self-signed cert
		},
	}
	client := &http.Client{Transport: transport}

	// Make HTTPS request through proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "success", resp.Header.Get("X-Test-Response"))
	assert.Equal(t, "Hello from HTTPS server", string(body))

	// Verify history contains decrypted traffic
	time.Sleep(100 * time.Millisecond)
	assert.GreaterOrEqual(t, proxy.History().Count(), 1)

	entry, ok := proxy.History().Get(0)
	require.True(t, ok)
	assert.Equal(t, "http/1.1", entry.Protocol)
	assert.Equal(t, "GET", entry.Request.Method)
	assert.Equal(t, 200, entry.Response.StatusCode)
	assert.Contains(t, string(entry.Response.Body), "Hello from HTTPS server")
}

func TestHTTPSProxy_HeadersPreserved(t *testing.T) {
	t.Parallel()

	// Test server that echoes headers
	var receivedHeaders http.Header
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(t.Context()) })

	// Create client with proxy
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	// Make request with custom headers
	req, err := http.NewRequest("GET", testServer.URL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Authorization", "Bearer token123")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Verify headers were forwarded
	assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer token123", receivedHeaders.Get("Authorization"))
}

func TestServerCapabilityCaching(t *testing.T) {
	t.Parallel()

	certManager, err := NewCertManager(t.TempDir())
	require.NoError(t, err)

	history := NewHistoryStore(store.NewMemStorage())
	http1Handler := &HTTP1Handler{history: history, maxBodyBytes: 1024 * 1024}
	http2Handler := NewHTTP2Handler(history, 1024*1024)

	handler := NewConnectHandler(certManager, http1Handler, http2Handler, history, 1024*1024)

	// Initially empty cache
	handler.capsMu.RLock()
	assert.Empty(t, handler.serverCaps)
	handler.capsMu.RUnlock()

	// Simulate caching a protocol
	handler.capsMu.Lock()
	handler.serverCaps["example.com:443"] = "http/1.1"
	handler.capsMu.Unlock()

	// Verify cache
	handler.capsMu.RLock()
	proto, ok := handler.serverCaps["example.com:443"]
	handler.capsMu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, "http/1.1", proto)
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}
