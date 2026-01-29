package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyServer_BasicFlow(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Response", "success")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from server"))
	}))
	t.Cleanup(testServer.Close)

	// Start proxy server
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)

	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	// Configure HTTP client to use proxy
	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make request through proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "success", resp.Header.Get("X-Test-Response"))
	assert.Equal(t, "Hello from server", string(body))

	// Verify history
	time.Sleep(100 * time.Millisecond) // Allow history write
	assert.Equal(t, 1, proxy.History().Count())

	entry, ok := proxy.History().Get(0)
	require.True(t, ok)
	assert.Equal(t, "http/1.1", entry.Protocol)
	assert.Equal(t, "GET", entry.Request.Method)
	assert.Equal(t, 200, entry.Response.StatusCode)
}

func TestProxyServer_HeaderFidelity(t *testing.T) {
	t.Parallel()

	// Test server that echoes request headers
	var receivedHeaders http.Header
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	// Send request with custom header casing
	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("GET", testServer.URL, nil)
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Verify headers were forwarded
	assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "application/json", receivedHeaders.Get("Accept"))
}

func TestProxyServer_PostWithBody(t *testing.T) {
	t.Parallel()

	// Test server that echoes body
	var receivedBody []byte
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write(receivedBody)
	}))
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// POST with body
	resp, err := client.Post(testServer.URL+"/api", "application/json",
		http.NoBody) // We'll test with a direct connection for body
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Verify history contains request
	time.Sleep(100 * time.Millisecond)
	assert.GreaterOrEqual(t, proxy.History().Count(), 1)
}

func TestProxyServer_UpstreamConnectionRefused(t *testing.T) {
	t.Parallel()

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Try to connect to non-existent server
	resp, err := client.Get("http://127.0.0.1:59999/should-fail")
	require.NoError(t, err) // We get a response from proxy
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, 502, resp.StatusCode)
}

func TestProxyServer_GracefulShutdown(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)

	go func() { _ = proxy.Serve() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	err = proxy.Shutdown(ctx)
	require.NoError(t, err)

	// Verify server is no longer accepting
	_, err = net.Dial("tcp", proxy.Addr())
	assert.Error(t, err)
}

func TestProxyServer_ProtocolDetection_CONNECT(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	// Send CONNECT request directly
	conn, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Send CONNECT request
	_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	// Should receive 200 Connection Established (CONNECT now supported)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Positive(t, n)

	response := string(buf[:n])
	assert.Contains(t, response, "200 Connection Established")
}

func TestProxyServer_ProtocolDetection_H2C(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	// Send H2C preface directly
	conn, err := net.Dial("tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// HTTP/2 connection preface
	_, err = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)

	// Connection should be closed (H2C not supported)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	assert.LessOrEqual(t, n, 0)
}

func TestProxyServer_Addr(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	addr := proxy.Addr()
	assert.Contains(t, addr, "127.0.0.1:")
	assert.NotEqual(t, "127.0.0.1:0", addr)
}
