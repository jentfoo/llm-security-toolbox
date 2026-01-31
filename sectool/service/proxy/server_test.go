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

func TestServe(t *testing.T) {
	// test cases are t.Parallel() instead due to speed

	t.Run("basic_http_flow", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Response", "success")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("Hello from server"))
		}))
		t.Cleanup(testServer.Close)

		proxy, client := setupProxyClient(t)

		req, _ := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/test", nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "success", resp.Header.Get("X-Test-Response"))
		assert.Equal(t, "Hello from server", string(body))

		time.Sleep(100 * time.Millisecond)
		assert.Equal(t, 1, proxy.History().Count())

		entry, ok := proxy.History().Get(0)
		require.True(t, ok)
		assert.Equal(t, "http/1.1", entry.Protocol)
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, 200, entry.Response.StatusCode)
	})

	t.Run("header_forwarding", func(t *testing.T) {
		t.Parallel()

		var receivedHeaders http.Header
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		_, client := setupProxyClient(t)

		req, _ := http.NewRequestWithContext(t.Context(), "GET", testServer.URL, nil)
		req.Header.Set("X-Custom-Header", "test-value")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "application/json", receivedHeaders.Get("Accept"))
	})

	t.Run("post_request", func(t *testing.T) {
		t.Parallel()

		var receivedBody []byte
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			_, _ = w.Write(receivedBody)
		}))
		t.Cleanup(testServer.Close)

		proxy, client := setupProxyClient(t)

		req, _ := http.NewRequestWithContext(t.Context(), "POST", testServer.URL+"/api", http.NoBody)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		time.Sleep(100 * time.Millisecond) // TODO - avoid the time.Sleep with push notification
		assert.GreaterOrEqual(t, proxy.History().Count(), 1)
	})

	t.Run("upstream_connection_refused", func(t *testing.T) {
		t.Parallel()

		_, client := setupProxyClient(t)

		req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://127.0.0.1:59999/should-fail", nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		assert.Equal(t, 502, resp.StatusCode)
	})

	t.Run("connect_request", func(t *testing.T) {
		t.Parallel()

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		conn, err := net.Dial("tcp", proxy.Addr())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.NoError(t, err)

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Positive(t, n)

		response := string(buf[:n])
		assert.Contains(t, response, "200 Connection Established")
	})
}

func TestShutdown(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)

	go func() { _ = proxy.Serve() }()

	t.Run("graceful_shutdown", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		t.Cleanup(cancel)

		err = proxy.Shutdown(ctx)
		require.NoError(t, err)

		_, err = net.Dial("tcp", proxy.Addr())
		assert.Error(t, err)
	})

	t.Run("double_shutdown_safe", func(t *testing.T) {
		err = proxy.Shutdown(t.Context())
		require.NoError(t, err)

		err = proxy.Shutdown(t.Context())
		assert.NoError(t, err)
	})
}

func setupProxyClient(t *testing.T) (*ProxyServer, *http.Client) {
	t.Helper()

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

	return proxy, client
}
