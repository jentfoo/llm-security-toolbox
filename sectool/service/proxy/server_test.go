package proxy

import (
	"bytes"
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

func TestServeEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty_connection_close", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		conn, err := net.Dial("tcp", proxy.Addr())
		require.NoError(t, err)
		// Close immediately without sending data
		_ = conn.Close()

		// Should not crash - just verify no panic
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("partial_request", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		conn, err := net.Dial("tcp", proxy.Addr())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		// Send incomplete request
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n"))
		// Close without completing headers
		_ = conn.Close()

		// Should not crash - just verify no panic
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("malformed_request_line", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		conn, err := net.Dial("tcp", proxy.Addr())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		// Send malformed request
		_, _ = conn.Write([]byte("INVALID\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			response := string(buf[:n])
			assert.Contains(t, response, "400")
		}
	})

	t.Run("history_persists_after_shutdown", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		proxy, client := setupProxyClient(t)

		req, _ := http.NewRequestWithContext(t.Context(), "GET", testServer.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		time.Sleep(100 * time.Millisecond)
		countBefore := proxy.History().Count()

		_ = proxy.Shutdown(context.Background())

		// History should still be accessible
		countAfter := proxy.History().Count()
		assert.Equal(t, countBefore, countAfter)
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

func TestProxyServerComponents(t *testing.T) {
	t.Parallel()

	t.Run("addr_before_serve", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		// Addr should return the listening address
		addr := proxy.Addr()
		assert.NotEmpty(t, addr)
		assert.Contains(t, addr, ":")
	})

	t.Run("history_accessible", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		history := proxy.History()
		assert.NotNil(t, history)
		assert.Equal(t, 0, history.Count())
	})

	t.Run("cert_manager_accessible", func(t *testing.T) {
		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		certManager := proxy.CertManager()
		assert.NotNil(t, certManager)
		assert.NotNil(t, certManager.CACert())
	})
}

func TestConcurrentConnections(t *testing.T) {
	t.Parallel()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(testServer.Close)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConnsPerHost: 10,
		},
	}

	// Send 10 concurrent requests
	const numRequests = 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/concurrent", nil)
			resp, err := client.Do(req)
			if err != nil {
				results <- err
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				results <- assert.AnError
				return
			}
			results <- nil
		}()
	}

	// Collect results
	var errors []error
	for i := 0; i < numRequests; i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	assert.Empty(t, errors)

	// Wait for history to be recorded
	time.Sleep(200 * time.Millisecond)
	assert.GreaterOrEqual(t, proxy.History().Count(), numRequests)
}

func TestProxyServerDifferentPorts(t *testing.T) {
	t.Parallel()

	t.Run("specific_port", func(t *testing.T) {
		// Create two proxies - first one will get a random port
		proxy1, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy1.Serve() }()
		t.Cleanup(func() { _ = proxy1.Shutdown(context.Background()) })

		// Create second proxy on a different random port
		proxy2, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
		require.NoError(t, err)
		go func() { _ = proxy2.Serve() }()
		t.Cleanup(func() { _ = proxy2.Shutdown(context.Background()) })

		// They should have different addresses
		assert.NotEqual(t, proxy1.Addr(), proxy2.Addr())
	})
}

func TestLargeRequestBody(t *testing.T) {
	t.Parallel()

	var receivedBodySize int
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodySize = len(body)
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	proxy, client := setupProxyClient(t)

	// Create a 1MB body
	largeBody := make([]byte, 1024*1024)
	for i := range largeBody {
		largeBody[i] = byte('A' + i%26)
	}

	req, _ := http.NewRequestWithContext(t.Context(), "POST", testServer.URL+"/upload", http.NoBody)
	req.Body = io.NopCloser(io.NewSectionReader(bytes.NewReader(largeBody), 0, int64(len(largeBody))))
	req.ContentLength = int64(len(largeBody))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, len(largeBody), receivedBodySize)

	// Verify history records the request (body may be truncated based on maxBodyBytes)
	time.Sleep(100 * time.Millisecond)
	assert.GreaterOrEqual(t, proxy.History().Count(), 1)
}

func TestProxyServerRuleApplier(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	// Initially no rule applier
	// Set a rule applier
	mockApplier := &mockRuleApplier{}
	proxy.SetRuleApplier(mockApplier)

	// Should not panic even if we set it multiple times
	proxy.SetRuleApplier(mockApplier)
	proxy.SetRuleApplier(nil)
}

type mockRuleApplier struct{}

func (m *mockRuleApplier) ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request {
	return req
}

func (m *mockRuleApplier) ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response {
	return resp
}

func (m *mockRuleApplier) ApplyH2RequestRules(req *H2RequestData) *H2RequestData {
	return req
}

func (m *mockRuleApplier) ApplyH2ResponseRules(resp *H2ResponseData) *H2ResponseData {
	return resp
}

func (m *mockRuleApplier) ApplyRequestBodyOnlyRules(body []byte) []byte {
	return body
}

func (m *mockRuleApplier) ApplyResponseBodyOnlyRules(body []byte, headers []Header) []byte {
	return body
}

func (m *mockRuleApplier) ApplyWSRules(payload []byte, direction string) []byte {
	return payload
}

func (m *mockRuleApplier) HasBodyRules(isRequest bool) bool {
	return false
}

func TestServeContextCancellation(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	// Start serving
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- proxy.Serve()
	}()

	// Shutdown before timeout
	err = proxy.Shutdown(ctx)
	require.NoError(t, err)

	// Serve should complete
	select {
	case <-serveDone:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not complete after shutdown")
	}
}

func TestMaxBodyBytesConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		maxBodyBytes int
	}{
		{"zero_no_limit", 0},
		{"small_limit", 1024},
		{"large_limit", 100 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewProxyServer(0, t.TempDir(), tt.maxBodyBytes)
			require.NoError(t, err)
			t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

			assert.NotNil(t, proxy.History())
		})
	}
}
