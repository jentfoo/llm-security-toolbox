package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestSender_Send(t *testing.T) {
	t.Parallel()

	t.Run("basic_get", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Echo-Method", r.Method)
			w.Header().Set("X-Echo-Path", r.URL.Path)
			w.WriteHeader(200)
			_, _ = w.Write([]byte("OK"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /test-path HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, "GET", result.Response.GetHeader("X-Echo-Method"))
		assert.Equal(t, "/test-path", result.Response.GetHeader("X-Echo-Path"))
		assert.Equal(t, []byte("OK"), result.Response.Body)
	})

	t.Run("post_with_body", func(t *testing.T) {
		var receivedBody []byte
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = body
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 5\r\n\r\nHello")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, []byte("Hello"), receivedBody)
	})

	t.Run("timeout", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			Timeouts: TimeoutConfig{ReadTimeout: 10 * time.Millisecond},
		}

		rawReq := []byte("GET / HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
		})

		require.Error(t, err)
	})

	t.Run("invalid_request", func(t *testing.T) {
		sender := &Sender{}

		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: []byte("INVALID"),
			Target: types.Target{
				Hostname:  "localhost",
				Port:      80,
				UsesHTTPS: false,
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse request")
	})

	t.Run("connection_refused", func(t *testing.T) {
		sender := &Sender{}

		rawReq := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  "localhost",
				Port:      1, // Port 1 typically not listening
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "connect")
	})

	t.Run("invalid_protocol", func(t *testing.T) {
		sender := &Sender{}

		rawReq := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  "localhost",
				Port:      8080,
				UsesHTTPS: false,
			},
			Protocol: "h3", // invalid protocol
			Force:    true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid protocol")
	})

	t.Run("force_cl_gt_body", func(t *testing.T) {
		// CL (100) > actual body (5): previously failed with parseRequest unexpected EOF.
		// With force=true and no modifications, raw bytes are sent directly.
		// The server may hang reading body, so we use a read timeout and
		// verify we don't get a "parse request" error.
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			Timeouts: TimeoutConfig{ReadTimeout: 500 * time.Millisecond},
		}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 100\r\n\r\nshort")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		// The raw bytes are sent successfully. The server may or may not
		// respond depending on how it handles CL mismatch, but the key
		// assertion is that we never get "parse request" errors.
		if err != nil {
			assert.NotContains(t, err.Error(), "parse request")
		}
	})

	t.Run("rejects_nul_header", func(t *testing.T) {
		sender := &Sender{}

		// NUL byte in header value - validation should reject
		rawReq := []byte("GET /api HTTP/1.1\r\nHost: localhost\r\nX-Bad: val\x00ue\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  "localhost",
				Port:      80,
				UsesHTTPS: false,
			},
			Force: false,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("allows_valid_request", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: false,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
	})

	t.Run("force_crlf_headers", func(t *testing.T) {
		// CRLF in header value creates two separate header lines on the wire.
		// force=true should send the raw bytes without error.
		var receivedHeaders http.Header
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		// Raw request with CRLF-injected headers (simulating what applyHeaderModifications produces)
		rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host +
			"\r\nX-Test: value\r\nX-Injected: crlf\r\n\r\n")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, "value", receivedHeaders.Get("X-Test"))
		assert.Equal(t, "crlf", receivedHeaders.Get("X-Injected"))
	})

	t.Run("force_te_cl_conflict", func(t *testing.T) {
		// Simulates CRLF injection creating TE: chunked alongside existing CL.
		// force=true sends raw bytes; server receives conflicting headers.
		// Server prioritizes TE: chunked and waits for a chunked terminator
		// that never arrives, causing a read timeout. This is expected behavior
		// that the tester must handle via timeouts.
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("received"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			Timeouts: TimeoutConfig{ReadTimeout: 500 * time.Millisecond},
		}

		rawReq := []byte("POST /test HTTP/1.1\r\nHost: " + serverURL.Host +
			"\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nX-Injected: crlf\r\n\r\nhello")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		// Server hangs waiting for chunked terminator -> read timeout
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read response")
	})

	t.Run("custom_method", func(t *testing.T) {
		var receivedMethod string
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("PROPFIND /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "PROPFIND", receivedMethod)
	})
}

// newH2TestServer creates an HTTP/2-enabled TLS test server.
func newH2TestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	return server
}

// newH1OnlyTLSServer creates a TLS server that only supports HTTP/1.1.
func newH1OnlyTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	return server
}

func TestSender_Send_H2(t *testing.T) {
	t.Parallel()

	t.Run("basic_get", func(t *testing.T) {
		var receivedMethod, receivedPath, receivedProto string
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedProto = r.Proto
			w.Header().Set("X-Custom", "h2-response")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("H2 OK"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /h2-test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, "GET", receivedMethod)
		assert.Equal(t, "/h2-test", receivedPath)
		assert.Equal(t, "HTTP/2.0", receivedProto)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, "h2-response", result.Response.GetHeader("X-Custom"))
		assert.Equal(t, []byte("H2 OK"), result.Response.Body)
	})

	t.Run("post_with_body", func(t *testing.T) {
		var receivedBody []byte
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 13\r\n\r\nH2 body test!")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("H2 body test!"), receivedBody)
	})

	t.Run("post_no_content_length", func(t *testing.T) {
		var receivedBody []byte
		var receivedCL string
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			receivedCL = r.Header.Get("Content-Length")
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		// captured H2 requests routinely carry no content-length (DATA frames carry the length)
		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\nH2 unframed body")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("H2 unframed body"), receivedBody)
		assert.Empty(t, receivedCL)
	})

	t.Run("server_no_h2", func(t *testing.T) {
		testServer := newH1OnlyTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET / HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "server does not support HTTP/2")
		assert.Contains(t, err.Error(), "replay as HTTP/1.1")
	})

	t.Run("requires_https", func(t *testing.T) {
		sender := &Sender{}

		rawReq := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  "localhost",
				Port:      80,
				UsesHTTPS: false,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP/2 requires HTTPS")
	})

	t.Run("filters_headers", func(t *testing.T) {
		var receivedHeaders http.Header
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET / HTTP/1.1\r\n" +
			"Host: " + serverURL.Host + "\r\n" +
			"Connection: keep-alive\r\n" +
			"Keep-Alive: timeout=5\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Upgrade: websocket\r\n" +
			"Proxy-Connection: keep-alive\r\n" +
			"TE: gzip\r\n" +
			"X-Custom: allowed\r\n" +
			"\r\n")

		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Empty(t, receivedHeaders.Get("Connection"))
		assert.Empty(t, receivedHeaders.Get("Keep-Alive"))
		assert.Empty(t, receivedHeaders.Get("Transfer-Encoding"))
		assert.Empty(t, receivedHeaders.Get("Upgrade"))
		assert.Empty(t, receivedHeaders.Get("Proxy-Connection"))
		assert.Empty(t, receivedHeaders.Get("TE"))
		assert.Equal(t, "allowed", receivedHeaders.Get("X-Custom"))
	})

	t.Run("large_body", func(t *testing.T) {
		// Create a body larger than the default initial flow control window (65535 bytes)
		largeBody := make([]byte, 100*1024)
		for i := range largeBody {
			largeBody[i] = byte('A' + (i % 26))
		}

		var receivedBody []byte
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			_, _ = w.Write([]byte("large body received"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("POST /upload HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: " +
			strconv.Itoa(len(largeBody)) + "\r\n\r\n")
		rawReq = append(rawReq, largeBody...)

		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, largeBody, receivedBody)
		assert.Equal(t, []byte("large body received"), result.Response.Body)
	})

	t.Run("early_error_response", func(t *testing.T) {
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(401)
			_, _ = w.Write([]byte("Unauthorized"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		largeBody := make([]byte, 100*1024)
		for i := range largeBody {
			largeBody[i] = byte('X')
		}

		sender := &Sender{}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: " +
			strconv.Itoa(len(largeBody)) + "\r\n\r\n")
		rawReq = append(rawReq, largeBody...)

		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 401, result.Response.StatusCode)
		assert.Equal(t, "Bearer", result.Response.GetHeader("WWW-Authenticate"))
		assert.Equal(t, []byte("Unauthorized"), result.Response.Body)
	})
}

func TestSender_SendWithRedirects(t *testing.T) {
	t.Parallel()

	t.Run("follows_redirect", func(t *testing.T) {
		var redirectCount int
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				redirectCount++
				w.Header().Set("Location", "/final")
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("Final destination"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /redirect HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("Final destination"), result.Response.Body)
		assert.Equal(t, 1, redirectCount)
	})

	t.Run("max_redirects", func(t *testing.T) {
		var redirectCount int
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectCount++
			w.Header().Set("Location", "/loop")
			w.WriteHeader(302)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /loop HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		_, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many redirects")
		assert.Equal(t, 10, redirectCount)
	})

	t.Run("applies_rules_to_redirect", func(t *testing.T) {
		var receivedHeaders []string
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = append(receivedHeaders, r.Header.Get("X-Injected"))
			if r.URL.Path == "/redirect" {
				w.Header().Set("Location", "/final")
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			RequestRuleApplier: func(req *types.RawHTTP1Request) *types.RawHTTP1Request {
				req.Headers = append(req.Headers, types.Header{Name: "X-Injected", Value: "rule-applied"})
				return req
			},
		}

		rawReq := []byte("GET /redirect HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		require.Len(t, receivedHeaders, 2)
		// Every hop including the first gets rules applied
		assert.Equal(t, "rule-applied", receivedHeaders[0])
		assert.Equal(t, "rule-applied", receivedHeaders[1])
		assert.Contains(t, string(result.ModifiedRequest), "X-Injected: rule-applied")
	})

	t.Run("append_rule_no_accumulation", func(t *testing.T) {
		var hopCounts []int
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hopCounts = append(hopCounts, len(r.Header.Values("X-Injected")))
			switch r.URL.Path {
			case "/a":
				w.Header().Set("Location", "/b")
				w.WriteHeader(302)
			case "/b":
				w.Header().Set("Location", "/c")
				w.WriteHeader(302)
			default:
				w.WriteHeader(200)
			}
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			RequestRuleApplier: func(req *types.RawHTTP1Request) *types.RawHTTP1Request {
				req.Headers = append(req.Headers, types.Header{Name: "X-Injected", Value: "once"})
				return req
			},
		}

		rawReq := []byte("GET /a HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target:     types.Target{Hostname: serverURL.Hostname(), Port: port},
			Force:      true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		require.Len(t, hopCounts, 3)
		for _, c := range hopCounts {
			assert.Equal(t, 1, c)
		}
	})

	t.Run("nil_applier_no_modified_request", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hop" {
				w.Header().Set("Location", "/final")
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /hop HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target:     types.Target{Hostname: serverURL.Hostname(), Port: port},
			Force:      true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Nil(t, result.ModifiedRequest)
	})

	t.Run("h2_preserves_protocol", func(t *testing.T) {
		var redirectCount int
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				redirectCount++
				w.Header().Set("Location", "/final")
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("H2 final"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /redirect HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.SendWithRedirects(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: types.Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: types.ProtocolH2,
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("H2 final"), result.Response.Body)
		assert.Equal(t, 1, redirectCount)
	})
}

func TestResolveRedirectLocation(t *testing.T) {
	t.Parallel()

	currentTarget := types.Target{
		Hostname:  "example.com",
		Port:      443,
		UsesHTTPS: true,
	}
	currentPath := "/current/page"

	tests := []struct {
		name       string
		location   string
		wantTarget types.Target
		wantPath   string
		wantErr    bool
	}{
		{
			name:     "absolute_https",
			location: "https://other.com/new/path",
			wantTarget: types.Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath: "/new/path",
		},
		{
			name:     "absolute_http",
			location: "http://other.com/new/path",
			wantTarget: types.Target{
				Hostname:  "other.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath: "/new/path",
		},
		{
			name:     "with_port",
			location: "https://other.com:8443/path",
			wantTarget: types.Target{
				Hostname:  "other.com",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath: "/path",
		},
		{
			name:     "with_query",
			location: "https://other.com/path?foo=bar",
			wantTarget: types.Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath: "/path?foo=bar",
		},
		{
			name:     "protocol_relative",
			location: "//other.com/path",
			wantTarget: types.Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath: "/path",
		},
		{
			name:       "absolute_path",
			location:   "/new/path",
			wantTarget: currentTarget,
			wantPath:   "/new/path",
		},
		{
			name:       "relative_sibling",
			location:   "sibling",
			wantTarget: currentTarget,
			wantPath:   "/current/sibling",
		},
		{
			name:       "relative_subdir",
			location:   "subdir/file",
			wantTarget: currentTarget,
			wantPath:   "/current/subdir/file",
		},
		// edge cases
		{
			name:       "empty_location",
			location:   "",
			wantTarget: currentTarget,
			wantPath:   "/current",
		},
		{
			name:       "location_with_fragment",
			location:   "/new#section",
			wantTarget: currentTarget,
			wantPath:   "/new#section",
		},
		{
			name:     "ipv6_host",
			location: "https://[::1]:8443/path",
			wantTarget: types.Target{
				Hostname:  "::1",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath: "/path",
		},
		{
			name:       "dot_relative",
			location:   "./sibling",
			wantTarget: currentTarget,
			wantPath:   "/current/sibling",
		},
		{
			name:       "dotdot_relative",
			location:   "../parent",
			wantTarget: currentTarget,
			wantPath:   "/parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, path, err := resolveRedirectLocation(tt.location, currentTarget, currentPath)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantTarget.Hostname, target.Hostname)
			assert.Equal(t, tt.wantTarget.Port, target.Port)
			assert.Equal(t, tt.wantTarget.UsesHTTPS, target.UsesHTTPS)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestPathWithoutQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no_query", "/path", "/path"},
		{"with_query", "/path?query=value", "/path"},
		{"empty_query", "/path?", "/path"},
		{"root_query", "/?query=value", "/"},
		{"root_only", "/", "/"},
		{"multi_params", "/path/to/file?a=b&c=d", "/path/to/file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, PathWithoutQuery(tt.input))
		})
	}
}

func TestQueryFromPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no_query", "/path", ""},
		{"with_query", "/path?query=value", "query=value"},
		{"empty_query", "/path?", ""},
		{"root_query", "/?a=b", "a=b"},
		{"multi_params", "/path?a=b&c=d", "a=b&c=d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, queryFromPath(tt.input))
		})
	}
}

func TestBuildRedirectRequest(t *testing.T) {
	t.Parallel()

	t.Run("status_302", func(t *testing.T) {
		originalReq := &types.RawHTTP1Request{
			Method:  "POST",
			Path:    "/original",
			Version: "HTTP/1.1",
			Headers: []types.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
				{Name: "Content-Length", Value: "10"},
				{Name: "Authorization", Value: "Bearer token"},
				{Name: "X-Custom", Value: "keep"},
			},
			Body: []byte(`{"a":"b"}`),
		}

		target := types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

		newReq, newTarget, _, err := buildRedirectRequest(originalReq, "/new-path", target, "/original", 302)
		require.NoError(t, err)

		assert.Equal(t, "GET", newReq.Method)
		assert.Equal(t, "/new-path", newReq.Path)
		assert.Empty(t, newReq.Body)
		assert.Equal(t, target.Hostname, newTarget.Hostname)
		assert.Equal(t, target.Port, newTarget.Port)
		assert.Equal(t, target.UsesHTTPS, newTarget.UsesHTTPS)
		assert.Equal(t, "keep", newReq.GetHeader("X-Custom"))
		assert.Empty(t, newReq.GetHeader("Content-Type"))
		assert.Empty(t, newReq.GetHeader("Content-Length"))
	})

	t.Run("status_307", func(t *testing.T) {
		originalReq := &types.RawHTTP1Request{
			Method:  "POST",
			Path:    "/original",
			Version: "HTTP/1.1",
			Headers: []types.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
				{Name: "Authorization", Value: "Bearer token"},
			},
			Body: []byte(`{"a":"b"}`),
		}

		target := types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

		newReq, newTarget, _, err := buildRedirectRequest(originalReq, "/new-path", target, "/original", 307)
		require.NoError(t, err)

		assert.Equal(t, "POST", newReq.Method)
		assert.Equal(t, "/new-path", newReq.Path)
		assert.Equal(t, originalReq.Body, newReq.Body)
		assert.Equal(t, target.Hostname, newTarget.Hostname)
	})

	t.Run("cross_origin", func(t *testing.T) {
		originalReq := &types.RawHTTP1Request{
			Method:  "GET",
			Path:    "/original",
			Version: "HTTP/1.1",
			Headers: []types.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Authorization", Value: "Bearer token"},
				{Name: "X-Custom", Value: "keep"},
			},
		}

		target := types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

		newReq, newTarget, _, err := buildRedirectRequest(originalReq, "https://other.com/path", target, "/original", 302)
		require.NoError(t, err)

		assert.Equal(t, "/path", newReq.Path)
		assert.Equal(t, "other.com", newTarget.Hostname)
		assert.Equal(t, 443, newTarget.Port)
		assert.True(t, newTarget.UsesHTTPS)
		assert.Equal(t, "Bearer token", newReq.GetHeader("Authorization"))
		assert.Equal(t, "keep", newReq.GetHeader("X-Custom"))
		assert.Equal(t, "other.com", newReq.GetHeader("Host"))
	})
}

// buildHeadersFrame serializes and re-reads a HEADERS frame so its
// HeaderBlockFragment doesn't alias another frame's framer buffer
func buildHeadersFrame(t *testing.T, streamID uint32, block []byte, endStream bool) *http2.HeadersFrame {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, http2.NewFramer(&buf, nil).WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     endStream,
	}))
	f, err := http2.NewFramer(nil, &buf).ReadFrame()
	require.NoError(t, err)
	hf, ok := f.(*http2.HeadersFrame)
	require.True(t, ok)
	return hf
}

func newTestH2Conn(t *testing.T) *h2Conn {
	t.Helper()
	c, _ := net.Pipe()
	t.Cleanup(func() { _ = c.Close() })
	return newH2Conn(c)
}

func TestReadH2Response(t *testing.T) {
	t.Parallel()

	discardFramer := func() *http2.Framer { return http2.NewFramer(io.Discard, bytes.NewReader(nil)) }

	t.Run("hpack_sync_across_streams", func(t *testing.T) {
		// upstream's single HPACK encoder
		enc := newTestH2Conn(t)

		// first block seeds the dynamic table on a non-target stream; the target
		// stream's block references the same header by index, so it only decodes
		// if the first block was decoded too
		hdrs := types.Headers{{Name: "x-shared", Value: "dyn-table-value"}}
		block1, err := enc.encodeHeaders(map[string]string{":status": "200"}, hdrs)
		require.NoError(t, err)
		block2, err := enc.encodeHeaders(map[string]string{":status": "200"}, hdrs)
		require.NoError(t, err)
		assert.Less(t, len(block2), len(block1)) // confirms indexed reference

		frames := []http2.Frame{
			buildHeadersFrame(t, 3, block1, true),
			buildHeadersFrame(t, 1, block2, true),
		}

		s := &Sender{}
		resp, err := s.readH2Response(discardFramer(), newTestH2Conn(t), 1, frames)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "dyn-table-value", resp.GetHeader("x-shared"))
	})

	t.Run("hpack_decode_error_surfaces", func(t *testing.T) {
		// corrupt block on a non-target stream must error now that we always decode
		frames := []http2.Frame{buildHeadersFrame(t, 3, []byte{0x40, 0x05}, true)}

		s := &Sender{}
		resp, err := s.readH2Response(discardFramer(), newTestH2Conn(t), 1, frames)
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("padding_counts_full_payload", func(t *testing.T) {
		enc := newTestH2Conn(t)
		statusBlock, err := enc.encodeHeaders(map[string]string{":status": "200"}, nil)
		require.NoError(t, err)

		body := []byte("padded-body")
		var dataBuf bytes.Buffer
		require.NoError(t, http2.NewFramer(&dataBuf, nil).WriteDataPadded(1, true, body, make([]byte, 40)))
		f, err := http2.NewFramer(nil, &dataBuf).ReadFrame()
		require.NoError(t, err)
		df, ok := f.(*http2.DataFrame)
		require.True(t, ok)
		// full payload (pad-length octet + data + padding) exceeds unpadded data
		wantConsumed := int32(df.Header().Length)
		assert.Greater(t, int(wantConsumed), len(df.Data()))

		frames := []http2.Frame{buildHeadersFrame(t, 1, statusBlock, false), df}

		dec := newTestH2Conn(t)
		s := &Sender{}
		resp, err := s.readH2Response(discardFramer(), dec, 1, frames)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, body, resp.Body)
		// receive window charged the full padded payload, not just len(Data())
		assert.Equal(t, localInitialWindow-wantConsumed, dec.recvWindowConn)
		assert.Equal(t, localInitialWindow-wantConsumed, dec.recvWindowStream[1])
	})
}
