package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSender_Send(t *testing.T) {
	t.Parallel()

	// Start test server
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
	ctx := context.Background()

	rawReq := []byte("GET /test-path HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
	})

	require.NoError(t, err)
	assert.Equal(t, 200, result.Response.StatusCode)
	assert.Equal(t, "GET", result.Response.GetHeader("X-Echo-Method"))
	assert.Equal(t, "/test-path", result.Response.GetHeader("X-Echo-Path"))
	assert.Equal(t, []byte("OK"), result.Response.Body)
}

func TestSender_Send_with_body(t *testing.T) {
	t.Parallel()

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
	ctx := context.Background()

	rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 5\r\n\r\nHello")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("Hello"), receivedBody)
}

func TestSender_Send_modifications(t *testing.T) {
	t.Parallel()

	var receivedHeaders http.Header
	var receivedBody []byte
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nX-Old: value\r\n\r\n")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Modifications: &Modifications{
			Method:        "POST",
			SetHeaders:    map[string]string{"X-New": "added"},
			RemoveHeaders: []string{"X-Old"},
			Body:          []byte("new body"),
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.NoError(t, err)
	assert.Equal(t, "added", receivedHeaders.Get("X-New"))
	assert.Empty(t, receivedHeaders.Get("X-Old"))
	assert.Equal(t, []byte("new body"), receivedBody)
}

func TestSender_Send_query_modifications(t *testing.T) {
	t.Parallel()

	var receivedQuery string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET /api?old=value&keep=this HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Modifications: &Modifications{
			SetParams:    map[string]string{"new": "param"},
			RemoveParams: []string{"old"},
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.NoError(t, err)
	assert.Contains(t, receivedQuery, "new=param")
	assert.Contains(t, receivedQuery, "keep=this")
	assert.NotContains(t, receivedQuery, "old=value")
}

func TestSender_Send_json_modification_error(t *testing.T) {
	t.Parallel()

	sender := &Sender{
		JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
			return nil, assert.AnError
		},
	}
	ctx := context.Background()

	rawReq := []byte("POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{}")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  "localhost",
			Port:      80,
			UsesHTTPS: false,
		},
		Modifications: &Modifications{
			SetJSON: map[string]any{"key": "value"},
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON modification failed")
}

func TestSender_SendWithRedirects(t *testing.T) {
	t.Parallel()

	redirectCount := 0
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
	ctx := context.Background()

	rawReq := []byte("GET /redirect HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := sender.SendWithRedirects(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.NoError(t, err)
	assert.Equal(t, 200, result.Response.StatusCode)
	assert.Equal(t, []byte("Final destination"), result.Response.Body)
	assert.Equal(t, 1, redirectCount)
}

func TestSender_SendWithRedirects_no_redirect(t *testing.T) {
	t.Parallel()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("No redirect"))
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := sender.SendWithRedirects(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.NoError(t, err)
	assert.Equal(t, 200, result.Response.StatusCode)
	assert.Equal(t, []byte("No redirect"), result.Response.Body)
}

func TestSender_SendWithRedirects_max_redirects(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		// Always redirect - will hit max limit
		w.Header().Set("Location", "/loop")
		w.WriteHeader(302)
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET /loop HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	_, err := sender.SendWithRedirects(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many redirects")
	assert.Equal(t, 10, redirectCount) // maxRedirects constant
}

func TestResolveRedirectLocation(t *testing.T) {
	t.Parallel()

	currentTarget := Target{
		Hostname:  "example.com",
		Port:      443,
		UsesHTTPS: true,
	}
	currentPath := "/current/page"

	tests := []struct {
		name       string
		location   string
		wantTarget Target
		wantPath   string
		wantErr    bool
	}{
		{
			name:     "absolute_https",
			location: "https://other.com/new/path",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath: "/new/path",
		},
		{
			name:     "absolute_http",
			location: "http://other.com/new/path",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath: "/new/path",
		},
		{
			name:     "absolute_with_port",
			location: "https://other.com:8443/path",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath: "/path",
		},
		{
			name:     "absolute_with_query",
			location: "https://other.com/path?foo=bar",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath: "/path?foo=bar",
		},
		{
			name:     "protocol_relative",
			location: "//other.com/path",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      443,
				UsesHTTPS: true, // inherits from current
			},
			wantPath: "/path",
		},
		{
			name:       "absolute_path",
			location:   "/new/path",
			wantTarget: currentTarget, // same target
			wantPath:   "/new/path",
		},
		{
			name:       "relative_path",
			location:   "sibling",
			wantTarget: currentTarget,
			wantPath:   "/current/sibling",
		},
		{
			name:       "relative_path_subdir",
			location:   "subdir/file",
			wantTarget: currentTarget,
			wantPath:   "/current/subdir/file",
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
		input string
		want  string
	}{
		{"/path", "/path"},
		{"/path?query=value", "/path"},
		{"/path?", "/path"},
		{"/?query=value", "/"},
		{"/", "/"},
		{"/path/to/file?a=b&c=d", "/path/to/file"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, pathWithoutQuery(tt.input))
		})
	}
}

func TestQueryFromPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"/path", ""},
		{"/path?query=value", "query=value"},
		{"/path?", ""},
		{"/?a=b", "a=b"},
		{"/path?a=b&c=d", "a=b&c=d"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, queryFromPath(tt.input))
		})
	}
}

func TestBuildRedirectRequest_301_302(t *testing.T) {
	t.Parallel()

	originalReq := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/original",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Content-Length", Value: "10"},
			{Name: "Authorization", Value: "Bearer token"},
			{Name: "X-Custom", Value: "keep"},
		},
		Body: []byte(`{"a":"b"}`),
	}

	target := Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

	// 302 should convert to GET and drop body
	newReq, newTarget, _, err := buildRedirectRequest(originalReq, "/new-path", target, "/original", 302)
	require.NoError(t, err)

	assert.Equal(t, "GET", newReq.Method)
	assert.Empty(t, newReq.Body)
	assert.Equal(t, target.Hostname, newTarget.Hostname)
	assert.Equal(t, "keep", newReq.GetHeader("X-Custom"))
	// Body headers should be stripped
	assert.Empty(t, newReq.GetHeader("Content-Type"))
	assert.Empty(t, newReq.GetHeader("Content-Length"))
}

func TestBuildRedirectRequest_307_308(t *testing.T) {
	t.Parallel()

	originalReq := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/original",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Authorization", Value: "Bearer token"},
		},
		Body: []byte(`{"a":"b"}`),
	}

	target := Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

	// 307 should preserve method and body
	newReq, _, _, err := buildRedirectRequest(originalReq, "/new-path", target, "/original", 307)
	require.NoError(t, err)

	assert.Equal(t, "POST", newReq.Method)
	assert.Equal(t, originalReq.Body, newReq.Body)
}

func TestBuildRedirectRequest_cross_origin(t *testing.T) {
	t.Parallel()

	originalReq := &RawHTTP1Request{
		Method:  "GET",
		Path:    "/original",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
			{Name: "Authorization", Value: "Bearer token"},
			{Name: "X-Custom", Value: "keep"},
		},
	}

	target := Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}

	// Cross-origin redirect should strip Authorization
	newReq, _, _, err := buildRedirectRequest(originalReq, "https://other.com/path", target, "/original", 302)
	require.NoError(t, err)

	assert.Empty(t, newReq.GetHeader("Authorization"))
	assert.Equal(t, "keep", newReq.GetHeader("X-Custom"))
	assert.Equal(t, "other.com", newReq.GetHeader("Host"))
}

func TestApplyQueryModifications(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Method:  "GET",
		Path:    "/api",
		Query:   "old=value&keep=this",
		Version: "HTTP/1.1",
	}

	mods := &Modifications{
		SetParams:    map[string]string{"new": "added", "keep": "modified"},
		RemoveParams: []string{"old"},
	}

	applyQueryModifications(req, mods)

	assert.Contains(t, req.Query, "new=added")
	assert.Contains(t, req.Query, "keep=modified")
	assert.NotContains(t, req.Query, "old=value")
}

func TestSender_Send_timeout(t *testing.T) {
	t.Parallel()

	// Server that delays response
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Timeout: 50 * time.Millisecond, // Very short timeout
	})

	require.Error(t, err)
}

func TestSender_Send_invalid_request(t *testing.T) {
	t.Parallel()

	sender := &Sender{}
	ctx := context.Background()

	_, err := sender.Send(ctx, SendOptions{
		RawRequest: []byte("INVALID"),
		Target: Target{
			Hostname:  "localhost",
			Port:      80,
			UsesHTTPS: false,
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse request")
}

func TestSender_Send_connection_refused(t *testing.T) {
	t.Parallel()

	sender := &Sender{}
	ctx := context.Background()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  "localhost",
			Port:      1, // Port 1 typically not listening
			UsesHTTPS: false,
		},
		Timeout: 1 * time.Second,
		Force:   true,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect")
}

func TestSender_JSONModifier(t *testing.T) {
	t.Parallel()

	var receivedBody []byte
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	serverURL, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(serverURL.Port())

	// Custom JSON modifier that just sets keys
	sender := &Sender{
		JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
			// Simple implementation for test
			return []byte(`{"modified":"true"}`), nil
		},
	}

	ctx := context.Background()
	rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 2\r\n\r\n{}")
	_, err := sender.Send(ctx, SendOptions{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      port,
			UsesHTTPS: false,
		},
		Modifications: &Modifications{
			SetJSON: map[string]any{"key": "value"},
		},
		Timeout: 10 * time.Second,
		Force:   true,
	})

	require.NoError(t, err)
	assert.Contains(t, string(receivedBody), "modified")
}
