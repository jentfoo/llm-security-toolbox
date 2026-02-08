package proxy

import (
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
			Target: Target{
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, []byte("Hello"), receivedBody)
	})

	t.Run("with_modifications", func(t *testing.T) {
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

		rawReq := []byte("GET /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nX-Old: value\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
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
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, "added", receivedHeaders.Get("X-New"))
		assert.Empty(t, receivedHeaders.Get("X-Old"))
		assert.Equal(t, []byte("new body"), receivedBody)
	})

	t.Run("query_modifications", func(t *testing.T) {
		var receivedQuery string
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedQuery = r.URL.RawQuery
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /api?old=value&keep=this HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		_, err := sender.Send(t.Context(), SendOptions{
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
			Force: true,
		})

		require.NoError(t, err)
		assert.Contains(t, receivedQuery, "new=param")
		assert.Contains(t, receivedQuery, "keep=this")
		assert.NotContains(t, receivedQuery, "old=value")
	})

	t.Run("json_modifier_error", func(t *testing.T) {
		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				return nil, assert.AnError
			},
		}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{}")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  "localhost",
				Port:      80,
				UsesHTTPS: false,
			},
			Modifications: &Modifications{
				SetJSON: map[string]any{"key": "value"},
			},
			Force: true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "JSON modification failed")
	})

	t.Run("json_modifier_success", func(t *testing.T) {
		var receivedBody []byte
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				return []byte(`{"modified":"true"}`), nil
			},
		}

		rawReq := []byte("POST /api HTTP/1.1\r\nHost: " + serverURL.Host + "\r\nContent-Length: 2\r\n\r\n{}")
		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Modifications: &Modifications{
				SetJSON: map[string]any{"key": "value"},
			},
			Force: false, // Content-Length should auto-update to match modified body
		})

		require.NoError(t, err)
		assert.Contains(t, string(receivedBody), "modified")
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
			Target: Target{
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
			Target: Target{
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
			Target: Target{
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
			Target: Target{
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
			Target: Target{
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
			Target: Target{
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
			name:     "with_port",
			location: "https://other.com:8443/path",
			wantTarget: Target{
				Hostname:  "other.com",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath: "/path",
		},
		{
			name:     "with_query",
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
			wantTarget: Target{
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

		newReq, newTarget, _, err := buildRedirectRequest(originalReq, "/new-path", target, "/original", 307)
		require.NoError(t, err)

		assert.Equal(t, "POST", newReq.Method)
		assert.Equal(t, "/new-path", newReq.Path)
		assert.Equal(t, originalReq.Body, newReq.Body)
		assert.Equal(t, target.Hostname, newTarget.Hostname)
	})

	t.Run("cross_origin", func(t *testing.T) {
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

func TestApplyQueryModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		query        string
		setParams    map[string]string
		removeParams []string
		wantContain  []string
		wantExclude  []string
	}{
		{
			name:         "add_and_modify",
			query:        "old=value&keep=this",
			setParams:    map[string]string{"new": "added", "keep": "modified"},
			removeParams: []string{"old"},
			wantContain:  []string{"new=added", "keep=modified"},
			wantExclude:  []string{"old=value"},
		},
		{
			name:        "add_param",
			query:       "existing=value",
			setParams:   map[string]string{"new": "param"},
			wantContain: []string{"existing=value", "new=param"},
		},
		{
			name:         "remove_param",
			query:        "keep=this&remove=that",
			removeParams: []string{"remove"},
			wantContain:  []string{"keep=this"},
			wantExclude:  []string{"remove=that"},
		},
		{
			name:         "add_and_remove",
			query:        "old=val",
			setParams:    map[string]string{"new": "val"},
			removeParams: []string{"old"},
			wantContain:  []string{"new=val"},
			wantExclude:  []string{"old=val"},
		},
		{
			name:        "empty_query_add",
			query:       "",
			setParams:   map[string]string{"key": "value"},
			wantContain: []string{"key=value"},
		},
		{
			name:         "remove_nonexistent",
			query:        "keep=this",
			removeParams: []string{"nonexistent"},
			wantContain:  []string{"keep=this"},
		},
		{
			name:        "override_existing",
			query:       "key=old",
			setParams:   map[string]string{"key": "new"},
			wantContain: []string{"key=new"},
			wantExclude: []string{"key=old"},
		},
		{
			name:        "special_characters",
			query:       "",
			setParams:   map[string]string{"param": "value with spaces&special=chars"},
			wantContain: []string{"param="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    "/test",
				Query:   tt.query,
				Version: "HTTP/1.1",
			}

			mods := &Modifications{
				SetParams:    tt.setParams,
				RemoveParams: tt.removeParams,
			}

			applyQueryModifications(req, mods)

			for _, want := range tt.wantContain {
				assert.Contains(t, req.Query, want)
			}
			for _, exclude := range tt.wantExclude {
				assert.NotContains(t, req.Query, exclude)
			}
		})
	}
}

func TestSender_ValidationBypass(t *testing.T) {
	t.Parallel()

	t.Run("force_bypasses_validation", func(t *testing.T) {
		var receivedMethod string
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		// Use an unusual but valid HTTP method
		rawReq := []byte("CUSTOMMETHOD / HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: false,
			},
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, "CUSTOMMETHOD", receivedMethod)
	})
}

func TestApplyModifications(t *testing.T) {
	t.Parallel()

	t.Run("nil_mods_is_noop", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Host", Value: "example.com"}},
		}

		sender := &Sender{}
		err := sender.applyModifications(req, nil, false)

		require.NoError(t, err)
		assert.Equal(t, "GET", req.Method)
		assert.Equal(t, "/test", req.Path)
		assert.Equal(t, "example.com", req.GetHeader("Host"))
	})

	t.Run("method_override", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			Method: "POST",
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "POST", req.Method)
	})

	t.Run("set_headers_adds_new", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Host", Value: "example.com"}},
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			SetHeaders: map[string]string{"X-Custom": "value"},
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "value", req.GetHeader("X-Custom"))
		assert.Equal(t, "example.com", req.GetHeader("Host"))
	})

	t.Run("set_headers_replaces_existing", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Authorization", Value: "Bearer old"}},
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			SetHeaders: map[string]string{"Authorization": "Bearer new"},
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "Bearer new", req.GetHeader("Authorization"))
	})

	t.Run("remove_headers", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Remove-Me", Value: "gone"},
			},
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			RemoveHeaders: []string{"X-Remove-Me"},
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "example.com", req.GetHeader("Host"))
		assert.Empty(t, req.GetHeader("X-Remove-Me"))
	})

	t.Run("set_params", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Query:   "existing=value",
			Version: "HTTP/1.1",
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			SetParams: map[string]string{"new": "param"},
		}, false)

		require.NoError(t, err)
		assert.Contains(t, req.Query, "existing=value")
		assert.Contains(t, req.Query, "new=param")
	})

	t.Run("remove_params", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Query:   "keep=yes&remove=me",
			Version: "HTTP/1.1",
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			RemoveParams: []string{"remove"},
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "keep=yes", req.Query)
	})

	t.Run("body_replacement", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "5"}},
			Body:    []byte("hello"),
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			Body: []byte("new body"),
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "new body", string(req.Body))
		assert.Equal(t, "8", req.GetHeader("Content-Length"))
	})

	t.Run("set_json", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "13"}},
			Body:    []byte(`{"key":"old"}`),
		}

		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				return []byte(`{"key":"new"}`), nil
			},
		}
		err := sender.applyModifications(req, &Modifications{
			SetJSON: map[string]any{"key": "new"},
		}, false)

		require.NoError(t, err)
		assert.JSONEq(t, `{"key":"new"}`, string(req.Body))
		assert.Equal(t, "13", req.GetHeader("Content-Length"))
	})

	t.Run("remove_json", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "25"}},
			Body:    []byte(`{"keep":"yes","drop":"no"}`),
		}

		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				return []byte(`{"keep":"yes"}`), nil
			},
		}
		err := sender.applyModifications(req, &Modifications{
			RemoveJSON: []string{"drop"},
		}, false)

		require.NoError(t, err)
		assert.JSONEq(t, `{"keep":"yes"}`, string(req.Body))
		assert.Equal(t, "14", req.GetHeader("Content-Length"))
	})

	t.Run("empty_body_with_set_json", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{},
			Body:    nil,
		}

		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				assert.Equal(t, []byte("{}"), body)
				return []byte(`{"new":"value"}`), nil
			},
		}
		err := sender.applyModifications(req, &Modifications{
			SetJSON: map[string]any{"new": "value"},
		}, false)

		require.NoError(t, err)
		assert.JSONEq(t, `{"new":"value"}`, string(req.Body))
	})

	t.Run("force", func(t *testing.T) {
		t.Run("force_skips_content_length_update_body", func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "POST",
				Path:    "/test",
				Version: "HTTP/1.1",
				Headers: []Header{{Name: "Content-Length", Value: "5"}},
				Body:    []byte("hello"),
			}

			sender := &Sender{}
			err := sender.applyModifications(req, &Modifications{
				Body: []byte("longer body content"),
			}, true) // force=true

			require.NoError(t, err)
			assert.Equal(t, "longer body content", string(req.Body))
			// Content-Length should NOT be updated when force=true
			assert.Equal(t, "5", req.GetHeader("Content-Length"))
		})

		t.Run("normal_updates_content_length_body", func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "POST",
				Path:    "/test",
				Version: "HTTP/1.1",
				Headers: []Header{{Name: "Content-Length", Value: "5"}},
				Body:    []byte("hello"),
			}

			sender := &Sender{}
			err := sender.applyModifications(req, &Modifications{
				Body: []byte("longer body content"),
			}, false) // force=false

			require.NoError(t, err)
			assert.Equal(t, "longer body content", string(req.Body))
			// Content-Length should be updated when force=false
			assert.Equal(t, "19", req.GetHeader("Content-Length"))
		})

		t.Run("force_skips_content_length_update_json", func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "POST",
				Path:    "/test",
				Version: "HTTP/1.1",
				Headers: []Header{{Name: "Content-Length", Value: "2"}},
				Body:    []byte("{}"),
			}

			sender := &Sender{
				JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
					return []byte(`{"key":"value"}`), nil
				},
			}
			err := sender.applyModifications(req, &Modifications{
				SetJSON: map[string]any{"key": "value"},
			}, true) // force=true

			require.NoError(t, err)
			assert.JSONEq(t, `{"key":"value"}`, string(req.Body))
			// Content-Length should NOT be updated when force=true
			assert.Equal(t, "2", req.GetHeader("Content-Length"))
		})
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("H2 body test!"), receivedBody)
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
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
			Target: Target{
				Hostname:  "localhost",
				Port:      80,
				UsesHTTPS: false,
			},
			Protocol: "h2",
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
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

	t.Run("with_modifications", func(t *testing.T) {
		var receivedHeaders http.Header
		var receivedBody []byte
		var receivedMethod string
		testServer := newH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedHeaders = r.Header
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, _ := url.Parse(testServer.URL)
		port, _ := strconv.Atoi(serverURL.Port())

		sender := &Sender{}

		rawReq := []byte("GET /original HTTP/1.1\r\n" +
			"Host: " + serverURL.Host + "\r\n" +
			"X-Remove: should-be-gone\r\n" +
			"\r\n")

		_, err := sender.Send(t.Context(), SendOptions{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
			Modifications: &Modifications{
				Method:        "POST",
				SetHeaders:    map[string]string{"X-Added": "new-value"},
				RemoveHeaders: []string{"X-Remove"},
				Body:          []byte("modified body"),
			},
			Force: true,
		})

		require.NoError(t, err)
		assert.Equal(t, "POST", receivedMethod)
		assert.Equal(t, "new-value", receivedHeaders.Get("X-Added"))
		assert.Empty(t, receivedHeaders.Get("X-Remove"))
		assert.Equal(t, []byte("modified body"), receivedBody)
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 401, result.Response.StatusCode)
		assert.Equal(t, "Bearer", result.Response.GetHeader("WWW-Authenticate"))
		assert.Equal(t, []byte("Unauthorized"), result.Response.Body)
	})
}

func TestSender_SendWithRedirects_H2(t *testing.T) {
	t.Parallel()

	t.Run("preserves_protocol", func(t *testing.T) {
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
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      port,
				UsesHTTPS: true,
			},
			Protocol: "h2",
			Force:    true,
		})

		require.NoError(t, err)
		assert.Equal(t, 200, result.Response.StatusCode)
		assert.Equal(t, []byte("H2 final"), result.Response.Body)
		assert.Equal(t, 1, redirectCount)
	})
}

func TestApplyModifications_User_ContentLength_Preserved(t *testing.T) {
	t.Parallel()

	t.Run("user_set_content_length_not_overwritten", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "5"}},
			Body:    []byte("hello"),
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			Body:       []byte("longer body content"),              // 19 bytes
			SetHeaders: map[string]string{"Content-Length": "100"}, // user explicitly sets CL
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "longer body content", string(req.Body))
		// User-specified Content-Length should be preserved, not auto-updated
		assert.Equal(t, "100", req.GetHeader("Content-Length"))
	})

	t.Run("auto_update_when_user_did_not_set_content_length", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "5"}},
			Body:    []byte("hello"),
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			Body:       []byte("longer body content"),          // 19 bytes
			SetHeaders: map[string]string{"X-Custom": "value"}, // user sets other headers but not CL
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "longer body content", string(req.Body))
		// Content-Length should be auto-updated since user didn't set it
		assert.Equal(t, "19", req.GetHeader("Content-Length"))
	})

	t.Run("user_set_content_length_case_insensitive", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "5"}},
			Body:    []byte("hello"),
		}

		sender := &Sender{}
		err := sender.applyModifications(req, &Modifications{
			Body:       []byte("new body"),                        // 8 bytes
			SetHeaders: map[string]string{"content-length": "42"}, // lowercase
		}, false)

		require.NoError(t, err)
		assert.Equal(t, "new body", string(req.Body))
		// User-specified Content-Length should be preserved (case-insensitive check)
		assert.Equal(t, "42", req.GetHeader("Content-Length"))
	})

	t.Run("json_modification_with_user_content_length", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Content-Length", Value: "2"}},
			Body:    []byte("{}"),
		}

		sender := &Sender{
			JSONModifier: func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error) {
				return []byte(`{"key":"value"}`), nil // 15 bytes
			},
		}
		err := sender.applyModifications(req, &Modifications{
			SetJSON:    map[string]any{"key": "value"},
			SetHeaders: map[string]string{"Content-Length": "999"},
		}, false)

		require.NoError(t, err)
		// User-specified Content-Length should be preserved
		assert.Equal(t, "999", req.GetHeader("Content-Length"))
	})
}

func TestSendOptions_Custom_Method(t *testing.T) {
	t.Parallel()

	// Test custom HTTP methods
	methods := []string{"PATCH", "DELETE", "OPTIONS", "PROPFIND", "CUSTOMMETHOD"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			wantMethod := method
			var receivedMethod string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.WriteHeader(200)
			}))
			t.Cleanup(testServer.Close)

			serverURL, _ := url.Parse(testServer.URL)
			port, _ := strconv.Atoi(serverURL.Port())

			sender := &Sender{}

			rawReq := []byte(wantMethod + " /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
			_, err := sender.Send(t.Context(), SendOptions{
				RawRequest: rawReq,
				Target: Target{
					Hostname:  serverURL.Hostname(),
					Port:      port,
					UsesHTTPS: false,
				},
			})

			require.NoError(t, err)
			assert.Equal(t, wantMethod, receivedMethod)
		})
	}
}
