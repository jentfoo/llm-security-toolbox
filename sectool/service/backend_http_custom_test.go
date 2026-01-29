package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomProxyBackend_CreateAndServe(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)

	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	addr := backend.Addr()
	assert.Contains(t, addr, "127.0.0.1:")
	assert.NotEqual(t, "127.0.0.1:0", addr)
}

func TestCustomProxyBackend_GetProxyHistory(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(testServer.Close)

	// Start custom proxy backend
	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	// Configure client to use proxy
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make request through proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Wait for history to be recorded
	time.Sleep(100 * time.Millisecond)

	// Get history
	ctx := context.Background()
	entries, err := backend.GetProxyHistory(ctx, 10, 0)
	require.NoError(t, err)

	assert.Len(t, entries, 1)
	assert.Contains(t, entries[0].Request, "GET")
	assert.Contains(t, entries[0].Response, "200")
}

func TestCustomProxyBackend_Rules_CRUD(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()

	// Add rule
	isRegex := false
	rule, err := backend.AddRule(ctx, ProxyRuleInput{
		Label:   "test-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "old-value",
		Replace: "new-value",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-rule", rule.Label)
	assert.Equal(t, RuleTypeRequestHeader, rule.Type)
	assert.Equal(t, "old-value", rule.Match)

	// List rules
	rules, err := backend.ListRules(ctx, false)
	require.NoError(t, err)
	assert.Len(t, rules, 1)

	// Update rule
	updated, err := backend.UpdateRule(ctx, "test-rule", ProxyRuleInput{
		Label:   "test-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "updated-value",
		Replace: "new-replacement",
	})
	require.NoError(t, err)
	assert.Equal(t, "updated-value", updated.Match)

	// Delete rule
	err = backend.DeleteRule(ctx, "test-rule")
	require.NoError(t, err)

	// Verify deleted
	rules, err = backend.ListRules(ctx, false)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestCustomProxyBackend_Rules_LabelUniqueness(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add first rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "a",
		Replace: "b",
	})
	require.NoError(t, err)

	// Try to add duplicate label
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "c",
		Replace: "d",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLabelExists)
}

func TestCustomProxyBackend_Rules_InvalidType(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Type:    "invalid_type",
		IsRegex: &isRegex,
		Match:   "a",
		Replace: "b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule type")
}

func TestCustomProxyBackend_Rules_Regex(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := true

	// Valid regex
	rule, err := backend.AddRule(ctx, ProxyRuleInput{
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   `\d+`,
		Replace: "NUMBER",
	})
	require.NoError(t, err)
	assert.True(t, rule.IsRegex)

	// Invalid regex
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   `[invalid`,
		Replace: "x",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestCustomProxyBackend_SendRequest(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "response")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from server"))
	}))
	t.Cleanup(testServer.Close)

	// Parse test server URL
	serverURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	// Create backend (doesn't need to serve for SendRequest)
	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()

	// Send request directly (not through proxy)
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := backend.SendRequest(ctx, "test", SendRequestInput{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      mustParsePort(t, serverURL.Port()),
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err)

	assert.Contains(t, string(result.Headers), "200")
	assert.Contains(t, string(result.Headers), "X-Test: response")
	assert.Equal(t, "Hello from server", string(result.Body))
}

func TestCustomProxyBackend_Close(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)

	go func() { _ = backend.Serve() }()
	time.Sleep(50 * time.Millisecond) // Let it start

	// Close should succeed
	err = backend.Close()
	require.NoError(t, err)

	// Double close should be safe
	err = backend.Close()
	require.NoError(t, err)
}

func TestCustomProxyBackend_ImplementsHttpBackend(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Compile-time check is in the source file, but we verify here too
	var _ HttpBackend = backend
}

func TestCustomProxyBackend_HTTPS_Proxy(t *testing.T) {
	t.Parallel()

	// Start HTTPS test server
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-HTTPS", "true")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Secure response"))
	}))
	t.Cleanup(testServer.Close)

	// Start custom proxy backend
	tempDir := t.TempDir()
	backend, err := NewCustomProxyBackend(0, tempDir, 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	// Client trusting our CA and the test server's CA
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: testServer.Client().Transport.(*http.Transport).TLSClientConfig,
	}
	// Also trust our proxy's CA
	transport.TLSClientConfig.InsecureSkipVerify = true

	client := &http.Client{Transport: transport}

	// Make HTTPS request through proxy
	resp, err := client.Get(testServer.URL + "/secure")
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "true", resp.Header.Get("X-HTTPS"))
	assert.Equal(t, "Secure response", string(body))
}

// mustParsePort parses a port string or returns 80 as default
func mustParsePort(t *testing.T, portStr string) int {
	t.Helper()
	if portStr == "" {
		return 80
	}
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)
	return port
}
