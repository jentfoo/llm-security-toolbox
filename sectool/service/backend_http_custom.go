package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/proxy"
)

// CustomProxyBackend implements HttpBackend using the custom proxy.
// This backend provides wire-level fidelity for security testing.
//
// Note: This is the replacement for GoProxyBackend. It is built in Phase 3
// but does not become the default until Phase 4 achieves feature parity.
type CustomProxyBackend struct {
	server *proxy.ProxyServer

	// Rules (managed by service layer, applied in future phase)
	rulesMu   sync.RWMutex
	httpRules []customStoredRule
	wsRules   []customStoredRule

	closed atomic.Bool
}

// customStoredRule is the persistent format for rules.
type customStoredRule struct {
	ID      string `json:"id"`
	Label   string `json:"label,omitempty"`
	Type    string `json:"type"`
	IsRegex bool   `json:"is_regex"`
	Match   string `json:"match"`
	Replace string `json:"replace"`

	// compiled is the pre-compiled regex (nil if not a regex rule)
	compiled *regexp.Regexp
}

// Compile-time check that CustomProxyBackend implements HttpBackend.
var _ HttpBackend = (*CustomProxyBackend)(nil)

// NewCustomProxyBackend creates a new custom proxy backend.
// Does NOT start serving - call Serve() separately (typically in a goroutine).
func NewCustomProxyBackend(port int, configDir string, maxBodyBytes int) (*CustomProxyBackend, error) {
	server, err := proxy.NewProxyServer(port, configDir, maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("create proxy server: %w", err)
	}

	b := &CustomProxyBackend{
		server: server,
	}

	return b, nil
}

// Serve starts the proxy server. Call in a goroutine.
func (b *CustomProxyBackend) Serve() error {
	return b.server.Serve()
}

// Addr returns the proxy listen address.
func (b *CustomProxyBackend) Addr() string {
	return b.server.Addr()
}

func (b *CustomProxyBackend) Close() error {
	if b.closed.Swap(true) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return b.server.Shutdown(ctx)
}

func (b *CustomProxyBackend) GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error) {
	entries := b.server.History().List(count, offset)

	result := make([]ProxyEntry, 0, len(entries))
	var buf bytes.Buffer
	for _, entry := range entries {
		var reqStr, respStr string
		if entry.Request != nil {
			reqStr = string(entry.Request.Serialize(&buf))
		}
		if entry.Response != nil {
			respStr = string(entry.Response.Serialize(&buf))
		}
		result = append(result, ProxyEntry{
			Request:  reqStr,
			Response: respStr,
		})
	}

	return result, nil
}

func (b *CustomProxyBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("custom: sending request %s to %s://%s:%d (follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, req.FollowRedirects)

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	if req.FollowRedirects {
		return FollowRedirects(ctx, req, time.Now(), 10, b.sendSingle)
	}
	return b.sendSingle(ctx, req, time.Now())
}

// sendSingle sends a single HTTP request and returns the response.
// This is copied from goproxy backend - it uses net/http which normalizes headers.
// TODO: Replace with wire-fidelity sender using custom parser/serializer in future phase.
func (b *CustomProxyBackend) sendSingle(ctx context.Context, req SendRequestInput, start time.Time) (*SendRequestResult, error) {
	// Parse raw request
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req.RawRequest)))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	// Set the URL
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	httpReq.URL.Scheme = scheme
	httpReq.URL.Host = fmt.Sprintf("%s:%d", req.Target.Hostname, req.Target.Port)
	httpReq.RequestURI = "" // Must clear for client requests

	body, err := io.ReadAll(httpReq.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	_ = httpReq.Body.Close()
	httpReq.Body = io.NopCloser(bytes.NewReader(body))

	// Create HTTP client with settings to preserve wire format as closely as possible
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false, // Prevent HTTP/2 upgrade to match HTTP/1.1 request format
		DisableCompression:  true,  // Prevent Accept-Encoding injection
		Proxy:               nil,   // Ignore environment proxy settings
		MaxIdleConnsPerHost: -1,    // Disable connection pooling
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	httpReq = httpReq.WithContext(ctx)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response headers
	var headerBuf bytes.Buffer
	headerBuf.WriteString(fmt.Sprintf("%s %d %s\r\n", resp.Proto, resp.StatusCode, resp.Status[4:]))
	for name, values := range resp.Header {
		for _, v := range values {
			headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", name, v))
		}
	}
	headerBuf.WriteString("\r\n")

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &SendRequestResult{
		Headers:  headerBuf.Bytes(),
		Body:     respBody,
		Duration: time.Since(start),
	}, nil
}

func (b *CustomProxyBackend) ListRules(ctx context.Context, websocket bool) ([]protocol.RuleEntry, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	rules := b.httpRules
	if websocket {
		rules = b.wsRules
	}

	result := make([]protocol.RuleEntry, 0, len(rules))
	for _, r := range rules {
		result = append(result, protocol.RuleEntry{
			RuleID:  r.ID,
			Label:   r.Label,
			Type:    r.Type,
			IsRegex: r.IsRegex,
			Match:   r.Match,
			Replace: r.Replace,
		})
	}
	return result, nil
}

func (b *CustomProxyBackend) AddRule(ctx context.Context, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	// Validate type (both HTTP and WebSocket types)
	if !validRuleTypes[input.Type] {
		return nil, fmt.Errorf("invalid rule type: %q", input.Type)
	}

	isRegex := input.IsRegex != nil && *input.IsRegex

	// Pre-compile regex if needed
	var compiled *regexp.Regexp
	if isRegex {
		var err error
		compiled, err = regexp.Compile(input.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	// Check label uniqueness across both slices
	if input.Label != "" {
		if b.labelExists(input.Label) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
	}

	rule := customStoredRule{
		ID:       ids.Generate(0),
		Label:    input.Label,
		Type:     input.Type,
		IsRegex:  isRegex,
		Match:    input.Match,
		Replace:  input.Replace,
		compiled: compiled,
	}
	if isWSType(input.Type) {
		b.wsRules = append(b.wsRules, rule)
	} else {
		b.httpRules = append(b.httpRules, rule)
	}

	return &protocol.RuleEntry{
		RuleID:  rule.ID,
		Label:   rule.Label,
		Type:    rule.Type,
		IsRegex: rule.IsRegex,
		Match:   rule.Match,
		Replace: rule.Replace,
	}, nil
}

func (b *CustomProxyBackend) UpdateRule(ctx context.Context, idOrLabel string, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	rule, isWS := b.findRule(idOrLabel)
	if rule == nil {
		return nil, ErrNotFound
	}

	// Validate type matches websocket category
	if isWSType(input.Type) != isWS {
		if isWS {
			return nil, fmt.Errorf("cannot update WebSocket rule with HTTP type %q", input.Type)
		}
		return nil, fmt.Errorf("cannot update HTTP rule with WebSocket type %q", input.Type)
	}

	// Validate rule type is known
	if !validRuleTypes[input.Type] {
		return nil, fmt.Errorf("invalid rule type: %q", input.Type)
	}

	// Check label uniqueness if changing
	if input.Label != "" && input.Label != rule.Label {
		if b.labelExistsExcluding(input.Label, rule.ID) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
		rule.Label = input.Label
	}

	// Determine new regex state
	newIsRegex := rule.IsRegex
	if input.IsRegex != nil {
		newIsRegex = *input.IsRegex
	}

	// Recompile regex if needed
	var compiled *regexp.Regexp
	if newIsRegex {
		var err error
		compiled, err = regexp.Compile(input.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	rule.Type = input.Type
	rule.Match = input.Match
	rule.Replace = input.Replace
	rule.IsRegex = newIsRegex
	rule.compiled = compiled

	return &protocol.RuleEntry{
		RuleID:  rule.ID,
		Label:   rule.Label,
		Type:    rule.Type,
		IsRegex: rule.IsRegex,
		Match:   rule.Match,
		Replace: rule.Replace,
	}, nil
}

func (b *CustomProxyBackend) DeleteRule(ctx context.Context, idOrLabel string) error {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	for i, r := range b.httpRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			b.httpRules = slices.Delete(b.httpRules, i, i+1)
			return nil
		}
	}
	for i, r := range b.wsRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			b.wsRules = slices.Delete(b.wsRules, i, i+1)
			return nil
		}
	}
	return ErrNotFound
}

// findRule finds a rule by ID or label, returning the rule and whether it's a WebSocket rule.
// Caller must hold rulesMu.
func (b *CustomProxyBackend) findRule(idOrLabel string) (*customStoredRule, bool) {
	for i := range b.httpRules {
		if b.httpRules[i].ID == idOrLabel || b.httpRules[i].Label == idOrLabel {
			return &b.httpRules[i], false
		}
	}
	for i := range b.wsRules {
		if b.wsRules[i].ID == idOrLabel || b.wsRules[i].Label == idOrLabel {
			return &b.wsRules[i], true
		}
	}
	return nil, false
}

// labelExists checks if a label is already in use. Caller must hold rulesMu.
func (b *CustomProxyBackend) labelExists(label string) bool {
	for _, r := range b.httpRules {
		if r.Label == label {
			return true
		}
	}
	for _, r := range b.wsRules {
		if r.Label == label {
			return true
		}
	}
	return false
}

// labelExistsExcluding checks if a label is in use by a rule other than excludeID.
// Caller must hold rulesMu.
func (b *CustomProxyBackend) labelExistsExcluding(label, excludeID string) bool {
	for _, r := range b.httpRules {
		if r.Label == label && r.ID != excludeID {
			return true
		}
	}
	for _, r := range b.wsRules {
		if r.Label == label && r.ID != excludeID {
			return true
		}
	}
	return false
}
