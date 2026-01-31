package service

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/proxy"
)

// CustomProxyBackend implements HttpBackend using the custom proxy.
// This backend provides wire-level fidelity for security testing including
// HTTP/1.1 and HTTP/2 support with header order preservation.
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

// Compile-time checks that CustomProxyBackend implements interfaces.
var _ HttpBackend = (*CustomProxyBackend)(nil)
var _ proxy.RuleApplier = (*CustomProxyBackend)(nil)

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

	// Wire backend as rule applier for the proxy handlers
	server.SetRuleApplier(b)

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
	for _, entry := range entries {
		// Use FormatRequest/FormatResponse which handles both HTTP/1.1 and HTTP/2
		reqStr := string(entry.FormatRequest())
		respStr := string(entry.FormatResponse())
		result = append(result, ProxyEntry{
			Request:  reqStr,
			Response: respStr,
			Protocol: entry.Protocol,
		})
	}

	return result, nil
}

func (b *CustomProxyBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "http/1.1"
	}
	log.Printf("custom: sending request %s to %s://%s:%d (protocol=%s, follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, protocol, req.FollowRedirects)

	// Build send options using the defaulted protocol for consistency with logging
	opts := proxy.SendOptions{
		RawRequest: req.RawRequest,
		Target: proxy.Target{
			Hostname:  req.Target.Hostname,
			Port:      req.Target.Port,
			UsesHTTPS: req.Target.UsesHTTPS,
		},
		Force:    req.Force,
		Timeout:  req.Timeout,
		Protocol: protocol,
	}

	// Create sender with JSON modifier
	sender := &proxy.Sender{
		JSONModifier: ModifyJSONBodyMap,
	}

	// Send request
	var result *proxy.SendResult
	var err error
	if req.FollowRedirects {
		result, err = sender.SendWithRedirects(ctx, opts)
	} else {
		result, err = sender.Send(ctx, opts)
	}
	if err != nil {
		return nil, err
	}

	// Convert response to SendRequestResult format
	var buf bytes.Buffer
	return &SendRequestResult{
		Headers:  result.Response.SerializeHeaders(&buf),
		Body:     result.Response.Body,
		Duration: result.Duration,
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

// =============================================================================
// RuleApplier Implementation
// =============================================================================

// ApplyRequestRules applies request header and body rules.
// Rules are applied in the order they were added.
func (b *CustomProxyBackend) ApplyRequestRules(req *proxy.RawHTTP1Request) *proxy.RawHTTP1Request {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []customStoredRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeRequestHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeRequestBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	// Apply header rules
	if len(headerRules) > 0 {
		req = b.applyRequestHeaderRules(req, headerRules)
	}

	// Apply body rules
	if len(bodyRules) > 0 && len(req.Body) > 0 {
		req = b.applyRequestBodyRules(req, bodyRules)
	}

	return req
}

// ApplyResponseRules applies response header and body rules.
// Handles decompression/recompression for body rules.
func (b *CustomProxyBackend) ApplyResponseRules(resp *proxy.RawHTTP1Response) *proxy.RawHTTP1Response {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []customStoredRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeResponseHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeResponseBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	// Apply header rules
	if len(headerRules) > 0 {
		resp = b.applyResponseHeaderRules(resp, headerRules)
	}

	// Apply body rules with compression handling
	if len(bodyRules) > 0 && len(resp.Body) > 0 {
		resp = b.applyResponseBodyRules(resp, bodyRules)
	}

	return resp
}

// ApplyWSRules applies WebSocket rules to frame payload.
func (b *CustomProxyBackend) ApplyWSRules(payload []byte, direction string) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	for _, rule := range b.wsRules {
		if rule.Type != RuleTypeWSBoth && rule.Type != direction {
			continue
		}
		payload = applyMatchReplaceRule(payload, rule)
	}
	return payload
}

// HasBodyRules returns true if there are body rules for request or response.
// Used by HTTP/2 handler to decide whether to buffer full bodies.
func (b *CustomProxyBackend) HasBodyRules(isRequest bool) bool {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	targetType := RuleTypeResponseBody
	if isRequest {
		targetType = RuleTypeRequestBody
	}

	for _, rule := range b.httpRules {
		if rule.Type == targetType {
			return true
		}
	}
	return false
}

// ApplyRequestBodyOnlyRules applies only body rules to a request body.
// Used by HTTP/2 where headers are sent separately before body.
func (b *CustomProxyBackend) ApplyRequestBodyOnlyRules(body []byte) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []customStoredRule
	for _, rule := range b.httpRules {
		if rule.Type == RuleTypeRequestBody {
			bodyRules = append(bodyRules, rule)
		}
	}

	if len(bodyRules) == 0 || len(body) == 0 {
		return body
	}

	modified := body
	for _, rule := range bodyRules {
		modified = applyMatchReplaceRule(modified, rule)
	}
	return modified
}

// ApplyResponseBodyOnlyRules applies only body rules to a response body.
// Used by HTTP/2 where headers are sent separately before body.
// Requires headers for Content-Encoding detection (compression-aware).
// IMPORTANT: In HTTP/2, headers are already sent before body arrives.
// If recompression fails, we must return the original body to avoid
// sending uncompressed data with Content-Encoding header still set.
func (b *CustomProxyBackend) ApplyResponseBodyOnlyRules(body []byte, headers []proxy.Header) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []customStoredRule
	for _, rule := range b.httpRules {
		if rule.Type == RuleTypeResponseBody {
			bodyRules = append(bodyRules, rule)
		}
	}

	if len(bodyRules) == 0 || len(body) == 0 {
		return body
	}

	// Get Content-Encoding from headers for compression handling
	var encoding string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-encoding") {
			encoding = h.Value
			break
		}
	}

	// Check if encoding is present but not supported
	if encoding != "" {
		_, supported := proxy.NormalizeEncoding(encoding)
		if !supported {
			log.Printf("proxy: unsupported Content-Encoding %q, skipping body rules", encoding)
			return body
		}
	}

	// Keep reference to original body for fallback cases
	originalBody := body

	// Decompress if needed
	decompressed, wasCompressed := proxy.Decompress(body, encoding)
	if wasCompressed && decompressed == nil {
		log.Printf("proxy: Content-Encoding %s but decompression failed, skipping body rules", encoding)
		return body
	}

	workingBody := body
	if wasCompressed {
		workingBody = decompressed
	}

	modified := workingBody

	// Apply each rule in order
	for _, rule := range bodyRules {
		modified = applyMatchReplaceRule(modified, rule)
	}

	// If no changes, return original body (still compressed if it was)
	if bytes.Equal(modified, workingBody) {
		return originalBody
	}

	// Recompress if originally compressed
	if wasCompressed {
		compressed, err := proxy.Compress(modified, encoding)
		if err != nil {
			// Recompression failed - return ORIGINAL body (skip rule application).
			// In HTTP/2, headers are already sent with Content-Encoding, so we cannot
			// return uncompressed data without corrupting the response.
			log.Printf("proxy: recompression failed, returning original body: %v", err)
			return originalBody
		}
		return compressed
	}

	return modified
}

// applyRequestHeaderRules applies header rules to request.
func (b *CustomProxyBackend) applyRequestHeaderRules(req *proxy.RawHTTP1Request, rules []customStoredRule) *proxy.RawHTTP1Request {
	// Serialize headers to text format
	var headerBuf bytes.Buffer
	for _, h := range req.Headers {
		headerBuf.WriteString(h.Name)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(h.Value)
		headerBuf.WriteString("\r\n")
	}

	original := headerBuf.Bytes()
	modified := original

	// Apply each rule in order
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return req
	}

	// Parse modified headers back
	req.Headers = parseHeadersFromText(modified)
	return req
}

// applyRequestBodyRules applies body rules to request.
func (b *CustomProxyBackend) applyRequestBodyRules(req *proxy.RawHTTP1Request, rules []customStoredRule) *proxy.RawHTTP1Request {
	original := req.Body
	modified := original

	// Apply each rule in order
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return req
	}

	// Update body and Content-Length
	req.Body = modified
	req.SetHeader("Content-Length", strconv.Itoa(len(modified)))
	return req
}

// applyResponseHeaderRules applies header rules to response.
func (b *CustomProxyBackend) applyResponseHeaderRules(resp *proxy.RawHTTP1Response, rules []customStoredRule) *proxy.RawHTTP1Response {
	// Serialize headers to text format
	var headerBuf bytes.Buffer
	for _, h := range resp.Headers {
		headerBuf.WriteString(h.Name)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(h.Value)
		headerBuf.WriteString("\r\n")
	}

	original := headerBuf.Bytes()
	modified := original

	// Apply each rule in order
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return resp
	}

	// Parse modified headers back
	resp.Headers = parseHeadersFromText(modified)
	return resp
}

// applyResponseBodyRules applies body rules to response with compression handling.
func (b *CustomProxyBackend) applyResponseBodyRules(resp *proxy.RawHTTP1Response, rules []customStoredRule) *proxy.RawHTTP1Response {
	encoding := resp.GetHeader("Content-Encoding")

	// Check if encoding is present but not supported (e.g., br, zstd, or multiple encodings)
	// Skip body rules entirely to avoid corrupting compressed content
	if encoding != "" {
		_, supported := proxy.NormalizeEncoding(encoding)
		if !supported {
			log.Printf("proxy: unsupported Content-Encoding %q, skipping body rules", encoding)
			return resp
		}
	}

	// Decompress if needed
	body := resp.Body
	decompressed, wasCompressed := proxy.Decompress(body, encoding)
	if wasCompressed && decompressed == nil {
		// Decompression failed - skip body rules
		log.Printf("proxy: Content-Encoding %s but decompression failed, skipping body rules", encoding)
		return resp
	}
	if wasCompressed {
		body = decompressed
	}

	original := body
	modified := body

	// Apply each rule in order
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return resp
	}

	// Recompress if originally compressed
	if wasCompressed {
		compressed, err := proxy.Compress(modified, encoding)
		if err != nil {
			// Recompression failed - send uncompressed
			log.Printf("proxy: recompression failed, sending uncompressed: %v", err)
			resp.RemoveHeader("Content-Encoding")
		} else {
			modified = compressed
		}
	}

	// Update body and Content-Length
	resp.Body = modified
	resp.SetHeader("Content-Length", strconv.Itoa(len(modified)))
	return resp
}

// applyMatchReplaceRule applies a single match/replace rule to data.
func applyMatchReplaceRule(input []byte, rule customStoredRule) []byte {
	if !rule.IsRegex {
		return bytes.ReplaceAll(input, []byte(rule.Match), []byte(rule.Replace))
	}

	re := rule.compiled
	if re == nil {
		var err error
		re, err = regexp.Compile(rule.Match)
		if err != nil {
			return input
		}
	}
	return re.ReplaceAll(input, []byte(rule.Replace))
}

// parseHeadersFromText parses "Name: Value\r\n" lines into Header slice.
func parseHeadersFromText(text []byte) []proxy.Header {
	var headers []proxy.Header
	lines := bytes.Split(text, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		idx := bytes.IndexByte(line, ':')
		if idx < 0 {
			// No colon - skip malformed line
			continue
		}
		name := string(line[:idx])
		value := string(bytes.TrimSpace(line[idx+1:]))
		headers = append(headers, proxy.Header{Name: name, Value: value})
	}
	return headers
}
