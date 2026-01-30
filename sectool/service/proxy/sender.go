package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	sendDialTimeout = 30 * time.Second
	maxRedirects    = 10
)

// JSONModifier modifies JSON body with set/remove operations.
// Provided by service layer to avoid circular imports.
type JSONModifier func(body []byte, setJSON map[string]any, removeJSON []string) ([]byte, error)

// Sender sends HTTP requests with wire-level fidelity.
type Sender struct {
	// JSONModifier is called to apply JSON modifications to request body.
	// If nil, SetJSON/RemoveJSON modifications are ignored.
	JSONModifier JSONModifier
}

// SendOptions configures request sending.
type SendOptions struct {
	RawRequest    []byte         // Raw HTTP request bytes
	Target        Target         // Where to send
	Modifications *Modifications // Optional changes
	Force         bool           // Bypass validation
	Timeout       time.Duration
}

// Modifications specifies changes to apply to a request.
type Modifications struct {
	Method        string            // Override HTTP method
	SetHeaders    map[string]string // Add or replace headers
	RemoveHeaders []string          // Remove headers by name
	Body          []byte            // Replace entire body (mutually exclusive with JSON mods)
	SetJSON       map[string]any    // Modify JSON fields
	RemoveJSON    []string          // Remove JSON fields
	SetParams     map[string]string // Set query parameters
	RemoveParams  []string          // Remove query parameters
}

// SendResult contains the response from a sent request.
type SendResult struct {
	Response *RawHTTP1Response
	Duration time.Duration
}

// Send sends a request and returns the response.
func (s *Sender) Send(ctx context.Context, opts SendOptions) (*SendResult, error) {
	start := time.Now()

	// Parse raw request
	req, err := ParseRequest(bytes.NewReader(opts.RawRequest))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	// Apply modifications
	if opts.Modifications != nil {
		if err := s.applyModifications(req, opts.Modifications); err != nil {
			return nil, fmt.Errorf("apply modifications: %w", err)
		}
	}

	// Validate request (unless force=true)
	if !opts.Force {
		if err := ValidateRequest(req); err != nil {
			return nil, fmt.Errorf("validation failed: %w (use force=true to bypass)", err)
		}
	}

	// Send request and get response
	resp, err := s.sendRequest(ctx, req, opts.Target, opts.Timeout)
	if err != nil {
		return nil, err
	}

	return &SendResult{
		Response: resp,
		Duration: time.Since(start),
	}, nil
}

// SendWithRedirects sends a request and follows redirects.
func (s *Sender) SendWithRedirects(ctx context.Context, opts SendOptions) (*SendResult, error) {
	start := time.Now()

	// Parse raw request
	req, err := ParseRequest(bytes.NewReader(opts.RawRequest))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	// Apply modifications
	if opts.Modifications != nil {
		if err := s.applyModifications(req, opts.Modifications); err != nil {
			return nil, fmt.Errorf("apply modifications: %w", err)
		}
	}

	// Validate request (unless force=true)
	if !opts.Force {
		if err := ValidateRequest(req); err != nil {
			return nil, fmt.Errorf("validation failed: %w (use force=true to bypass)", err)
		}
	}

	currentReq := req
	currentTarget := opts.Target
	currentPath := req.Path
	if req.Query != "" {
		currentPath = req.Path + "?" + req.Query
	}

	for i := 0; i < maxRedirects; i++ {
		resp, err := s.sendRequest(ctx, currentReq, currentTarget, opts.Timeout)
		if err != nil {
			return nil, err
		}

		// Check for redirect
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return &SendResult{
				Response: resp,
				Duration: time.Since(start),
			}, nil
		}

		location := resp.GetHeader("Location")
		if location == "" {
			return &SendResult{
				Response: resp,
				Duration: time.Since(start),
			}, nil
		}

		// Build redirect request
		currentReq, currentTarget, currentPath, err = buildRedirectRequest(currentReq, location, currentTarget, currentPath, resp.StatusCode)
		if err != nil {
			// Can't follow redirect, return current response
			return &SendResult{
				Response: resp,
				Duration: time.Since(start),
			}, nil
		}
	}

	return nil, fmt.Errorf("too many redirects (max %d)", maxRedirects)
}

// sendRequest sends a single request and returns the response.
func (s *Sender) sendRequest(ctx context.Context, req *RawHTTP1Request, target Target, timeout time.Duration) (*RawHTTP1Response, error) {
	// Determine dial timeout
	dialTimeout := sendDialTimeout
	if timeout > 0 && timeout < dialTimeout {
		dialTimeout = timeout
	}

	// Connect to target
	targetAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	var conn net.Conn
	var err error

	if target.UsesHTTPS {
		tlsDialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: dialTimeout},
			Config: &tls.Config{
				ServerName:         target.Hostname,
				InsecureSkipVerify: true, // Required for security testing
				MinVersion:         tls.VersionTLS10,
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", targetAddr)
	} else {
		dialer := &net.Dialer{Timeout: dialTimeout}
		conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer func() { _ = conn.Close() }()

	// Set deadline from timeout
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// Send request
	var buf bytes.Buffer
	if _, err := conn.Write(req.Serialize(&buf)); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Read response
	resp, err := ParseResponse(bufio.NewReader(conn), req.Method)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

// applyModifications applies all modifications to a request.
func (s *Sender) applyModifications(req *RawHTTP1Request, mods *Modifications) error {
	// 1. Method override
	if mods.Method != "" {
		req.Method = mods.Method
	}

	// 2. Query parameter modifications
	if len(mods.SetParams) > 0 || len(mods.RemoveParams) > 0 {
		applyQueryModifications(req, mods)
	}

	// 3. Header modifications (sets, then removes)
	// Sort keys for deterministic order (map iteration is random)
	if len(mods.SetHeaders) > 0 {
		headerNames := make([]string, 0, len(mods.SetHeaders))
		for name := range mods.SetHeaders {
			headerNames = append(headerNames, name)
		}
		slices.Sort(headerNames)
		for _, name := range headerNames {
			req.SetHeader(name, mods.SetHeaders[name])
		}
	}
	for _, name := range mods.RemoveHeaders {
		req.RemoveHeader(name)
	}

	// 4. Body modifications (mutually exclusive)
	if mods.Body != nil {
		req.Body = mods.Body
		req.SetHeader("Content-Length", strconv.Itoa(len(mods.Body)))
	} else if len(mods.SetJSON) > 0 || len(mods.RemoveJSON) > 0 {
		if s.JSONModifier != nil {
			if len(req.Body) == 0 && len(mods.SetJSON) > 0 {
				req.Body = []byte("{}")
			}
			modified, err := s.JSONModifier(req.Body, mods.SetJSON, mods.RemoveJSON)
			if err != nil {
				return fmt.Errorf("JSON modification failed: %w", err)
			}
			req.Body = modified
			req.SetHeader("Content-Length", strconv.Itoa(len(modified)))
		}
	}

	return nil
}

// applyQueryModifications modifies query parameters in the request path.
func applyQueryModifications(req *RawHTTP1Request, mods *Modifications) {
	// Parse existing query
	values, _ := url.ParseQuery(req.Query)

	// Remove params first
	for _, key := range mods.RemoveParams {
		values.Del(key)
	}

	// Set params
	for key, value := range mods.SetParams {
		values.Set(key, value)
	}

	// Rebuild query
	req.Query = values.Encode()
}

// buildRedirectRequest builds a new request for following a redirect.
func buildRedirectRequest(originalReq *RawHTTP1Request, location string, currentTarget Target, currentPath string, status int) (*RawHTTP1Request, Target, string, error) {
	// Determine method and body preservation
	preserveMethod := status == 307 || status == 308
	preserveBody := status == 307 || status == 308

	// Resolve location
	newTarget, newPath, err := resolveRedirectLocation(location, currentTarget, currentPath)
	if err != nil {
		return nil, Target{}, "", err
	}

	// Determine if cross-origin
	isCrossOrigin := newTarget.Hostname != currentTarget.Hostname

	// Build new request
	newReq := &RawHTTP1Request{
		Method:   "GET",
		Path:     pathWithoutQuery(newPath),
		Query:    queryFromPath(newPath),
		Version:  originalReq.Version,
		Protocol: originalReq.Protocol,
	}

	if preserveMethod {
		newReq.Method = originalReq.Method
	}
	if preserveBody {
		newReq.Body = originalReq.Body
	}

	// Build Host header
	host := newTarget.Hostname
	if (newTarget.UsesHTTPS && newTarget.Port != 443) || (!newTarget.UsesHTTPS && newTarget.Port != 80) {
		host = fmt.Sprintf("%s:%d", newTarget.Hostname, newTarget.Port)
	}

	// Copy headers, applying redirect rules
	for _, h := range originalReq.Headers {
		lowerName := strings.ToLower(h.Name)

		// Skip Host (will be set)
		if lowerName == "host" {
			continue
		}

		// Skip body-related headers if not preserving body
		if !preserveBody && (lowerName == "content-length" || lowerName == "content-type" ||
			lowerName == "content-encoding" || lowerName == "transfer-encoding") {
			continue
		}

		// Skip Authorization on cross-origin redirects
		if isCrossOrigin && lowerName == "authorization" {
			continue
		}

		newReq.Headers = append(newReq.Headers, h)
	}

	// Set Host header
	newReq.SetHeader("Host", host)

	// Update Content-Length if body changed
	if preserveBody && len(newReq.Body) > 0 {
		newReq.SetHeader("Content-Length", strconv.Itoa(len(newReq.Body)))
	}

	return newReq, newTarget, newPath, nil
}

// resolveRedirectLocation resolves a Location header to target and path.
func resolveRedirectLocation(location string, currentTarget Target, currentPath string) (Target, string, error) {
	// Absolute URL
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		u, err := url.Parse(location)
		if err != nil {
			return Target{}, "", err
		}

		target := Target{
			Hostname:  u.Hostname(),
			UsesHTTPS: u.Scheme == "https",
		}
		if u.Port() != "" {
			target.Port, _ = strconv.Atoi(u.Port())
		} else if target.UsesHTTPS {
			target.Port = 443
		} else {
			target.Port = 80
		}

		return target, u.RequestURI(), nil
	}

	// Protocol-relative URL
	if strings.HasPrefix(location, "//") {
		scheme := "https"
		if !currentTarget.UsesHTTPS {
			scheme = "http"
		}
		u, err := url.Parse(scheme + ":" + location)
		if err != nil {
			return Target{}, "", err
		}

		target := Target{
			Hostname:  u.Hostname(),
			UsesHTTPS: scheme == "https",
		}
		if u.Port() != "" {
			target.Port, _ = strconv.Atoi(u.Port())
		} else if target.UsesHTTPS {
			target.Port = 443
		} else {
			target.Port = 80
		}

		return target, u.RequestURI(), nil
	}

	// Absolute path
	if strings.HasPrefix(location, "/") {
		return currentTarget, location, nil
	}

	// Relative path
	baseDir := path.Dir(pathWithoutQuery(currentPath))
	if baseDir == "." {
		baseDir = "/"
	}
	resolved := path.Join(baseDir, location)
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}

	return currentTarget, resolved, nil
}

// pathWithoutQuery returns the path portion before any query string.
func pathWithoutQuery(p string) string {
	if idx := strings.Index(p, "?"); idx >= 0 {
		return p[:idx]
	}
	return p
}

// queryFromPath extracts the query string from a path (without the ?).
func queryFromPath(p string) string {
	if idx := strings.Index(p, "?"); idx >= 0 {
		return p[idx+1:]
	}
	return ""
}
