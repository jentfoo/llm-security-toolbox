package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
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

	// Protocol specifies the original request's protocol.
	// Values: "http/1.1", "h2", or "" (defaults to http/1.1)
	// When "h2", the sender will negotiate HTTP/2 with the server.
	Protocol string
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
	resp, err := s.sendRequestWithProtocol(ctx, req, opts.Target, opts.Timeout, opts.Protocol)
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
	currentProtocol := opts.Protocol
	if req.Query != "" {
		currentPath = req.Path + "?" + req.Query
	}

	for i := 0; i < maxRedirects; i++ {
		resp, err := s.sendRequestWithProtocol(ctx, currentReq, currentTarget, opts.Timeout, currentProtocol)
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
		var newTarget Target
		currentReq, newTarget, currentPath, err = buildRedirectRequest(currentReq, location, currentTarget, currentPath, resp.StatusCode)
		if err != nil {
			// Can't follow redirect, return current response
			return &SendResult{
				Response: resp,
				Duration: time.Since(start),
			}, nil
		}

		// Check for cross-origin redirect (different scheme, host, or port).
		// Per spec, cross-origin includes scheme/port changes for header stripping.
		isCrossOrigin := newTarget.Hostname != currentTarget.Hostname ||
			newTarget.Port != currentTarget.Port ||
			newTarget.UsesHTTPS != currentTarget.UsesHTTPS

		// For cross-origin H2 redirects, the new target's H2 capability will be
		// probed when sendRequestWithProtocol attempts the TLS handshake with H2 ALPN.
		// If the server doesn't support H2, an error is returned (per spec: no silent downgrade).
		// Same-origin redirects maintain the current protocol.
		if isCrossOrigin && currentProtocol == "h2" && !newTarget.UsesHTTPS {
			// H2 requires HTTPS - if redirect goes to HTTP, that's a protocol mismatch
			return nil, errors.New("cross-origin redirect from HTTPS to HTTP cannot maintain HTTP/2; replay as HTTP/1.1 manually if desired")
		}
		currentTarget = newTarget
	}

	return nil, fmt.Errorf("too many redirects (max %d)", maxRedirects)
}

// sendRequestWithProtocol sends a single request with protocol preference.
func (s *Sender) sendRequestWithProtocol(ctx context.Context, req *RawHTTP1Request, target Target, timeout time.Duration, protocol string) (*RawHTTP1Response, error) {
	// Validate protocol value
	switch protocol {
	case "", "http/1.1", "h2":
		// Valid values
	default:
		return nil, fmt.Errorf("invalid protocol %q: must be \"http/1.1\", \"h2\", or empty", protocol)
	}

	// Determine dial timeout
	dialTimeout := sendDialTimeout
	if timeout > 0 && timeout < dialTimeout {
		dialTimeout = timeout
	}

	// Connect to target
	targetAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	var conn net.Conn
	var err error

	// HTTP/2 requires HTTPS
	if protocol == "h2" && !target.UsesHTTPS {
		return nil, errors.New("HTTP/2 requires HTTPS; cannot send h2 request to non-TLS target")
	}

	if target.UsesHTTPS {
		// Build ALPN list based on protocol preference
		var nextProtos []string
		minVersion := uint16(tls.VersionTLS10)
		if protocol == "h2" {
			// Prefer H2, fallback to H1
			nextProtos = []string{"h2", "http/1.1"}
			// HTTP/2 requires TLS 1.2+ in practice (ALPN extension, cipher requirements)
			minVersion = tls.VersionTLS12
		} else {
			// HTTP/1.1 only
			nextProtos = []string{"http/1.1"}
		}

		tlsDialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: dialTimeout},
			Config: &tls.Config{
				ServerName:         target.Hostname,
				InsecureSkipVerify: true, // Required for security testing
				MinVersion:         minVersion,
				NextProtos:         nextProtos,
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
		}

		// Check negotiated protocol
		tlsConn := conn.(*tls.Conn)
		negotiated := tlsConn.ConnectionState().NegotiatedProtocol

		if protocol == "h2" {
			if negotiated == "h2" {
				// Send as HTTP/2
				defer func() { _ = conn.Close() }()
				if timeout > 0 {
					_ = conn.SetDeadline(time.Now().Add(timeout))
				}
				return s.sendH2Request(ctx, conn, req, target)
			}
			// Server doesn't support H2, return error
			_ = conn.Close()
			return nil, fmt.Errorf("server does not support HTTP/2 (negotiated %q); original request was HTTP/2, replay as HTTP/1.1 manually if desired", negotiated)
		}
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

	// Send request as HTTP/1.1
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

	// Cross-origin includes scheme, host, or port changes (for header stripping decisions)
	isCrossOrigin := newTarget.Hostname != currentTarget.Hostname ||
		newTarget.Port != currentTarget.Port ||
		newTarget.UsesHTTPS != currentTarget.UsesHTTPS

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

// sendH2Request sends a request using HTTP/2 protocol.
// The connection must already be established with ALPN negotiating "h2".
func (s *Sender) sendH2Request(ctx context.Context, conn net.Conn, req *RawHTTP1Request, target Target) (*RawHTTP1Response, error) {
	// Create HTTP/2 connection wrapper
	h2c := newH2Conn(conn)

	// Create framer for writing
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = nil // We decode HPACK ourselves

	// Send client preface (magic + SETTINGS)
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("send H2 preface: %w", err)
	}

	// Send our SETTINGS frame
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: localInitialWindow},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderListSize},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0}, // Disable server push
	); err != nil {
		return nil, fmt.Errorf("send H2 SETTINGS: %w", err)
	}

	// Read server's SETTINGS
	if err := s.readH2SettingsAndAck(framer, h2c); err != nil {
		return nil, fmt.Errorf("H2 handshake: %w", err)
	}

	// Build request path
	requestPath := req.Path
	if req.Query != "" {
		requestPath = req.Path + "?" + req.Query
	}

	// Derive :authority from Host header (may have been modified during replay).
	// Fall back to target if Host header is absent.
	authority := req.GetHeader("Host")
	if authority == "" {
		authority = target.Hostname
		if target.Port != 443 {
			authority = fmt.Sprintf("%s:%d", target.Hostname, target.Port)
		}
	}

	// Build pseudo-headers
	pseudos := map[string]string{
		":method":    req.Method,
		":path":      requestPath,
		":scheme":    "https",
		":authority": authority,
	}

	// Encode headers using HPACK (filters forbidden H2 headers including Host)
	encoded, err := h2c.encodeHeaders(pseudos, req.Headers)
	if err != nil {
		return nil, fmt.Errorf("encode H2 headers: %w", err)
	}

	// Determine flags
	streamID := uint32(1) // Client uses odd stream IDs
	hasBody := len(req.Body) > 0
	endStream := !hasBody

	// Get peer's max frame size for chunking
	maxFrameSize := int(h2c.getMaxFrameSize())

	// Send HEADERS frame (with CONTINUATION if header block exceeds max frame size)
	if err := s.writeH2Headers(framer, streamID, encoded, endStream, maxFrameSize); err != nil {
		return nil, err
	}

	// Initialize stream send window
	h2c.initStreamSendWindow(streamID)

	// Buffer for frames read during flow control waiting.
	// These may include early response frames (e.g., auth failures) that arrive
	// before we finish sending the request body.
	var bufferedFrames []http2.Frame

	// Send DATA frames if body present (chunked to max frame size with flow control)
	if hasBody {
		if err := s.writeH2DataWithReader(ctx, framer, h2c, streamID, req.Body, maxFrameSize, &bufferedFrames); err != nil {
			return nil, err
		}
	}

	// Read response, processing any buffered frames first
	return s.readH2Response(framer, h2c, streamID, bufferedFrames)
}

// writeH2Headers writes HEADERS and any required CONTINUATION frames.
func (s *Sender) writeH2Headers(framer *http2.Framer, streamID uint32, encoded []byte, endStream bool, maxFrameSize int) error {
	if len(encoded) <= maxFrameSize {
		// Fits in single HEADERS frame
		return framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: encoded,
			EndStream:     endStream,
			EndHeaders:    true,
		})
	}

	// Need CONTINUATION frames
	first := encoded[:maxFrameSize]
	rest := encoded[maxFrameSize:]

	// Send initial HEADERS (no END_HEADERS)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: first,
		EndStream:     endStream,
		EndHeaders:    false,
	}); err != nil {
		return fmt.Errorf("send H2 HEADERS: %w", err)
	}

	// Send CONTINUATION frames
	for len(rest) > 0 {
		chunk := rest
		endHeaders := true
		if len(rest) > maxFrameSize {
			chunk = rest[:maxFrameSize]
			endHeaders = false
		}
		if err := framer.WriteContinuation(streamID, endHeaders, chunk); err != nil {
			return fmt.Errorf("send H2 CONTINUATION: %w", err)
		}
		rest = rest[len(chunk):]
	}

	return nil
}

// writeH2DataWithReader writes DATA frames with integrated flow control frame reading.
// For small bodies that fit in the initial window, no reading is needed.
// For larger bodies, we poll for WINDOW_UPDATE frames when blocked.
// Any non-control frames read during flow control waiting are buffered for later processing.
func (s *Sender) writeH2DataWithReader(ctx context.Context, framer *http2.Framer, h2c *h2Conn, streamID uint32, body []byte, maxFrameSize int, bufferedFrames *[]http2.Frame) error {
	remaining := body

	for len(remaining) > 0 {
		// Determine chunk size (limited by max frame size)
		chunkSize := len(remaining)
		if chunkSize > maxFrameSize {
			chunkSize = maxFrameSize
		}

		// Try to consume send window
		if !h2c.consumeSendWindow(streamID, chunkSize) {
			// Not enough window - poll for WINDOW_UPDATE frames
			if err := s.pollForWindowUpdate(ctx, framer, h2c, streamID, chunkSize, bufferedFrames); err != nil {
				return err
			}
		}

		// Send DATA frame
		isLast := len(remaining) <= chunkSize
		chunk := remaining[:chunkSize]
		if err := framer.WriteData(streamID, isLast, chunk); err != nil {
			return fmt.Errorf("send H2 DATA: %w", err)
		}

		remaining = remaining[chunkSize:]
	}

	return nil
}

// pollForWindowUpdate reads frames until we have enough send window credit.
// Processes WINDOW_UPDATE, SETTINGS, PING, and detects RST_STREAM/GOAWAY.
// Any response frames (HEADERS, DATA, CONTINUATION) are buffered for later processing
// by readH2Response to prevent frame loss during large request body uploads.
func (s *Sender) pollForWindowUpdate(ctx context.Context, framer *http2.Framer, h2c *h2Conn, streamID uint32, needed int, bufferedFrames *[]http2.Frame) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("connection closed while waiting for flow control")
			}
			return fmt.Errorf("read frame while waiting for window update: %w", err)
		}

		switch f := frame.(type) {
		case *http2.WindowUpdateFrame:
			h2c.updateSendWindow(f.StreamID, f.Increment)
			// Check if we now have enough credit
			if h2c.consumeSendWindow(streamID, needed) {
				return nil
			}

		case *http2.SettingsFrame:
			if !f.IsAck() {
				var settings []http2.Setting
				_ = f.ForeachSetting(func(s http2.Setting) error {
					settings = append(settings, s)
					return nil
				})
				h2c.updateSettings(settings)
				for _, s := range settings {
					if s.ID == http2.SettingInitialWindowSize {
						h2c.updateSendWindowFromSettings(s.Val)
					}
				}
				_ = framer.WriteSettingsAck()
				// Settings might have updated window, check again
				if h2c.consumeSendWindow(streamID, needed) {
					return nil
				}
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				_ = framer.WritePing(true, f.Data)
			}

		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return fmt.Errorf("stream reset during body send: %v", f.ErrCode)
			}
			// Buffer RST_STREAM for other streams
			*bufferedFrames = append(*bufferedFrames, f)

		case *http2.GoAwayFrame:
			return fmt.Errorf("server sent GOAWAY during body send: %s", string(f.DebugData()))

		case *http2.HeadersFrame, *http2.DataFrame, *http2.ContinuationFrame:
			// Buffer response frames - server may send early response (e.g., auth failure)
			// before we finish uploading the request body
			*bufferedFrames = append(*bufferedFrames, f)

		default:
			// Ignore other control frames
		}
	}
}

// readH2SettingsAndAck reads server SETTINGS and sends ACK.
// Returns after receiving server SETTINGS and sending our ACK, without
// waiting for server to ACK our settings. This is more resilient against
// misbehaving servers while remaining spec-compliant.
func (s *Sender) readH2SettingsAndAck(framer *http2.Framer, h2c *h2Conn) error {
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("read frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				// Server ACKed our settings - continue waiting for server's own SETTINGS
				continue
			}
			// Process server settings
			var settings []http2.Setting
			_ = f.ForeachSetting(func(s http2.Setting) error {
				settings = append(settings, s)
				return nil
			})
			h2c.updateSettings(settings)
			// Update flow control windows from INITIAL_WINDOW_SIZE
			for _, s := range settings {
				if s.ID == http2.SettingInitialWindowSize {
					h2c.updateSendWindowFromSettings(s.Val)
				}
			}
			// Send ACK
			if err := framer.WriteSettingsAck(); err != nil {
				return fmt.Errorf("send SETTINGS ACK: %w", err)
			}
			// Handshake complete - we've received server settings and sent our ACK.
			// Server's ACK of our settings (if it arrives) will be handled during
			// response reading.
			return nil

		case *http2.GoAwayFrame:
			return fmt.Errorf("server sent GOAWAY: %s", string(f.DebugData()))

		case *http2.WindowUpdateFrame:
			h2c.updateSendWindow(f.StreamID, f.Increment)

		default:
			// Ignore other frames during handshake
		}
	}
}

// readH2Response reads an HTTP/2 response from the framer.
// It first processes any frames buffered during flow control waiting,
// then continues reading from the framer.
func (s *Sender) readH2Response(framer *http2.Framer, h2c *h2Conn, streamID uint32, bufferedFrames []http2.Frame) (*RawHTTP1Response, error) {
	var headers []Header
	var trailers []Header
	var statusCode int
	var body bytes.Buffer
	var gotInitialHeaders bool

	// Header block accumulator for HEADERS + CONTINUATION reassembly.
	// HPACK requires decoding the complete block, not individual fragments.
	var headerBlock bytes.Buffer
	var headersEndStream bool

	// Index into buffered frames
	bufIdx := 0

	// getNextFrame returns the next frame, first from buffer, then from framer
	getNextFrame := func() (http2.Frame, error) {
		if bufIdx < len(bufferedFrames) {
			f := bufferedFrames[bufIdx]
			bufIdx++
			return f, nil
		}
		return framer.ReadFrame()
	}

	for {
		frame, err := getNextFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}

			// Start accumulating header block
			headerBlock.Reset()
			headerBlock.Write(f.HeaderBlockFragment())
			headersEndStream = f.StreamEnded()

			// Only decode when END_HEADERS is set (no CONTINUATION follows)
			if f.HeadersEnded() {
				pseudos, hdrs, err := h2c.decodeHeaders(headerBlock.Bytes())
				if err != nil {
					return nil, fmt.Errorf("decode headers: %w", err)
				}

				if !gotInitialHeaders {
					// First HEADERS block: response headers
					if status, ok := pseudos[":status"]; ok {
						statusCode, _ = strconv.Atoi(status)
					}
					headers = hdrs
					gotInitialHeaders = true
				} else {
					// Subsequent HEADERS block: trailers (append to trailers, don't overwrite headers)
					trailers = append(trailers, hdrs...)
				}

				if headersEndStream {
					return buildH2ResponseWithTrailers(statusCode, headers, trailers, body.Bytes()), nil
				}
			}

		case *http2.ContinuationFrame:
			if f.StreamID != streamID {
				continue
			}

			// Accumulate continuation fragment
			headerBlock.Write(f.HeaderBlockFragment())

			// Decode only when END_HEADERS is set
			if f.HeadersEnded() {
				pseudos, hdrs, err := h2c.decodeHeaders(headerBlock.Bytes())
				if err != nil {
					return nil, fmt.Errorf("decode headers: %w", err)
				}

				if !gotInitialHeaders {
					// First HEADERS block: response headers
					if status, ok := pseudos[":status"]; ok {
						statusCode, _ = strconv.Atoi(status)
					}
					headers = hdrs
					gotInitialHeaders = true
				} else {
					// Subsequent HEADERS block: trailers
					trailers = append(trailers, hdrs...)
				}

				if headersEndStream {
					return buildH2ResponseWithTrailers(statusCode, headers, trailers, body.Bytes()), nil
				}
			}

		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}

			// Consume receive window (track how much data we've received)
			dataLen := len(f.Data())
			if dataLen > 0 {
				if err := h2c.consumeRecvWindow(streamID, dataLen); err != nil {
					return nil, fmt.Errorf("flow control error: %w", err)
				}
			}

			body.Write(f.Data())

			// Check if we need to send WINDOW_UPDATE to keep data flowing
			if connUpdate, streamUpdate := h2c.needsWindowUpdate(streamID); connUpdate > 0 || streamUpdate > 0 {
				if connUpdate > 0 {
					_ = framer.WriteWindowUpdate(0, connUpdate)
				}
				if streamUpdate > 0 {
					_ = framer.WriteWindowUpdate(streamID, streamUpdate)
				}
			}

			if f.StreamEnded() {
				return buildH2ResponseWithTrailers(statusCode, headers, trailers, body.Bytes()), nil
			}

		case *http2.RSTStreamFrame:
			if f.StreamID != streamID {
				continue
			}
			return nil, fmt.Errorf("stream reset: %v", f.ErrCode)

		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("server sent GOAWAY: %s", string(f.DebugData()))

		case *http2.WindowUpdateFrame:
			h2c.updateSendWindow(f.StreamID, f.Increment)

		case *http2.SettingsFrame:
			if !f.IsAck() {
				// Process settings and ACK
				var settings []http2.Setting
				_ = f.ForeachSetting(func(s http2.Setting) error {
					settings = append(settings, s)
					return nil
				})
				h2c.updateSettings(settings)
				for _, s := range settings {
					if s.ID == http2.SettingInitialWindowSize {
						h2c.updateSendWindowFromSettings(s.Val)
					}
				}
				// Send ACK (ignore errors during response reading)
				_ = framer.WriteSettingsAck()
			}

		case *http2.PingFrame:
			// Respond to pings
			if !f.IsAck() {
				_ = framer.WritePing(true, f.Data)
			}

		default:
			// Ignore other frames
		}
	}

	// Connection closed without proper stream end
	if statusCode > 0 {
		return buildH2ResponseWithTrailers(statusCode, headers, trailers, body.Bytes()), nil
	}
	return nil, errors.New("connection closed before response complete")
}

// buildH2ResponseWithTrailers creates a RawHTTP1Response from HTTP/2 response data.
// Trailers are appended to headers for compatibility with HTTP/1.1-style response handling.
func buildH2ResponseWithTrailers(statusCode int, headers, trailers []Header, body []byte) *RawHTTP1Response {
	allHeaders := headers
	if len(trailers) > 0 {
		allHeaders = append(allHeaders, trailers...)
	}
	return &RawHTTP1Response{
		Version:    "HTTP/2",
		StatusCode: statusCode,
		StatusText: http.StatusText(statusCode),
		Headers:    allHeaders,
		Body:       body,
	}
}
