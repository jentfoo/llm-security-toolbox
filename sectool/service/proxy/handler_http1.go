package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TODO - make timeout constants configurable
const (
	dialTimeout  = 30 * time.Second
	readTimeout  = 10 * time.Minute
	writeTimeout = 10 * time.Minute

	protocolHTTP11 = "http/1.1"
)

type HTTP1Handler struct {
	history      *HistoryStore
	maxBodyBytes int
}

// Handle processes a single HTTP/1.1 request.
func (h *HTTP1Handler) Handle(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) {
	startTime := time.Now()
	var buf bytes.Buffer

	req, err := ParseRequest(clientReader)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, ErrEmptyRequest) {
			log.Printf("proxy: failed to parse request: %v", err)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return
	}

	// Extract target from request
	target, err := h.extractTarget(req)
	if err != nil {
		log.Printf("proxy: failed to extract target: %v", err)
		h.sendError(clientConn, 400, "Bad Request: "+err.Error())
		return
	}

	// Rewrite proxy-form to origin-form
	h.rewriteToOriginForm(req, target)
	req.Protocol = protocolHTTP11

	// Connect to upstream
	upstreamAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	dialer := net.Dialer{Timeout: dialTimeout}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		log.Printf("proxy: failed to connect to %s: %v", upstreamAddr, err)
		h.sendError(clientConn, 502, "Bad Gateway: connection refused")
		h.storeEntry(req, nil, startTime)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	// Set write deadline
	_ = upstreamConn.SetWriteDeadline(time.Now().Add(writeTimeout))

	// Forward request to upstream
	if _, err := upstreamConn.Write(req.Serialize(&buf)); err != nil {
		log.Printf("proxy: failed to send request to %s: %v", upstreamAddr, err)
		h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		h.storeEntry(req, nil, startTime)
		return
	}

	// Set read deadline
	_ = upstreamConn.SetReadDeadline(time.Now().Add(readTimeout))

	// Parse response from upstream
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := ParseResponse(upstreamReader, req.Method)
	if err != nil {
		log.Printf("proxy: failed to parse response from %s: %v", upstreamAddr, err)
		h.sendError(clientConn, 502, "Bad Gateway: malformed response")
		h.storeEntry(req, nil, startTime)
		return
	}

	// Forward response to client
	_ = clientConn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := clientConn.Write(resp.Serialize(&buf)); err != nil {
		log.Printf("proxy: failed to send response to client: %v", err)
	}

	// Truncate response bodies if needed before storing in history
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.Body = req.Body[:h.maxBodyBytes]
	}
	if h.maxBodyBytes > 0 && len(resp.Body) > h.maxBodyBytes {
		resp.Body = resp.Body[:h.maxBodyBytes]
	}

	// Store in history
	h.storeEntry(req, resp, startTime)
}

// extractTarget determines the upstream server from the request.
func (h *HTTP1Handler) extractTarget(req *RawHTTP1Request) (*Target, error) {
	// Check for proxy-form URL (absolute URI)
	if strings.HasPrefix(req.Path, "http://") || strings.HasPrefix(req.Path, "https://") {
		return h.parseProxyFormURL(req.Path)
	}

	// Fallback to Host header
	host := req.GetHeader("Host")
	if host == "" {
		return nil, errors.New("no Host header and not a proxy-form request")
	}

	return h.parseHostPort(host, false)
}

// parseProxyFormURL parses an absolute URI like http://example.com:8080/path
func (h *HTTP1Handler) parseProxyFormURL(rawURL string) (*Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy-form URL: %w", err)
	}

	usesHTTPS := u.Scheme == "https"
	return h.parseHostPort(u.Host, usesHTTPS)
}

// parseHostPort parses host:port, defaulting port based on scheme.
// Handles IPv6 addresses with brackets (e.g., "[::1]:8080" or "[::1]").
func (h *HTTP1Handler) parseHostPort(hostPort string, usesHTTPS bool) (*Target, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port specified, use default
		// Handle IPv6 addresses with brackets but no port (e.g., "[::1]")
		host = strings.TrimSuffix(strings.TrimPrefix(hostPort, "["), "]")
		if usesHTTPS {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	return &Target{
		Hostname:  host,
		Port:      port,
		UsesHTTPS: usesHTTPS,
	}, nil
}

// rewriteToOriginForm converts proxy-form requests to origin-form.
func (h *HTTP1Handler) rewriteToOriginForm(req *RawHTTP1Request, target *Target) {
	// If path is an absolute URI, extract just the path component
	if strings.HasPrefix(req.Path, "http://") || strings.HasPrefix(req.Path, "https://") {
		u, err := url.Parse(req.Path)
		if err != nil {
			return
		}
		req.Path = u.Path
		if req.Path == "" {
			req.Path = "/"
		}
		// Query was already separated by parser
	}

	// Ensure Host header is set correctly
	hostHeader := target.Hostname
	if (target.UsesHTTPS && target.Port != 443) || (!target.UsesHTTPS && target.Port != 80) {
		hostHeader = fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	}
	req.SetHeader("Host", hostHeader)
}

// sendError writes an HTTP error response to the client.
func (h *HTTP1Handler) sendError(conn net.Conn, code int, message string) {
	resp := &RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: code,
		StatusText: message,
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Connection", Value: "close"},
		},
		Body: []byte(message + "\n"),
	}
	_, _ = conn.Write(resp.Serialize(bytes.NewBuffer(nil)))
}

// storeEntry saves the request/response pair to history.
func (h *HTTP1Handler) storeEntry(req *RawHTTP1Request, resp *RawHTTP1Response, startTime time.Time) {
	entry := &HistoryEntry{
		Protocol:  protocolHTTP11,
		Request:   req,
		Response:  resp,
		Timestamp: startTime,
		Duration:  time.Since(startTime),
	}
	h.history.Store(entry)
}

// HandleTLS handles HTTP/1.1 traffic over already-established TLS connections.
// Used by CONNECT handler after TLS handshake is complete.
// Loops handling request/response pairs until connection closes.
func (h *HTTP1Handler) HandleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader *bufio.Reader, upstreamReader *bufio.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !h.handleSingleTLS(ctx, clientConn, upstreamConn, clientReader, upstreamReader) {
			return
		}
	}
}

// handleSingleTLS handles a single HTTP/1.1 request/response exchange over TLS.
// Returns true to continue processing more requests, false to close connection.
func (h *HTTP1Handler) handleSingleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader, upstreamReader *bufio.Reader) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	// Parse request from client
	req, err := ParseRequest(clientReader)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, ErrEmptyRequest) {
			log.Printf("proxy: failed to parse TLS request: %v", err)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	req.Protocol = protocolHTTP11

	// Set write deadline on upstream
	_ = upstreamConn.SetWriteDeadline(time.Now().Add(writeTimeout))

	// Forward request to upstream
	if _, err := upstreamConn.Write(req.Serialize(&buf)); err != nil {
		log.Printf("proxy: failed to send TLS request: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		h.storeEntry(req, nil, startTime)
		return false
	}

	// Set read deadline on upstream
	_ = upstreamConn.SetReadDeadline(time.Now().Add(readTimeout))

	// Parse response from upstream
	resp, err := ParseResponse(upstreamReader, req.Method)
	if err != nil {
		log.Printf("proxy: failed to parse TLS response: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: malformed response")
		h.storeEntry(req, nil, startTime)
		return false
	}

	// Forward response to client
	_ = clientConn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := clientConn.Write(resp.Serialize(&buf)); err != nil {
		log.Printf("proxy: failed to send TLS response to client: %v", err)
		return false
	}

	// Truncate bodies if needed before storing in history
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.Body = req.Body[:h.maxBodyBytes]
	}
	if h.maxBodyBytes > 0 && len(resp.Body) > h.maxBodyBytes {
		resp.Body = resp.Body[:h.maxBodyBytes]
	}

	// Store in history
	h.storeEntry(req, resp, startTime)

	// Check Connection header for keep-alive
	connHeader := strings.ToLower(resp.GetHeader("Connection"))
	return connHeader != "close"
}
