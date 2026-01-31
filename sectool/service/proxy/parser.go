package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

var (
	ErrEmptyRequest    = errors.New("empty request")
	ErrEmptyResponse   = errors.New("empty response")
	ErrInvalidRequest  = errors.New("invalid request line")
	ErrInvalidResponse = errors.New("invalid status line")
)

// parseRequest parses an HTTP/1.1 request from the reader.
// Returns error only for truly unparseable input.
// Tolerant of malformed input to support security testing.
func parseRequest(r io.Reader) (*RawHTTP1Request, error) {
	br := bufio.NewReader(r)

	line, err := readLine(br)
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, ErrEmptyRequest
		} else if len(line) == 0 {
			return nil, err
		}
		// Continue with partial line
	}

	method, path, query, version, err := ParseRequestLine(line)
	if err != nil {
		return nil, err
	}

	req := &RawHTTP1Request{
		Method:   method,
		Path:     path,
		Query:    query,
		Version:  version,
		Protocol: strings.ToLower(version),
	}

	if req.Headers, err = readHeaders(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Determine body handling
	if req.Body, req.Trailers, err = readRequestBody(br, req); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return req, nil
}

// parseResponse parses an HTTP/1.1 response from the reader.
// The request method is needed to determine body handling for HEAD responses.
func parseResponse(r io.Reader, requestMethod string) (*RawHTTP1Response, error) {
	br := bufio.NewReader(r)

	// Read status line
	line, err := readLine(br)
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, ErrEmptyResponse
		} else if len(line) == 0 {
			return nil, err
		}
	}

	version, code, text, err := parseStatusLine(line)
	if err != nil {
		return nil, err
	}

	resp := &RawHTTP1Response{
		Version:    version,
		StatusCode: code,
		StatusText: text,
	}

	if resp.Headers, err = readHeaders(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Determine body handling - HEAD responses have no body
	if requestMethod == "HEAD" {
		return resp, nil
	}

	// 1xx, 204, 304 responses have no body
	if code < 200 || code == 204 || code == 304 {
		return resp, nil
	}

	if resp.Body, resp.Trailers, err = readResponseBody(br, resp); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return resp, nil
}

// readLine reads a line from the reader, handling both CRLF and bare LF.
// Returns the line without the line ending.
func readLine(br *bufio.Reader) ([]byte, error) {
	// TODO - Consider handling bare CR (\r without \n) as line ending per HTTP spec edge case
	line, err := br.ReadBytes('\n')
	if err != nil {
		// No \n found - trim any trailing CR and return
		line = bytes.TrimSuffix(line, []byte("\r"))
		return line, err
	}
	line = line[:len(line)-1]
	line = bytes.TrimSuffix(line, []byte("\r"))
	return line, nil
}

// ParseRequestLine extracts method, path, query, version from request line.
// Tolerant: accepts malformed lines if method and path are extractable.
func ParseRequestLine(line []byte) (method, path, query, version string, err error) {
	s := string(line)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 2 {
		return "", "", "", "", ErrInvalidRequest
	}

	method = parts[0]
	fullPath := parts[1]
	if len(parts) >= 3 {
		version = strings.TrimSpace(parts[2])
	} else {
		version = "HTTP/1.1" // Default if missing
	}

	// Handle proxy-form URLs (absolute URIs like http://host/path)
	if strings.HasPrefix(fullPath, "http://") || strings.HasPrefix(fullPath, "https://") {
		// Keep full URL as path for proxy-form requests
		if idx := strings.Index(fullPath, "?"); idx >= 0 {
			path = fullPath[:idx]
			query = fullPath[idx+1:]
		} else {
			path = fullPath
		}
		return method, path, query, version, nil
	}

	// Origin-form: split path and query
	if idx := strings.Index(fullPath, "?"); idx >= 0 {
		path = fullPath[:idx]
		query = fullPath[idx+1:]
	} else {
		path = fullPath
	}

	return method, path, query, version, nil
}

// parseStatusLine extracts version, status code, status text from status line.
func parseStatusLine(line []byte) (version string, code int, text string, err error) {
	s := string(line)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 2 {
		return "", 0, "", ErrInvalidResponse
	}

	version = parts[0]
	code, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", ErrInvalidResponse
	}

	if len(parts) >= 3 {
		text = parts[2]
	}

	return version, code, text, nil
}

// readHeaders reads headers until an empty line.
// Handles obs-fold (continuation lines starting with SP or HTAB).
func readHeaders(br *bufio.Reader) ([]Header, error) {
	var headers []Header
	for {
		line, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return headers, err
		}

		// Empty line signals end of headers
		if len(line) == 0 {
			return headers, nil
		}

		// Check for obs-fold (continuation line)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Append to previous header value
			if len(headers) > 0 {
				// Join with a single space, trimming the leading whitespace
				headers[len(headers)-1].Value += " " + strings.TrimLeft(string(line), " \t")
			}
			if errors.Is(err, io.EOF) {
				return headers, nil
			}
			continue
		}

		header := parseHeaderLine(line)
		headers = append(headers, header)

		if errors.Is(err, io.EOF) {
			return headers, nil
		}
	}
}

// parseHeaderLine parses "Name: Value" into Header struct.
// Preserves whitespace anomalies in header name (e.g., "Header " with trailing space).
func parseHeaderLine(line []byte) Header {
	idx := bytes.IndexByte(line, ':')
	if idx < 0 {
		// No colon - treat entire line as name with empty value
		return Header{Name: string(line), Value: ""}
	}

	// Name includes everything before colon (preserving whitespace anomalies)
	name := string(line[:idx])

	// Value is everything after colon, with leading/trailing whitespace trimmed
	value := strings.TrimSpace(string(line[idx+1:]))

	return Header{Name: name, Value: value}
}

// readRequestBody reads the request body based on headers.
func readRequestBody(br *bufio.Reader, req *RawHTTP1Request) (body, trailers []byte, err error) {
	// Check for chunked encoding first (takes precedence over Content-Length)
	te := req.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		return readChunkedBody(br)
	}

	clStr := req.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl <= 0 {
			return nil, nil, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, err
	}

	// No body indicator for requests
	return nil, nil, nil
}

// readResponseBody reads the response body based on headers.
func readResponseBody(br *bufio.Reader, resp *RawHTTP1Response) (body, trailers []byte, err error) {
	// Check for chunked encoding first
	te := resp.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		return readChunkedBody(br)
	}

	clStr := resp.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl < 0 {
			// Invalid CL, try reading to EOF
			body, err := io.ReadAll(br)
			return body, nil, err
		} else if cl == 0 {
			return nil, nil, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, err
	}

	// No Content-Length or chunked: read until EOF
	body, err = io.ReadAll(br)
	return body, nil, err
}

// readChunkedBody reads chunked transfer encoding.
// Returns decoded body and any trailing headers as raw bytes.
func readChunkedBody(br *bufio.Reader) (body, trailers []byte, err error) {
	var bodyBuf bytes.Buffer
	for {
		sizeLine, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return bodyBuf.Bytes(), nil, err
		}

		// Parse chunk size (may have chunk extensions after ;)
		sizeStr := string(sizeLine)
		if idx := strings.IndexByte(sizeStr, ';'); idx >= 0 {
			sizeStr = sizeStr[:idx]
		}
		sizeStr = strings.TrimSpace(sizeStr)

		size, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			// Invalid chunk size - return what we have
			return bodyBuf.Bytes(), nil, nil
		}

		if size == 0 {
			// Last chunk - read trailers
			trailers, _ = readTrailers(br)
			return bodyBuf.Bytes(), trailers, nil
		}

		// Read chunk data
		chunk := make([]byte, size)
		if _, err = io.ReadFull(br, chunk); err != nil {
			return bodyBuf.Bytes(), nil, err
		}
		bodyBuf.Write(chunk)

		// Read trailing CRLF after chunk data
		_, _ = readLine(br)
	}
}

// readTrailers reads trailer headers after the last chunk.
func readTrailers(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return buf.Bytes(), err
		}

		if len(line) == 0 {
			// Empty line ends trailers
			return buf.Bytes(), nil
		}

		buf.Write(line)
		buf.WriteString("\r\n")

		if errors.Is(err, io.EOF) {
			return buf.Bytes(), nil
		}
	}
}

// Serialize reconstructs wire bytes from the request components.
// Uses Content-Length framing (not chunked) for the body.
// This method does not modify the receiver.
//
// TODO - Add chunked encoding support for wire-fidelity replay. Currently all
// requests are normalized to Content-Length framing, which prevents replaying
// chunked requests "as-captured" for protocol-level testing (e.g., HTTP smuggling).
func (r *RawHTTP1Request) Serialize(buf *bytes.Buffer) []byte {
	buf.Reset()
	// Request line
	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(r.Path)
	if r.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(r.Query)
	}
	buf.WriteByte(' ')
	buf.WriteString(r.Version)
	buf.WriteString("\r\n")

	// Build headers list, filtering chunked TE and Content-Length
	headers := make([]Header, 0, len(r.Headers)+1)
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			continue // Skip Transfer-Encoding: chunked (we use Content-Length instead)
		} else if strings.EqualFold(h.Name, "Content-Length") {
			continue // skip content length, added below with an updated value
		}

		headers = append(headers, h)
	}

	// Add Content-Length if body present and not already set
	if len(r.Body) > 0 {
		headers = append(headers, Header{
			Name:  "Content-Length",
			Value: strconv.Itoa(len(r.Body)),
		})
	}

	// Write headers
	for _, h := range headers {
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	// Header terminator
	buf.WriteString("\r\n")

	buf.Write(r.Body)

	return buf.Bytes()
}

// Serialize reconstructs wire bytes from the response components.
// This method does not modify the receiver.
func (r *RawHTTP1Response) Serialize(buf *bytes.Buffer) []byte {
	r.SerializeHeaders(buf)
	buf.Write(r.Body)
	return buf.Bytes()
}

// SerializeHeaders reconstructs the status line and headers only (no body).
// Useful for SendRequestResult where headers and body are returned separately.
func (r *RawHTTP1Response) SerializeHeaders(buf *bytes.Buffer) []byte {
	buf.Reset()
	// Status line
	buf.WriteString(r.Version)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.StatusCode))
	if r.StatusText != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.StatusText)
	}
	buf.WriteString("\r\n")

	// Build headers list, filtering chunked TE and Content-Length
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			continue // Skip Transfer-Encoding: chunked (we use Content-Length instead)
		} else if strings.EqualFold(h.Name, "Content-Length") {
			continue // skip Content-Length, added below
		}

		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}
	if len(r.Body) > 0 {
		buf.WriteString("Content-Length: ")
		buf.WriteString(strconv.Itoa(len(r.Body)))
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n") // Header terminator
	return buf.Bytes()
}
