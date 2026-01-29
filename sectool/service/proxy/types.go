package proxy

import "time"

// Header represents a single HTTP header preserving original formatting.
type Header struct {
	// Name preserves original casing and whitespace anomalies
	// (e.g., "Content-Type", "content-type", or "Header " with trailing space)
	Name string `json:"name"`

	// Value is the header value with leading/trailing whitespace trimmed
	Value string `json:"value"`
}

// RawHTTP1Request represents a parsed HTTP/1.1 request with wire-level fidelity.
// The Serialize() method reconstructs wire bytes from the stored components.
type RawHTTP1Request struct {
	// Request line components
	Method  string `json:"method"`          // "GET", "POST", etc.
	Path    string `json:"path"`            // path without query string, e.g., "/path"
	Query   string `json:"query,omitempty"` // query string without leading ?, e.g., "foo=bar"
	Version string `json:"version"`         // "HTTP/1.1" or "HTTP/1.0"

	// Headers preserves order and original name casing/whitespace
	Headers []Header `json:"headers"`

	// Body is the request body (decoded if chunked, raw otherwise)
	// For chunked encoding, this contains the reassembled body without chunk framing
	Body []byte `json:"body,omitempty"`

	// Trailers for chunked encoding (raw bytes, rare but must preserve)
	Trailers []byte `json:"trailers,omitempty"`

	// Protocol metadata for replay fidelity
	Protocol string `json:"protocol"` // "http/1.1" - stored for history/replay
}

// RawHTTP1Response represents a parsed HTTP/1.1 response with wire-level fidelity.
type RawHTTP1Response struct {
	// Status line components
	Version    string `json:"version"`               // "HTTP/1.1" or "HTTP/1.0"
	StatusCode int    `json:"status_code"`           // 200, 404, etc.
	StatusText string `json:"status_text,omitempty"` // "OK", "Not Found", etc.

	// Headers preserves order and original name casing
	Headers []Header `json:"headers"`

	// Body is the response body (decoded if chunked, raw otherwise)
	Body []byte `json:"body,omitempty"`

	// Trailers for chunked encoding (raw bytes)
	Trailers []byte `json:"trailers,omitempty"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
// Returns empty string if not found.
func (r *RawHTTP1Request) GetHeader(name string) string {
	for _, h := range r.Headers {
		if equalFoldASCII(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// GetHeader returns the first header value with the given name (case-insensitive).
// Returns empty string if not found.
func (r *RawHTTP1Response) GetHeader(name string) string {
	for _, h := range r.Headers {
		if equalFoldASCII(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// SetHeader sets or replaces the first header with the given name (case-insensitive).
// If not found, appends a new header.
func (r *RawHTTP1Request) SetHeader(name, value string) {
	for i, h := range r.Headers {
		if equalFoldASCII(h.Name, name) {
			r.Headers[i].Value = value
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Request) RemoveHeader(name string) {
	filtered := r.Headers[:0]
	for _, h := range r.Headers {
		if !equalFoldASCII(h.Name, name) {
			filtered = append(filtered, h)
		}
	}
	r.Headers = filtered
}

// equalFoldASCII compares two ASCII strings case-insensitively.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// HistoryEntry represents a stored request/response pair.
// Embeds the parsed types directly for memory efficiency.
// The Serialize() methods on Request/Response reconstruct wire bytes on demand.
type HistoryEntry struct {
	// Offset is the monotonic history index
	Offset uint32 `json:"offset"`

	// Protocol identifies the HTTP version: "http/1.1" or "h2"
	Protocol string `json:"protocol"`

	// HTTP/1.1 request/response (nil for HTTP/2)
	Request  *RawHTTP1Request  `json:"request,omitempty"`
	Response *RawHTTP1Response `json:"response,omitempty"`

	// Timing metadata
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

// Target specifies where to send a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}
