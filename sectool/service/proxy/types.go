package proxy

import (
	"strings"
	"time"
)

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
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// GetHeader returns the first header value with the given name (case-insensitive).
// Returns empty string if not found.
func (r *RawHTTP1Response) GetHeader(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// SetHeader sets or replaces the first header with the given name (case-insensitive).
// If not found, appends a new header.
func (r *RawHTTP1Request) SetHeader(name, value string) {
	for i, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
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
		if !strings.EqualFold(h.Name, name) {
			filtered = append(filtered, h)
		}
	}
	r.Headers = filtered
}

// SetHeader sets or replaces the first header with the given name (case-insensitive).
// If not found, appends a new header.
func (r *RawHTTP1Response) SetHeader(name, value string) {
	for i, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			r.Headers[i].Value = value
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Response) RemoveHeader(name string) {
	filtered := r.Headers[:0]
	for _, h := range r.Headers {
		if !strings.EqualFold(h.Name, name) {
			filtered = append(filtered, h)
		}
	}
	r.Headers = filtered
}

// HistoryEntry represents a stored request/response pair.
// Embeds the parsed types directly for memory efficiency.
// The Serialize() methods on Request/Response reconstruct wire bytes on demand.
type HistoryEntry struct {
	// Offset is the monotonic history index
	Offset uint32 `json:"offset"`

	// Protocol identifies the HTTP version: "http/1.1", "h2", or "websocket"
	Protocol string `json:"protocol"`

	// HTTP/1.1 request/response (nil for HTTP/2)
	Request  *RawHTTP1Request  `json:"request,omitempty"`
	Response *RawHTTP1Response `json:"response,omitempty"`

	// HTTP/2 request/response (nil for HTTP/1.1)
	H2Request  *H2RequestData  `json:"h2_request,omitempty"`
	H2Response *H2ResponseData `json:"h2_response,omitempty"`
	H2StreamID uint32          `json:"h2_stream_id,omitempty"` // for debugging/correlation

	// WSFrames contains WebSocket frames for Protocol="websocket" entries.
	// The handshake is stored in Request/Response; frames are appended here.
	WSFrames []WSFrame `json:"ws_frames,omitempty"`

	// Timing metadata
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

// WSFrame represents a single WebSocket frame stored in history.
type WSFrame struct {
	// Direction is "to-server" or "to-client"
	Direction string `json:"direction"`

	// Opcode is the WebSocket opcode (1=text, 2=binary, 8=close, 9=ping, 10=pong)
	Opcode byte `json:"opcode"`

	// Payload is the frame payload (unmasked)
	Payload []byte `json:"payload,omitempty"`

	// Timestamp when the frame was captured
	Timestamp time.Time `json:"timestamp"`
}

// H2RequestData represents an HTTP/2 request for history storage.
type H2RequestData struct {
	// Pseudo-headers
	Method    string `json:"method"`    // from :method
	Scheme    string `json:"scheme"`    // from :scheme
	Authority string `json:"authority"` // from :authority
	Path      string `json:"path"`      // from :path

	// Regular headers (not pseudo-headers)
	Headers []Header `json:"headers"`

	// Body is the request body
	Body []byte `json:"body,omitempty"`
}

// H2ResponseData represents an HTTP/2 response for history storage.
type H2ResponseData struct {
	// StatusCode from :status pseudo-header
	StatusCode int `json:"status_code"`

	// Regular headers (not pseudo-headers)
	Headers []Header `json:"headers"`

	// Body is the response body
	Body []byte `json:"body,omitempty"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *H2RequestData) GetHeader(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *H2RequestData) SetHeader(name, value string) {
	for i, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			r.Headers[i].Value = value
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *H2ResponseData) GetHeader(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *H2ResponseData) SetHeader(name, value string) {
	for i, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			r.Headers[i].Value = value
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// Target specifies where to send a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}

// RuleApplier applies match/replace rules to requests and responses.
// Implemented by the service layer (CustomProxyBackend).
// Rules are applied in the order they were added (list order).
type RuleApplier interface {
	// ApplyRequestRules applies request header and body rules.
	// Returns the modified request (may be same instance if no changes).
	ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request

	// ApplyResponseRules applies response header and body rules.
	// Handles decompression/recompression for body rules.
	ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response

	// ApplyRequestBodyOnlyRules applies only body rules to a request body.
	// Used by HTTP/2 where headers are sent separately before body.
	// Does not apply header rules.
	ApplyRequestBodyOnlyRules(body []byte) []byte

	// ApplyResponseBodyOnlyRules applies only body rules to a response body.
	// Used by HTTP/2 where headers are sent separately before body.
	// Requires headers for Content-Encoding detection (compression-aware).
	// Does not apply header rules.
	ApplyResponseBodyOnlyRules(body []byte, headers []Header) []byte

	// ApplyWSRules applies WebSocket rules to frame payload.
	// direction is "ws:to-server" or "ws:to-client".
	ApplyWSRules(payload []byte, direction string) []byte

	// HasBodyRules returns true if there are body rules for request or response.
	// Used by HTTP/2 handler to decide whether to buffer full bodies.
	// isRequest=true checks for request_body rules, false checks for response_body rules.
	HasBodyRules(isRequest bool) bool
}
