package mcp

// ProxyHistoryEntry represents a single NDJSON entry from get_proxy_http_history.
type ProxyHistoryEntry struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Notes    string `json:"notes"`
}

// SendRequestParams are the parameters for send_http1_request.
type SendRequestParams struct {
	Content        string
	TargetHostname string
	TargetPort     int
	UsesHTTPS      bool
}

// SendHTTP2RequestParams are the parameters for send_http2_request.
// HTTP/2 uses pseudo-headers (:method, :path, :authority, :scheme) and regular headers.
type SendHTTP2RequestParams struct {
	PseudoHeaders  map[string]string // e.g. {":method": "GET", ":path": "/", ":authority": "example.com"}
	Headers        map[string]string // e.g. {"User-Agent": "sectool"}
	RequestBody    string
	TargetHostname string
	TargetPort     int
	UsesHTTPS      bool
}

// RepeaterTabParams are the parameters for create_repeater_tab.
type RepeaterTabParams struct {
	TabName        string
	Content        string
	TargetHostname string
	TargetPort     int
	UsesHTTPS      bool
}

// IntruderParams are the parameters for send_to_intruder.
type IntruderParams struct {
	TabName        string
	Content        string
	TargetHostname string
	TargetPort     int
	UsesHTTPS      bool
}

// WebSocketHistoryEntry represents a single entry from proxy websocket history.
type WebSocketHistoryEntry struct {
	Direction string `json:"direction"`
	Payload   string `json:"payload"`
	Opcode    string `json:"opcode,omitempty"`
}
