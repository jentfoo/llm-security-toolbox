package wire

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the major.minor contract version.
type ProtocolVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// Capabilities are the parameterized seams a sidecar declares.
type Capabilities struct {
	EarlyClaim      *EarlyClaim      `json:"early_claim,omitempty"`
	UpgradeClaim    *UpgradeClaim    `json:"upgrade_claim,omitempty"`
	InjectionTarget *InjectionTarget `json:"injection_target,omitempty"`
}

// PortRange is an inclusive TCP port span [Low, High].
type PortRange struct {
	Low  int `json:"low"`
	High int `json:"high"`
}

// TLSClaim configures TLS termination for an early claim.
type TLSClaim struct {
	Terminate bool   `json:"terminate"`
	SNIMatch  string `json:"sni_match,omitempty"`
}

// EarlyClaim claims TCP connections at accept on a port range.
// MagicBytesPrefix carries base64-encoded opening bytes.
type EarlyClaim struct {
	PortRange        PortRange `json:"port_range"`
	TLS              *TLSClaim `json:"tls,omitempty"`
	MagicBytesPrefix string    `json:"magic_bytes_prefix,omitempty"`
	HostMatch        string    `json:"host_match,omitempty"`
	Probe            bool      `json:"probe,omitempty"`
	ProbeMaxBytes    int       `json:"probe_max_bytes,omitempty"`
}

// UpgradeClaim claims a byte stream after an HTTP upgrade signal.
type UpgradeClaim struct {
	HostPattern   string   `json:"host_pattern,omitempty"`
	PathPattern   string   `json:"path_pattern,omitempty"`
	UpgradeSignal string   `json:"upgrade_signal,omitempty"` // http_101 | connect
	MethodSet     []string `json:"method_set,omitempty"`
}

// InjectionTarget declares the sidecar can originate outbound messages.
type InjectionTarget struct {
	TargetSchema json.RawMessage `json:"target_schema,omitempty"`
}

// MCPTool is a tool definition the sidecar provides.
type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// RegisterParams is the sidecar's first message.
type RegisterParams struct {
	Name            string          `json:"name"`
	Version         string          `json:"version,omitempty"`
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	Protocols       []string        `json:"protocols"`
	Capabilities    Capabilities    `json:"capabilities"`
	MCPTools        []MCPTool       `json:"mcp_tools,omitempty"`
	InstanceID      string          `json:"instance_id,omitempty"`
	Resume          bool            `json:"resume,omitempty"`
}

// RegisterResult is sectool's response to register.
type RegisterResult struct {
	ProtocolVersion ProtocolVersion   `json:"protocol_version"`
	AssignedSeams   []string          `json:"assigned_seams"`
	RulesSnapshot   []json.RawMessage `json:"rules_snapshot"`
	ServerTime      string            `json:"server_time"`
}

// ShutdownParams requests a graceful close.
type ShutdownParams struct {
	DrainSeconds int `json:"drain_seconds"`
}

// ShutdownResult acknowledges a shutdown request.
type ShutdownResult struct {
	Ack bool `json:"ack"`
}

// Header is a single name-value metadata entry on a message.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BodyCodec describes how Body was derived from BodyRaw: the ordered transform
// chain (e.g. decryption, decompression, de-framing) and the logical content-type.
// Used on replay to re-encode a mutated Body back to the wire form.
type BodyCodec struct {
	Transforms  []string `json:"transforms,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}

// FlowMessage is one side of a flow: request or response. Body is the logical
// payload every tool operates on; BodyRaw/BodyCodec carry the wire form when it
// is not natively decodable by sectool. Byte fields are base64 in JSON.
type FlowMessage struct {
	Method     string     `json:"method,omitempty"`
	Path       string     `json:"path,omitempty"`
	Query      string     `json:"query,omitempty"`
	StatusCode int        `json:"status_code,omitempty"`
	StatusText string     `json:"status_text,omitempty"`
	Headers    []Header   `json:"headers,omitempty"`
	Body       []byte     `json:"body,omitempty"`
	BodyRaw    []byte     `json:"body_raw,omitempty"`
	BodyCodec  *BodyCodec `json:"body_codec,omitempty"`
}

// Flow is a captured exchange a sidecar publishes via push_flow. FlowID is empty
// on first emission (sectool assigns) and set to re-target an existing flow for
// two-phase completion or session/stream teardown.
type Flow struct {
	FlowID       string         `json:"flow_id,omitempty"`
	Adapter      string         `json:"adapter,omitempty"`
	ProtocolTag  string         `json:"protocol_tag,omitempty"`
	Direction    string         `json:"direction,omitempty"`
	ParentFlowID string         `json:"parent_flow_id,omitempty"`
	Scheme       string         `json:"scheme,omitempty"`
	Port         int            `json:"port,omitempty"`
	Request      *FlowMessage   `json:"request,omitempty"`
	Response     *FlowMessage   `json:"response,omitempty"`
	StartedAt    time.Time      `json:"started_at,omitempty"`
	CompletedAt  time.Time      `json:"completed_at,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
}

// PushFlowParams is the Flow emitted via push_flow.
type PushFlowParams = Flow

// PushFlowResult carries the flow_id sectool assigned (or echoed back).
type PushFlowResult struct {
	FlowID string `json:"flow_id"`
}

// LogParams is a structured diagnostic log line.
type LogParams struct {
	Level   string         `json:"level,omitempty"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// ReportMetricsParams carries counter and gauge samples.
type ReportMetricsParams struct {
	Counters map[string]int64   `json:"counters,omitempty"`
	Gauges   map[string]float64 `json:"gauges,omitempty"`
}

// CoreQueryParams invokes a read-side core tool by name.
type CoreQueryParams struct {
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params,omitempty"`
}

// CoreQueryResult is the core tool's result text.
type CoreQueryResult struct {
	Content string `json:"content"`
	IsError bool   `json:"is_error,omitempty"`
}

// StreamWrite is one entry in a writes array: bytes for sectool to write to the
// named stream's socket. StreamID may differ from the stream an event arrived on.
type StreamWrite struct {
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// StreamResult replies to stream_open and stream_deliver with optional bytes to
// write back to one or more sockets.
type StreamResult struct {
	Writes []StreamWrite `json:"writes,omitempty"`
}

// StreamOpenParams announces that a claim fired and a new stream exists.
type StreamOpenParams struct {
	StreamID     string `json:"stream_id"`
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	MatchedClaim string `json:"matched_claim,omitempty"`
	PeerAddr     string `json:"peer_addr,omitempty"`
}

// StreamDeliverParams carries inbound socket bytes for a stream.
type StreamDeliverParams struct {
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// StreamEndedParams notifies the sidecar that a stream closed.
type StreamEndedParams struct {
	StreamID string `json:"stream_id"`
	Reason   string `json:"reason,omitempty"`
}

// CloseStreamParams is a sidecar-initiated proactive stream close.
type CloseStreamParams struct {
	StreamID string `json:"stream_id"`
	Reason   string `json:"reason,omitempty"`
}

// StreamWriteParams is a sidecar-initiated proactive write, for keepalives and
// other timer-driven output outside an event Response.
type StreamWriteParams struct {
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// ClaimProbeParams asks the sidecar whether a buffered opening stream is its
// protocol, for an early_claim that set probe.
type ClaimProbeParams struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	PeerAddr string `json:"peer_addr,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

// ClaimProbeResult is the sidecar's claim decision. A false claim is normal
// control flow, not an error.
type ClaimProbeResult struct {
	Claim bool `json:"claim"`
}
