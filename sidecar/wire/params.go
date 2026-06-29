package wire

import "encoding/json"

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
