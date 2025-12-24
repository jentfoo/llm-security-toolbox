package service

import (
	"context"
	"time"
)

// HttpBackend defines the interface for proxy history and request sending.
// This abstraction allows switching between Burp MCP and future built-in proxies.
type HttpBackend interface {
	// Close shuts down the backend.
	Close() error

	// GetProxyHistory retrieves proxy HTTP history entries.
	// Returns up to count entries starting from offset.
	GetProxyHistory(ctx context.Context, count, offset int) ([]ProxyEntry, error)

	// GetProxyHistoryRegex retrieves filtered proxy HTTP history entries.
	// The regex syntax is backend-specific (Java regex for Burp).
	GetProxyHistoryRegex(ctx context.Context, regex string, count, offset int) ([]ProxyEntry, error)

	// SendRequest sends an HTTP request and returns the response.
	// The request is raw HTTP bytes. Response is returned as headers and body.
	SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error)
}

// ProxyEntry represents a single proxy history entry in backend-agnostic form.
type ProxyEntry struct {
	Request  string // Raw HTTP request
	Response string // Raw HTTP response
	Notes    string // User annotations
}

// Target specifies the destination for a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}

// SendRequestInput contains all parameters for sending a request.
type SendRequestInput struct {
	RawRequest      []byte
	Target          Target
	FollowRedirects bool
	Timeout         time.Duration
}

// SendRequestResult contains the response from a sent request.
type SendRequestResult struct {
	Headers  []byte
	Body     []byte
	Duration time.Duration
}
