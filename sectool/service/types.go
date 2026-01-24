package service

import (
	"context"
	"errors"
	"net"
	"os"
)

// HealthMetricProvider is a function that returns a metric value for a given key.
type HealthMetricProvider func() string

// IsTimeoutError returns true if the error is a timeout.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	} else if errors.Is(err, context.DeadlineExceeded) {
		return true
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// =============================================================================
// Proxy Types
// =============================================================================

// ProxyListRequest contains filters for proxy list queries.
type ProxyListRequest struct {
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	Method       string `json:"method,omitempty"`
	Status       string `json:"status,omitempty"`
	Contains     string `json:"contains,omitempty"`
	ContainsBody string `json:"contains_body,omitempty"`
	Since        string `json:"since,omitempty"`
	ExcludeHost  string `json:"exclude_host,omitempty"`
	ExcludePath  string `json:"exclude_path,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// HasFilters returns true if any filter is set.
func (r *ProxyListRequest) HasFilters() bool {
	return r.Host != "" || r.Path != "" || r.Method != "" || r.Status != "" ||
		r.Contains != "" || r.ContainsBody != "" || r.Since != "" ||
		r.ExcludeHost != "" || r.ExcludePath != "" || r.Limit > 0
}

// ProxySummaryResponse is the response for proxy_summary.
type ProxySummaryResponse struct {
	Aggregates []SummaryEntry `json:"aggregates"`
}

// ProxyListResponse is the response for proxy_list.
type ProxyListResponse struct {
	Flows []FlowSummary `json:"flows"`
}

// SummaryEntry represents grouped traffic by (host, path, method, status).
type SummaryEntry struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

// FlowSummary represents a single proxy history entry in list view.
type FlowSummary struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
}

// RequestLine contains path and version from the HTTP request line.
type RequestLine struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// ProxyGetResponse is the response for the proxy_get MCP tool.
// Returns full request and response data for a proxy history entry.
type ProxyGetResponse struct {
	FlowID            string              `json:"flow_id"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	ReqHeaders        string              `json:"request_headers"`
	ReqHeadersParsed  map[string][]string `json:"request_headers_parsed,omitempty"`
	ReqLine           *RequestLine        `json:"request_line,omitempty"`
	ReqBody           string              `json:"request_body"`
	ReqSize           int                 `json:"request_size"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
}

// =============================================================================
// Response Types
// =============================================================================

// ResponseDetails contains HTTP response summary fields.
type ResponseDetails struct {
	Status      int    `json:"status"`
	StatusLine  string `json:"status_line"`
	RespHeaders string `json:"response_headers"`
	RespPreview string `json:"response_preview,omitempty"`
	RespSize    int    `json:"response_size"`
}

// =============================================================================
// Replay Types
// =============================================================================

// ReplaySendRequest contains options for replay_send.
type ReplaySendRequest struct {
	FlowID          string   `json:"flow_id,omitempty"`
	Target          string   `json:"target,omitempty"`
	AddHeaders      []string `json:"add_headers,omitempty"`
	RemoveHeaders   []string `json:"remove_headers,omitempty"`
	Path            string   `json:"path,omitempty"`
	Query           string   `json:"query,omitempty"`
	SetQuery        []string `json:"set_query,omitempty"`
	RemoveQuery     []string `json:"remove_query,omitempty"`
	SetJSON         []string `json:"set_json,omitempty"`
	RemoveJSON      []string `json:"remove_json,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	Timeout         string   `json:"timeout,omitempty"`
	Force           bool     `json:"force,omitempty"`
}

// ReplaySendResponse is the response for replay_send.
type ReplaySendResponse struct {
	ReplayID string `json:"replay_id"`
	Duration string `json:"duration"`
	ResponseDetails
}

// ReplayGetResponse is the response for replay_get.
type ReplayGetResponse struct {
	ReplayID          string              `json:"replay_id"`
	Duration          string              `json:"duration"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
}

// =============================================================================
// OAST Types
// =============================================================================

// OastCreateResponse is the response for oast_create.
type OastCreateResponse struct {
	OastID string `json:"oast_id"`
	Domain string `json:"domain"`
	Label  string `json:"label,omitempty"`
}

// OastPollResponse is the response for oast_poll.
type OastPollResponse struct {
	Events       []OastEvent `json:"events"`
	DroppedCount int         `json:"dropped_count,omitempty"`
}

// OastEvent represents a single OAST interaction event.
type OastEvent struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastListResponse is the response for oast_list.
type OastListResponse struct {
	Sessions []OastSession `json:"sessions"`
}

// OastSession represents an active OAST session.
type OastSession struct {
	OastID    string `json:"oast_id"`
	Domain    string `json:"domain"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at"`
}

// OastGetResponse is the response for oast_get.
type OastGetResponse struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastDeleteResponse is the response for oast_delete.
type OastDeleteResponse struct{}

// =============================================================================
// Rule Types
// =============================================================================

// RuleListResponse is the response for proxy_rule_list.
type RuleListResponse struct {
	Rules []RuleEntry `json:"rules"`
}

// RuleEntry represents a match/replace rule.
type RuleEntry struct {
	RuleID  string `json:"rule_id"`
	Label   string `json:"label,omitempty"`
	Type    string `json:"type"`
	IsRegex bool   `json:"is_regex,omitempty"`
	Match   string `json:"match,omitempty"`
	Replace string `json:"replace,omitempty"`
}

// RuleDeleteResponse is the response for proxy_rule_delete.
type RuleDeleteResponse struct{}

// =============================================================================
// Crawler Types
// =============================================================================

// CrawlCreateResponse is the response for crawl_create.
type CrawlCreateResponse struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlSeedResponse is the response for crawl_seed.
type CrawlSeedResponse struct {
	AddedCount int `json:"added_count"`
}

// CrawlStatusResponse is the response for crawl_status.
type CrawlStatusResponse struct {
	State           string `json:"state"`
	URLsQueued      int    `json:"urls_queued"`
	URLsVisited     int    `json:"urls_visited"`
	URLsErrored     int    `json:"urls_errored"`
	FormsDiscovered int    `json:"forms_discovered"`
	Duration        string `json:"duration"`
	LastActivity    string `json:"last_activity"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// CrawlSummaryResponse is the response for crawl_summary.
type CrawlSummaryResponse struct {
	SessionID  string         `json:"session_id"`
	State      string         `json:"state"`
	Duration   string         `json:"duration"`
	Aggregates []SummaryEntry `json:"aggregates"`
}

// CrawlListResponse is the response for crawl_list.
type CrawlListResponse struct {
	Flows  []CrawlFlowAPI  `json:"flows,omitempty"`
	Forms  []CrawlFormAPI  `json:"forms,omitempty"`
	Errors []CrawlErrorAPI `json:"errors,omitempty"`
}

// CrawlFlowAPI is the API representation of CrawlFlow (summary).
type CrawlFlowAPI struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
	Duration       string `json:"duration"`
	FoundOn        string `json:"found_on,omitempty"`
}

// CrawlFormAPI is the API representation of DiscoveredForm.
type CrawlFormAPI struct {
	FormID  string         `json:"form_id"`
	URL     string         `json:"url"`
	Action  string         `json:"action"`
	Method  string         `json:"method"`
	HasCSRF bool           `json:"has_csrf"`
	Inputs  []FormInputAPI `json:"inputs"`
}

// FormInputAPI is the API representation of FormInput.
type FormInputAPI struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// CrawlErrorAPI is the API representation of CrawlError.
type CrawlErrorAPI struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error"`
}

// formsToAPI converts DiscoveredForm slice to API format.
func formsToAPI(forms []DiscoveredForm) []CrawlFormAPI {
	result := make([]CrawlFormAPI, 0, len(forms))
	for _, f := range forms {
		inputs := make([]FormInputAPI, 0, len(f.Inputs))
		for _, inp := range f.Inputs {
			inputs = append(inputs, FormInputAPI(inp))
		}
		result = append(result, CrawlFormAPI{
			FormID:  f.ID,
			URL:     f.URL,
			Action:  f.Action,
			Method:  f.Method,
			HasCSRF: f.HasCSRF,
			Inputs:  inputs,
		})
	}
	return result
}

// CrawlSessionsResponse is the response for crawl_sessions.
type CrawlSessionsResponse struct {
	Sessions []CrawlSessionAPI `json:"sessions"`
}

// CrawlSessionAPI is the API representation of CrawlSessionInfo.
type CrawlSessionAPI struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlStopResponse is the response for crawl_stop.
type CrawlStopResponse struct {
	Stopped bool `json:"stopped"`
}
