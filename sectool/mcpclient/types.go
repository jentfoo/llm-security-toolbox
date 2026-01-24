package mcpclient

import "encoding/json"

// ProxySummaryOpts are options for ProxySummary.
type ProxySummaryOpts struct {
	Host         string
	Path         string
	Method       string
	Status       string
	Contains     string
	ContainsBody string
	ExcludeHost  string
	ExcludePath  string
}

// ProxySummaryResponse is the response from proxy_summary.
type ProxySummaryResponse struct {
	Summary []SummaryEntry `json:"aggregates"`
}

// SummaryEntry is an aggregated traffic entry.
type SummaryEntry struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

// ProxyListOpts are options for ProxyList.
type ProxyListOpts struct {
	Host         string
	Path         string
	Method       string
	Status       string
	Contains     string
	ContainsBody string
	Since        string
	ExcludeHost  string
	ExcludePath  string
	Limit        int
	Offset       int
}

// ProxyListResponse is the response from proxy_list.
type ProxyListResponse struct {
	Flows []FlowEntry `json:"flows"`
}

// FlowEntry is a proxy history entry.
type FlowEntry struct {
	FlowID   string `json:"flow_id"`
	Method   string `json:"method"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	RespSize int    `json:"response_length"`
}

// ProxyGetResponse is the response from proxy_get.
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

// RequestLine contains parsed request line components.
type RequestLine struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// RuleListResponse is the response from proxy_rule_list.
type RuleListResponse struct {
	Rules []RuleEntry `json:"rules"`
}

// RuleEntry is a proxy match/replace rule.
type RuleEntry struct {
	RuleID  string `json:"rule_id"`
	Type    string `json:"type"`
	Label   string `json:"label,omitempty"`
	IsRegex bool   `json:"is_regex"`
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

// RuleAddOpts are options for ProxyRuleAdd.
type RuleAddOpts struct {
	Type    string
	Match   string
	Replace string
	Label   string
	IsRegex bool
}

// RuleUpdateOpts are options for ProxyRuleUpdate.
type RuleUpdateOpts struct {
	Type    string
	Match   string
	Replace string
	Label   string
	IsRegex *bool // nil = preserve existing, non-nil = set to value
}

// ReplaySendOpts are options for ReplaySend.
type ReplaySendOpts struct {
	FlowID          string
	Body            string
	Target          string
	AddHeaders      []string
	RemoveHeaders   []string
	Path            string
	Query           string
	SetQuery        []string
	RemoveQuery     []string
	SetJSON         map[string]interface{}
	RemoveJSON      []string
	FollowRedirects bool
	Timeout         string
	Force           bool
}

// ReplaySendResponse is the response from replay_send.
// Handles both nested (response:{...}) and flat field formats via custom unmarshaling.
type ReplaySendResponse struct {
	ReplayID string          `json:"replay_id"`
	Duration string          `json:"duration"`
	Response ResponseDetails `json:"response,omitempty"`
}

// ResponseDetails contains response information.
type ResponseDetails struct {
	Status      int    `json:"status"`
	StatusLine  string `json:"status_line"`
	RespHeaders string `json:"response_headers"`
	RespSize    int    `json:"response_size"`
	RespPreview string `json:"response_preview"`
}

// UnmarshalJSON handles both nested and flat response formats.
// Server returns flat fields; this normalizes into the Response field.
func (r *ReplaySendResponse) UnmarshalJSON(data []byte) error {
	// Intermediate struct to capture both formats
	type flat struct {
		ReplayID    string          `json:"replay_id"`
		Duration    string          `json:"duration"`
		Response    ResponseDetails `json:"response"`
		Status      int             `json:"status"`
		StatusLine  string          `json:"status_line"`
		RespHeaders string          `json:"response_headers"`
		RespSize    int             `json:"response_size"`
		RespPreview string          `json:"response_preview"`
	}

	var f flat
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}

	r.ReplayID = f.ReplayID
	r.Duration = f.Duration
	r.Response = f.Response

	// Normalize flat fields into Response if nested is empty
	if r.Response.Status == 0 && f.Status != 0 {
		r.Response.Status = f.Status
		r.Response.StatusLine = f.StatusLine
		r.Response.RespHeaders = f.RespHeaders
		r.Response.RespSize = f.RespSize
		r.Response.RespPreview = f.RespPreview
	}

	return nil
}

// ReplayGetResponse is the response from replay_get.
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

// RequestSendOpts are options for RequestSend.
type RequestSendOpts struct {
	URL             string
	Method          string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         string
}

// OastCreateResponse is the response from oast_create.
type OastCreateResponse struct {
	OastID string `json:"oast_id"`
	Domain string `json:"domain"`
	Label  string `json:"label,omitempty"`
}

// OastPollResponse is the response from oast_poll.
type OastPollResponse struct {
	Events       []OastEvent `json:"events"`
	DroppedCount int         `json:"dropped_count,omitempty"`
}

// OastEvent is an OAST interaction event.
type OastEvent struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastGetResponse is the response from oast_get.
type OastGetResponse struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastListResponse is the response from oast_list.
type OastListResponse struct {
	Sessions []OastSession `json:"sessions"`
}

// OastSession is an OAST session entry.
type OastSession struct {
	OastID    string `json:"oast_id"`
	Domain    string `json:"domain"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at"`
}

// CrawlCreateOpts are options for CrawlCreate.
type CrawlCreateOpts struct {
	Label             string
	SeedURLs          string
	SeedFlows         string
	Domains           string
	Headers           map[string]string
	MaxDepth          int
	MaxRequests       int
	Delay             string
	Parallelism       int
	IncludeSubdomains *bool
	SubmitForms       bool
	IgnoreRobots      bool
}

// CrawlCreateResponse is the response from crawl_create.
type CrawlCreateResponse struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlSeedResponse is the response from crawl_seed.
type CrawlSeedResponse struct {
	AddedCount int `json:"added_count"`
}

// CrawlStatusResponse is the response from crawl_status.
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

// CrawlSummaryResponse is the response from crawl_summary.
type CrawlSummaryResponse struct {
	SessionID  string         `json:"session_id"`
	State      string         `json:"state"`
	Duration   string         `json:"duration"`
	Aggregates []SummaryEntry `json:"aggregates"`
}

// CrawlListOpts are options for CrawlList.
type CrawlListOpts struct {
	Type         string // "urls", "forms", "errors"
	Host         string
	Path         string
	Method       string
	Status       string
	Contains     string
	ContainsBody string
	ExcludeHost  string
	ExcludePath  string
	Since        string
	Limit        int
	Offset       int
}

// CrawlListResponse is the response from crawl_list.
type CrawlListResponse struct {
	Flows  []CrawlFlow  `json:"flows,omitempty"`
	Forms  []CrawlForm  `json:"forms,omitempty"`
	Errors []CrawlError `json:"errors,omitempty"`
}

// CrawlFlow is a crawled request/response.
type CrawlFlow struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
	Duration       string `json:"duration"`
	FoundOn        string `json:"found_on,omitempty"`
}

// CrawlForm is a discovered form.
type CrawlForm struct {
	FormID  string      `json:"form_id"`
	URL     string      `json:"url"`
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	HasCSRF bool        `json:"has_csrf"`
	Inputs  []FormInput `json:"inputs"`
}

// FormInput is a form input field.
type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// CrawlError is a crawl error.
type CrawlError struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error"`
}

// CrawlSessionsResponse is the response from crawl_sessions.
type CrawlSessionsResponse struct {
	Sessions []CrawlSessionEntry `json:"sessions"`
}

// CrawlSessionEntry is a crawl session entry.
type CrawlSessionEntry struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlGetResponse is the response from crawl_get.
type CrawlGetResponse struct {
	FlowID            string              `json:"flow_id"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	FoundOn           string              `json:"found_on,omitempty"`
	Depth             int                 `json:"depth"`
	ReqHeaders        string              `json:"request_headers"`
	ReqHeadersParsed  map[string][]string `json:"request_headers_parsed,omitempty"`
	ReqBody           string              `json:"request_body"`
	ReqSize           int                 `json:"request_size"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
	Truncated         bool                `json:"truncated,omitempty"`
	Duration          string              `json:"duration"`
}
