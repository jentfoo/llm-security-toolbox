package service

// Flow source constants for display and sorting.
const (
	SourceProxy  = "proxy"
	SourceReplay = "replay"
	SourceCrawl  = "crawl"
)

// Output mode constants for poll tools.
const (
	OutputModeFlows   = "flows"
	OutputModeSummary = "summary"
	OutputModeForms   = "forms"
	OutputModeErrors  = "errors"
	OutputModeEvents  = "events"
)

// ProxyListRequest contains filters for proxy list queries.
type ProxyListRequest struct {
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	Method       string `json:"method,omitempty"`
	Status       string `json:"status,omitempty"`
	SearchHeader string `json:"search_header,omitempty"`
	SearchBody   string `json:"search_body,omitempty"`
	Since        string `json:"since,omitempty"`
	ExcludeHost  string `json:"exclude_host,omitempty"`
	ExcludePath  string `json:"exclude_path,omitempty"`
	Adapter      string `json:"adapter,omitempty"`
	ProtocolTag  string `json:"protocol_tag,omitempty"`
	ParentFlowID string `json:"parent_flow_id,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
	Source       string `json:"source,omitempty"`
}

// HasFilters returns true if any filter is set.
func (r *ProxyListRequest) HasFilters() bool {
	return r.Host != "" || r.Path != "" || r.Method != "" || r.Status != "" ||
		r.SearchHeader != "" || r.SearchBody != "" || r.Since != "" ||
		r.ExcludeHost != "" || r.ExcludePath != "" || r.Adapter != "" ||
		r.ProtocolTag != "" || r.ParentFlowID != "" || r.Limit > 0 ||
		r.Source != ""
}
