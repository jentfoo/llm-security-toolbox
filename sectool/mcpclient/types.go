package mcpclient

// =============================================================================
// Proxy Options
// =============================================================================

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

// =============================================================================
// Replay Options
// =============================================================================

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

// RequestSendOpts are options for RequestSend.
type RequestSendOpts struct {
	URL             string
	Method          string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         string
}

// =============================================================================
// Crawl Options
// =============================================================================

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
