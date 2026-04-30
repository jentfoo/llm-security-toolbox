package agent

import (
	"regexp"
	"strings"
)

// underscoreRun collapses runs of '_' to a single '_' for canonical matching.
var underscoreRun = regexp.MustCompile(`_+`)

// canonicalToolName returns a normalized form of a tool name suitable for
// fallback lookup when the model emits a near-miss spelling. Lowercases the
// input and collapses runs of underscores to a single one. Recovers the
// real-world failure of `mcp_sectool__proxy_poll` (single underscore between
// segments) → `mcp__sectool__proxy_poll` (the registered name).
func canonicalToolName(s string) string {
	return underscoreRun.ReplaceAllString(strings.ToLower(s), "_")
}
