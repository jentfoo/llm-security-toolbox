package agent

import (
	"regexp"
	"strings"
)

// underscoreRun collapses runs of '_' to a single '_' for canonical matching.
var underscoreRun = regexp.MustCompile(`_+`)

// canonicalToolName returns s lowercased with runs of underscores
// collapsed to a single underscore.
func canonicalToolName(s string) string {
	return underscoreRun.ReplaceAllString(strings.ToLower(s), "_")
}
