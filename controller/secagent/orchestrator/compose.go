package orchestrator

import (
	"github.com/go-appsec/secagent/agent"
)

// noneSentinel is the placeholder rendered where a list has no items.
const noneSentinel = "(none)"

// ComposeVerifier returns the verifier's per-iteration history: a single
// user-role directive message.
func ComposeVerifier(directiveBody string) []agent.Message {
	return []agent.Message{{Role: "user", Content: directiveBody}}
}
