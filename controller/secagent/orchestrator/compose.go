package orchestrator

import (
	"github.com/go-appsec/secagent/agent"
)

// noneSentinel is the human-readable token used wherever a list-style
// rendering needs to signal "nothing here." Extracted as a constant so
// goconst doesn't flag the repeated literal across compose / prompts.
const noneSentinel = "(none)"

// ComposeVerifier builds the verifier's per-iteration history. The
// verifier remains the "fresh narrow context every iter" role: each
// iteration starts with [system, user] where the user message is just the
// substep-1 directive body. Pending-candidate state and verifier
// dispositions are already rendered structurally inside that directive
// (BuildVerifierPrompt + BuildVerifierContinuePrompt), and the mission
// anchor lives in the verifier's system prompt — so no separate recap
// section is needed.
func ComposeVerifier(directiveBody string) []agent.Message {
	return []agent.Message{{Role: "user", Content: directiveBody}}
}
