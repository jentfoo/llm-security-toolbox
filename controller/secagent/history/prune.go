package history

import (
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/go-appsec/secagent/agent"
)

// PruneToolResults drops tool-result messages whose ToolCallID is in
// dropSet, strips matching ToolCalls from preceding assistant messages,
// and removes assistant messages left with no ToolCalls and no content.
// inScope decides per-index eligibility; nil treats every index as
// eligible. Out-of-scope messages pass through verbatim. keptIndices
// reports which original indices survived so callers can rebuild parallel
// arrays (e.g. Chronicle.iters, DirectorChat.Meta).
func PruneToolResults(
	msgs []agent.Message,
	dropSet map[string]struct{},
	inScope func(int) bool,
) (kept []agent.Message, keptIndices []int, droppedToolResults int) {
	kept = make([]agent.Message, 0, len(msgs))
	keptIndices = make([]int, 0, len(msgs))
	for i, m := range msgs {
		if inScope != nil && !inScope(i) {
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
			continue
		}
		switch m.Role {
		case agent.RoleTool:
			if _, drop := dropSet[m.ToolCallID]; drop {
				droppedToolResults++
				continue
			}
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
		case agent.RoleAssistant:
			if len(m.ToolCalls) == 0 {
				kept = append(kept, m)
				keptIndices = append(keptIndices, i)
				continue
			}
			out := m
			out.ToolCalls = bulk.SliceFilter(func(tc agent.ToolCall) bool {
				_, drop := dropSet[tc.ID]
				return !drop
			}, m.ToolCalls)
			if len(out.ToolCalls) == 0 && strings.TrimSpace(out.Content) == "" {
				continue
			}
			kept = append(kept, out)
			keptIndices = append(keptIndices, i)
		default:
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
		}
	}
	return kept, keptIndices, droppedToolResults
}
