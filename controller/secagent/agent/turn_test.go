package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyEscalation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		summary        TurnSummary
		candidateFound bool
		want           string
	}{
		{"timeout_silent_escalation", TurnSummary{TimedOut: true}, false, "silent"},
		{"candidate_found", TurnSummary{ToolCalls: []ToolCallRecord{{Name: "x"}}}, true, "candidate"},
		{"silent_no_tools_no_flows", TurnSummary{AssistantText: "done"}, false, "silent"},
		{"productive_with_tools", TurnSummary{ToolCalls: []ToolCallRecord{{Name: "x"}}}, false, ""},
		{"productive_with_flows", TurnSummary{FlowIDs: []string{"abc123"}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEscalation(tc.summary, tc.candidateFound)
			assert.Equal(t, tc.want, got)
		})
	}
}
