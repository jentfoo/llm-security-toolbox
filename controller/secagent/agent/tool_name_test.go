package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalToolName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "single_underscore_typo", in: "mcp_sectool__proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "double_underscore_real", in: "mcp__sectool__proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "uppercase_normalized", in: "MCP__sectool__X", want: "mcp_sectool_x"},
		{name: "already_canonical", in: "mcp_sectool_proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "triple_underscore", in: "mcp___sectool___X", want: "mcp_sectool_x"},
		{name: "leading_trailing_underscore", in: "__foo__", want: "_foo_"},
		{name: "no_underscores", in: "poll", want: "poll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canonicalToolName(tc.in))
		})
	}
}
