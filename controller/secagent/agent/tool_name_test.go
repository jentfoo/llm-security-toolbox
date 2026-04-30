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
		{"single_underscore_typo", "mcp_sectool__proxy_poll", "mcp_sectool_proxy_poll"},
		{"double_underscore_real", "mcp__sectool__proxy_poll", "mcp_sectool_proxy_poll"},
		{"uppercase_normalized", "MCP__sectool__X", "mcp_sectool_x"},
		{"already_canonical", "mcp_sectool_proxy_poll", "mcp_sectool_proxy_poll"},
		{"triple_underscore", "mcp___sectool___X", "mcp_sectool_x"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, canonicalToolName(c.in))
		})
	}
}
