package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripThinkBlocks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no_think", "hello", "hello"},
		{"think_lower", "a<think>hidden</think>b", "ab"},
		{"think_upper", "a<THINK>hidden</THINK>b", "ab"},
		{"multiline", "a<think>line1\nline2</think>b", "ab"},
		{"thinking_tag", "a<thinking>x</thinking>b", "ab"},
		{"reasoning_tag", "a<reasoning>x</reasoning>b", "ab"},
		{"pipe_tag", "a<|thinking|>x<|/thinking|>b", "ab"},
		{"two_blocks", "a<think>x</think>b<think>y</think>c", "abc"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripThinkBlocks(tc.in))
		})
	}
}
