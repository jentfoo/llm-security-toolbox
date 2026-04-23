package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveKeepThinkTurns(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		configured int
		maxContext int
		want       int
	}{
		{"auto_small_context", 0, 32_768, 4},
		{"auto_edge_128k_exact", 0, 128_000, 4},
		{"auto_large_context", 0, 200_000, 8},
		{"auto_very_large", 0, 1_000_000, 8},
		{"explicit_override_small_ctx", 2, 32_768, 2},
		{"explicit_override_large_ctx", 12, 200_000, 12},
		{"explicit_one", 1, 32_768, 1},
		{"negative_treated_as_auto", -1, 32_768, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{KeepThinkTurns: tc.configured}
			assert.Equal(t, tc.want, c.EffectiveKeepThinkTurns(tc.maxContext))
		})
	}
}
