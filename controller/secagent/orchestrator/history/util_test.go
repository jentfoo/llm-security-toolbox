package history

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		max      int
		expected string
	}{
		{"fits", "hi", 10, "hi"},
		{"truncated", "abcdef", 2, "a…"},
		{"zero_max", "abcdef", 0, "…"},
		{"exact_fit", "abc", 3, "abc"},
		{"empty_input", "", 5, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, Short(c.in, c.max))
		})
	}
}
