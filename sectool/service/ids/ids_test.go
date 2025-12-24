package ids

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerate(t *testing.T) {
	t.Run("default_length", func(t *testing.T) {
		id := Generate(DefaultLength)
		assert.Len(t, id, DefaultLength)
	})

	t.Run("custom_length", func(t *testing.T) {
		for _, length := range []int{4, 6, 8, 10, 16} {
			id := Generate(length)
			assert.Len(t, id, length)
		}
	})

	t.Run("zero_length_uses_default", func(t *testing.T) {
		id := Generate(0)
		assert.Len(t, id, DefaultLength)
	})

	t.Run("negative_length_uses_default", func(t *testing.T) {
		id := Generate(-1)
		assert.Len(t, id, DefaultLength)
	})

	t.Run("only_base62_characters", func(t *testing.T) {
		base62Pattern := regexp.MustCompile("^[0-9A-Za-z]+$")
		for range 100 {
			id := Generate(DefaultLength)
			assert.Regexp(t, base62Pattern, id)
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		seen := make(map[string]bool)
		count := 10000

		for range count {
			id := Generate(DefaultLength)
			if seen[id] {
				t.Fatalf("duplicate ID generated: %s", id)
			}
			seen[id] = true
		}

		assert.Len(t, seen, count)
	})
}

func BenchmarkGenerate(b *testing.B) {
	for range b.N {
		Generate(DefaultLength)
	}
}
