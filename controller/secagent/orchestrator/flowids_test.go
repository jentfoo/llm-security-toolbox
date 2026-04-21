package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFlowIDs(t *testing.T) {
	t.Parallel()
	t.Run("plain_text", func(t *testing.T) {
		got := ExtractFlowIDs("flow_id=abc123 and flow_id=def456")
		assert.Equal(t, []string{"abc123", "def456"}, got)
	})
	t.Run("dict_keys", func(t *testing.T) {
		got := ExtractFlowIDs(map[string]any{"flow_id": "aaaa11", "other": "ignore"})
		assert.Equal(t, []string{"aaaa11"}, got)
	})
	t.Run("nested_slice", func(t *testing.T) {
		got := ExtractFlowIDs([]any{
			map[string]any{"flow_a": "ID_AAA1"},
			map[string]any{"flow_b": "ID_BBB2"},
		})
		assert.Equal(t, []string{"ID_AAA1", "ID_BBB2"}, got)
	})
	t.Run("dedup", func(t *testing.T) {
		got := ExtractFlowIDs("flow_id=abc123", "flow_id=abc123")
		assert.Equal(t, []string{"abc123"}, got)
	})
	t.Run("rejects_bare_flow_word", func(t *testing.T) {
		got := ExtractFlowIDs("the flow chart shows details")
		assert.Empty(t, got)
	})
}
