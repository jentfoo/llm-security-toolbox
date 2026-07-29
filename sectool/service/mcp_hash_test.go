package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// The digest matrix is covered by hash.TestComputeHash/TestComputeHash_HMAC; these
// assert only the MCP wiring: the sha256 default, the algorithm/type alias, HMAC via
// the key param, and the required-input guard.

func TestHandleHash(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("sha256_default", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
		})
		assert.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", text)
	})

	t.Run("type_alias", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
			"type":  "md5",
		})
		assert.Equal(t, "098f6bcd4621d373cade4e832627b4f6", text)
	})

	t.Run("hmac_via_key", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
			"key":   "secret",
		})
		assert.Equal(t, "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", text)
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "hash", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}
