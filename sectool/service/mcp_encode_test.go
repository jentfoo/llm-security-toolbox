package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// The per-type encoding matrix is covered by encoding.TestEncode/TestDecode; these
// assert only the MCP wiring: encoder output is returned, the required-input guard,
// and error propagation.

func TestHandleEncode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("success", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode", map[string]interface{}{
			"input": "hello world&test=<value>",
			"type":  "url",
		})
		assert.Equal(t, "hello+world%26test%3D%3Cvalue%3E", text)
	})

	t.Run("error_propagates", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode", map[string]interface{}{
			"input": "test",
			"type":  "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid type")
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode", map[string]interface{}{
			"type": "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}

func TestHandleDecode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("success", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "decode", map[string]interface{}{
			"input": "hello+world%26test%3D%3Cvalue%3E",
			"type":  "url",
		})
		assert.Equal(t, "hello world&test=<value>", text)
	})

	t.Run("error_propagates", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"input": "%ZZ%invalid",
			"type":  "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "URL decode error")
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"type": "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}
