package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/jwt"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

func testMakeJWT(header, payload map[string]interface{}) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".test-signature"
}

// JWT decode behaviors (expiry, alg none, bearer prefix, malformed variants) are
// covered by jwt.TestDecodeJWT*; these assert only the MCP wiring: the jwt.Result is
// JSON-serialized through the tool, error propagation, and the required-token guard.

func TestHandleJWTDecode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("valid_jwt", func(t *testing.T) {
		now := time.Now()
		token := testMakeJWT(
			map[string]interface{}{"alg": "HS256", "typ": "JWT"},
			map[string]interface{}{"sub": "123", "exp": float64(now.Add(1 * time.Hour).Unix()), "iat": float64(now.Unix())},
		)

		var result jwt.Result
		text := CallMCPToolTextOK(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": token,
		})
		require.NoError(t, json.Unmarshal([]byte(text), &result))
		assert.Equal(t, "HS256", result.Header["alg"])
		assert.Equal(t, "123", result.Payload["sub"])
		assert.Empty(t, result.Issues)
		assert.Contains(t, result.Expiry, "expires in")
	})

	t.Run("error_propagates", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": "not-a-jwt",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid JWT")
	})

	t.Run("missing_token", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "jwt_decode", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "token is required")
	})
}
