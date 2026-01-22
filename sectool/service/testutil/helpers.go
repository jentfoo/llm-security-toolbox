package testutil

import (
	"context"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
)

// ConnectBurpSSEOrSkip connects to Burp MCP using SSE client and skips if unavailable.
// Used for MCP server tests that need the mcp-go client.
func ConnectBurpSSEOrSkip(t *testing.T) *mcpclient.Client {
	t.Helper()

	AcquireBurpLock(t)

	burpClient, err := mcpclient.NewSSEMCPClient(config.DefaultBurpMCPURL)
	if err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	if err := burpClient.Start(context.Background()); err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err = burpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	if err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	t.Cleanup(func() { _ = burpClient.Close() })
	return burpClient
}

// CallMCPTool calls an MCP tool and returns the result.
func CallMCPTool(t *testing.T, client *mcpclient.Client, name string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	result, err := client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	require.NoError(t, err)
	return result
}

// ExtractMCPText extracts text content from an MCP tool result.
func ExtractMCPText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	require.NotEmpty(t, result.Content, "result should have content")
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("no text content found in result")
	return ""
}
