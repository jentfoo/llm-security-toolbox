package service

import (
	"context"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	burpmcp "github.com/go-harden/llm-security-toolbox/sectool/service/mcp"
	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// connectBurpOrSkip connects to Burp MCP and skips if unavailable.
func connectBurpOrSkip(t *testing.T) *burpmcp.BurpClient {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.AcquireBurpLock(t)

	client := burpmcp.New(config.DefaultBurpMCPURL)
	if err := client.Connect(t.Context()); err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// setupIntegrationServer creates a server with MCP enabled.
// Returns server, MCP client, and cleanup function.
func setupIntegrationServer(t *testing.T) (*Server, *mcpclient.Client, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Verify Burp is available (ConnectBurpSSEOrSkip acquires lock internally)
	burpClient := testutil.ConnectBurpSSEOrSkip(t)
	_ = burpClient.Close()

	workDir := t.TempDir()
	srv, err := NewServer(DaemonFlags{
		WorkDir:      workDir,
		BurpMCPURL:   config.DefaultBurpMCPURL,
		MCP:          true,
		MCPPort:      0, // Let OS pick a port
		WorkflowMode: WorkflowModeNone,
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	require.NotNil(t, srv.mcpServer, "MCP server should be started")

	// Use in-process client for reliability
	mcpClient, err := mcpclient.NewInProcessClient(srv.mcpServer.server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	require.NoError(t, err)

	cleanup := func() {
		_ = mcpClient.Close()
		srv.RequestShutdown()
		<-serverErr
	}

	return srv, mcpClient, cleanup
}

// cleanupAllRules removes all HTTP and WebSocket rules via backend.
func cleanupAllRules(t *testing.T, backend HttpBackend) {
	t.Helper()

	ctx := t.Context()

	// Clean up HTTP rules
	rules, err := backend.ListRules(ctx, false)
	if err == nil {
		for _, r := range rules {
			_ = backend.DeleteRule(ctx, r.RuleID)
		}
	}

	// Clean up WebSocket rules
	wsRules, err := backend.ListRules(ctx, true)
	if err == nil {
		for _, r := range wsRules {
			_ = backend.DeleteRule(ctx, r.RuleID)
		}
	}
}
