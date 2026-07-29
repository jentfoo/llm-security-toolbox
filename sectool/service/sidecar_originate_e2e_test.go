//go:build unix

package service

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

type originateHarness struct {
	mcp     *mcpclient.Client
	conn    *sidecar.Conn
	adapter string
}

// startOriginateHarness boots a native backend + MCP server with native
// origination wired, plus a registered sidecar. allowedDomains, when non-nil,
// is written as the config allowlist to exercise scope policy.
func startOriginateHarness(t *testing.T, allowedDomains []string) *originateHarness {
	t.Helper()
	const adapter = "origin-sidecar"

	var configPath string
	if allowedDomains != nil {
		configPath = filepath.Join(t.TempDir(), "config.json")
		cfg := config.DefaultConfig()
		cfg.AllowedDomains = allowedDomains
		require.NoError(t, cfg.Save(configPath))
	}

	sb := startSidecarBackend(t, scsidecar.Config{}, configPath)
	conn := sb.dial(t, sidecar.Registration{
		Name:      adapter,
		Protocols: []string{"custom/1"},
	})
	return &originateHarness{mcp: sb.mcp, conn: conn, adapter: adapter}
}

func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// TestSidecarOriginateNativeE2E drives invoke_adapter at the reserved "sectool"
// adapter against a real upstream, asserting mutations reach the wire, the flow
// is attributed to the caller, and wait_for_response gates the response form.
func TestSidecarOriginateNativeE2E(t *testing.T) {
	t.Parallel()

	var gotURI, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key":"real"}`))
	}))
	t.Cleanup(upstream.Close)

	h := startOriginateHarness(t, nil)

	t.Run("mutations_and_attribution", func(t *testing.T) {
		wait := true
		res, err := h.conn.InvokeAdapter(t.Context(), wire.InvokeAdapterParams{
			Adapter: "sectool",
			Target: jsonRaw(t, map[string]any{
				"url":     upstream.URL + "/key",
				"method":  "POST",
				"headers": map[string]string{"Content-Type": "application/json"},
			}),
			Payload: jsonRaw(t, map[string]any{"body": `{"v":1}`}),
			Mutations: []wire.Mutation{
				{Op: "set_json", Name: "v", Value: "2"},
				{Op: "set_query", Name: "id", Value: "7"},
			},
			WaitForResponse: &wait,
		})
		require.NoError(t, err)
		require.Len(t, res.NewFlowIDs, 1)
		require.NotNil(t, res.Response)
		assert.Equal(t, 200, res.Response.StatusCode)
		assert.JSONEq(t, `{"key":"real"}`, string(res.Response.Body))

		// Mutations reached the wire: query param added, JSON field overridden.
		assert.Contains(t, gotURI, "id=7")
		assert.JSONEq(t, `{"v":2}`, gotBody)

		// Flow is in history, attributed to the calling sidecar.
		poll, perr := h.mcp.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Limit: 100})
		require.NoError(t, perr)
		i := slices.IndexFunc(poll.Flows, func(f protocol.FlowEntry) bool { return f.FlowID == res.NewFlowIDs[0] })
		require.GreaterOrEqual(t, i, 0)
		assert.Equal(t, h.adapter, poll.Flows[i].InvokedBy)
	})

	t.Run("no_wait_omits_response", func(t *testing.T) {
		var wait bool
		res, err := h.conn.InvokeAdapter(t.Context(), wire.InvokeAdapterParams{
			Adapter:         "sectool",
			Target:          jsonRaw(t, map[string]any{"url": upstream.URL + "/ping"}),
			WaitForResponse: &wait,
		})
		require.NoError(t, err)
		require.Len(t, res.NewFlowIDs, 1)
		assert.Nil(t, res.Response)
	})

	t.Run("response_body_decompressed", func(t *testing.T) {
		gz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(`{"key":"gz"}`))
			_ = zw.Close()
		}))
		t.Cleanup(gz.Close)

		res, err := h.conn.InvokeAdapter(t.Context(), wire.InvokeAdapterParams{
			Adapter: "sectool",
			Target:  jsonRaw(t, map[string]any{"url": gz.URL}),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Response)
		// Body is the logical payload, not the gzip wire bytes.
		assert.JSONEq(t, `{"key":"gz"}`, string(res.Response.Body))
	})
}

// TestSidecarOriginateNativeScope confirms native origination honors the domain
// allowlist inside the shared send path.
func TestSidecarOriginateNativeScope(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	h := startOriginateHarness(t, []string{"example.invalid"})

	_, err := h.conn.InvokeAdapter(t.Context(), wire.InvokeAdapterParams{
		Adapter: "sectool",
		Target:  jsonRaw(t, map[string]any{"url": upstream.URL}),
	})
	require.Error(t, err)
	var we *wire.Error
	require.ErrorAs(t, err, &we)
	assert.Equal(t, wire.CodeInjectSendFailed, we.Code)
}
