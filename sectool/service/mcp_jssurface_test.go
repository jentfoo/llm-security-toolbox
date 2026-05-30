package service

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleJSAnalyze(t *testing.T) {
	t.Parallel()

	t.Run("javascript_bundle_full", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		// A prior proxy flow that the JS bundle's URL should match against
		priorFlowID := mockHTTP.AddProxyEntry(
			"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)

		jsBody := `
fetch('/api/users', {method: 'POST'});
axios.get('/api/items');
new WebSocket('wss://example.com/ws');
window.location.href = '/login';
var key = 'AKIAIOSFODNN7EXAMPLE';
//# sourceMappingURL=app.js.map
`
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID})

		assert.Equal(t, "javascript", resp.Source)

		endpointURLs := make(map[string]protocol.ExtractedEndpoint, len(resp.Endpoints))
		for _, e := range resp.Endpoints {
			endpointURLs[e.URL] = e
		}
		require.Contains(t, endpointURLs, "/api/users")
		assert.Equal(t, "POST", endpointURLs["/api/users"].Method)
		assert.Equal(t, "fetch", endpointURLs["/api/users"].Library)
		assert.Equal(t, priorFlowID, endpointURLs["/api/users"].LastFlow)

		require.Contains(t, endpointURLs, "/api/items")
		assert.Empty(t, endpointURLs["/api/items"].LastFlow)

		require.Contains(t, endpointURLs, "wss://example.com/ws")
		assert.Equal(t, "websocket", endpointURLs["wss://example.com/ws"].Library)

		assert.Contains(t, resp.SourceMaps, "app.js.map")

		require.Len(t, resp.Secrets, 1)
		assert.Equal(t, "aws_access_key", resp.Secrets[0].Kind)
		assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", resp.Secrets[0].Value)
	})

	t.Run("html_inline", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		html := `<html><head>
<script src="/static/bundle.js"></script>
<script>fetch('/api/inline');</script>
</head></html>`
		flowID := mockHTTP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+html,
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": flowID})

		assert.Equal(t, "html-inline", resp.Source)
		assert.Equal(t, []string{"/static/bundle.js"}, resp.ScriptSrc)

		assert.True(t, slices.ContainsFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/inline"
		}))
	})

	t.Run("last_flow_query_fallback", func(t *testing.T) {
		cases := []struct {
			name        string
			historyPath string
			jsFetchPath string
		}{
			{"js_bare_history_query", "/api/things?id=1", "/api/things"},
			{"js_query_history_bare", "/api/things", "/api/things?x=1"},
			{"exact_match_wins", "/api/things?id=1", "/api/things?id=1"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

				historyFlowID := mockHTTP.AddProxyEntry(
					"GET "+tc.historyPath+" HTTP/1.1\r\nHost: example.com\r\n\r\n",
					"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
					"",
				)

				jsBody := "fetch('" + tc.jsFetchPath + "');"
				bundleFlowID := mockHTTP.AddProxyEntry(
					"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
					"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
					"",
				)

				resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
					map[string]interface{}{"flow_id": bundleFlowID})

				idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
					return e.URL == tc.jsFetchPath
				})
				require.GreaterOrEqual(t, idx, 0)
				assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
			})
		}
	})

	t.Run("cross_host_not_annotated", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		// /api/things lives on a different host than the bundle
		mockHTTP.AddProxyEntry(
			"GET /api/things HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/things');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/things"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Empty(t, resp.Endpoints[idx].LastFlow)
	})

	t.Run("same_host_path_relative_matches", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		historyFlowID := mockHTTP.AddProxyEntry(
			"GET /api/things HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/things');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/things"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("relative_literal_resolves_to_history", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		historyFlowID := mockHTTP.AddProxyEntry(
			"GET /login/assets/User-x.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n//asset",
			"",
		)
		// Bundle at /login/app.js references a document-relative asset.
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /login/app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar u=\"assets/User-x.js\";",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID, "include_assets": true})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "assets/User-x.js"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("relative_resolves_against_extensionless_doc", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		historyFlowID := mockHTTP.AddProxyEntry(
			"GET /login/assets/User-x.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n//asset",
			"",
		)
		// HTML document served at extensionless route /login (no trailing slash);
		// the document-relative asset must resolve under /login/ via the dir fallback.
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+
				`<script>var u="assets/User-x.js";</script>`,
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID, "include_assets": true})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "assets/User-x.js"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("trailing_slash_and_fragment_match", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		historyFlowID := mockHTTP.AddProxyEntry(
			"GET /api/things/ HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/things');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/things"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("absolute_url_matches_own_host", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		apiFlowID := mockHTTP.AddProxyEntry(
			"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('https://api.example.com/v1/users');",
			"",
		)

		// Cross-host endpoint: requires origin=full (filtered under same-origin default)
		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID, "origin": "full"})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "https://api.example.com/v1/users"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, apiFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("assets_dropped_by_default", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		// A vite-style chunk manifest plus a real API endpoint
		jsBody := `var __vite__mapDeps=["assets/index-BMaEmbqv.js","assets/Loading-Dz9iJOJs.css"];` +
			`fetch("/api/real");`
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
			"",
		)
		hasURL := func(eps []protocol.ExtractedEndpoint, u string) bool {
			return slices.ContainsFunc(eps, func(e protocol.ExtractedEndpoint) bool { return e.URL == u })
		}

		def := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID})
		assert.True(t, hasURL(def.Endpoints, "/api/real"))
		assert.False(t, hasURL(def.Endpoints, "assets/index-BMaEmbqv.js"))
		assert.False(t, hasURL(def.Endpoints, "assets/Loading-Dz9iJOJs.css"))
		// script_blocks is omitted for pure JS
		assert.Zero(t, def.Stats.ScriptBlocks)

		withAssets := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": bundleFlowID, "include_assets": true})
		assert.True(t, hasURL(withAssets.Endpoints, "assets/index-BMaEmbqv.js"))
	})

	t.Run("origin_modes", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		jsBody := `fetch('/api/local');` +
			`fetch('https://cdn.lib.com/a');fetch('https://cdn.lib.com/b');` +
			`fetch('https://use.typekit.net/x');`
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
			"",
		)
		call := func(origin string) protocol.JSAnalyzeResponse {
			return CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_surface",
				map[string]interface{}{"flow_id": bundleFlowID, "origin": origin})
		}
		hasURL := func(eps []protocol.ExtractedEndpoint, u string) bool {
			return slices.ContainsFunc(eps, func(e protocol.ExtractedEndpoint) bool { return e.URL == u })
		}

		// same-origin (default): only the relative path
		def := call("same-origin")
		assert.True(t, hasURL(def.Endpoints, "/api/local"))
		assert.False(t, hasURL(def.Endpoints, "https://cdn.lib.com/a"))
		assert.Empty(t, def.OriginSummary)

		// full: everything
		full := call("full")
		assert.True(t, hasURL(full.Endpoints, "/api/local"))
		assert.True(t, hasURL(full.Endpoints, "https://use.typekit.net/x"))

		// summary: no endpoints, per-host counts with same-origin flagged first
		sum := call("summary")
		assert.Empty(t, sum.Endpoints)
		require.NotEmpty(t, sum.OriginSummary)
		assert.Equal(t, "app.example.com", sum.OriginSummary[0].Origin)
		counts := make(map[string]int)
		for _, o := range sum.OriginSummary {
			counts[o.Origin] = o.Count
		}
		assert.Equal(t, 2, counts["cdn.lib.com"])
		assert.Equal(t, 1, counts["app.example.com"])

		// specific host set: only that host's endpoints
		drill := call("use.typekit.net")
		assert.True(t, hasURL(drill.Endpoints, "https://use.typekit.net/x"))
		assert.False(t, hasURL(drill.Endpoints, "/api/local"))
		assert.False(t, hasURL(drill.Endpoints, "https://cdn.lib.com/a"))
	})

	t.Run("rejects_non_js", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		flowID := mockHTTP.AddProxyEntry(
			"GET /data.json HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"x\":1}",
			"",
		)

		result := CallMCPTool(t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": flowID})
		require.True(t, result.IsError)
	})

	t.Run("unknown_flow", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "js_surface",
			map[string]interface{}{"flow_id": "no-such-flow"})
		require.True(t, result.IsError)
	})
}

func TestNormalizePathKey(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"/x", "/x"},
		{"/x/", "/x"},
		{"/x#frag", "/x"},
		{"/x/#frag", "/x"},
		{"/", "/"},
		{"/x/?a=1", "/x?a=1"},
		{"/x?a=1", "/x?a=1"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizePathKey(tc.in))
		})
	}
}

func TestEndpointHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"/api/x", ""},
		{"assets/User-x.js", ""},
		{"/api/${...}/users", ""},
		{"https://a.com/x", "a.com"},
		{"http://a.com:8080/x", "a.com:8080"},
		{"//cdn.example.com/lib.js", "cdn.example.com"},
		{"wss://ws.example.com/socket", "ws.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, endpointHost(tc.in))
		})
	}
}

func TestSameOriginHosts(t *testing.T) {
	t.Parallel()

	t.Run("bundle_host_only", func(t *testing.T) {
		set := sameOriginHosts("app.example.com", "Content-Type: text/javascript")
		assert.Contains(t, set, "app.example.com")
		assert.Len(t, set, 1)
	})

	t.Run("cors_specific_host_added", func(t *testing.T) {
		set := sameOriginHosts("cdn.example.com",
			"Access-Control-Allow-Origin: https://app.example.com")
		assert.Contains(t, set, "cdn.example.com")
		assert.Contains(t, set, "app.example.com")
	})

	t.Run("cors_wildcard_ignored", func(t *testing.T) {
		set := sameOriginHosts("app.example.com", "Access-Control-Allow-Origin: *")
		assert.Len(t, set, 1)
		assert.Contains(t, set, "app.example.com")
	})
}

func TestApplyOrigin(t *testing.T) {
	t.Parallel()

	eps := []protocol.ExtractedEndpoint{
		{URL: "/api/local"},
		{URL: "https://cdn.lib.com/a"},
		{URL: "https://cdn.lib.com/b"},
		{URL: "https://api.partner.com/x"},
	}
	same := map[string]struct{}{"app.example.com": {}}

	t.Run("same_origin_keeps_relative_only", func(t *testing.T) {
		out, summary := applyOrigin(eps, same, "app.example.com", originSameOrigin)
		assert.Nil(t, summary)
		assert.Len(t, out, 1)
		assert.Equal(t, "/api/local", out[0].URL)
	})

	t.Run("full_keeps_all", func(t *testing.T) {
		out, summary := applyOrigin(eps, same, "app.example.com", originFull)
		assert.Nil(t, summary)
		assert.Len(t, out, 4)
	})

	t.Run("summary_per_host_same_first", func(t *testing.T) {
		out, summary := applyOrigin(eps, same, "app.example.com", originSummary)
		assert.Nil(t, out)
		assert.Equal(t, "app.example.com", summary[0].Origin)
		counts := make(map[string]int, len(summary))
		for _, o := range summary {
			counts[o.Origin] = o.Count
		}
		assert.Equal(t, 1, counts["app.example.com"])
		assert.Equal(t, 2, counts["cdn.lib.com"])
		assert.Equal(t, 1, counts["api.partner.com"])
	})

	t.Run("specific_host_set", func(t *testing.T) {
		out, summary := applyOrigin(eps, same, "app.example.com", "cdn.lib.com")
		assert.Nil(t, summary)
		assert.Len(t, out, 2)
		for _, e := range out {
			assert.Equal(t, "https://cdn.lib.com", e.URL[:len("https://cdn.lib.com")])
		}
	})
}
