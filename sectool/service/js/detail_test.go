package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// listEndpoint returns the deduped endpoint matching method+url from AnalyzeJS.
func listEndpoint(t *testing.T, src, method, url string) protocol.ExtractedEndpoint {
	t.Helper()

	r := AnalyzeJS([]byte(src))
	for _, e := range r.Endpoints {
		if e.Method == method && e.URL == url {
			return e
		}
	}
	t.Fatalf("endpoint %s %s not found in %+v", method, url, r.Endpoints)
	return protocol.ExtractedEndpoint{}
}

// detailFor resolves the endpoint_id from the list, then returns the js_endpoint detail.
func detailFor(t *testing.T, src, method, url string) *protocol.JSEndpointResponse {
	t.Helper()

	ep := listEndpoint(t, src, method, url)
	require.NotEmpty(t, ep.EndpointID, "expected endpoint_id for %s %s", method, url)
	resp, ok := AnalyzeJSEndpoint([]byte(src), ep.EndpointID)
	require.True(t, ok)
	return resp
}

func fieldMap(fields []protocol.JSField) map[string]string {
	m := make(map[string]string, len(fields))
	for _, f := range fields {
		m[f.Name] = f.Value
	}
	return m
}

func TestAnalyzeJSEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("fetch_json_body_fields", func(t *testing.T) {
		src := `fetch('/api/users', {method: 'POST', body: JSON.stringify({name, email})});`
		resp := detailFor(t, src, "POST", "/api/users")
		require.Len(t, resp.CallSites, 1)
		cs := resp.CallSites[0]
		require.NotNil(t, cs.Body)
		assert.Equal(t, "json", cs.Body.ContentType)
		assert.ElementsMatch(t, []string{"name", "email"}, []string{cs.Body.Fields[0].Name, cs.Body.Fields[1].Name})
	})

	t.Run("static_and_dynamic_headers", func(t *testing.T) {
		src := `fetch('/api/data', {headers: {'X-API-Key': 'abc', 'Authorization': 'Bearer ' + t}});`
		resp := detailFor(t, src, "", "/api/data")
		require.Len(t, resp.CallSites, 1)
		h := fieldMap(resp.CallSites[0].Headers)
		assert.Equal(t, "abc", h["X-API-Key"])
		assert.Contains(t, h["Authorization"], "Bearer")
	})

	t.Run("path_params_and_query", func(t *testing.T) {
		src := "fetch(`/users/${userId}?active=true`);"
		resp := detailFor(t, src, "", "/users/${...}?active=true")
		require.Len(t, resp.CallSites, 1)
		cs := resp.CallSites[0]
		assert.Equal(t, []string{"userId"}, cs.PathParams)
		assert.Equal(t, "true", fieldMap(cs.Query)["active"])
	})

	t.Run("axios_object_form", func(t *testing.T) {
		src := `axios({url: '/api/x', method: 'post', data: {a: 1}, headers: {H: 'v'}, params: {p: 'q'}});`
		resp := detailFor(t, src, "POST", "/api/x")
		require.Len(t, resp.CallSites, 1)
		cs := resp.CallSites[0]
		require.NotNil(t, cs.Body)
		assert.Equal(t, "1", fieldMap(cs.Body.Fields)["a"])
		assert.Equal(t, "v", fieldMap(cs.Headers)["H"])
		assert.Equal(t, "q", fieldMap(cs.Query)["p"])
	})

	t.Run("axios_get_params_only", func(t *testing.T) {
		// params-sourced query is not in the list URL, so it must make the endpoint queryable
		src := `axios.get('/search', {params: {q: 'x', page: 2}});`
		resp := detailFor(t, src, "GET", "/search")
		require.Len(t, resp.CallSites, 1)
		q := fieldMap(resp.CallSites[0].Query)
		assert.Equal(t, "x", q["q"])
		assert.Equal(t, "2", q["page"])
	})

	t.Run("axios_shortcut_post_body", func(t *testing.T) {
		src := `axios.post('/api/y', {x: 1});`
		resp := detailFor(t, src, "POST", "/api/y")
		require.Len(t, resp.CallSites, 1)
		require.NotNil(t, resp.CallSites[0].Body)
		assert.Contains(t, fieldMap(resp.CallSites[0].Body.Fields), "x")
	})

	t.Run("websocket_path_params", func(t *testing.T) {
		src := "new WebSocket(`wss://h.test/room/${roomId}`);"
		resp := detailFor(t, src, "", "wss://h.test/room/${...}")
		require.Len(t, resp.CallSites, 1)
		assert.Equal(t, []string{"roomId"}, resp.CallSites[0].PathParams)
	})

	t.Run("multiple_call_sites_grouped", func(t *testing.T) {
		src := `fetch('/api/u', {method: 'POST', body: JSON.stringify({a})});
fetch('/api/u', {method: 'POST'});`
		resp := detailFor(t, src, "POST", "/api/u")
		assert.Len(t, resp.CallSites, 2)
	})

	t.Run("no_match_returns_false", func(t *testing.T) {
		_, ok := AnalyzeJSEndpoint([]byte(`fetch('/api/u', {method: 'POST', body: JSON.stringify({a})});`), "zzzzzz")
		assert.False(t, ok)
	})
}

func TestEndpointIDGating(t *testing.T) {
	t.Parallel()

	t.Run("method_only_no_id", func(t *testing.T) {
		ep := listEndpoint(t, `fetch('/api/z', {method: 'POST'});`, "POST", "/api/z")
		assert.Empty(t, ep.EndpointID)
	})

	t.Run("bare_literal_no_id", func(t *testing.T) {
		ep := listEndpoint(t, `var u = '/just/a/path/here';`, "", "/just/a/path/here")
		assert.Equal(t, libLiteral, ep.Library)
		assert.Empty(t, ep.EndpointID)
	})

	t.Run("body_gets_id", func(t *testing.T) {
		ep := listEndpoint(t, `fetch('/api/b', {method: 'POST', body: JSON.stringify({x})});`, "POST", "/api/b")
		assert.NotEmpty(t, ep.EndpointID)
		assert.Equal(t, EndpointID("POST", "/api/b"), ep.EndpointID)
	})

	t.Run("distinct_method", func(t *testing.T) {
		assert.NotEqual(t, EndpointID("GET", "/x"), EndpointID("POST", "/x"))
	})
}
