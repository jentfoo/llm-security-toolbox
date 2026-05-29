package js

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLooksLikeURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"https_with_query", "https://example.com/path?q=1", true},
		{"http_root", "http://example.com/", true},
		{"wss_path", "wss://ws.example/socket", true},
		{"protocol_relative", "//cdn.example.com/x.js", true},
		{"absolute_path", "/api/users", true},
		{"absolute_path_query", "/api/users?id=1", true},
		{"dot_relative", "./local", true},
		{"dot_dot_relative", "../up/over", true},
		{"bare_relative", "api/users", true},
		{"asset_relative", "assets/main.js", true},
		{"template_interpolation", "/api/users/${id}", true},
		{"plain_text_rejected", "hello world", false},
		{"i18n_key_rejected", "translation.key", false},
		{"bare_ident_rejected", "foo", false},
		{"angle_brackets_rejected", "https://example.com/<script>", false},
		{"empty_rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, looksLikeURL(tc.in))
		})
	}
}

func TestLooksLikeWebSocketURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ws_scheme", "ws://x/y", true},
		{"wss_scheme", "wss://x/y", true},
		{"ws_template_host", "ws://${host}/sock", true},
		{"wss_template_path", "wss://example.com/${path}", true},
		{"bare_text_rejected", "notaurl", false},
		{"absolute_path_rejected", "/socket", false},
		{"https_rejected", "https://example.com/", false},
		{"protocol_relative_rejected", "//cdn/foo", false},
		{"empty_rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, looksLikeWebSocketURL(tc.in))
		})
	}
}

func TestIsAsset(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want bool
	}{
		{"assets/index-BMaEmbqv.js", true},
		{"./authContext-jXxQusJa.js", true},
		{"/static/app.css", true},
		{"https://cdn.example.com/lib.woff2", true},
		{"/fonts/x.ttf?v=2", true},
		{"/api/users", false},
		{"/api/users.json", false}, // data, not a static asset
		{"/api/report.xml", false},
		{"/api/${id}/users", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, IsAsset(tc.in))
		})
	}
}

func TestAcceptCandidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string // "" means rejected
	}{
		{"rooted_two_segments", "/api/org", "/api/org"},
		{"rooted_hyphen_segment", "/api/email-login", "/api/email-login"},
		{"rooted_camel_segment", "/api/appIdBundle/revoke", "/api/appIdBundle/revoke"},
		{"absolute_dotted_host", "https://api.example.com/v1/x", "https://api.example.com/v1/x"},
		{"absolute_host_with_port", "https://api.example.com:8443/v1/x", "https://api.example.com:8443/v1/x"},
		{"protocol_relative_dotted", "//use.typekit.net/c/641466/x", "//use.typekit.net/c/641466/x"},
		{"templated_host_salvages_path", "{scheme}://{hostname}/af/641466", "/af/641466"},
		{"asset_relative_extension", "assets/User-BdP5f-lC.js", "assets/User-BdP5f-lC.js"},
		{"escaped_slash_path", `\/api\/org`, "/api/org"},
		{"template_placeholder_normalized", "/api/${id}/users", "/api/${...}/users"},
		{"reject_mime_type", "application/json", ""},
		{"reject_placeholder_only_host", "https://${t}", ""},
		{"reject_base64_token", "/BOnNT28UC/F4GogAGqG", ""},
		{"reject_bare_relative_no_ext", "home/title", ""},
		// single-segment recall behind a placeholder base
		{"single_seg_root", "/login", "/login"},
		{"single_seg_placeholder_base", "${host}/methods", "/methods"},
		{"single_seg_printf_base", "%s/saml-login", "/saml-login"},
		{"single_seg_versionish", "/v1", "/v1"},
		{"reject_single_char_seg", "/g", ""},
		{"reject_numeric_seg", "/2", ""},
		{"reject_placeholder_seg", "/${id}", ""},
		{"reject_display_template", "${a}/${b}", ""},
		// regex literals stored as strings/templates (metachar body + flag suffix)
		{"reject_regex_tilde", "/~1/g", ""},
		{"reject_regex_template", "/.${id}/g", ""},
		{"reject_bare_slash", "/", ""},
		// flag-shaped final segment is coincidental: ordinary short paths are kept
		{"keep_word_path_flag_suffix", "/api/g", "/api/g"},
		{"keep_short_path_flag_letters", "/x/y", "/x/y"},
		// length/shape bound: swallowed code and oversized blobs are rejected
		{"reject_code_punctuation", "/foo(),bytesCount:t.bytesCount", ""},
		{"reject_regex_dollar", "/.css$/i.test", ""},
		{"reject_oversized", "/x" + strings.Repeat("a", 1200), ""},
		{"keep_query_url", "/api/x?id=1&t=2", "/api/x?id=1&t=2"},
		// /regex/.method() calls captured as paths
		{"reject_regex_test_tail", "/Android/.test", ""},
		{"reject_regex_flag_test_tail", "/Trident/i.test", ""},
		{"keep_path_named_test", "/api/test", "/api/test"},
		// bogus hosts and CSS-in-JS; comma-list and gRPC-colon paths must survive
		{"reject_bogus_host", "//.+", ""},
		{"reject_css_in_js", "/2,opacity:1,backgroundColor:x.slate", ""},
		{"keep_comma_list_path", "/items/1,2,3", "/items/1,2,3"},
		{"keep_grpc_colon_path", "/v1/models/x:gen", "/v1/models/x:gen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, acceptCandidate(tc.in))
		})
	}
}

func TestExtractFromSource(t *testing.T) {
	t.Parallel()

	endpointURLs := func(got Extracted) map[string]string {
		m := make(map[string]string, len(got.Endpoints))
		for _, e := range got.Endpoints {
			m[e.URL] = e.Library
		}
		return m
	}

	t.Run("captures_source_map_url", func(t *testing.T) {
		src := []byte(`var x=1;
//# sourceMappingURL=app.js.map`)
		pr := parseSource(src)
		got, _ := extractFromSource(src, pr.ast)
		assert.Equal(t, []string{"app.js.map"}, got.SourceMaps)
	})

	t.Run("returns_token_literals_for_secrets", func(t *testing.T) {
		src := []byte(`var k = "secret-value-x";`)
		_, literals := extractFromSource(src, nil)
		assert.Contains(t, literals, "secret-value-x")
	})

	t.Run("ast_nil_still_scans_literals", func(t *testing.T) {
		// With a nil AST the AST visitor is skipped, but URL-shaped literals
		// still flow into Endpoints as libLiteral entries via the raw scan.
		src := []byte(`var x = '/api/from-tokens';`)
		got, _ := extractFromSource(src, nil)
		require.Len(t, got.Endpoints, 1)
		assert.Equal(t, "/api/from-tokens", got.Endpoints[0].URL)
		assert.Equal(t, libLiteral, got.Endpoints[0].Library)
	})

	t.Run("literal_does_not_duplicate_sink_url", func(t *testing.T) {
		src := []byte(`fetch('/api/x'); var also = '/api/x';`)
		pr := parseSource(src)
		got, _ := extractFromSource(src, pr.ast)
		var matches int
		for _, e := range got.Endpoints {
			if e.URL == "/api/x" {
				matches++
			}
		}
		assert.Equal(t, 1, matches)
	})

	t.Run("templated_path_behind_placeholder", func(t *testing.T) {
		// tdewolff cannot parse this; the raw scan must still recover the path
		// out of the "%s"-prefixed template.
		src := []byte(`var u="%s/api/org",v="%s/api/auth/jwt"...`)
		got, _ := extractFromSource(src, nil)
		urls := endpointURLs(got)
		assert.Contains(t, urls, "/api/org")
		assert.Contains(t, urls, "/api/auth/jwt")
	})

	t.Run("recovers_after_truncation", func(t *testing.T) {
		src := []byte(`var a="/api/before"; var b="https://x.com/` + "\n" +
			`x; fetch("/api/after"); var c="https://y.com/api/last`)
		got, _ := extractFromSource(src, nil)
		urls := endpointURLs(got)
		assert.Contains(t, urls, "/api/before")
		assert.Contains(t, urls, "/api/after")
	})

	t.Run("recovers_escaped_slash_path", func(t *testing.T) {
		// "\x2fapi\x2forg" has no literal slash byte; recovery comes from the
		// decoded-literal pass.
		src := []byte("var u=\"\\x2fapi\\x2forg\";")
		got, _ := extractFromSource(src, nil)
		assert.Contains(t, endpointURLs(got), "/api/org")
	})

	t.Run("rejects_mime_and_division", func(t *testing.T) {
		src := []byte(`var ct="application/json"; var x = a/b;`)
		got, _ := extractFromSource(src, nil)
		assert.Empty(t, got.Endpoints)
	})

	t.Run("method_via_variable_propagation", func(t *testing.T) {
		// URL indirected through a variable: method/library should still attach,
		// and the literal scan must not also list a bare /api/foo.
		src := []byte("const n=`${x}/api/foo`; fetch(n,{method:\"POST\"});")
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		require.Len(t, got.Endpoints, 1)
		assert.Equal(t, "${...}/api/foo", got.Endpoints[0].URL)
		assert.Equal(t, "POST", got.Endpoints[0].Method)
		assert.Equal(t, libFetch, got.Endpoints[0].Library)
	})

	t.Run("method_wrapper_identifier", func(t *testing.T) {
		src := []byte(`var u="/api/x"; buildRequest("POST", u);`)
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		require.Len(t, got.Endpoints, 1)
		assert.Equal(t, "/api/x", got.Endpoints[0].URL)
		assert.Equal(t, "POST", got.Endpoints[0].Method)
		assert.Equal(t, libRequest, got.Endpoints[0].Library)
	})

	t.Run("method_wrapper_member", func(t *testing.T) {
		src := []byte(`api.request("GET", "/api/y");`)
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		require.Len(t, got.Endpoints, 1)
		assert.Equal(t, "GET", got.Endpoints[0].Method)
		assert.Equal(t, libRequest, got.Endpoints[0].Library)
	})

	t.Run("method_wrapper_xhr_open_stays_xhr", func(t *testing.T) {
		// xhr.open(method, url) matches the wrapper shape too, but the specific
		// sink is emitted first and wins dedupe (applied by AnalyzeJS).
		res := AnalyzeJS([]byte(`var xhr=new XMLHttpRequest(); xhr.open("GET","/api/g");`))
		require.Len(t, res.Endpoints, 1)
		assert.Equal(t, libXHR, res.Endpoints[0].Library)
	})

	t.Run("method_wrapper_requires_url", func(t *testing.T) {
		// non-URL second arg yields nothing (confident signal only).
		src := []byte(`t("POST", someVar);`)
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		assert.Empty(t, got.Endpoints)
	})

	t.Run("definite_sink_keeps_slashless_file", func(t *testing.T) {
		// A definite sink (fetch) tells us the arg is a request target, so a
		// slash-less relative file is kept — but a bare i18n key is not.
		src := []byte(`fetch("config.json"); axios.get("translation.key");`)
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		require.Len(t, got.Endpoints, 1)
		assert.Equal(t, "config.json", got.Endpoints[0].URL)
		assert.Equal(t, libFetch, got.Endpoints[0].Library)
	})

	t.Run("sink_rejects_non_url_args", func(t *testing.T) {
		// base64 alphabet constant and an error-message template are not URLs and
		// must not be reported as endpoints despite looking method-call-shaped.
		src := []byte(`var d="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";` +
			`buildRequest("POST", d); request("GET", "state-${id}");`)
		pr := parseSource(src)
		require.NoError(t, pr.err)
		got, _ := extractFromSource(src, pr.ast)
		assert.Empty(t, got.Endpoints)
	})
}
