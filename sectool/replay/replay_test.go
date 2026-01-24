package replay

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		headers  map[string]string
		toDelete string
		expected map[string]string
	}{
		{
			name:     "exact_match",
			headers:  map[string]string{"Content-Type": "application/json"},
			toDelete: "Content-Type",
			expected: map[string]string{},
		},
		{
			name:     "case_insensitive_match",
			headers:  map[string]string{"Content-Type": "application/json"},
			toDelete: "content-type",
			expected: map[string]string{},
		},
		{
			name:     "uppercase_input",
			headers:  map[string]string{"content-type": "application/json"},
			toDelete: "CONTENT-TYPE",
			expected: map[string]string{},
		},
		{
			name:     "with_whitespace",
			headers:  map[string]string{"Content-Type": "application/json"},
			toDelete: "  Content-Type  ",
			expected: map[string]string{},
		},
		{
			name:     "no_match",
			headers:  map[string]string{"Content-Type": "application/json"},
			toDelete: "Accept",
			expected: map[string]string{"Content-Type": "application/json"},
		},
		{
			name:     "multiple_headers_delete_one",
			headers:  map[string]string{"Content-Type": "application/json", "Accept": "text/html"},
			toDelete: "content-type",
			expected: map[string]string{"Accept": "text/html"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteHeaderCaseInsensitive(tt.headers, tt.toDelete)
			assert.Equal(t, tt.expected, tt.headers)
		})
	}
}

func TestApplyHeaderModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		headers       map[string]string
		addHeaders    []string
		removeHeaders []string
		expected      map[string]string
	}{
		{
			name:          "add_single_header",
			headers:       map[string]string{"Accept": "text/html"},
			addHeaders:    []string{"X-Custom: value"},
			removeHeaders: nil,
			expected:      map[string]string{"Accept": "text/html", "X-Custom": "value"},
		},
		{
			name:          "remove_single_header",
			headers:       map[string]string{"Accept": "text/html", "Content-Type": "application/json"},
			addHeaders:    nil,
			removeHeaders: []string{"Content-Type"},
			expected:      map[string]string{"Accept": "text/html"},
		},
		{
			name:          "add_and_remove",
			headers:       map[string]string{"Accept": "text/html"},
			addHeaders:    []string{"X-New: new-value"},
			removeHeaders: []string{"Accept"},
			expected:      map[string]string{"X-New": "new-value"},
		},
		{
			name:          "add_overwrites_existing",
			headers:       map[string]string{"Accept": "text/html"},
			addHeaders:    []string{"Accept: application/json"},
			removeHeaders: nil,
			expected:      map[string]string{"Accept": "application/json"},
		},
		{
			name:          "remove_case_insensitive",
			headers:       map[string]string{"Content-Type": "application/json"},
			addHeaders:    nil,
			removeHeaders: []string{"content-type"},
			expected:      map[string]string{},
		},
		{
			name:          "header_canonicalized",
			headers:       map[string]string{},
			addHeaders:    []string{"x-custom-header: value"},
			removeHeaders: nil,
			expected:      map[string]string{"X-Custom-Header": "value"},
		},
		{
			name:          "invalid_header_format_ignored",
			headers:       map[string]string{"Accept": "text/html"},
			addHeaders:    []string{"invalid-no-colon"},
			removeHeaders: nil,
			expected:      map[string]string{"Accept": "text/html"},
		},
		{
			name:          "original_not_modified",
			headers:       map[string]string{"Accept": "text/html"},
			addHeaders:    []string{"X-New: value"},
			removeHeaders: nil,
			expected:      map[string]string{"Accept": "text/html", "X-New": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make(map[string]string)
			for k, v := range tt.headers {
				original[k] = v
			}

			result := applyHeaderModifications(tt.headers, tt.addHeaders, tt.removeHeaders)
			assert.Equal(t, tt.expected, result)

			// Verify original wasn't modified (except in "original_not_modified" test which doesn't check this)
			if tt.name != "original_not_modified" {
				assert.Equal(t, original, tt.headers)
			}
		})
	}
}

func TestApplyURLModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		baseURL     string
		target      string
		path        string
		query       string
		setQuery    []string
		removeQuery []string
		expected    string
		wantErr     bool
	}{
		{
			name:     "no_modifications",
			baseURL:  "https://example.com/api/v1?foo=bar",
			expected: "https://example.com/api/v1?foo=bar",
		},
		{
			name:     "change_target_host",
			baseURL:  "https://example.com/api/v1?foo=bar",
			target:   "https://staging.example.com",
			expected: "https://staging.example.com/api/v1?foo=bar",
		},
		{
			name:     "change_path",
			baseURL:  "https://example.com/api/v1",
			path:     "/api/v2",
			expected: "https://example.com/api/v2",
		},
		{
			name:     "replace_entire_query",
			baseURL:  "https://example.com/api?old=value",
			query:    "new=value",
			expected: "https://example.com/api?new=value",
		},
		{
			name:     "set_query_param",
			baseURL:  "https://example.com/api?existing=keep",
			setQuery: []string{"new=added"},
			expected: "https://example.com/api?existing=keep&new=added",
		},
		{
			name:        "remove_query_param",
			baseURL:     "https://example.com/api?remove=this&keep=that",
			removeQuery: []string{"remove"},
			expected:    "https://example.com/api?keep=that",
		},
		{
			name:        "set_and_remove_query",
			baseURL:     "https://example.com/api?a=1&b=2",
			setQuery:    []string{"c=3"},
			removeQuery: []string{"a"},
			expected:    "https://example.com/api?b=2&c=3",
		},
		{
			name:     "target_with_path_override",
			baseURL:  "https://example.com/old/path",
			target:   "https://new.example.com",
			path:     "/new/path",
			expected: "https://new.example.com/new/path",
		},
		{
			name:    "invalid_base_url",
			baseURL: "://invalid",
			wantErr: true,
		},
		{
			name:    "invalid_target_url",
			baseURL: "https://example.com/api",
			target:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := applyURLModifications(tt.baseURL, tt.target, tt.path, tt.query, tt.setQuery, tt.removeQuery)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildURLFromHTTPRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      *http.Request
		target   string
		expected string
		wantErr  bool
	}{
		{
			name: "with_target",
			req: &http.Request{
				Method: "GET",
				Host:   "original.com",
				URL:    mustParseURL("/api/v1?q=test"),
			},
			target:   "https://override.com",
			expected: "https://override.com/api/v1?q=test",
		},
		{
			name: "from_host_header",
			req: &http.Request{
				Method: "GET",
				Host:   "example.com",
				URL:    mustParseURL("/path"),
			},
			expected: "https://example.com/path",
		},
		{
			name: "localhost_uses_http",
			req: &http.Request{
				Method: "GET",
				Host:   "localhost:8080",
				URL:    mustParseURL("/api"),
			},
			expected: "http://localhost:8080/api",
		},
		{
			name: "127_uses_http",
			req: &http.Request{
				Method: "GET",
				Host:   "127.0.0.1:3000",
				URL:    mustParseURL("/test"),
			},
			expected: "http://127.0.0.1:3000/test",
		},
		{
			name: "no_host_no_target",
			req: &http.Request{
				Method: "GET",
				Host:   "",
				Header: http.Header{},
				URL:    mustParseURL("/path"),
			},
			wantErr: true,
		},
		{
			name: "host_from_header",
			req: &http.Request{
				Method: "GET",
				Host:   "",
				Header: http.Header{"Host": []string{"from-header.com"}},
				URL:    mustParseURL("/path"),
			},
			expected: "https://from-header.com/path",
		},
		{
			name: "invalid_target",
			req: &http.Request{
				Method: "GET",
				Host:   "example.com",
				URL:    mustParseURL("/path"),
			},
			target:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildURLFromHTTPRequest(tt.req, tt.target)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
