package proxy

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

func newTestEntry(method, path string) *HistoryEntry {
	return &HistoryEntry{
		Protocol: "http/1.1",
		Request: &RawHTTP1Request{
			Method:  method,
			Path:    path,
			Version: "HTTP/1.1",
		},
		Timestamp: time.Now(),
	}
}

// newTestEntryAt produces a test entry with an explicit timestamp.
func newTestEntryAt(method, path string, ts time.Time) *HistoryEntry {
	e := newTestEntry(method, path)
	e.Timestamp = ts
	return e
}

func TestHistoryStore_Store(t *testing.T) {
	t.Parallel()

	t.Run("returns_unique_flow_id", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		seen := make(map[string]bool)
		for i := 0; i < 5; i++ {
			id := h.Store(newTestEntry("GET", "/"))
			assert.NotEmpty(t, id)
			assert.False(t, seen[id], "flow_id collision: %s", id)
			seen[id] = true
		}
		assert.Equal(t, 5, h.Count())
	})

	t.Run("populates_flow_id_on_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := newTestEntry("POST", "/api")
		flowID := h.Store(entry)
		assert.Equal(t, flowID, entry.FlowID)
	})

	t.Run("concurrent_writes", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		const numGoroutines = 10
		const entriesPerGoroutine = 100
		var wg sync.WaitGroup
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < entriesPerGoroutine; j++ {
					h.Store(newTestEntry("GET", "/"))
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, numGoroutines*entriesPerGoroutine, h.Count())
	})
}

func TestHistoryStore_Get(t *testing.T) {
	t.Parallel()

	t.Run("retrieves_stored_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		flowID := h.Store(newTestEntry("GET", "/foo"))
		got, ok := h.Get(flowID)
		require.True(t, ok)
		assert.Equal(t, flowID, got.FlowID)
		assert.Equal(t, "/foo", got.Request.Path)
	})

	t.Run("not_found", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		_, ok := h.Get("nonexistent")
		assert.False(t, ok)
	})

	t.Run("serialization_roundtrip", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: ts,
			Duration:  250 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/data",
				Query:   "foo=bar",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "x-custom", Value: "value"},
				},
				Body: []byte(`{"key":"value"}`),
			},
			Response: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 201,
				StatusText: "Created",
				Headers:    []Header{{Name: "Content-Type", Value: "application/json"}},
				Body:       []byte(`{"id":123}`),
			},
		}

		flowID := h.Store(entry)
		got, ok := h.Get(flowID)
		require.True(t, ok)

		assert.Equal(t, entry.Protocol, got.Protocol)
		assert.Equal(t, ts, got.Timestamp)
		assert.Equal(t, entry.Duration, got.Duration)
		assert.Equal(t, entry.Request.Method, got.Request.Method)
		assert.Equal(t, entry.Request.Path, got.Request.Path)
		assert.Equal(t, entry.Request.Query, got.Request.Query)
		assert.Equal(t, entry.Request.Version, got.Request.Version)
		assert.Equal(t, entry.Request.Headers, got.Request.Headers)
		assert.Equal(t, entry.Request.Body, got.Request.Body)
		assert.Equal(t, entry.Response.Version, got.Response.Version)
		assert.Equal(t, entry.Response.StatusCode, got.Response.StatusCode)
		assert.Equal(t, entry.Response.StatusText, got.Response.StatusText)
		assert.Equal(t, entry.Response.Headers, got.Response.Headers)
		assert.Equal(t, entry.Response.Body, got.Response.Body)
	})
}

func TestHistoryStore_Page(t *testing.T) {
	t.Parallel()

	t.Run("oldest_first_with_cursor", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		var ids []string
		for i := 0; i < 5; i++ {
			ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
		}

		entries := h.Page(2, "")
		require.Len(t, entries, 2)
		assert.Equal(t, ids[0], entries[0].FlowID)
		assert.Equal(t, ids[1], entries[1].FlowID)

		entries = h.Page(2, entries[len(entries)-1].FlowID)
		require.Len(t, entries, 2)
		assert.Equal(t, ids[2], entries[0].FlowID)
		assert.Equal(t, ids[3], entries[1].FlowID)

		entries = h.Page(2, entries[len(entries)-1].FlowID)
		require.Len(t, entries, 1)
		assert.Equal(t, ids[4], entries[0].FlowID)
	})

	t.Run("unknown_cursor_starts_from_beginning", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		first := h.Store(newTestEntryAt("GET", "/", base))
		h.Store(newTestEntryAt("GET", "/", base.Add(time.Millisecond)))

		entries := h.Page(1, "never-existed")
		require.Len(t, entries, 1)
		assert.Equal(t, first, entries[0].FlowID)
	})

	t.Run("empty_store", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entries := h.Page(10, "")
		assert.Empty(t, entries)
	})
}

func TestHistoryStore_PageMeta(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	base := time.Now()
	flow1 := h.Store(newTestEntryAt("POST", "/a", base))
	flow2 := h.Store(newTestEntryAt("GET", "/b", base.Add(time.Millisecond)))

	metas := h.PageMeta(10, "")
	require.Len(t, metas, 2)
	assert.Equal(t, flow1, metas[0].FlowID)
	assert.Equal(t, "POST", metas[0].Method)
	assert.Equal(t, flow2, metas[1].FlowID)
	assert.Equal(t, "GET", metas[1].Method)
	assert.False(t, metas[0].Timestamp.IsZero())
}

func TestHistoryStore_Delete(t *testing.T) {
	t.Parallel()

	t.Run("removes_entries", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		first := h.Store(newTestEntry("GET", "/"))
		second := h.Store(newTestEntry("GET", "/"))

		deleted := h.Delete(first)
		assert.Equal(t, 1, deleted)
		assert.Equal(t, 1, h.Count())

		_, ok := h.Get(first)
		assert.False(t, ok)
		_, ok = h.Get(second)
		assert.True(t, ok)
	})

	t.Run("idempotent_unknown_id", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		assert.Equal(t, 0, h.Delete("nonexistent"))
	})

	t.Run("deleted_cursor_falls_back_to_beginning", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		first := h.Store(newTestEntryAt("GET", "/", base))
		h.Store(newTestEntryAt("GET", "/", base.Add(time.Millisecond)))
		h.Delete(first)

		entries := h.Page(10, first)
		assert.Len(t, entries, 1)
	})

	t.Run("multi_id_with_unknowns", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		ids := make([]string, 5)
		for i := range ids {
			ids[i] = h.Store(newTestEntry("GET", "/"))
		}

		deleted := h.Delete(ids[0], "nope1", ids[2], "nope2", ids[4])
		assert.Equal(t, 3, deleted)
		assert.Equal(t, 2, h.Count())

		_, ok := h.Get(ids[1])
		assert.True(t, ok)
		_, ok = h.Get(ids[3])
		assert.True(t, ok)
	})

	t.Run("empty_input", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		h.Store(newTestEntry("GET", "/"))
		assert.Equal(t, 0, h.Delete())
		assert.Equal(t, 1, h.Count())
	})
}

func TestHistoryStore_Update(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	flowID := h.Store(newTestEntry("GET", "/"))
	entry, ok := h.Get(flowID)
	require.True(t, ok)

	entry.WSFrames = []WSFrame{{Direction: "to-server", Opcode: 1, Payload: []byte("hi")}}
	h.Update(entry)

	got, ok := h.Get(flowID)
	require.True(t, ok)
	require.Len(t, got.WSFrames, 1)
	assert.Equal(t, "hi", string(got.WSFrames[0].Payload))
}

func TestHistoryStore_TimestampOrdering(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	base := time.Now()
	var ids []string
	for i := 0; i < 20; i++ {
		ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
	}

	entries := h.Page(20, "")
	require.Len(t, entries, 20)
	for i, e := range entries {
		assert.Equal(t, ids[i], e.FlowID)
	}
}

func TestHistoryStore_Recovery(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := newHistoryStore(storage)

	base := time.Now()
	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
	}

	// Recreate store from same storage; recovery should rebuild ordering.
	h2 := newHistoryStore(storage)
	t.Cleanup(h2.Close)

	assert.Equal(t, 3, h2.Count())
	entries := h2.Page(10, "")
	require.Len(t, entries, 3)
	for i, e := range entries {
		assert.Equal(t, ids[i], e.FlowID)
	}
}

func TestFormatRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   *HistoryEntry
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/test",
					Version: "HTTP/1.1",
					Headers: []Header{{Name: "Host", Value: "example.com"}},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "GET /test HTTP/1.1")
				assert.Contains(t, string(result), "Host: example.com")
			},
		},
		{
			name: "h2_request",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Method:    "POST",
					Path:      "/api",
					Authority: "example.com",
					Headers:   []Header{{Name: "content-type", Value: "application/json"}},
					Body:      []byte(`{"test":1}`),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "POST /api HTTP/1.1")
				assert.Contains(t, string(result), "host: example.com")
				assert.Contains(t, string(result), "content-type: application/json")
				assert.Contains(t, string(result), `{"test":1}`)
			},
		},
		{
			name:    "nil_http1_request",
			entry:   &HistoryEntry{Protocol: "http/1.1"},
			wantNil: true,
		},
		{
			name:    "nil_h2_request",
			entry:   &HistoryEntry{Protocol: "h2"},
			wantNil: true,
		},
		{
			name: "h2_nil_headers",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Method:    "GET",
					Path:      "/test",
					Authority: "example.com",
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "GET /test HTTP/1.1")
				assert.Contains(t, string(result), "host: example.com")
			},
		},
		{
			name: "http1_empty_body",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/",
					Version: "HTTP/1.1",
					Headers: []Header{{Name: "Host", Value: "example.com"}},
					Body:    []byte{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "GET / HTTP/1.1")
			},
		},
	}

	var buf bytes.Buffer // reuse to validate reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatRequest(&buf)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestFormatResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   *HistoryEntry
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Version:    "HTTP/1.1",
					StatusCode: 200,
					StatusText: "OK",
					Headers:    []Header{{Name: "Content-Type", Value: "text/plain"}},
					Body:       []byte("Hello"),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "HTTP/1.1 200 OK")
				assert.Contains(t, string(result), "Content-Type: text/plain")
				assert.Contains(t, string(result), "Hello")
			},
		},
		{
			name: "h2_response",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					StatusCode: 201,
					Headers:    []Header{{Name: "content-type", Value: "application/json"}},
					Body:       []byte(`{"id":1}`),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "HTTP/2 201 Created")
				assert.Contains(t, string(result), "content-type: application/json")
				assert.Contains(t, string(result), `{"id":1}`)
			},
		},
		{
			name:    "nil_http1_response",
			entry:   &HistoryEntry{Protocol: "http/1.1"},
			wantNil: true,
		},
		{
			name:    "nil_h2_response",
			entry:   &HistoryEntry{Protocol: "h2"},
			wantNil: true,
		},
		{
			name: "h2_nonstandard_status",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: &H2ResponseData{StatusCode: 999},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				// StatusText should default to empty for non-standard codes
				assert.Contains(t, string(result), "HTTP/2 999")
			},
		},
		{
			name: "http1_empty_body",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Version:    "HTTP/1.1",
					StatusCode: 204,
					StatusText: "No Content",
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				assert.Contains(t, string(result), "HTTP/1.1 204 No Content")
			},
		},
	}

	var buf bytes.Buffer // reuse to validate reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatResponse(&buf)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestGetPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Path: "/api/users"},
			},
			want: "/api/users",
		},
		{
			name: "h2_no_query",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Path: "/api/data"},
			},
			want: "/api/data",
		},
		{
			name: "h2_strips_query",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Path: "/search?q=test&page=1"},
			},
			want: "/search",
		},
		{
			name:  "nil_http1",
			entry: &HistoryEntry{Protocol: "http/1.1"},
			want:  "",
		},
		{
			name:  "nil_h2",
			entry: &HistoryEntry{Protocol: "h2"},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetPath())
		})
	}
}

func TestGetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Headers: []Header{{Name: "Host", Value: "example.com"}}},
			},
			want: "example.com",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Authority: "api.example.com"},
			},
			want: "api.example.com",
		},
		{
			name:  "nil_http1",
			entry: &HistoryEntry{Protocol: "http/1.1"},
			want:  "",
		},
		{
			name:  "nil_h2",
			entry: &HistoryEntry{Protocol: "h2"},
			want:  "",
		},
		{
			name: "http1_case_insensitive",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Headers: []Header{{Name: "host", Value: "lowercase.com"}}},
			},
			want: "lowercase.com",
		},
		{
			name: "http1_no_host_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Headers: []Header{{Name: "X-Custom", Value: "value"}}},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetHost())
		})
	}
}

func TestGetRequestHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      *HistoryEntry
		headerName string
		want       string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Headers: []Header{{Name: "Content-Type", Value: "application/json"}}},
			},
			headerName: "Content-Type",
			want:       "application/json",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Headers: []Header{{Name: "authorization", Value: "Bearer token"}}},
			},
			headerName: "authorization",
			want:       "Bearer token",
		},
		{
			name:       "nil_request",
			entry:      &HistoryEntry{Protocol: "http/1.1"},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name: "case_insensitive_lookup",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Headers: []Header{{Name: "Content-Type", Value: "text/plain"}}},
			},
			headerName: "content-type",
			want:       "text/plain",
		},
		{
			name: "first_matching_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{Headers: []Header{
					{Name: "X-Custom", Value: "first"},
					{Name: "x-custom", Value: "second"},
				}},
			},
			headerName: "X-Custom",
			want:       "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetRequestHeader(tt.headerName))
		})
	}
}

func TestGetResponseHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      *HistoryEntry
		headerName string
		want       string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{Headers: []Header{{Name: "Content-Type", Value: "text/html"}}},
			},
			headerName: "Content-Type",
			want:       "text/html",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: &H2ResponseData{Headers: []Header{{Name: "x-request-id", Value: "abc123"}}},
			},
			headerName: "x-request-id",
			want:       "abc123",
		},
		{
			name:       "nil_response",
			entry:      &HistoryEntry{Protocol: "http/1.1"},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name: "case_insensitive_lookup",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{Headers: []Header{{Name: "Content-Type", Value: "text/plain"}}},
			},
			headerName: "content-type",
			want:       "text/plain",
		},
		{
			name: "first_matching_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{Headers: []Header{
					{Name: "Set-Cookie", Value: "first=1"},
					{Name: "Set-Cookie", Value: "second=2"},
				}},
			},
			headerName: "Set-Cookie",
			want:       "first=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetResponseHeader(tt.headerName))
		})
	}
}

func TestHistoryStore_PageConcurrent(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	const initial = 100
	const writers = 5
	const writerIterations = 50
	const readers = 5
	const readerIterations = 50

	for i := 0; i < initial; i++ {
		h.Store(newTestEntry("GET", "/"))
	}

	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < readerIterations; j++ {
				_ = h.Page(10, "")
				_ = h.PageMeta(10, "")
			}
		}()
	}
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writerIterations; j++ {
				h.Store(newTestEntry("POST", "/concurrent"))
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, initial+writers*writerIterations, h.Count())

	entries := h.Page(10, "")
	require.Len(t, entries, 10)
	for _, e := range entries {
		assert.NotEmpty(t, e.GetMethod())
		assert.NotEmpty(t, e.GetPath())
	}
}

func TestHistoryStore_UpdateConcurrent(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	flowID := h.Store(newTestEntry("GET", "/"))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entry, ok := h.Get(flowID)
			if !ok {
				return
			}
			entry.Response = &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200 + idx,
			}
			h.Update(entry)
		}(i)
	}
	wg.Wait()

	got, ok := h.Get(flowID)
	require.True(t, ok)
	require.NotNil(t, got.Response)
	assert.Equal(t, "HTTP/1.1", got.Response.Version)
	assert.GreaterOrEqual(t, got.Response.StatusCode, 200)
	assert.Less(t, got.Response.StatusCode, 210)
}
