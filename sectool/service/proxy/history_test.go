package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("assigns_sequential_offsets", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		for i := 0; i < 5; i++ {
			entry := &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/",
					Version: "HTTP/1.1",
				},
			}
			offset := h.Store(entry)
			assert.Equal(t, uint32(i), offset)
		}
		assert.Equal(t, 5, h.Count())
	})

	t.Run("concurrent_writes", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		var wg sync.WaitGroup
		const numGoroutines = 10
		const entriesPerGoroutine = 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < entriesPerGoroutine; j++ {
					entry := &HistoryEntry{
						Protocol: "http/1.1",
						Request: &RawHTTP1Request{
							Method:  "GET",
							Path:    "/",
							Version: "HTTP/1.1",
						},
					}
					h.Store(entry)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, numGoroutines*entriesPerGoroutine, h.Count())

		for i := uint32(0); i < uint32(numGoroutines*entriesPerGoroutine); i++ {
			_, ok := h.Get(i)
			assert.True(t, ok)
		}
	})
}

func TestGet(t *testing.T) {
	t.Parallel()

	t.Run("retrieves_stored_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/test",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			Response: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
		}

		offset := h.Store(entry)
		retrieved, ok := h.Get(offset)

		require.True(t, ok)
		assert.Equal(t, uint32(0), retrieved.Offset)
		assert.Equal(t, "http/1.1", retrieved.Protocol)
		assert.Equal(t, "GET", retrieved.Request.Method)
		assert.Equal(t, "/test", retrieved.Request.Path)
		assert.Equal(t, 200, retrieved.Response.StatusCode)
		assert.Equal(t, []byte("Hello"), retrieved.Response.Body)
	})

	t.Run("not_found", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		_, ok := h.Get(999)
		assert.False(t, ok)
	})

	t.Run("serialization_roundtrip", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:  250 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/api/data",
				Query:    "foo=bar",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "x-custom-header", Value: "value"},
				},
				Body: []byte(`{"key":"value"}`),
			},
			Response: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 201,
				StatusText: "Created",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
				},
				Body: []byte(`{"id":123}`),
			},
		}

		offset := h.Store(entry)
		retrieved, ok := h.Get(offset)
		require.True(t, ok)

		assert.Equal(t, entry.Protocol, retrieved.Protocol)
		assert.Equal(t, entry.Timestamp, retrieved.Timestamp)
		assert.Equal(t, entry.Duration, retrieved.Duration)

		assert.Equal(t, entry.Request.Method, retrieved.Request.Method)
		assert.Equal(t, entry.Request.Path, retrieved.Request.Path)
		assert.Equal(t, entry.Request.Query, retrieved.Request.Query)
		assert.Equal(t, entry.Request.Version, retrieved.Request.Version)
		assert.Equal(t, entry.Request.Headers, retrieved.Request.Headers)
		assert.Equal(t, entry.Request.Body, retrieved.Request.Body)

		assert.Equal(t, entry.Response.Version, retrieved.Response.Version)
		assert.Equal(t, entry.Response.StatusCode, retrieved.Response.StatusCode)
		assert.Equal(t, entry.Response.StatusText, retrieved.Response.StatusText)
		assert.Equal(t, entry.Response.Headers, retrieved.Response.Headers)
		assert.Equal(t, entry.Response.Body, retrieved.Response.Body)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	for i := 0; i < 10; i++ {
		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/" + string(rune('a'+i)),
				Version: "HTTP/1.1",
			},
		}
		h.Store(entry)
	}

	tests := []struct {
		name      string
		count     int
		offset    uint32
		wantLen   int
		wantFirst string
		wantLast  string
	}{
		{
			name:      "first_five",
			count:     5,
			offset:    0,
			wantLen:   5,
			wantFirst: "/a",
			wantLast:  "/e",
		},
		{
			name:      "from_offset_five",
			count:     5,
			offset:    5,
			wantLen:   5,
			wantFirst: "/f",
			wantLast:  "/j",
		},
		{
			name:      "partial_remaining",
			count:     5,
			offset:    8,
			wantLen:   2,
			wantFirst: "/i",
			wantLast:  "/j",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := h.List(tt.count, tt.offset)
			assert.Len(t, entries, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, entries[0].Request.Path)
				assert.Equal(t, tt.wantLast, entries[len(entries)-1].Request.Path)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	t.Run("updates_existing_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/original",
				Version: "HTTP/1.1",
			},
		}
		offset := h.Store(entry)

		entry.Response = &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Body:       []byte("response body"),
		}
		h.Update(entry)

		retrieved, ok := h.Get(offset)
		require.True(t, ok)
		assert.Equal(t, "/original", retrieved.Request.Path)
		require.NotNil(t, retrieved.Response)
		assert.Equal(t, 200, retrieved.Response.StatusCode)
		assert.Equal(t, []byte("response body"), retrieved.Response.Body)
	})

	t.Run("ignores_nonexistent", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Offset:   999,
			Protocol: "http/1.1",
		}
		h.Update(entry) // should not panic
	})
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
			name: "nil_http1_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			wantNil: true,
		},
		{
			name: "nil_h2_request",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: nil,
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatRequest()
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
			name: "nil_http1_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			wantNil: true,
		},
		{
			name: "nil_h2_response",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: nil,
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatResponse()
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestGetMethod(t *testing.T) {
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
				Request:  &RawHTTP1Request{Method: "POST"},
			},
			want: "POST",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Method: "PUT"},
			},
			want: "PUT",
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			want: "",
		},
		{
			name: "nil_h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetMethod())
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
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Path: "/api/data"},
			},
			want: "/api/data",
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			want: "",
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
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "Host", Value: "example.com"}},
				},
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
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
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

func TestGetStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  int
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{StatusCode: 200},
			},
			want: 200,
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: &H2ResponseData{StatusCode: 404},
			},
			want: 404,
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetStatusCode())
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
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "Content-Type", Value: "application/json"}},
				},
			},
			headerName: "Content-Type",
			want:       "application/json",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Headers: []Header{{Name: "authorization", Value: "Bearer token"}},
				},
			},
			headerName: "authorization",
			want:       "Bearer token",
		},
		{
			name: "nil_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			headerName: "Content-Type",
			want:       "",
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
				Response: &RawHTTP1Response{
					Headers: []Header{{Name: "Content-Type", Value: "text/html"}},
				},
			},
			headerName: "Content-Type",
			want:       "text/html",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					Headers: []Header{{Name: "x-request-id", Value: "abc123"}},
				},
			},
			headerName: "x-request-id",
			want:       "abc123",
		},
		{
			name: "nil_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			headerName: "Content-Type",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetResponseHeader(tt.headerName))
		})
	}
}
