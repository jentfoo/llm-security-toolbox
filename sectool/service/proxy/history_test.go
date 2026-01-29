package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func TestHistoryStore_StoreAndGet(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
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
	assert.Equal(t, uint32(0), offset)

	retrieved, ok := h.Get(offset)
	require.True(t, ok)
	assert.Equal(t, uint32(0), retrieved.Offset)
	assert.Equal(t, "http/1.1", retrieved.Protocol)
	assert.Equal(t, "GET", retrieved.Request.Method)
	assert.Equal(t, "/test", retrieved.Request.Path)
	assert.Equal(t, 200, retrieved.Response.StatusCode)
	assert.Equal(t, []byte("Hello"), retrieved.Response.Body)
}

func TestHistoryStore_AutoIncrement(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
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
}

func TestHistoryStore_GetNotFound(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
	t.Cleanup(h.Close)

	_, ok := h.Get(999)
	assert.False(t, ok)
}

func TestHistoryStore_List(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
	t.Cleanup(h.Close)

	// Store 10 entries
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

	// List first 5
	entries := h.List(5, 0)
	assert.Len(t, entries, 5)
	assert.Equal(t, "/a", entries[0].Request.Path)
	assert.Equal(t, "/e", entries[4].Request.Path)

	// List from offset 5
	entries = h.List(5, 5)
	assert.Len(t, entries, 5)
	assert.Equal(t, "/f", entries[0].Request.Path)
	assert.Equal(t, "/j", entries[4].Request.Path)

	// List from offset 8, only 2 remaining
	entries = h.List(5, 8)
	assert.Len(t, entries, 2)
	assert.Equal(t, "/i", entries[0].Request.Path)
	assert.Equal(t, "/j", entries[1].Request.Path)
}

func TestHistoryStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
	t.Cleanup(h.Close)

	var wg sync.WaitGroup
	numGoroutines := 10
	entriesPerGoroutine := 100

	// Concurrent writes
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

	// Verify all entries are retrievable
	for i := uint32(0); i < uint32(numGoroutines*entriesPerGoroutine); i++ {
		_, ok := h.Get(i)
		assert.True(t, ok)
	}
}

func TestHistoryStore_SerializationRoundTrip(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := NewHistoryStore(storage)
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

	// Verify all fields survived serialization
	assert.Equal(t, entry.Protocol, retrieved.Protocol)
	assert.Equal(t, entry.Timestamp, retrieved.Timestamp)
	assert.Equal(t, entry.Duration, retrieved.Duration)

	// Request
	assert.Equal(t, entry.Request.Method, retrieved.Request.Method)
	assert.Equal(t, entry.Request.Path, retrieved.Request.Path)
	assert.Equal(t, entry.Request.Query, retrieved.Request.Query)
	assert.Equal(t, entry.Request.Version, retrieved.Request.Version)
	assert.Equal(t, entry.Request.Headers, retrieved.Request.Headers)
	assert.Equal(t, entry.Request.Body, retrieved.Request.Body)

	// Response
	assert.Equal(t, entry.Response.Version, retrieved.Response.Version)
	assert.Equal(t, entry.Response.StatusCode, retrieved.Response.StatusCode)
	assert.Equal(t, entry.Response.StatusText, retrieved.Response.StatusText)
	assert.Equal(t, entry.Response.Headers, retrieved.Response.Headers)
	assert.Equal(t, entry.Response.Body, retrieved.Response.Body)
}
