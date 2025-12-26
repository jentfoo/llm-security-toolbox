package store

import (
	"sync"
	"time"
)

// RequestEntry stores a request/response pair with metadata.
type RequestEntry struct {
	Headers   []byte
	Body      []byte
	Duration  time.Duration
	CreatedAt time.Time
}

// RequestStore holds ephemeral request/response results. Thread-safe.
// Used for storing replay results and other transient request data.
type RequestStore struct {
	mu      sync.RWMutex
	entries map[string]*RequestEntry
}

// NewRequestStore creates a new empty RequestStore.
func NewRequestStore() *RequestStore {
	return &RequestStore{
		entries: make(map[string]*RequestEntry),
	}
}

// Store adds or updates an entry.
func (s *RequestStore) Store(id string, entry *RequestEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	s.entries[id] = entry
}

// Get retrieves an entry by ID. Returns nil and false if not found.
func (s *RequestStore) Get(id string) (*RequestEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[id]
	return e, ok
}

// Delete removes an entry by ID.
func (s *RequestStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, id)
}

// Count returns the number of stored entries.
func (s *RequestStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.entries)
}

func (s *RequestStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = make(map[string]*RequestEntry)
}
