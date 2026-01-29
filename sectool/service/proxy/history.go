package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

// HistoryStore provides typed access to proxy history backed by store.Storage.
type HistoryStore struct {
	mu         sync.RWMutex
	storage    store.Storage
	nextOffset uint32
	offsetKeys map[uint32]string // offset → storage key
}

// NewHistoryStore creates a history store using the provided storage backend.
func NewHistoryStore(storage store.Storage) *HistoryStore {
	return &HistoryStore{
		storage:    storage,
		offsetKeys: make(map[uint32]string),
	}
}

// Store adds an entry and assigns the next offset.
// Returns the assigned offset.
func (h *HistoryStore) Store(entry *HistoryEntry) uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()

	offset := h.nextOffset
	h.nextOffset++

	entry.Offset = offset
	key := fmt.Sprintf("proxy:history:%d", offset)
	h.offsetKeys[offset] = key

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("proxy: failed to marshal history entry %d: %v", offset, err)
		return offset
	}

	if err := h.storage.Save(key, data); err != nil {
		log.Printf("proxy: failed to save history entry %d: %v", offset, err)
	}
	return offset
}

// Get retrieves an entry by offset.
func (h *HistoryStore) Get(offset uint32) (*HistoryEntry, bool) {
	h.mu.RLock()
	key, exists := h.offsetKeys[offset]
	h.mu.RUnlock()

	if !exists {
		return nil, false
	}

	data, found, err := h.storage.Load(key)
	if err != nil || !found {
		return nil, false
	}

	var entry HistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	return &entry, true
}

// List returns entries starting from startOffset, up to count.
// Returns entries in offset order.
func (h *HistoryStore) List(count int, startOffset uint32) []*HistoryEntry {
	h.mu.RLock()
	maxOffset := h.nextOffset
	h.mu.RUnlock()

	var entries []*HistoryEntry
	for offset := startOffset; offset < maxOffset && len(entries) < count; offset++ {
		if entry, ok := h.Get(offset); ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

// Count returns total number of entries.
func (h *HistoryStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return int(h.nextOffset)
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	h.storage.Close()
}
