package store

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("register_and_lookup", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "hash1")
		assert.NotEmpty(t, flowID)
		assert.Len(t, flowID, 6) // default ID length

		entry, ok := store.Lookup(flowID)
		require.True(t, ok)
		assert.Equal(t, uint32(0), entry.Offset)
		assert.Equal(t, "hash1", entry.Hash)
	})

	t.Run("lookup_not_found", func(t *testing.T) {
		store := NewFlowStore()

		entry, ok := store.Lookup("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, entry)
	})

	t.Run("register_same_offset_returns_same_id", func(t *testing.T) {
		store := NewFlowStore()

		id1 := store.Register(5, "hash1")
		id2 := store.Register(5, "hash2") // different hash, same offset

		assert.Equal(t, id1, id2)
	})

	t.Run("lookup_by_hash", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "unique_hash")
		flowIDs := store.LookupByHash("unique_hash")

		require.Len(t, flowIDs, 1)
		assert.Equal(t, flowID, flowIDs[0])
	})

	t.Run("lookup_by_hash_not_found", func(t *testing.T) {
		store := NewFlowStore()

		flowIDs := store.LookupByHash("nonexistent")
		assert.Nil(t, flowIDs)
	})

	t.Run("lookup_by_hash_collision", func(t *testing.T) {
		store := NewFlowStore()

		// Register two entries with the same hash (simulating collision)
		id1 := store.Register(0, "same_hash")
		id2 := store.Register(1, "same_hash")

		flowIDs := store.LookupByHash("same_hash")
		require.Len(t, flowIDs, 2)
		assert.Contains(t, flowIDs, id1)
		assert.Contains(t, flowIDs, id2)
	})

	t.Run("lookup_by_offset", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(42, "hash")
		foundID, ok := store.LookupByOffset(42)

		assert.True(t, ok)
		assert.Equal(t, flowID, foundID)
	})

	t.Run("lookup_by_offset_not_found", func(t *testing.T) {
		store := NewFlowStore()

		foundID, ok := store.LookupByOffset(999)
		assert.False(t, ok)
		assert.Empty(t, foundID)
	})

	t.Run("update_offset", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "hash")

		ok := store.UpdateOffset(flowID, 100)
		assert.True(t, ok)

		entry, _ := store.Lookup(flowID)
		assert.Equal(t, uint32(100), entry.Offset)

		_, found := store.LookupByOffset(0)
		assert.False(t, found)

		foundID, found := store.LookupByOffset(100)
		assert.True(t, found)
		assert.Equal(t, flowID, foundID)
	})

	t.Run("update_offset_not_found", func(t *testing.T) {
		store := NewFlowStore()

		ok := store.UpdateOffset("nonexistent", 100)
		assert.False(t, ok)
	})

	t.Run("clear", func(t *testing.T) {
		store := NewFlowStore()

		store.Register(0, "hash1")
		store.Register(1, "hash2")
		store.Register(2, "hash3")

		assert.Equal(t, 3, store.Count())

		store.Clear()

		assert.Equal(t, 0, store.Count())
	})

	t.Run("count", func(t *testing.T) {
		store := NewFlowStore()

		assert.Equal(t, 0, store.Count())

		store.Register(0, "hash1")
		assert.Equal(t, 1, store.Count())

		store.Register(1, "hash2")
		assert.Equal(t, 2, store.Count())

		// Same offset should not increase count
		store.Register(0, "hash3")
		assert.Equal(t, 2, store.Count())
	})

	t.Run("all_flow_ids", func(t *testing.T) {
		store := NewFlowStore()

		id1 := store.Register(0, "hash1")
		id2 := store.Register(1, "hash2")
		id3 := store.Register(2, "hash3")

		allIDs := store.AllFlowIDs()
		assert.Len(t, allIDs, 3)
		assert.Contains(t, allIDs, id1)
		assert.Contains(t, allIDs, id2)
		assert.Contains(t, allIDs, id3)
	})

	t.Run("empty_hash", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "")

		// Should still work
		entry, ok := store.Lookup(flowID)
		require.True(t, ok)
		assert.Empty(t, entry.Hash)

		// But hash lookup should return nothing
		flowIDs := store.LookupByHash("")
		assert.Nil(t, flowIDs)
	})
}

func TestStoreConcurrency(t *testing.T) {
	t.Parallel()

	store := NewFlowStore()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := range 100 {
		wg.Add(1)
		go func(offset uint32) {
			defer wg.Done()
			store.Register(offset, "hash")
		}(uint32(i))
	}

	// Concurrent lookups
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Count()
			store.AllFlowIDs()
		}()
	}

	wg.Wait()

	// Verify final state
	assert.Equal(t, 100, store.Count())
}
