package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAtomicWriteFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")

	require.NoError(t, AtomicWriteFile(path, []byte("first"), 0600))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first", string(got))

	// Overwrite an existing target (rename-replace path).
	require.NoError(t, AtomicWriteFile(path, []byte("second"), 0600))
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(got))

	// No temp file left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}
