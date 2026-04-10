package testutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// AcquireBurpLock acquires an exclusive lock on Burp MCP.
// The lock is automatically released when the test completes.
func AcquireBurpLock(t *testing.T) {
	t.Helper()

	lockPath := filepath.Join(os.TempDir(), "sectool-burp-test.lock")

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open lock file: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})

	require.Eventually(t, func() bool {
		return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
	}, 60*time.Second, 10*time.Millisecond, "timeout waiting for Burp MCP lock")
}
