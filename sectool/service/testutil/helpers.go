package testutil

import (
	"testing"
	"time"
)

// WaitForCount polls until the count reaches the expected value or 10s timeout.
// Uses 1ms polling interval for fast response without excessive CPU usage.
func WaitForCount(t *testing.T, getCount func() int, expected int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		last = getCount()
		if last >= expected {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for count %d, got %d", expected, last)
}
