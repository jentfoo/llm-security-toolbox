package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// WaitForCount polls until the count reaches the expected value or 10s timeout.
func WaitForCount(t *testing.T, getCount func() int, expected int) {
	t.Helper()

	require.Eventually(t, func() bool {
		return getCount() >= expected
	}, 10*time.Second, time.Millisecond)
}
