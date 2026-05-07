package testutil

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/stretchr/testify/require"
)

// NewInteractsh starts a polling interactsh-lite client and returns its callback domain
// plus a waitFor function that blocks until an HTTP interaction matching the given method
// and path (empty matches any path) arrives. Skips the test if OAST is unreachable.
func NewInteractsh(t *testing.T) (string, func(method, path string) *oobclient.Interaction) {
	t.Helper()

	oob, err := oobclient.New(t.Context(), oobclient.Options{})
	if err != nil {
		t.Skipf("interactsh OAST not available: %v", err)
	}
	t.Cleanup(func() { _ = oob.Close() })

	var mu sync.Mutex
	var received []*oobclient.Interaction

	require.NoError(t, oob.StartPolling(10*time.Millisecond, func(i *oobclient.Interaction) {
		if i.Protocol == "dns" {
			return // skip common DNS interactions
		}
		mu.Lock()
		defer mu.Unlock()

		received = append(received, i)
	}))

	waitFor := func(method, path string) *oobclient.Interaction {
		t.Helper()

		prefix := method + " " + path
		var match *oobclient.Interaction
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()

			for _, i := range received {
				if strings.HasPrefix(i.RawRequest, prefix) {
					match = i
					return true
				}
			}
			return false
		}, 15*time.Second, 10*time.Millisecond, "no %s %s interaction received", method, path)
		return match
	}

	return oob.Domain(), waitFor
}
