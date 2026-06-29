package sidecar

import (
	"context"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// StartPing originates ping notifications at the given interval until ctx is
// cancelled or the connection closes. Answering sectool's pings is automatic.
func (c *Conn) StartPing(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.peer.Done():
				return
			case <-t.C:
				if err := c.peer.Notify(wire.MethodPing, nil); err != nil {
					return
				}
			}
		}
	}()
}
