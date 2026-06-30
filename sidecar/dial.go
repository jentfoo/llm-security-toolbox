package sidecar

import (
	"context"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// DialUpstream asks sectool to open an upstream TCP connection (subject to scope
// policy, optionally TLS-terminated) and bridge it as a new stream. It returns
// the upstream stream_id; its bytes arrive via the Handler's OnStreamDeliver
// and the sidecar writes to it through the writes of any stream event Response.
func (c *Conn) DialUpstream(ctx context.Context, p wire.DialUpstreamParams) (string, error) {
	var res wire.DialUpstreamResult
	if rpcErr := c.peer.Call(ctx, wire.MethodDialUpstream, p, &res); rpcErr != nil {
		return "", rpcErr
	}
	return res.StreamID, nil
}
