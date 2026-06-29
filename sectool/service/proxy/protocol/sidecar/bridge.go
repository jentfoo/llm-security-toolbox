package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// probeTimeout bounds a claim_probe round-trip during connection claiming.
const probeTimeout = 5 * time.Second

// bridge fronts a registered sidecar as an in-process adapter, routing matching
// proxy connections to the sidecar through its claim seams.
type bridge struct {
	rec     *Record
	streams *streamSet
}

func newBridge(rec *Record) *bridge {
	return &bridge{rec: rec, streams: newStreamSet()}
}

func (b *bridge) Name() string { return b.rec.Name }

// ClaimEarly matches the sidecar's early_claim against a freshly accepted stream
// (raw bytes) or a decrypted post-TLS stream re-offered after ClaimTLS matched.
func (b *bridge) ClaimEarly(c *protocol.EarlyClaimCtx) bool {
	ec := b.rec.Capabilities.EarlyClaim
	if ec == nil || !b.rec.Healthy() {
		return false
	}
	// The pre-handshake SNI/host/port gate already matched for a TLS re-entry; a
	// raw accept matches the connection's local port here.
	if !c.TLSTerminated && !portInRange(localPort(c.ClientConn), ec.PortRange) {
		return false
	}
	if ec.MagicBytesPrefix != "" {
		prefix, err := base64.StdEncoding.DecodeString(ec.MagicBytesPrefix)
		if err != nil || len(prefix) == 0 || !matchPrefix(c, prefix) {
			return false
		}
	}
	if ec.Probe {
		return b.runProbe(c)
	}
	return true
}

// ServeEarly drives the claimed connection as a byte stream.
func (b *bridge) ServeEarly(ctx context.Context, c *protocol.EarlyClaimCtx) {
	b.streams.serveClient(ctx, b.rec, c)
}

// ClaimTLS gates a TLS connection before termination on SNI and CONNECT target.
func (b *bridge) ClaimTLS(sni, host string, port int) bool {
	ec := b.rec.Capabilities.EarlyClaim
	if ec == nil || ec.TLS == nil || !ec.TLS.Terminate || !b.rec.Healthy() {
		return false
	}
	if !portInRange(port, ec.PortRange) {
		return false
	}
	if ec.TLS.SNIMatch != "" && ec.TLS.SNIMatch != sni {
		return false
	}
	if ec.HostMatch != "" && ec.HostMatch != host {
		return false
	}
	return true
}

func (b *bridge) ClaimUpgrade(*protocol.UpgradeClaimCtx) bool { return false }

func (b *bridge) ServeUpgrade(context.Context, *protocol.UpgradeClaimCtx, protocol.UpgradeConns) {}

// shutdown closes the sidecar's active client streams; called when the sidecar
// connection drops so no claimed socket is orphaned.
func (b *bridge) shutdown() { b.streams.closeAll() }

// runProbe asks the sidecar whether the buffered opening bytes are its protocol.
// A probe fault or a false reply declines, falling through to the next adapter.
func (b *bridge) runProbe(c *protocol.EarlyClaimCtx) bool {
	ec := b.rec.Capabilities.EarlyClaim
	var host string
	var port int
	if c.Target != nil {
		host, port = c.Target.Hostname, c.Target.Port
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	var res wire.ClaimProbeResult
	if err := b.rec.peer.Call(ctx, wire.MethodClaimProbe, wire.ClaimProbeParams{
		Host:     host,
		Port:     port,
		PeerAddr: c.ClientConn.RemoteAddr().String(),
		Data:     openingBytes(c, ec.ProbeMaxBytes),
	}, &res); err != nil {
		return false
	}
	return res.Claim
}

// matchPrefix reports whether the stream's opening bytes start with prefix,
// without consuming them so a decline can fall through to the next adapter.
func matchPrefix(c *protocol.EarlyClaimCtx, prefix []byte) bool {
	got, err := c.ClientReader.Peek(len(prefix))
	return err == nil && bytes.Equal(got, prefix)
}

// openingBytes peeks up to max bytes already buffered for the stream, blocking
// only for the first byte. The bytes are not consumed.
func openingBytes(c *protocol.EarlyClaimCtx, max int) []byte {
	if max <= 0 {
		max = 1
	}
	if _, err := c.ClientReader.Peek(1); err != nil {
		return nil
	}
	n := min(max, c.ClientReader.Buffered())
	b, _ := c.ClientReader.Peek(n)
	return b
}

// portInRange reports whether p falls in r; an unset range matches any port.
func portInRange(p int, r wire.PortRange) bool {
	if r.Low == 0 && r.High == 0 {
		return true
	}
	return p >= r.Low && p <= r.High
}

func localPort(c net.Conn) int {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// Adapter is the proxy claim surface a sidecar bridge fulfills: the early and
// upgrade seams. The manager inserts a registered sidecar's Adapter into the
// proxy claim registry to route matching connections to the sidecar.
type Adapter interface {
	protocol.EarlyAdapter
	protocol.UpgradeAdapter
}

var _ Adapter = (*bridge)(nil)
var _ protocol.TLSEarlyAdapter = (*bridge)(nil)
