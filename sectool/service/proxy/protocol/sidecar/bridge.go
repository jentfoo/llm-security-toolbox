package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// probeTimeout bounds a claim_probe round-trip during connection claiming.
const probeTimeout = 5 * time.Second

// bridge fronts a registered sidecar as an in-process adapter, routing matching
// proxy connections to the sidecar through its claim seams.
type bridge struct {
	rec     *Record
	streams *streamSet
	flows   FlowSink
}

func newBridge(rec *Record, flows FlowSink) *bridge {
	return &bridge{rec: rec, streams: newStreamSet(), flows: flows}
}

func (b *bridge) Name() string { return b.rec.Name }

// ClaimEarly matches the sidecar's early_claim against a freshly accepted stream
// (raw bytes) or a decrypted post-TLS stream re-offered after ClaimTLS matched.
func (b *bridge) ClaimEarly(c *protocol.EarlyClaimCtx) bool {
	ec := b.rec.Capabilities.EarlyClaim
	if ec == nil || !b.rec.Healthy() {
		return false
	}
	// Pre-handshake SNI/host/port gate already matched for a TLS re-entry; a raw
	// accept matches the connection's local port here
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

// ClaimUpgrade matches the sidecar's upgrade_claim against a parsed HTTP upgrade
// request or an established CONNECT tunnel.
func (b *bridge) ClaimUpgrade(c *protocol.UpgradeClaimCtx) bool {
	uc := b.rec.Capabilities.UpgradeClaim
	if uc == nil || !b.rec.Healthy() {
		return false
	}
	return matchUpgrade(uc, c)
}

// ServeUpgrade captures the triggering request as a flow, synthesizes the upgrade
// response, and hands the post-upgrade bytes to the sidecar as a stream.
func (b *bridge) ServeUpgrade(ctx context.Context, c *protocol.UpgradeClaimCtx, conns protocol.UpgradeConns) {
	// Sidecar drives its own upstream via dial_upstream; release any the proxy pre-dialed on the TLS path
	if conns.UpstreamConn != nil {
		_ = conns.UpstreamConn.Close()
	}
	resp := upgradeResponse(c)
	flowID := b.captureUpgrade(c, resp)
	// http_101 response synthesized here; the connect 200 was already sent by the CONNECT handler
	if c.Signal != "connect" {
		var buf bytes.Buffer
		if _, err := conns.ClientConn.Write(resp.SerializeRaw(&buf)); err != nil {
			return
		}
	}
	host, path := upgradeInfo(c)
	b.streams.serveUpgrade(ctx, b.rec, conns, flowID, wireHeaders(c.Req.Headers), host, path)
}

// captureUpgrade records the triggering request (with the synthesized response) as
// a normal flow, returning its flow_id or "" when the capture filter excludes it.
func (b *bridge) captureUpgrade(c *protocol.UpgradeClaimCtx, resp *types.RawHTTP1Response) string {
	var port int
	scheme := types.SchemeHTTP
	if c.Target != nil {
		port, scheme = c.Target.Port, c.Target.Scheme()
	}
	now := time.Now()
	flow := &types.Flow{
		Adapter:           b.rec.Name,
		ProtocolTag:       types.ProtocolHTTP11,
		Scheme:            scheme,
		Port:              port,
		Request:           types.RequestToMessage(c.Req),
		Response:          types.ResponseToMessage(resp),
		StartedAt:         now,
		CompletedAt:       now,
		SidecarVersion:    b.rec.Version,
		SidecarInstanceID: b.rec.InstanceID,
	}
	if !b.flows.ShouldCapture(flow) {
		return ""
	}
	return b.flows.Store(flow)
}

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

// matchUpgrade reports whether an upgrade claim matches the request: same signal
// (defaulting http_101), method, and host/path patterns. An http_101 claim also
// requires the request to carry an Upgrade header so a plain request is not taken.
func matchUpgrade(uc *wire.UpgradeClaim, c *protocol.UpgradeClaimCtx) bool {
	signal := uc.UpgradeSignal
	if signal == "" {
		signal = "http_101"
	}
	if signal != c.Signal {
		return false
	}
	if signal == "http_101" && c.Req.GetHeader("Upgrade") == "" {
		return false
	}
	if len(uc.MethodSet) > 0 && !slices.Contains(uc.MethodSet, c.Req.Method) {
		return false
	}
	var host string
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return patternMatch(uc.HostPattern, host) && patternMatch(uc.PathPattern, upgradePath(c))
}

// upgradeResponse builds the response sectool synthesizes for the claim: a 101
// echoing the request's Upgrade token, or a 200 for the already-sent connect reply.
func upgradeResponse(c *protocol.UpgradeClaimCtx) *types.RawHTTP1Response {
	if c.Signal == "connect" {
		return &types.RawHTTP1Response{Version: "HTTP/1.1", StatusCode: 200, StatusText: "Connection Established"}
	}
	return &types.RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: 101,
		StatusText: "Switching Protocols",
		Headers: types.Headers{
			{Name: "Upgrade", Value: c.Req.GetHeader("Upgrade")},
			{Name: "Connection", Value: "Upgrade"},
		},
	}
}

// upgradeInfo derives the stream_open host/path from the triggering request.
func upgradeInfo(c *protocol.UpgradeClaimCtx) (host, path string) {
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return host, upgradePath(c)
}

// upgradePath is the request path used for claim matching and stream_open: the
// query-stripped request path, or empty for a connect tunnel which has no path.
func upgradePath(c *protocol.UpgradeClaimCtx) string {
	if c.Signal == "connect" {
		return ""
	}
	p, _, _ := strings.Cut(c.Req.Path, "?")
	return p
}

// wireHeaders converts parsed request headers to the wire shape for stream_open.
func wireHeaders(hs types.Headers) []wire.Header {
	if len(hs) == 0 {
		return nil
	}
	out := make([]wire.Header, len(hs))
	for i, h := range hs {
		out[i] = wire.Header{Name: h.Name, Value: h.Value}
	}
	return out
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

// A bridge fulfills both proxy claim seams: TLSEarlyAdapter (which embeds
// EarlyAdapter) and UpgradeAdapter. The manager inserts it into the proxy claim
// registry to route matching connections to the sidecar.
var _ protocol.TLSEarlyAdapter = (*bridge)(nil)
var _ protocol.UpgradeAdapter = (*bridge)(nil)
