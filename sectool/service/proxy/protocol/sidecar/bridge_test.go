package sidecar

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// localAddrConn is a net.Conn whose LocalAddr reports a fixed TCP port.
type localAddrConn struct {
	net.Conn
	port int
}

func (c localAddrConn) LocalAddr() net.Addr  { return &net.TCPAddr{Port: c.port} }
func (c localAddrConn) RemoteAddr() net.Addr { return &net.TCPAddr{Port: 1} }

func earlyCtx(localPort int, opening []byte) *protocol.EarlyClaimCtx {
	return &protocol.EarlyClaimCtx{
		ClientConn:   localAddrConn{port: localPort},
		ClientReader: bufio.NewReader(bytes.NewReader(opening)),
	}
}

func newTestBridge(ec *wire.EarlyClaim, healthy bool) *bridge {
	rec := &Record{Name: "sc", Capabilities: wire.Capabilities{EarlyClaim: ec}}
	rec.healthy.Store(healthy)
	return newBridge(rec)
}

func TestBridgeClaimEarly(t *testing.T) {
	t.Parallel()

	mqtt := []byte{0x10, 0x20} // CONNECT control packet prefix
	magic := wire.EarlyClaim{
		PortRange:        wire.PortRange{Low: 1883, High: 1883},
		MagicBytesPrefix: base64.StdEncoding.EncodeToString(mqtt),
	}

	t.Run("port_and_magic_match", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.True(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("port_out_of_range", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.False(t, b.ClaimEarly(earlyCtx(9999, mqtt)))
	})
	t.Run("magic_mismatch", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.False(t, b.ClaimEarly(earlyCtx(1883, []byte("GET /"))))
	})
	t.Run("unhealthy_declines", func(t *testing.T) {
		b := newTestBridge(&magic, false)
		assert.False(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("unset_range_matches_any_port", func(t *testing.T) {
		b := newTestBridge(&wire.EarlyClaim{}, true)
		assert.True(t, b.ClaimEarly(earlyCtx(40000, nil)))
	})
}

func TestBridgeClaimTLS(t *testing.T) {
	t.Parallel()

	ec := &wire.EarlyClaim{
		PortRange: wire.PortRange{Low: 443, High: 443},
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "ctrl.example.com"},
	}

	t.Run("sni_and_port_match", func(t *testing.T) {
		assert.True(t, newTestBridge(ec, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443))
	})
	t.Run("sni_mismatch", func(t *testing.T) {
		assert.False(t, newTestBridge(ec, true).ClaimTLS("other.example.com", "other.example.com", 443))
	})
	t.Run("port_mismatch", func(t *testing.T) {
		assert.False(t, newTestBridge(ec, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 8443))
	})
	t.Run("non_terminating_claim_declines", func(t *testing.T) {
		raw := &wire.EarlyClaim{PortRange: wire.PortRange{Low: 443, High: 443}}
		assert.False(t, newTestBridge(raw, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443))
	})
}

func TestStreamWriteUnknownStream(t *testing.T) {
	t.Parallel()

	err := newStreamSet().streamWrite("missing", []byte("x"))
	if assert.NotNil(t, err) {
		assert.Equal(t, wire.CodeUnknownStream, err.Code)
	}
}
