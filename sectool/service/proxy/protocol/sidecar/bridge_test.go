package sidecar

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
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

// terminatedCtx is a decrypted post-CONNECT stream re-offered to the early seam.
func terminatedCtx(sni, host string, port int, opening []byte) *protocol.EarlyClaimCtx {
	return &protocol.EarlyClaimCtx{
		TLSTerminated: true,
		SNI:           sni,
		Target:        &types.Target{Hostname: host, Port: port, UsesHTTPS: true},
		ClientConn:    localAddrConn{port: 8080},
		ClientReader:  bufio.NewReader(bytes.NewReader(opening)),
	}
}

func newEarlyBridge(t *testing.T, ecs []wire.EarlyClaim, healthy bool) *bridge {
	t.Helper()

	early, err := compileEarlyClaims(ecs)
	require.NoError(t, err)
	rec := &Record{Name: "sc", early: early}
	rec.healthy.Store(healthy)
	return newBridge(rec, nil)
}

func newUpgradeBridge(t *testing.T, ucs []wire.UpgradeClaim, healthy bool) *bridge {
	t.Helper()

	upgrade, err := compileUpgradeClaims(ucs)
	require.NoError(t, err)
	rec := &Record{Name: "sc", upgrade: upgrade}
	rec.healthy.Store(healthy)
	return newBridge(rec, nil)
}

func upgradeCtx(signal, method, host, path, upgradeHdr string) *protocol.UpgradeClaimCtx {
	req := &types.RawHTTP1Request{Method: method, Path: path, Version: "HTTP/1.1"}
	if upgradeHdr != "" {
		req.Headers = types.Headers{{Name: "Upgrade", Value: upgradeHdr}}
	}
	return &protocol.UpgradeClaimCtx{Req: req, Target: &types.Target{Hostname: host, Port: 443}, Signal: signal}
}

func TestBridgeClaimEarly(t *testing.T) {
	t.Parallel()

	mqtt := []byte{0x10, 0x20} // CONNECT control packet prefix
	magic := wire.EarlyClaim{
		PortRange:        wire.PortRange{Low: 1883, High: 1883},
		MagicBytesPrefix: base64.StdEncoding.EncodeToString(mqtt),
	}

	t.Run("port_and_magic_match", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{magic}, true)
		assert.True(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("unhealthy_declines", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{magic}, false)
		assert.False(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("either_claim_matches", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{
			{PortRange: wire.PortRange{Low: 1883, High: 1883}, MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte{0x10})},
			{PortRange: wire.PortRange{Low: 5222, High: 5222}, MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("<?xml"))},
		}, true)
		assert.True(t, b.ClaimEarly(earlyCtx(1883, []byte{0x10})))
		assert.True(t, b.ClaimEarly(earlyCtx(5222, []byte("<?xml"))))
		assert.False(t, b.ClaimEarly(earlyCtx(1883, []byte("<?xml"))))
		assert.False(t, b.ClaimEarly(earlyCtx(9999, []byte{0x10})))
	})

	// TLS re-entry: a decrypted post-CONNECT stream is offered to every early claim,
	// so the claim's declared scope must still gate it.
	t.Run("terminated_target_port_out_of_range", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 1883, High: 1883}}}, true)
		assert.False(t, b.ClaimEarly(terminatedCtx("app.example.com", "app.example.com", 443, nil)))
	})
	t.Run("terminated_target_port_in_range", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 1883, High: 1883}}}, true)
		assert.True(t, b.ClaimEarly(terminatedCtx("mqtt.example.com", "mqtt.example.com", 1883, nil)))
	})
	t.Run("terminated_host_mismatch", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{{HostMatch: "mqtt.example.com"}}, true)
		assert.False(t, b.ClaimEarly(terminatedCtx("app.example.com", "app.example.com", 443, nil)))
	})
	t.Run("terminated_sni_mismatch", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{{
			TLS: &wire.TLSClaim{Terminate: true, SNIMatch: "mqtt.example.com"},
		}}, true)
		assert.False(t, b.ClaimEarly(terminatedCtx("app.example.com", "app.example.com", 443, nil)))
	})
	t.Run("terminated_magic_still_claims", func(t *testing.T) {
		b := newEarlyBridge(t, []wire.EarlyClaim{{MagicBytesPrefix: base64.StdEncoding.EncodeToString(mqtt)}}, true)
		assert.True(t, b.ClaimEarly(terminatedCtx("mqtt.example.com", "mqtt.example.com", 8883, mqtt)))
	})
}

func TestBridgeClaimTLS(t *testing.T) {
	t.Parallel()

	ec := wire.EarlyClaim{
		PortRange: wire.PortRange{Low: 443, High: 443},
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "ctrl.example.com"},
	}

	t.Run("sni_and_port_match", func(t *testing.T) {
		spec, ok := newEarlyBridge(t, []wire.EarlyClaim{ec}, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443)
		assert.True(t, ok)
		assert.Nil(t, spec)
	})
	t.Run("cert_spec_translated", func(t *testing.T) {
		withCert := wire.EarlyClaim{
			PortRange: wire.PortRange{Low: 443, High: 443},
			TLS: &wire.TLSClaim{Terminate: true, Cert: &wire.TLSCertSpec{
				DNSNames:    []string{"alt.example.com"},
				IPAddresses: []string{"10.0.0.1", "not-an-ip"},
				URIs:        []string{"spiffe://example.com/svc"},
				CommonName:  "legacy.example.com",
			}},
		}
		spec, ok := newEarlyBridge(t, []wire.EarlyClaim{withCert}, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443)
		require.True(t, ok)
		require.NotNil(t, spec)
		assert.Equal(t, []string{"alt.example.com"}, spec.DNSNames)
		require.Len(t, spec.IPAddresses, 1) // invalid IP dropped
		assert.Equal(t, "10.0.0.1", spec.IPAddresses[0].String())
		require.Len(t, spec.URIs, 1)
		assert.Equal(t, "spiffe://example.com/svc", spec.URIs[0].String())
		assert.Equal(t, "legacy.example.com", spec.CommonName)
	})
}

func TestBridgeClaimUpgrade(t *testing.T) {
	t.Parallel()

	t.Run("http_101_host_path_method_match", func(t *testing.T) {
		uc := wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/control", UpgradeSignal: "http_101", MethodSet: []string{"POST"}}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "ctrl.example.com", "/control", "custom-control-protocol")))
	})
	t.Run("http_101_requires_upgrade_header", func(t *testing.T) {
		uc := wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "ctrl.example.com", "/control", "")))
	})
	t.Run("method_not_in_set", func(t *testing.T) {
		uc := wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101", MethodSet: []string{"POST"}}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "h", "/control", "x")))
	})
	t.Run("host_mismatch", func(t *testing.T) {
		uc := wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "other.example.com", "/x", "websocket")))
	})
	t.Run("signal_mismatch", func(t *testing.T) {
		uc := wire.UpgradeClaim{UpgradeSignal: "connect"}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "h", "/x", "websocket")))
	})
	t.Run("connect_signal_match", func(t *testing.T) {
		uc := wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: "connect"}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("connect", "CONNECT", "ctrl.example.com", "ctrl.example.com:443", "")))
	})
	t.Run("unhealthy_declines", func(t *testing.T) {
		uc := wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(t, []wire.UpgradeClaim{uc}, false)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "h", "/control", "x")))
	})
	t.Run("either_claim_matches", func(t *testing.T) {
		b := newUpgradeBridge(t, []wire.UpgradeClaim{
			{HostPattern: "ctrl.example.com", PathPattern: "/ts2021", UpgradeSignal: "http_101"},
			{HostPattern: "ctrl.example.com", PathPattern: "/derp", UpgradeSignal: "http_101"},
		}, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "ctrl.example.com", "/ts2021", "x")))
		assert.True(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "ctrl.example.com", "/derp", "x")))
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "ctrl.example.com", "/other", "x")))
	})
}
