package sidecar

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// mustCompileEarly compiles a single claim for match/conflict assertions.
func mustCompileEarly(t *testing.T, ec wire.EarlyClaim) *earlyClaim {
	t.Helper()

	out, err := compileEarlyClaims([]wire.EarlyClaim{ec})
	require.NoError(t, err)
	return &out[0]
}

func TestCompileEarlyClaims(t *testing.T) {
	t.Parallel()

	t.Run("unset_range_spans_all_ports", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{})
		assert.Equal(t, wire.PortRange{Low: portMin, High: portMax}, c.ports)
		assert.True(t, c.matchPort(1))
		assert.True(t, c.matchPort(portMax))
	})
	t.Run("magic_prefix_decoded", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("MQTT"))})
		assert.Equal(t, []byte("MQTT"), c.prefix)
	})
	t.Run("cert_spec_precomputed", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{TLS: &wire.TLSClaim{
			Terminate: true,
			Cert:      &wire.TLSCertSpec{IPAddresses: []string{"10.0.0.1", "nope"}},
		}})
		require.NotNil(t, c.cert)
		require.Len(t, c.cert.IPAddresses, 1)
		assert.Equal(t, "10.0.0.1", c.cert.IPAddresses[0].String())
	})
	t.Run("empty_cert_spec_dropped", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true, Cert: &wire.TLSCertSpec{}}})
		assert.Nil(t, c.cert)
	})

	t.Run("inverted_range_rejected", func(t *testing.T) {
		_, err := compileEarlyClaims([]wire.EarlyClaim{{PortRange: wire.PortRange{Low: 900, High: 100}}})
		assert.Error(t, err)
	})
	t.Run("out_of_bounds_range_rejected", func(t *testing.T) {
		_, err := compileEarlyClaims([]wire.EarlyClaim{{PortRange: wire.PortRange{Low: 1, High: 70000}}})
		assert.Error(t, err)
	})
	t.Run("invalid_base64_rejected", func(t *testing.T) {
		_, err := compileEarlyClaims([]wire.EarlyClaim{{MagicBytesPrefix: "not base64!"}})
		assert.Error(t, err)
	})
	t.Run("negative_probe_max_rejected", func(t *testing.T) {
		_, err := compileEarlyClaims([]wire.EarlyClaim{{Probe: true, ProbeMaxBytes: -1}})
		assert.Error(t, err)
	})
}

func TestEarlyClaimMatchTLS(t *testing.T) {
	t.Parallel()

	term := mustCompileEarly(t, wire.EarlyClaim{
		PortRange: wire.PortRange{Low: 443, High: 443},
		HostMatch: "ctrl.example.com",
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "ctrl.example.com"},
	})

	assert.True(t, term.matchTLS("ctrl.example.com", "ctrl.example.com", 443))
	assert.False(t, term.matchTLS("other.example.com", "ctrl.example.com", 443))
	assert.False(t, term.matchTLS("ctrl.example.com", "other.example.com", 443))
	assert.False(t, term.matchTLS("ctrl.example.com", "ctrl.example.com", 8443))

	raw := mustCompileEarly(t, wire.EarlyClaim{PortRange: wire.PortRange{Low: 443, High: 443}})
	assert.False(t, raw.matchTLS("ctrl.example.com", "ctrl.example.com", 443))
}

func TestEarlyClaimBlanketOnPort(t *testing.T) {
	t.Parallel()

	t.Run("wildcard_with_no_matcher", func(t *testing.T) {
		assert.True(t, mustCompileEarly(t, wire.EarlyClaim{}).blanketOnPort(8080))
	})
	t.Run("explicit_range_covering_port", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{PortRange: wire.PortRange{Low: 8000, High: 8100}})
		assert.True(t, c.blanketOnPort(8080))
	})
	t.Run("magic_prefix_distinguishes", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("MQTT"))})
		assert.False(t, c.blanketOnPort(8080))
	})
	t.Run("probe_distinguishes", func(t *testing.T) {
		assert.False(t, mustCompileEarly(t, wire.EarlyClaim{Probe: true}).blanketOnPort(8080))
	})
	t.Run("terminate_claims_another_seam", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true}})
		assert.False(t, c.blanketOnPort(8080))
	})
	t.Run("range_outside_port", func(t *testing.T) {
		c := mustCompileEarly(t, wire.EarlyClaim{PortRange: wire.PortRange{Low: 1883, High: 1883}})
		assert.False(t, c.blanketOnPort(8080))
	})
	t.Run("no_native_port_configured", func(t *testing.T) {
		assert.False(t, mustCompileEarly(t, wire.EarlyClaim{}).blanketOnPort(0))
	})
}

func TestEarlyClaimConflict(t *testing.T) {
	t.Parallel()

	prefix := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name     string
		a, b     wire.EarlyClaim
		conflict bool
	}{
		{
			name:     "disjoint_ranges",
			a:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 1, High: 10}},
			b:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 11, High: 20}},
			conflict: false,
		},
		{
			name:     "overlapping_ranges_no_matcher",
			a:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 1, High: 10}},
			b:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 5, High: 15}},
			conflict: true,
		},
		{
			name:     "wildcard_versus_explicit",
			a:        wire.EarlyClaim{},
			b:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 1883, High: 1883}},
			conflict: true,
		},
		{
			name:     "wildcard_versus_wildcard",
			a:        wire.EarlyClaim{},
			b:        wire.EarlyClaim{},
			conflict: true,
		},
		{
			name:     "distinct_prefixes",
			a:        wire.EarlyClaim{MagicBytesPrefix: prefix("AB")},
			b:        wire.EarlyClaim{MagicBytesPrefix: prefix("CD")},
			conflict: false,
		},
		{
			name:     "prefix_of_other",
			a:        wire.EarlyClaim{MagicBytesPrefix: prefix("AB")},
			b:        wire.EarlyClaim{MagicBytesPrefix: prefix("ABC")},
			conflict: true,
		},
		{
			name:     "both_probe_may_chain",
			a:        wire.EarlyClaim{Probe: true},
			b:        wire.EarlyClaim{Probe: true},
			conflict: false,
		},
		{
			name:     "mixed_probe_and_prefix",
			a:        wire.EarlyClaim{Probe: true},
			b:        wire.EarlyClaim{MagicBytesPrefix: prefix("AB")},
			conflict: true,
		},
		{
			name:     "terminate_versus_raw_separate_seams",
			a:        wire.EarlyClaim{MagicBytesPrefix: prefix("MQTT")},
			b:        wire.EarlyClaim{PortRange: wire.PortRange{Low: 443, High: 443}, TLS: &wire.TLSClaim{Terminate: true}},
			conflict: false,
		},
		{
			name:     "distinct_sni",
			a:        wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true, SNIMatch: "a.example.com"}},
			b:        wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true, SNIMatch: "b.example.com"}},
			conflict: false,
		},
		{
			name:     "same_sni",
			a:        wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true, SNIMatch: "a.example.com"}},
			b:        wire.EarlyClaim{TLS: &wire.TLSClaim{Terminate: true, SNIMatch: "a.example.com"}},
			conflict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := mustCompileEarly(t, tt.a), mustCompileEarly(t, tt.b)
			assert.Equal(t, tt.conflict, earlyClaimConflict(a, b))
			assert.Equal(t, tt.conflict, earlyClaimConflict(b, a))
		})
	}
}
