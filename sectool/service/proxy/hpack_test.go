package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestDecodeHeaders(t *testing.T) {
	t.Parallel()

	// Create a connection pair for testing
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Encode some headers first to get a valid HPACK block
	pseudos := map[string]string{
		":method":    "GET",
		":scheme":    "https",
		":authority": "example.com",
		":path":      "/test",
	}
	headers := []Header{
		{Name: "user-agent", Value: "test/1.0"},
		{Name: "accept", Value: "*/*"},
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	// Now decode the block using a fresh connection (different HPACK state)
	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "GET", decodedPseudos[":method"])
	assert.Equal(t, "https", decodedPseudos[":scheme"])
	assert.Equal(t, "example.com", decodedPseudos[":authority"])
	assert.Equal(t, "/test", decodedPseudos[":path"])

	assert.Len(t, decodedHeaders, 2)
	assert.Equal(t, "user-agent", decodedHeaders[0].Name)
	assert.Equal(t, "test/1.0", decodedHeaders[0].Value)
}

func TestEncodeHeaders_Order(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Test that pseudo-headers are encoded before regular headers
	pseudos := map[string]string{
		":status": "200",
	}
	headers := []Header{
		{Name: "content-type", Value: "text/plain"},
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	// Decode and verify
	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "200", decodedPseudos[":status"])
	assert.Len(t, decodedHeaders, 1)
	assert.Equal(t, "content-type", decodedHeaders[0].Name)
}

func TestDecodeHeaders_InvalidBlock(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Invalid HPACK block
	_, _, err := h.decodeHeaders([]byte{0xff, 0xff, 0xff})
	assert.Error(t, err)
}

func TestH2Conn_IndependentHPACKState(t *testing.T) {
	t.Parallel()

	// Create two independent connections
	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	t.Cleanup(func() {
		_ = c1a.Close()
		_ = c1b.Close()
		_ = c2a.Close()
		_ = c2b.Close()
	})

	h1 := newH2Conn(c1a)
	h2 := newH2Conn(c2a)

	// Encode headers on h1
	pseudos1 := map[string]string{":method": "POST"}
	headers1 := []Header{{Name: "x-custom", Value: "value1"}}
	encoded1, err := h1.encodeHeaders(pseudos1, headers1)
	require.NoError(t, err)

	// Encode different headers on h2
	pseudos2 := map[string]string{":method": "GET"}
	headers2 := []Header{{Name: "x-other", Value: "value2"}}
	encoded2, err := h2.encodeHeaders(pseudos2, headers2)
	require.NoError(t, err)

	// Both should produce valid HPACK blocks
	assert.NotEmpty(t, encoded1)
	assert.NotEmpty(t, encoded2)
}

func TestUpdateSettings(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Verify defaults
	assert.Equal(t, uint32(16384), h.getMaxFrameSize())

	// Update settings
	h.updateSettings([]http2.Setting{
		{ID: http2.SettingMaxFrameSize, Val: 32768},
	})

	assert.Equal(t, uint32(32768), h.getMaxFrameSize())
}

func TestEncodeHeaders_EmptyHeaders(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Encode with only pseudo-headers
	pseudos := map[string]string{
		":status": "204",
	}

	encoded, err := h.encodeHeaders(pseudos, nil)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	// Decode and verify
	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "204", decodedPseudos[":status"])
	assert.Empty(t, decodedHeaders)
}

func TestEncodeHeaders_MultipleValues(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	pseudos := map[string]string{
		":method": "GET",
		":path":   "/",
	}
	headers := []Header{
		{Name: "accept", Value: "text/html"},
		{Name: "accept", Value: "application/json"}, // Duplicate header name
		{Name: "accept-encoding", Value: "gzip, deflate"},
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)

	// Decode and verify
	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "GET", decodedPseudos[":method"])
	assert.Len(t, decodedHeaders, 3)
}

func TestUpdateSettings_WindowSize(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Create a stream send window by sending some data
	h.initStreamSendWindow(1)
	h.consumeSendWindow(1, 1000)
	assert.Equal(t, int32(65535-1000), h.sendWindowStream[1])

	// When peer sends SETTINGS with new INITIAL_WINDOW_SIZE, it tells us their receive window.
	// This affects OUR send windows (how much we can send to them).
	//
	// In handleSettingsFrame(), the order is:
	// 1. updateSendWindowFromSettings() is called during ForeachSetting (BEFORE updateSettings)
	// 2. updateSettings() caches the new value
	//
	// We must follow the same order here.
	newInitial := uint32(131070) // double the default

	// First, update send windows (uses old initialWindowSize for delta calculation)
	h.updateSendWindowFromSettings(newInitial)

	// Then, cache the new value
	h.updateSettings([]http2.Setting{
		{ID: http2.SettingInitialWindowSize, Val: newInitial},
	})
	assert.Equal(t, newInitial, h.initialWindowSize)

	// Send window should be adjusted by delta
	// old=65535, new=131070, delta=65535
	// stream was at 64535, should now be at 64535+65535=130070
	assert.Equal(t, int32(130070), h.sendWindowStream[1])
}
