package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestDecodeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		pseudos         map[string]string
		headers         []Header
		wantErr         bool
		invalidBlock    []byte
		expectedPseudos map[string]string
		expectedHeaders []Header
	}{
		{
			name: "request_headers",
			pseudos: map[string]string{
				":method":    "GET",
				":scheme":    "https",
				":authority": "example.com",
				":path":      "/test",
			},
			headers: []Header{
				{Name: "user-agent", Value: "test/1.0"},
				{Name: "accept", Value: "*/*"},
			},
			expectedPseudos: map[string]string{
				":method":    "GET",
				":scheme":    "https",
				":authority": "example.com",
				":path":      "/test",
			},
			expectedHeaders: []Header{
				{Name: "user-agent", Value: "test/1.0"},
				{Name: "accept", Value: "*/*"},
			},
		},
		{
			name:         "invalid_block",
			invalidBlock: []byte{0xff, 0xff, 0xff},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			h := newH2Conn(serverConn)

			var block []byte
			var err error

			if tt.invalidBlock != nil {
				block = tt.invalidBlock
			} else {
				block, err = h.encodeHeaders(tt.pseudos, tt.headers)
				require.NoError(t, err)
				require.NotEmpty(t, block)
			}

			h2 := newH2Conn(clientConn)
			decodedPseudos, decodedHeaders, err := h2.decodeHeaders(block)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			for k, v := range tt.expectedPseudos {
				assert.Equal(t, v, decodedPseudos[k])
			}
			assert.Len(t, decodedHeaders, len(tt.expectedHeaders))
			for i, h := range tt.expectedHeaders {
				assert.Equal(t, h.Name, decodedHeaders[i].Name)
				assert.Equal(t, h.Value, decodedHeaders[i].Value)
			}
		})
	}
}

func TestEncodeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		pseudos         map[string]string
		headers         []Header
		expectedPseudos map[string]string
		expectedCount   int
	}{
		{
			name: "response_status",
			pseudos: map[string]string{
				":status": "200",
			},
			headers: []Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expectedPseudos: map[string]string{
				":status": "200",
			},
			expectedCount: 1,
		},
		{
			name: "empty_headers",
			pseudos: map[string]string{
				":status": "204",
			},
			headers:         nil,
			expectedPseudos: map[string]string{":status": "204"},
			expectedCount:   0,
		},
		{
			name: "multiple_values",
			pseudos: map[string]string{
				":method": "GET",
				":path":   "/",
			},
			headers: []Header{
				{Name: "accept", Value: "text/html"},
				{Name: "accept", Value: "application/json"},
				{Name: "accept-encoding", Value: "gzip, deflate"},
			},
			expectedPseudos: map[string]string{
				":method": "GET",
				":path":   "/",
			},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			h := newH2Conn(serverConn)

			encoded, err := h.encodeHeaders(tt.pseudos, tt.headers)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			h2 := newH2Conn(clientConn)
			decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
			require.NoError(t, err)

			for k, v := range tt.expectedPseudos {
				assert.Equal(t, v, decodedPseudos[k])
			}
			assert.Len(t, decodedHeaders, tt.expectedCount)
		})
	}
}

func TestNewH2Conn(t *testing.T) {
	t.Parallel()

	t.Run("independent_hpack_state", func(t *testing.T) {
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

		pseudos1 := map[string]string{":method": "POST"}
		headers1 := []Header{{Name: "x-custom", Value: "value1"}}
		encoded1, err := h1.encodeHeaders(pseudos1, headers1)
		require.NoError(t, err)

		pseudos2 := map[string]string{":method": "GET"}
		headers2 := []Header{{Name: "x-other", Value: "value2"}}
		encoded2, err := h2.encodeHeaders(pseudos2, headers2)
		require.NoError(t, err)

		assert.NotEmpty(t, encoded1)
		assert.NotEmpty(t, encoded2)
	})
}

func TestUpdateSettings(t *testing.T) {
	t.Parallel()

	t.Run("max_frame_size", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		assert.Equal(t, uint32(16384), h.getMaxFrameSize())

		h.updateSettings([]http2.Setting{
			{ID: http2.SettingMaxFrameSize, Val: 32768},
		})

		assert.Equal(t, uint32(32768), h.getMaxFrameSize())
	})

	t.Run("initial_window_size", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		h.initStreamSendWindow(1)
		h.consumeSendWindow(1, 1000)
		assert.Equal(t, int32(65535-1000), h.sendWindowStream[1])

		newInitial := uint32(131070)

		h.updateSendWindowFromSettings(newInitial)

		h.updateSettings([]http2.Setting{
			{ID: http2.SettingInitialWindowSize, Val: newInitial},
		})
		assert.Equal(t, newInitial, h.initialWindowSize)

		// old=65535, new=131070, delta=65535
		// stream was at 64535, should now be at 64535+65535=130070
		assert.Equal(t, int32(130070), h.sendWindowStream[1])
	})
}

func TestHeaderListSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pseudos  map[string]string
		headers  []Header
		expected int
	}{
		{
			name:     "empty",
			pseudos:  nil,
			headers:  nil,
			expected: 0,
		},
		{
			name: "pseudos_only",
			pseudos: map[string]string{
				":method": "GET",
			},
			headers:  nil,
			expected: len(":method") + len("GET") + 32,
		},
		{
			name:    "headers_only",
			pseudos: nil,
			headers: []Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expected: len("content-type") + len("text/plain") + 32,
		},
		{
			name: "mixed",
			pseudos: map[string]string{
				":status": "200",
			},
			headers: []Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expected: len(":status") + len("200") + 32 + len("content-type") + len("text/plain") + 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, headerListSize(tt.pseudos, tt.headers))
		})
	}
}

func TestConsumeRecvWindow(t *testing.T) {
	t.Parallel()

	t.Run("within_limits", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.recvWindowStream[1] = localInitialWindow

		err := h.consumeRecvWindow(1, 1000)
		require.NoError(t, err)
		assert.Equal(t, int32(localInitialWindow-1000), h.recvWindowConn)
		assert.Equal(t, int32(localInitialWindow-1000), h.recvWindowStream[1])
	})

	t.Run("exceeds_connection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.recvWindowConn = 100

		err := h.consumeRecvWindow(1, 200)
		require.Error(t, err)
		var fcErr *flowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(0), fcErr.StreamID)
	})

	t.Run("exceeds_stream", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.recvWindowStream[1] = 100

		err := h.consumeRecvWindow(1, 200)
		require.Error(t, err)
		var fcErr *flowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(1), fcErr.StreamID)
	})
}

func TestNeedsWindowUpdate(t *testing.T) {
	t.Parallel()

	t.Run("no_update_needed", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.recvWindowStream[1] = localInitialWindow

		connUpdate, streamUpdate := h.needsWindowUpdate(1)
		assert.Equal(t, uint32(0), connUpdate)
		assert.Equal(t, uint32(0), streamUpdate)
	})

	t.Run("update_needed", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.recvWindowConn = 1000
		h.recvWindowStream[1] = 1000

		connUpdate, streamUpdate := h.needsWindowUpdate(1)
		assert.Equal(t, uint32(localInitialWindow-1000), connUpdate)
		assert.Equal(t, uint32(localInitialWindow-1000), streamUpdate)
		assert.Equal(t, int32(localInitialWindow), h.recvWindowConn)
		assert.Equal(t, int32(localInitialWindow), h.recvWindowStream[1])
	})
}

func TestConsumeSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.initStreamSendWindow(1)

		ok := h.consumeSendWindow(1, 1000)
		assert.True(t, ok)
		assert.Equal(t, int32(65535-1000), h.sendWindowConn)
		assert.Equal(t, int32(65535-1000), h.sendWindowStream[1])
	})

	t.Run("blocked_connection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = 100
		h.initStreamSendWindow(1)

		ok := h.consumeSendWindow(1, 200)
		assert.False(t, ok)
	})

	t.Run("blocked_stream", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowStream[1] = 100

		ok := h.consumeSendWindow(1, 200)
		assert.False(t, ok)
	})
}

func TestUpdateSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("connection_level", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		initial := h.sendWindowConn

		h.updateSendWindow(0, 1000)
		assert.Equal(t, initial+1000, h.sendWindowConn)
	})

	t.Run("stream_level", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.initStreamSendWindow(1)
		initial := h.sendWindowStream[1]

		h.updateSendWindow(1, 1000)
		assert.Equal(t, initial+1000, h.sendWindowStream[1])
	})
}

func TestGetAvailableSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("min_of_both", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = 1000
		h.sendWindowStream[1] = 500

		available := h.getAvailableSendWindow(1)
		assert.Equal(t, 500, available)
	})

	t.Run("negative_clamped", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = -100
		h.sendWindowStream[1] = 500

		available := h.getAvailableSendWindow(1)
		assert.Equal(t, 0, available)
	})
}

func TestRemoveStreamWindow(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)
	h.recvWindowStream[1] = 1000
	h.sendWindowStream[1] = 1000

	h.removeStreamWindow(1)

	_, recvOk := h.recvWindowStream[1]
	_, sendOk := h.sendWindowStream[1]
	assert.False(t, recvOk)
	assert.False(t, sendOk)
}

func TestClose(t *testing.T) {
	t.Parallel()

	t.Run("closes_channel", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		h.close()

		select {
		case <-h.closeCh:
			// Expected
		default:
			t.Fatal("closeCh should be closed")
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		h.close()
		h.close()

		select {
		case <-h.closeCh:
			// Expected
		default:
			t.Fatal("closeCh should be closed")
		}
	})
}

func TestEnqueueWrite(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		ctx := context.Background()

		ok := h.enqueueWrite(ctx, []byte("test"))
		assert.True(t, ok)
	})

	t.Run("context_cancelled", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		// Fill the write buffer so select must choose between ctx.Done and blocked write
		for range 256 {
			h.writeCh <- []byte{}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		ok := h.enqueueWrite(ctx, []byte("test"))
		assert.False(t, ok)
	})

	t.Run("closed_connection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		// Fill the write buffer so select must choose between closeCh and blocked write
		for range 256 {
			h.writeCh <- []byte{}
		}
		h.close()
		ctx := context.Background()

		ok := h.enqueueWrite(ctx, []byte("test"))
		assert.False(t, ok)
	})
}

func TestFlowCtrlWait(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	waitCh := h.flowCtrlWait()

	go func() {
		time.Sleep(10 * time.Millisecond)
		h.updateSendWindow(0, 1000)
	}()

	select {
	case <-waitCh:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("flowCtrlWait channel should be closed")
	}
}
