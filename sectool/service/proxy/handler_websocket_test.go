package proxy

import (
	"bytes"
	"testing"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *RawHTTP1Request
		want bool
	}{
		{
			name: "valid_websocket_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: true,
		},
		{
			name: "case_insensitive_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "WebSocket"},
					{Name: "Connection", Value: "upgrade"},
				},
			},
			want: true,
		},
		{
			name: "connection_keep_alive_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "keep-alive, Upgrade"},
				},
			},
			want: true,
		},
		{
			name: "missing_upgrade_header",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: false,
		},
		{
			name: "missing_connection_header",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
				},
			},
			want: false,
		},
		{
			name: "wrong_upgrade_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "h2c"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: false,
		},
		{
			name: "connection_no_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "close"},
				},
			},
			want: false,
		},
		{
			name: "empty_request",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWebSocketUpgrade(tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadWSFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		frameBytes  []byte
		wantFin     bool
		wantRsv     byte
		wantOpcode  byte
		wantPayload []byte
		wantErr     bool
	}{
		{
			name:        "text_frame_unmasked",
			frameBytes:  []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hello"),
		},
		{
			name: "text_frame_masked",
			frameBytes: []byte{
				0x81, 0x85, // FIN=1, opcode=1, MASK=1, len=5
				0x37, 0xfa, 0x21, 0x3d, // mask key
				0x7f, 0x9f, 0x4d, 0x51, 0x58, // masked "Hello"
			},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hello"),
		},
		{
			name:        "binary_frame",
			frameBytes:  []byte{0x82, 0x04, 0x00, 0x01, 0x02, 0x03},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  2,
			wantPayload: []byte{0x00, 0x01, 0x02, 0x03},
		},
		{
			name:        "close_frame",
			frameBytes:  []byte{0x88, 0x02, 0x03, 0xe8}, // code 1000
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  8,
			wantPayload: []byte{0x03, 0xe8},
		},
		{
			name:        "ping_frame",
			frameBytes:  []byte{0x89, 0x04, 'p', 'i', 'n', 'g'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  9,
			wantPayload: []byte("ping"),
		},
		{
			name:        "pong_frame",
			frameBytes:  []byte{0x8A, 0x04, 'p', 'o', 'n', 'g'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  10,
			wantPayload: []byte("pong"),
		},
		{
			name:        "continuation_frame",
			frameBytes:  []byte{0x00, 0x03, 'a', 'b', 'c'},
			wantFin:     false,
			wantRsv:     0,
			wantOpcode:  0,
			wantPayload: []byte("abc"),
		},
		{
			name:        "fragment_first_part",
			frameBytes:  []byte{0x01, 0x03, 'H', 'e', 'l'}, // FIN=0, opcode=1
			wantFin:     false,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hel"),
		},
		{
			name:        "empty_payload",
			frameBytes:  []byte{0x81, 0x00},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte{},
		},
		{
			name: "126_byte_length",
			frameBytes: append(
				[]byte{0x81, 126, 0x00, 200}, // len=200
				bytes.Repeat([]byte{'x'}, 200)...,
			),
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: bytes.Repeat([]byte{'x'}, 200),
		},
		{
			name:        "rsv_bits_set",
			frameBytes:  []byte{0xF1, 0x02, 'h', 'i'}, // RSV1,2,3 all set
			wantFin:     true,
			wantRsv:     0x07,
			wantOpcode:  1,
			wantPayload: []byte("hi"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, err := readWSFrame(bytes.NewReader(tt.frameBytes))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantFin, frame.fin)
			assert.Equal(t, tt.wantRsv, frame.rsv)
			assert.Equal(t, tt.wantOpcode, frame.opcode)
			assert.Equal(t, tt.wantPayload, frame.payload)
		})
	}
}

func TestReadWSFrame_errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		frameBytes []byte
	}{
		{
			name:       "empty_input",
			frameBytes: []byte{},
		},
		{
			name:       "truncated_header",
			frameBytes: []byte{0x81},
		},
		{
			name:       "truncated_extended_length",
			frameBytes: []byte{0x81, 126, 0x00}, // missing second length byte
		},
		{
			name:       "truncated_payload",
			frameBytes: []byte{0x81, 0x05, 'H', 'e'}, // len says 5, only 2 bytes
		},
		{
			name:       "truncated_mask_key",
			frameBytes: []byte{0x81, 0x85, 0x37, 0xfa}, // mask flag set but only 2 mask bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readWSFrame(bytes.NewReader(tt.frameBytes))
			require.Error(t, err)
		})
	}
}

func TestEncodeWSFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		frame      *wsFrame
		checkLen   int
		checkFirst byte
	}{
		{
			name: "text_unmasked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("Hello"),
			},
			checkLen:   7, // 2 header + 5 payload
			checkFirst: 0x81,
		},
		{
			name: "text_masked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  true,
				mask:    [4]byte{0x37, 0xfa, 0x21, 0x3d},
				payload: []byte("Hello"),
			},
			checkLen:   11, // 2 header + 4 mask + 5 payload
			checkFirst: 0x81,
		},
		{
			name: "binary_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  2,
				masked:  false,
				payload: []byte{0x00, 0x01, 0x02},
			},
			checkLen:   5, // 2 header + 3 payload
			checkFirst: 0x82,
		},
		{
			name: "close_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  8,
				masked:  false,
				payload: []byte{0x03, 0xe8},
			},
			checkLen:   4,
			checkFirst: 0x88,
		},
		{
			name: "ping_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  9,
				masked:  false,
				payload: []byte("ping"),
			},
			checkLen:   6,
			checkFirst: 0x89,
		},
		{
			name: "pong_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  10,
				masked:  false,
				payload: []byte("pong"),
			},
			checkLen:   6,
			checkFirst: 0x8A,
		},
		{
			name: "empty_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte{},
			},
			checkLen:   2,
			checkFirst: 0x81,
		},
		{
			name: "fin_false",
			frame: &wsFrame{
				fin:     false,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("hi"),
			},
			checkLen:   4,
			checkFirst: 0x01, // FIN bit not set
		},
		{
			name: "rsv_bits",
			frame: &wsFrame{
				fin:     true,
				rsv:     0x07, // all RSV bits set
				opcode:  1,
				masked:  false,
				payload: []byte("hi"),
			},
			checkLen:   4,
			checkFirst: 0xF1, // FIN + RSV1,2,3 + opcode 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeWSFrame(tt.frame)

			assert.Len(t, encoded, tt.checkLen)
			assert.Equal(t, tt.checkFirst, encoded[0])
		})
	}
}

func TestEncodeWSFrame_roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame *wsFrame
	}{
		{
			name: "text_unmasked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("Hello, World!"),
			},
		},
		{
			name: "binary_data",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  2,
				masked:  false,
				payload: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			},
		},
		{
			name: "medium_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: bytes.Repeat([]byte("x"), 200), // > 125 bytes
			},
		},
		{
			name: "large_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: bytes.Repeat([]byte("y"), 70000), // > 65535 bytes
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeWSFrame(tt.frame)
			decoded, err := readWSFrame(bytes.NewReader(encoded))
			require.NoError(t, err)

			assert.Equal(t, tt.frame.fin, decoded.fin)
			assert.Equal(t, tt.frame.rsv, decoded.rsv)
			assert.Equal(t, tt.frame.opcode, decoded.opcode)
			assert.Equal(t, tt.frame.payload, decoded.payload)
		})
	}
}

func TestEncodeWSFrame_masked_roundtrip(t *testing.T) {
	t.Parallel()

	frame := &wsFrame{
		fin:     true,
		rsv:     0,
		opcode:  1,
		masked:  true,
		mask:    [4]byte{0x12, 0x34, 0x56, 0x78},
		payload: []byte("Hello, masked frame!"),
	}

	encoded := encodeWSFrame(frame)
	decoded, err := readWSFrame(bytes.NewReader(encoded))
	require.NoError(t, err)

	assert.Equal(t, frame.fin, decoded.fin)
	assert.Equal(t, frame.opcode, decoded.opcode)
	// Payload should match after unmasking during read
	assert.Equal(t, frame.payload, decoded.payload)
}

func TestOpcodeToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		opcode byte
		want   string
	}{
		{0, "continuation"},
		{1, "text"},
		{2, "binary"},
		{8, "close"},
		{9, "ping"},
		{10, "pong"},
		{3, "unknown-3"},
		{15, "unknown-15"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, opcodeToString(tt.opcode))
		})
	}
}

func TestNewWebSocketHandler(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	t.Cleanup(history.Close)

	certManager, err := NewCertManager(t.TempDir())
	require.NoError(t, err)

	handler := NewWebSocketHandler(history, certManager)

	assert.NotNil(t, handler)
	assert.Equal(t, history, handler.history)
	assert.Equal(t, certManager, handler.certManager)
	assert.Nil(t, handler.ruleApplier)
}

func TestWebSocketHandler_SetRuleApplier(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	history := NewHistoryStore(storage)
	t.Cleanup(history.Close)

	handler := NewWebSocketHandler(history, nil)

	// Mock rule applier
	applier := &mockRuleApplier{}
	handler.SetRuleApplier(applier)

	assert.Equal(t, applier, handler.ruleApplier)
}

// mockRuleApplier implements RuleApplier for testing
type mockRuleApplier struct {
	requestCalled  bool
	responseCalled bool
	wsCalled       bool
}

func (m *mockRuleApplier) ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request {
	m.requestCalled = true
	return req
}

func (m *mockRuleApplier) ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response {
	m.responseCalled = true
	return resp
}

func (m *mockRuleApplier) ApplyWSRules(payload []byte, direction string) []byte {
	m.wsCalled = true
	return payload
}

func (m *mockRuleApplier) HasBodyRules(isRequest bool) bool {
	return false
}
