package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecompress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		data           []byte
		encoding       string
		wantData       []byte
		wantCompressed bool
	}{
		{
			name:           "gzip_valid",
			data:           gzipBytes(t, []byte("Hello, World!")),
			encoding:       "gzip",
			wantData:       []byte("Hello, World!"),
			wantCompressed: true,
		},
		{
			name:           "deflate_valid",
			data:           deflateBytes(t, []byte("Hello, World!")),
			encoding:       "deflate",
			wantData:       []byte("Hello, World!"),
			wantCompressed: true,
		},
		{
			name:           "unknown_encoding",
			data:           []byte("plain text"),
			encoding:       "br", // brotli not supported
			wantData:       []byte("plain text"),
			wantCompressed: false,
		},
		{
			name:           "empty_encoding",
			data:           []byte("plain text"),
			encoding:       "",
			wantData:       []byte("plain text"),
			wantCompressed: false,
		},
		{
			name:           "identity_encoding",
			data:           []byte("plain text"),
			encoding:       "identity",
			wantData:       []byte("plain text"),
			wantCompressed: false,
		},
		{
			name:           "gzip_empty_body",
			data:           gzipBytes(t, []byte("")),
			encoding:       "gzip",
			wantData:       []byte{},
			wantCompressed: true,
		},
		{
			name:           "deflate_empty_body",
			data:           deflateBytes(t, []byte("")),
			encoding:       "deflate",
			wantData:       []byte{},
			wantCompressed: true,
		},
		// Normalization tests
		{
			name:           "gzip_uppercase",
			data:           gzipBytes(t, []byte("Upper Case")),
			encoding:       "GZIP",
			wantData:       []byte("Upper Case"),
			wantCompressed: true,
		},
		{
			name:           "gzip_mixed_case",
			data:           gzipBytes(t, []byte("Mixed Case")),
			encoding:       "GzIp",
			wantData:       []byte("Mixed Case"),
			wantCompressed: true,
		},
		{
			name:           "gzip_whitespace",
			data:           gzipBytes(t, []byte("Whitespace")),
			encoding:       " gzip ",
			wantData:       []byte("Whitespace"),
			wantCompressed: true,
		},
		{
			name:           "x_gzip_alias",
			data:           gzipBytes(t, []byte("X-Gzip")),
			encoding:       "x-gzip",
			wantData:       []byte("X-Gzip"),
			wantCompressed: true,
		},
		{
			name:           "deflate_uppercase",
			data:           deflateBytes(t, []byte("Upper Deflate")),
			encoding:       "DEFLATE",
			wantData:       []byte("Upper Deflate"),
			wantCompressed: true,
		},
		{
			name:           "multiple_encodings_skipped",
			data:           gzipBytes(t, []byte("Multi")),
			encoding:       "gzip, br",
			wantData:       gzipBytes(t, []byte("Multi")), // returned unchanged
			wantCompressed: false,
		},
		{
			name:           "zlib_wrapped_deflate",
			data:           zlibBytes(t, []byte("Zlib Wrapped")),
			encoding:       "deflate",
			wantData:       []byte("Zlib Wrapped"),
			wantCompressed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wasCompressed := Decompress(tt.data, tt.encoding)

			assert.Equal(t, tt.wantCompressed, wasCompressed)
			assert.Equal(t, tt.wantData, got)
		})
	}
}

func TestDecompress_invalid_data(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		encoding string
	}{
		{
			name:     "gzip_invalid",
			data:     []byte("not gzip data"),
			encoding: "gzip",
		},
		{
			name:     "deflate_invalid",
			data:     []byte{0xFF, 0xFE, 0xFD}, // invalid deflate
			encoding: "deflate",
		},
		{
			name:     "gzip_truncated",
			data:     gzipBytes(t, []byte("Hello"))[:5], // truncated
			encoding: "gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wasCompressed := Decompress(tt.data, tt.encoding)

			assert.True(t, wasCompressed)
			assert.Nil(t, got)
		})
	}
}

func TestCompress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		encoding string
		wantErr  bool
	}{
		{
			name:     "gzip_valid",
			data:     []byte("Hello, World!"),
			encoding: "gzip",
			wantErr:  false,
		},
		{
			name:     "deflate_valid",
			data:     []byte("Hello, World!"),
			encoding: "deflate",
			wantErr:  false,
		},
		{
			name:     "unknown_encoding",
			data:     []byte("plain text"),
			encoding: "br", // brotli not supported, returns data unchanged
			wantErr:  false,
		},
		{
			name:     "empty_encoding",
			data:     []byte("plain text"),
			encoding: "",
			wantErr:  false,
		},
		{
			name:     "gzip_empty_body",
			data:     []byte{},
			encoding: "gzip",
			wantErr:  false,
		},
		{
			name:     "deflate_empty_body",
			data:     []byte{},
			encoding: "deflate",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.data, tt.encoding)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, compressed)
		})
	}
}

func TestCompress_roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		encoding string
	}{
		{
			name:     "gzip_roundtrip",
			data:     []byte("Hello, World! This is test data for compression."),
			encoding: "gzip",
		},
		{
			name:     "deflate_roundtrip",
			data:     []byte("Hello, World! This is test data for compression."),
			encoding: "deflate",
		},
		{
			name:     "gzip_binary_data",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
			encoding: "gzip",
		},
		{
			name:     "deflate_binary_data",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
			encoding: "deflate",
		},
		{
			name:     "gzip_large_data",
			data:     bytes.Repeat([]byte("x"), 10000),
			encoding: "gzip",
		},
		{
			name:     "deflate_large_data",
			data:     bytes.Repeat([]byte("y"), 10000),
			encoding: "deflate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.data, tt.encoding)
			require.NoError(t, err)

			decompressed, wasCompressed := Decompress(compressed, tt.encoding)
			assert.True(t, wasCompressed)
			assert.Equal(t, tt.data, decompressed)
		})
	}
}

func TestCompress_unknown_returns_original(t *testing.T) {
	t.Parallel()

	original := []byte("plain text data")
	result, err := Compress(original, "unknown")

	require.NoError(t, err)
	assert.Equal(t, original, result)
}

// gzipBytes compresses data using gzip
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(data)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// deflateBytes compresses data using deflate
func deflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = fw.Write(data)
	require.NoError(t, err)
	require.NoError(t, fw.Close())
	return buf.Bytes()
}

// zlibBytes compresses data using zlib (zlib-wrapped deflate)
func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
