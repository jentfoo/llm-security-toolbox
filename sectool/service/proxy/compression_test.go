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

func TestNormalizeEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		encoding      string
		wantNorm      string
		wantSupported bool
	}{
		{"gzip", "gzip", "gzip", true},
		{"gzip_uppercase", "GZIP", "gzip", true},
		{"gzip_mixed_case", "GzIp", "gzip", true},
		{"gzip_whitespace", " gzip ", "gzip", true},
		{"x_gzip_alias", "x-gzip", "gzip", true},
		{"deflate", "deflate", "deflate", true},
		{"deflate_uppercase", "DEFLATE", "deflate", true},
		{"identity", "identity", "identity", false},
		{"brotli_unsupported", "br", "br", false},
		{"empty", "", "", false},
		{"multiple_encodings", "gzip, br", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNorm, gotSupported := NormalizeEncoding(tt.encoding)

			assert.Equal(t, tt.wantNorm, gotNorm)
			assert.Equal(t, tt.wantSupported, gotSupported)
		})
	}
}

func TestDecompress(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name           string
			data           []byte
			encoding       string
			wantData       []byte
			wantCompressed bool
		}{
			{
				name:           "gzip",
				data:           gzipBytes(t, []byte("Hello, World!")),
				encoding:       "gzip",
				wantData:       []byte("Hello, World!"),
				wantCompressed: true,
			},
			{
				name:           "deflate",
				data:           deflateBytes(t, []byte("Hello, World!")),
				encoding:       "deflate",
				wantData:       []byte("Hello, World!"),
				wantCompressed: true,
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
	})

	t.Run("unsupported_encoding", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"brotli", []byte("plain text"), "br"},
			{"empty", []byte("plain text"), ""},
			{"identity", []byte("plain text"), "identity"},
			{"multiple_encodings", gzipBytes(t, []byte("Multi")), "gzip, br"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, wasCompressed := Decompress(tt.data, tt.encoding)

				assert.False(t, wasCompressed)
				assert.Equal(t, tt.data, got)
			})
		}
	})

	t.Run("invalid_data", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip_invalid", []byte("not gzip data"), "gzip"},
			{"deflate_invalid", []byte{0xFF, 0xFE, 0xFD}, "deflate"},
			{"gzip_truncated", gzipBytes(t, []byte("Hello"))[:5], "gzip"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, wasCompressed := Decompress(tt.data, tt.encoding)

				assert.True(t, wasCompressed)
				assert.Nil(t, got)
			})
		}
	})
}

func TestCompress(t *testing.T) {
	t.Parallel()

	t.Run("supported_encodings", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip", []byte("Hello, World!"), "gzip"},
			{"deflate", []byte("Hello, World!"), "deflate"},
			{"gzip_empty_body", []byte{}, "gzip"},
			{"deflate_empty_body", []byte{}, "deflate"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				compressed, err := Compress(tt.data, tt.encoding)

				require.NoError(t, err)
				assert.NotNil(t, compressed)
			})
		}
	})

	t.Run("unsupported_returns_original", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"unknown", []byte("plain text data"), "unknown"},
			{"brotli", []byte("plain text"), "br"},
			{"empty", []byte("plain text"), ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := Compress(tt.data, tt.encoding)

				require.NoError(t, err)
				assert.Equal(t, tt.data, result)
			})
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip", []byte("Hello, World! This is test data for compression."), "gzip"},
			{"deflate", []byte("Hello, World! This is test data for compression."), "deflate"},
			{"gzip_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "gzip"},
			{"deflate_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "deflate"},
			{"gzip_large_data", bytes.Repeat([]byte("x"), 10000), "gzip"},
			{"deflate_large_data", bytes.Repeat([]byte("y"), 10000), "deflate"},
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
	})
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(data)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

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

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
