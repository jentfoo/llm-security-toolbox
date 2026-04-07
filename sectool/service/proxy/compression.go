package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/go-analyze/bulk"
	"github.com/klauspost/compress/zstd"
)

// Compression encoding constants
const (
	encodingGzip    = "gzip"
	encodingDeflate = "deflate"
	encodingBrotli  = "br"
	encodingZstd    = "zstd"
)

// NormalizeEncoding normalizes a Content-Encoding header value.
// Returns the normalized encoding and whether it's a single supported encoding.
// Multiple encodings (e.g., "gzip, br") return ("", false) since we can't partially decode.
func NormalizeEncoding(encoding string) (string, bool) {
	encoding = strings.TrimSpace(strings.ToLower(encoding))

	// Check for multiple encodings (comma-separated)
	if strings.Contains(encoding, ",") {
		// Multiple encodings - we can't partially decode, so skip
		return "", false
	}

	// Normalize to canonical form
	switch encoding {
	case encodingGzip, "x-gzip":
		return encodingGzip, true
	case encodingDeflate:
		return encodingDeflate, true
	case encodingBrotli:
		return encodingBrotli, true
	case encodingZstd:
		return encodingZstd, true
	default:
		return encoding, false
	}
}

// Decompress decompresses data based on Content-Encoding.
// Returns (decompressed data, wasCompressed).
// If wasCompressed is true but returned data is nil, decompression failed.
// Unknown encodings return (original data, false).
//
// Handles:
// - Case variations: "GZIP", "Gzip" normalized to "gzip"
// - Whitespace: " gzip " trimmed
// - x-gzip alias: treated as gzip
// - deflate: tries raw DEFLATE first, then zlib-wrapped
// - br: Brotli decompression
// - zstd: Zstandard decompression
// - Multiple encodings (e.g., "gzip, br"): skipped (can't partially decode)
func Decompress(data []byte, encoding string) ([]byte, bool) {
	normalized, supported := NormalizeEncoding(encoding)
	if !supported {
		return data, false // unknown or multiple encodings
	}

	switch normalized {
	case encodingGzip:
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, true // compressed but failed
		}
		defer func() { _ = gr.Close() }()
		decompressed, err := io.ReadAll(gr)
		if err != nil {
			return nil, true // compressed but failed
		}
		return decompressed, true

	case encodingDeflate:
		// deflate can be raw DEFLATE or zlib-wrapped - try raw first
		decompressed, err := decompressRawDeflate(data)
		if err == nil {
			return decompressed, true
		}
		decompressed, err = decompressZlib(data)
		if err == nil {
			return decompressed, true
		}
		return nil, true // compressed but failed

	case encodingBrotli:
		decompressed, err := io.ReadAll(brotli.NewReader(bytes.NewReader(data)))
		if err != nil {
			return nil, true // compressed but failed
		}
		return decompressed, true

	case encodingZstd:
		decoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, true // compressed but failed
		}
		defer decoder.Close()
		decompressed, err := io.ReadAll(decoder)
		if err != nil {
			return nil, true // compressed but failed
		}
		return decompressed, true

	default:
		return data, false // not compressed
	}
}

// decompressRawDeflate attempts raw DEFLATE decompression.
func decompressRawDeflate(data []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = fr.Close() }()
	return io.ReadAll(fr)
}

// decompressZlib attempts zlib-wrapped DEFLATE decompression.
func decompressZlib(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(zr)
}

// Compress compresses data with the specified encoding.
// Returns (compressed data, error).
// Unknown encodings return the original data unchanged.
//
// Handles the same normalization as Decompress for consistency.
func Compress(data []byte, encoding string) ([]byte, error) {
	normalized, supported := NormalizeEncoding(encoding)
	if !supported {
		return data, nil // unknown encoding, return unchanged
	}

	var buf bytes.Buffer
	switch normalized {
	case encodingGzip:
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			_ = gw.Close()
			return nil, err
		} else if err := gw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	case encodingDeflate:
		// Use raw DEFLATE (most interoperable for recompression)
		if fw, err := flate.NewWriter(&buf, flate.DefaultCompression); err != nil {
			return nil, err
		} else if _, err := fw.Write(data); err != nil {
			_ = fw.Close()
			return nil, err
		} else if err := fw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	case encodingBrotli:
		bw := brotli.NewWriter(&buf)
		if _, err := bw.Write(data); err != nil {
			_ = bw.Close()
			return nil, err
		} else if err := bw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	case encodingZstd:
		encoder, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := encoder.Write(data); err != nil {
			_ = encoder.Close()
			return nil, err
		}
		if err := encoder.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	default:
		return data, nil
	}
}

// FilterSupportedEncodings filters an Accept-Encoding header value to only include encodings the
// proxy can decompress/recompress. Preserves quality values and ordering.
// Falls back to all supported encodings when the input contains no encoding supported by the proxy.
func FilterSupportedEncodings(acceptEncoding string) string {
	supported := bulk.SliceFilterInPlace(func(part string) bool {
		trimmed := strings.TrimSpace(part)
		// Extract encoding name (before optional ;q= quality value)
		name := trimmed
		if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
			name = strings.TrimSpace(trimmed[:idx])
		}
		_, supported := NormalizeEncoding(name)
		return supported
	}, strings.Split(acceptEncoding, ","))
	if len(supported) == 0 {
		return strings.Join([]string{encodingGzip, encodingDeflate, encodingBrotli, encodingZstd}, ", ")
	}
	return strings.Join(supported, ",")
}
