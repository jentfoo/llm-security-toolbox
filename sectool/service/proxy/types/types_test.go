package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawHTTP1Request_Clone(t *testing.T) {
	t.Parallel()

	orig := &RawHTTP1Request{
		Method:  "GET",
		Path:    "/",
		Version: "HTTP/1.1",
		Headers: Headers{
			{Name: "Host", Value: "example.com"},
			{Name: "Accept-Encoding", Value: "gzip"},
		},
		Body: []byte("body"),
	}

	c := orig.Clone()
	require.Len(t, c.Headers, 2)

	// Mutating the clone's headers must not affect the original
	c.Headers[0].Value = "evil.com"
	c.SetHeader("Accept-Encoding", "identity")
	c.Headers = append(c.Headers, Header{Name: "X-New", Value: "1"})

	assert.Equal(t, "example.com", orig.GetHeader("Host"))
	assert.Equal(t, "gzip", orig.GetHeader("Accept-Encoding"))
	assert.Len(t, orig.Headers, 2)
}

func TestMessage(t *testing.T) {
	t.Parallel()

	t.Run("request_roundtrip", func(t *testing.T) {
		orig := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/submit",
			Query:   "a=1&b=2",
			Version: "HTTP/1.1",
			Headers: Headers{
				{Name: "Host", Value: "example.com", RawLine: []byte("Host: example.com"), LineEnding: EndingBareLF},
				{Name: "Content-Length", Value: "5"},
			},
			Body:              []byte("hello"),
			Chunks:            []ChunkFrame{{Size: 5}},
			Protocol:          ProtocolHTTP11,
			RequestLineEnding: EndingBareLF,
			HeaderBlockEnding: EndingCRLF,
		}

		got := RequestToMessage(orig).toRawRequest()
		assert.Equal(t, orig, got)

		var bufA, bufB bytes.Buffer
		assert.Equal(t, orig.SerializeRaw(&bufA), got.SerializeRaw(&bufB))
	})

	t.Run("response_roundtrip", func(t *testing.T) {
		orig := &RawHTTP1Response{
			Version:           "HTTP/1.1",
			StatusCode:        200,
			StatusText:        "OK",
			Headers:           Headers{{Name: "Content-Type", Value: "text/plain"}},
			Body:              []byte("body"),
			Trailers:          []byte("X-Trailer: 1\r\n"),
			StatusLineEnding:  EndingBareLF,
			HeaderBlockEnding: EndingCRLF,
			CloseDelimited:    true,
		}

		got := ResponseToMessage(orig).toRawResponse()
		assert.Equal(t, orig, got)

		var bufA, bufB bytes.Buffer
		assert.Equal(t, orig.SerializeRaw(&bufA), got.SerializeRaw(&bufB))
	})

	t.Run("header_helpers", func(t *testing.T) {
		m := &Message{Headers: Headers{{Name: "X-One", Value: "1"}}}
		assert.Equal(t, "1", m.GetHeader("x-one"))

		m.SetHeader("X-Two", "2")
		assert.Equal(t, "2", m.GetHeader("X-Two"))

		m.RemoveHeader("x-one")
		assert.Empty(t, m.GetHeader("X-One"))

		m.Chunks = []ChunkFrame{{Size: 1}}
		m.SetBody([]byte("new"))
		assert.Equal(t, []byte("new"), m.Body)
		assert.Nil(t, m.Chunks)
	})
}

func TestTarget_Addr(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "example.com:8443", (&Target{Hostname: "example.com", Port: 8443}).Addr())
	assert.Equal(t, "[::1]:8080", (&Target{Hostname: "::1", Port: 8080}).Addr())
}

func TestTarget_HostHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tgt  Target
		want string
	}{
		{"http_default_port", Target{Hostname: "example.com", Port: 80}, "example.com"},
		{"https_default_port", Target{Hostname: "example.com", Port: 443, UsesHTTPS: true}, "example.com"},
		{"http_custom_port", Target{Hostname: "example.com", Port: 8080}, "example.com:8080"},
		{"https_custom_port", Target{Hostname: "example.com", Port: 8443, UsesHTTPS: true}, "example.com:8443"},
		{"ipv6_default_port", Target{Hostname: "::1", Port: 80}, "[::1]"},
		{"ipv6_custom_port", Target{Hostname: "::1", Port: 8080}, "[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.tgt.HostHeader())
		})
	}
}
