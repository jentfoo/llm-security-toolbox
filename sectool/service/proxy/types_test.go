package proxy

import (
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

	// Mutating the clone's headers must not affect the original.
	c.Headers[0].Value = "evil.com"
	c.SetHeader("Accept-Encoding", "identity")
	c.Headers = append(c.Headers, Header{Name: "X-New", Value: "1"})

	assert.Equal(t, "example.com", orig.GetHeader("Host"))
	assert.Equal(t, "gzip", orig.GetHeader("Accept-Encoding"))
	assert.Len(t, orig.Headers, 2)
}
