package sidecar

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

func TestFlowDest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		flow   *types.Flow
		host   string
		port   int
		scheme string
	}{
		{
			name: "host_header_with_port",
			flow: &types.Flow{Scheme: "https", Port: 8443, Request: &types.Message{
				Headers: types.Headers{{Name: "Host", Value: "echo.test:8443"}},
			}},
			host: "echo.test", port: 8443, scheme: "https",
		},
		{
			name: "host_header_no_port",
			flow: &types.Flow{Scheme: "http", Port: 80, Request: &types.Message{
				Headers: types.Headers{{Name: "Host", Value: "example.com"}},
			}},
			host: "example.com", port: 80, scheme: "http",
		},
		{
			name: "no_request_side",
			flow: &types.Flow{Scheme: "https", Port: 443},
			host: "", port: 443, scheme: "https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, scheme := flowDest(tc.flow)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
			assert.Equal(t, tc.scheme, scheme)
		})
	}
}
