//go:build unix

package sidecar

import "net"

// networkFor selects the dial network from the address shape: a host:port is
// loopback TCP; any other value is a Unix domain socket path.
func networkFor(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return "tcp"
	}
	return "unix"
}
