//go:build unix

package sidecar

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listen binds a Unix domain socket, creating its directory 0700 and the socket
// 0600. A stale socket file is removed first.
func listen(socket string) (net.Listener, error) {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sidecar: create socket dir: %w", err)
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("sidecar: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("sidecar: listen unix %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("sidecar: chmod socket: %w", err)
	}
	return ln, nil
}
