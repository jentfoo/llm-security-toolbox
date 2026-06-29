package sidecar

import "github.com/go-appsec/toolbox/sidecar/wire"

// Registration declares the adapter's identity and capabilities for the
// register handshake. ProtocolVersion defaults to the SDK's compiled contract
// version when left zero.
type Registration struct {
	Name            string
	Version         string
	Protocols       []string
	Capabilities    wire.Capabilities
	MCPTools        []wire.MCPTool
	InstanceID      string
	Resume          bool
	ProtocolVersion wire.ProtocolVersion
}

func (r Registration) toParams() wire.RegisterParams {
	pv := r.ProtocolVersion
	if pv.Major == 0 && pv.Minor == 0 {
		pv = wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor}
	}
	return wire.RegisterParams{
		Name:            r.Name,
		Version:         r.Version,
		ProtocolVersion: pv,
		Protocols:       r.Protocols,
		Capabilities:    r.Capabilities,
		MCPTools:        r.MCPTools,
		InstanceID:      r.InstanceID,
		Resume:          r.Resume,
	}
}

// Handler is the sidecar's inbound callback surface.
type Handler interface {
	// OnShutdown is invoked when sectool requests a graceful close. The SDK
	// acknowledges automatically after this returns, so the sidecar should
	// finish in-flight work here before returning.
	OnShutdown(drainSeconds int)
}

// ShutdownFunc adapts a function to Handler.
type ShutdownFunc func(drainSeconds int)

func (f ShutdownFunc) OnShutdown(d int) {
	if f != nil {
		f(d)
	}
}

type nopHandler struct{}

func (nopHandler) OnShutdown(int) {}
