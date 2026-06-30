package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// ErrMajorVersionMismatch is returned by Dial when sectool rejects the
// registration because the contract major versions differ.
var ErrMajorVersionMismatch = errors.New("sidecar: protocol major version mismatch")

// registerTimeout bounds the registration handshake.
const registerTimeout = 10 * time.Second

// Conn is a registered connection to sectool.
type Conn struct {
	peer       *wire.Peer
	name       string
	negotiated wire.ProtocolVersion
	seams      []string
	rules      *RuleCache

	mu      sync.Mutex
	handler Handler
}

// Dial connects to sectool at addr, performs the register handshake, and returns
// the established connection. The network is inferred from addr (a host:port is
// loopback TCP; otherwise the per-OS default, a Unix domain socket on unix).
func Dial(addr string, reg Registration) (*Conn, error) {
	network := networkFor(addr)
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("sidecar: dial %s %s: %w", network, addr, err)
	}

	c := &Conn{handler: nopHandler{}, name: reg.Name, rules: newRuleCache(reg.Name)}
	c.peer = wire.NewPeer(raw, connHandler{c})
	go func() { _ = c.peer.Run(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	var result wire.RegisterResult
	if rpcErr := c.peer.Call(ctx, wire.MethodRegister, reg.toParams(), &result); rpcErr != nil {
		_ = c.peer.Close()
		if rpcErr.Code == wire.CodeMajorVersionMismatch {
			return nil, fmt.Errorf("%w: %s", ErrMajorVersionMismatch, rpcErr.Message)
		}
		return nil, fmt.Errorf("sidecar: register: %w", rpcErr)
	}

	c.negotiated = result.ProtocolVersion
	c.seams = result.AssignedSeams
	// Seed the hot-path rule cache from the registration snapshot.
	_ = c.rules.replace(0, result.RulesSnapshot)
	return c, nil
}

// Serve installs the inbound handler and blocks until ctx is cancelled or the
// connection closes (e.g. after sectool's shutdown). Returns ctx.Err() on
// cancellation, nil on a clean remote close.
func (c *Conn) Serve(ctx context.Context, h Handler) error {
	if h == nil {
		h = nopHandler{}
	}
	c.mu.Lock()
	c.handler = h
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		_ = c.peer.Close()
		return ctx.Err()
	case <-c.peer.Done():
		return nil
	}
}

// AdapterName returns the adapter name this connection registered under.
func (c *Conn) AdapterName() string { return c.name }

// Rules returns the hot-path rule cache, kept current by sectool's sync_rules pushes.
func (c *Conn) Rules() *RuleCache { return c.rules }

// Negotiated returns the effective contract version agreed at registration.
func (c *Conn) Negotiated() wire.ProtocolVersion { return c.negotiated }

// Seams returns the capability claims sectool accepted at registration.
func (c *Conn) Seams() []string { return c.seams }

// Peer exposes the underlying JSON-RPC peer for advanced use (e.g. originating
// notifications). Most adapters only need Serve.
func (c *Conn) Peer() *wire.Peer { return c.peer }

// Close terminates the connection.
func (c *Conn) Close() error { return c.peer.Close() }

func (c *Conn) currentHandler() Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handler
}

// connHandler routes inbound traffic: ping is auto-answered with pong; shutdown
// drains via the user handler then acks.
type connHandler struct{ c *Conn }

func (h connHandler) HandleRequest(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
	switch method {
	case wire.MethodShutdown:
		var p wire.ShutdownParams
		_ = json.Unmarshal(params, &p)
		h.c.currentHandler().OnShutdown(p.DrainSeconds)
		return wire.ShutdownResult{Ack: true}, nil
	case wire.MethodStreamOpen:
		return streamReply(h, params, func(sh StreamHandler, p wire.StreamOpenParams) ([]wire.StreamWrite, error) {
			return sh.OnStreamOpen(p)
		})
	case wire.MethodStreamDeliver:
		return streamReply(h, params, func(sh StreamHandler, p wire.StreamDeliverParams) ([]wire.StreamWrite, error) {
			return sh.OnStreamDeliver(p)
		})
	case wire.MethodClaimProbe:
		prober, ok := h.c.currentHandler().(ClaimProber)
		if !ok {
			return nil, wire.NewError(wire.CodeClaimProbeFault, "claim_probe: no prober")
		}
		var p wire.ClaimProbeParams
		_ = json.Unmarshal(params, &p)
		claim, err := prober.OnClaimProbe(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeClaimProbeFault, "claim_probe: "+err.Error())
		}
		return wire.ClaimProbeResult{Claim: claim}, nil
	case wire.MethodSyncRules:
		var p wire.SyncRulesParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeRuleRejected, "sync_rules: invalid params")
		}
		if err := h.c.rules.replace(p.SnapshotVersion, p.Rules); err != nil {
			return nil, wire.NewError(wire.CodeRuleRejected, "sync_rules: "+err.Error())
		}
		return wire.SyncRulesResult{Ack: true, AppliedVersion: p.SnapshotVersion}, nil
	case wire.MethodSidecarSend:
		sh, ok := h.c.currentHandler().(SendHandler)
		if !ok {
			return nil, wire.NewError(wire.CodeTransportInternal, "sidecar_send: no send handler")
		}
		var p wire.SidecarSendParams
		_ = json.Unmarshal(params, &p)
		res, err := sh.OnSidecarSend(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, "sidecar_send: "+err.Error())
		}
		return res, nil
	case wire.MethodPing:
		return struct{}{}, nil
	default:
		return nil, wire.NewError(-32601, "method not found: "+method)
	}
}

// streamReply dispatches a stream Request to the StreamHandler and wraps its
// writes in a StreamResult. A handler that does not implement StreamHandler
// (despite an early_claim) is a transport error.
func streamReply[P any](h connHandler, params json.RawMessage, call func(StreamHandler, P) ([]wire.StreamWrite, error)) (any, *wire.Error) {
	sh, ok := h.c.currentHandler().(StreamHandler)
	if !ok {
		return nil, wire.NewError(wire.CodeTransportInternal, "stream event: no stream handler")
	}
	var p P
	_ = json.Unmarshal(params, &p)
	writes, err := call(sh, p)
	if err != nil {
		return nil, wire.NewError(wire.CodeTransportInternal, err.Error())
	}
	return wire.StreamResult{Writes: writes}, nil
}

func (h connHandler) HandleNotification(_ context.Context, method string, params json.RawMessage) {
	switch method {
	case wire.MethodPing:
		_ = h.c.peer.Notify(wire.MethodPong, nil)
	case wire.MethodStreamEnded:
		if sh, ok := h.c.currentHandler().(StreamHandler); ok {
			var p wire.StreamEndedParams
			_ = json.Unmarshal(params, &p)
			sh.OnStreamEnded(p)
		}
	}
}
