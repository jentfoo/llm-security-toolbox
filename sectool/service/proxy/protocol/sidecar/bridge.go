package sidecar

import (
	"context"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
)

// bridge fronts a registered sidecar as an in-process adapter, routing matching
// proxy connections to the sidecar through its claim seams.
type bridge struct {
	rec *Record
}

func newBridge(rec *Record) *bridge { return &bridge{rec: rec} }

func (b *bridge) Name() string { return b.rec.Name }

func (b *bridge) ClaimEarly(*protocol.EarlyClaimCtx) bool { return false }

func (b *bridge) ServeEarly(context.Context, *protocol.EarlyClaimCtx) {}

func (b *bridge) ClaimUpgrade(*protocol.UpgradeClaimCtx) bool { return false }

func (b *bridge) ServeUpgrade(context.Context, *protocol.UpgradeClaimCtx, protocol.UpgradeConns) {}

// Adapter is the proxy claim surface a sidecar bridge fulfills: the early and
// upgrade seams. The manager inserts a registered sidecar's Adapter into the
// proxy claim registry to route matching connections to the sidecar.
type Adapter interface {
	protocol.EarlyAdapter
	protocol.UpgradeAdapter
}

var _ Adapter = (*bridge)(nil)
