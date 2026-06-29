package protocol

import "context"

// Registry holds the ordered claim seams for the native proxy backend; first
// claim wins. The fallthrough early adapter (ClaimEarly always true) must be last.
type Registry struct {
	Early   []EarlyAdapter
	Upgrade []UpgradeAdapter
}

// DispatchEarly serves the connection with the first early adapter that claims it.
func (r *Registry) DispatchEarly(ctx context.Context, c *EarlyClaimCtx) {
	for _, a := range r.Early {
		if a.ClaimEarly(c) {
			a.ServeEarly(ctx, c)
			return
		}
	}
}

// ClaimUpgrade returns the first upgrade adapter that claims the parsed request.
func (r *Registry) ClaimUpgrade(c *UpgradeClaimCtx) (UpgradeAdapter, bool) {
	for _, a := range r.Upgrade {
		if a.ClaimUpgrade(c) {
			return a, true
		}
	}
	return nil, false
}
