package sidecar

import (
	"fmt"
	"slices"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// checkConflicts validates a registration and its compiled claims against reserved
// names and already registered sidecars. Callers hold m.mu.
func (m *Manager) checkConflicts(p *wire.RegisterParams, early []earlyClaim, upgrade []upgradeClaim) *wire.Error {
	if slices.Contains(m.cfg.ReservedNames, p.Name) {
		return wire.NewError(wire.CodeDuplicateRegistration,
			"adapter name conflicts with a built-in adapter: "+p.Name).
			WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: p.Name})
	} else if err := m.checkEarlyClaims(p.Name, early); err != nil {
		return err
	} else if err := m.checkUpgradeClaims(p.Name, upgrade); err != nil {
		return err
	}
	return m.checkToolNames(p)
}

// checkToolNames rejects a registration whose mcp_tools names duplicate one
// another, collide with a core tool, or collide with another sidecar's tool. Also
// rejects while the core tool set is unavailable, since nothing can be checked
// against it. Callers hold m.mu.
func (m *Manager) checkToolNames(p *wire.RegisterParams) *wire.Error {
	if len(p.MCPTools) == 0 {
		return nil
	}
	coreNames := m.coreInvoke.CoreToolNames()
	if len(coreNames) == 0 {
		return wire.NewError(wire.CodeRegistrationRejected,
			"mcp_tools cannot be registered until the core tools are available").
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	owner := map[string]string{} // tool name -> owning adapter
	for _, n := range coreNames {
		owner[n] = types.AdapterScopeCore
	}
	for _, r := range m.records {
		for _, t := range r.MCPTools {
			owner[t.Name] = r.Name
		}
	}
	seen := map[string]struct{}{}
	for _, t := range p.MCPTools {
		if _, dup := seen[t.Name]; dup {
			return wire.NewError(wire.CodeToolNameConflict,
				"duplicate mcp_tool name in registration: "+t.Name).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: p.Name})
		}
		seen[t.Name] = struct{}{}
		if other, taken := owner[t.Name]; taken {
			return wire.NewError(wire.CodeToolNameConflict,
				fmt.Sprintf("mcp_tool name %q already provided by adapter %q", t.Name, other)).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: other})
		}
	}
	return nil
}

// checkEarlyClaims validates a registration's early claims against the native
// proxy port, each other (intra-registration self-overlap), and every already
// registered adapter's early claims. Callers hold m.mu.
func (m *Manager) checkEarlyClaims(name string, claims []earlyClaim) *wire.Error {
	for i := range claims {
		ec := &claims[i]
		if ec.blanketOnPort(m.cfg.NativeProxyPort) {
			return wire.NewError(wire.CodeCapabilityConflict,
				fmt.Sprintf("early_claim port range %d-%d covers the native proxy port %d with no distinguishing matcher",
					ec.ports.Low, ec.ports.High, m.cfg.NativeProxyPort)).
				WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: "native-proxy"})
		}
		// intra-registration: this claim must be distinct from its siblings
		for j := i + 1; j < len(claims); j++ {
			if earlyClaimConflict(ec, &claims[j]) {
				return wire.NewError(wire.CodeCapabilityConflict,
					fmt.Sprintf("early_claim port range %d-%d overlaps another claim in the same registration with no distinguishing matcher",
						ec.ports.Low, ec.ports.High)).
					WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: name})
			}
		}
		for _, r := range m.records {
			for k := range r.early {
				if earlyClaimConflict(ec, &r.early[k]) {
					return wire.NewError(wire.CodeCapabilityConflict,
						fmt.Sprintf("early_claim port range %d-%d overlaps adapter %q with no distinguishing matcher",
							ec.ports.Low, ec.ports.High, r.Name)).
						WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: r.Name})
				}
			}
		}
	}
	return nil
}

// checkUpgradeClaims validates a registration's upgrade claims against each other
// (intra-registration self-overlap) and every already registered adapter's
// upgrade claims. Callers hold m.mu.
func (m *Manager) checkUpgradeClaims(name string, claims []upgradeClaim) *wire.Error {
	for i := range claims {
		uc := &claims[i]
		for j := i + 1; j < len(claims); j++ {
			if upgradeClaimConflict(uc, &claims[j]) {
				return wire.NewError(wire.CodeCapabilityConflict,
					fmt.Sprintf("upgrade_claim (%s %s) overlaps another claim in the same registration with incomparable specificity",
						uc.host.src, uc.path.src)).
					WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: name})
			}
		}
		for _, r := range m.records {
			for k := range r.upgrade {
				if upgradeClaimConflict(uc, &r.upgrade[k]) {
					return wire.NewError(wire.CodeCapabilityConflict,
						fmt.Sprintf("upgrade_claim (%s %s) overlaps adapter %q with incomparable specificity",
							uc.host.src, uc.path.src, r.Name)).
						WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: r.Name})
				}
			}
		}
	}
	return nil
}
