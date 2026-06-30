package sidecar

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// handleRegister validates and stores a registration, returning the new record
// and the result, or an error.
func (m *Manager) handleRegister(peer *wire.Peer, fingerprint string, p *wire.RegisterParams) (*Record, *wire.RegisterResult, *wire.Error) {
	if p.Name == "" {
		return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: name is required")
	}
	if p.ProtocolVersion.Major != wire.VersionMajor {
		return nil, nil, wire.NewError(wire.CodeMajorVersionMismatch,
			fmt.Sprintf("contract major mismatch: sectool %d, sidecar %d", wire.VersionMajor, p.ProtocolVersion.Major)).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	effMinor := min(wire.VersionMinor, p.ProtocolVersion.Minor)
	if effMinor < 0 {
		effMinor = 0
	}
	if p.InstanceID != "" {
		if _, err := uuid.Parse(p.InstanceID); err != nil {
			return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: instance_id must be a valid UUID").
				WithData(&wire.ErrorData{Adapter: p.Name})
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var carried *resumeEntry
	if p.InstanceID != "" {
		if st, ok := m.resumeState[p.InstanceID]; ok {
			if p.Resume {
				carried = st
			}
			delete(m.resumeState, p.InstanceID)
		}
	}

	// Handle an existing record for this name: a recognized reconnect or a stale
	// (closed) record is replaced; a live record with a different instance is a
	// duplicate-name conflict.
	if existing, ok := m.records[p.Name]; ok {
		reconnect := p.InstanceID != "" && existing.InstanceID == p.InstanceID
		switch {
		case reconnect:
			if p.Resume && carried == nil {
				carried = &resumeEntry{ownedFlows: existing.ownedFlows, inFlight: existing.inFlight}
			}
			m.removeLocked(existing)
		case !existing.alive():
			m.removeLocked(existing)
		default:
			return nil, nil, wire.NewError(wire.CodeDuplicateRegistration,
				"adapter name already registered: "+p.Name).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: existing.Name})
		}
	}

	if rpcErr := m.checkConflicts(p); rpcErr != nil {
		return nil, nil, rpcErr
	}

	now := m.now()
	rec := &Record{
		Name:          p.Name,
		Version:       p.Version,
		ProtoVersion:  wire.ProtocolVersion{Major: wire.VersionMajor, Minor: effMinor},
		Protocols:     p.Protocols,
		Capabilities:  p.Capabilities,
		MCPTools:      p.MCPTools,
		InstanceID:    p.InstanceID,
		AssignedSeams: assignedSeams(p.Capabilities),
		peer:          peer,
		resume:        p.Resume,
		liveness:      Liveness{LastActivity: now, LastPongRecv: now, SocketFingerprint: fingerprint},
	}
	rec.healthy.Store(true)
	rec.bridge = newBridge(rec, m.flows)
	if carried != nil {
		rec.ownedFlows, rec.inFlight = carried.ownedFlows, carried.inFlight
	} else {
		rec.ownedFlows, rec.inFlight = map[string]struct{}{}, map[string]struct{}{}
	}

	m.records[p.Name] = rec
	if p.InstanceID != "" {
		m.byInstance[p.InstanceID] = rec
	}
	if rec.Capabilities.EarlyClaim != nil {
		m.registry.InsertEarly(rec.bridge)
	}
	if rec.Capabilities.UpgradeClaim != nil {
		m.reorderUpgradeClaims()
	}

	return rec, &wire.RegisterResult{
		ProtocolVersion: rec.ProtoVersion,
		AssignedSeams:   rec.AssignedSeams,
		RulesSnapshot:   []json.RawMessage{},
		ServerTime:      now.Format(time.RFC3339Nano),
	}, nil
}

// reorderUpgradeClaims re-inserts every upgrade-claiming sidecar bridge so the
// most-specific matchers are evaluated first (ahead of the built-in adapters).
// Callers hold mu.
func (m *Manager) reorderUpgradeClaims() {
	recs := make([]*Record, 0, len(m.records))
	for _, r := range m.records {
		if r.Capabilities.UpgradeClaim != nil {
			recs = append(recs, r)
		}
	}
	slices.SortStableFunc(recs, func(a, b *Record) int {
		switch {
		case dominates(a.Capabilities.UpgradeClaim, b.Capabilities.UpgradeClaim):
			return -1
		case dominates(b.Capabilities.UpgradeClaim, a.Capabilities.UpgradeClaim):
			return 1
		default:
			return 0
		}
	})
	for _, r := range recs {
		m.registry.RemoveUpgrade(r.Name)
	}
	// InsertUpgrade prepends, so inserting least-specific first leaves the
	// most-specific at the front.
	for i := len(recs) - 1; i >= 0; i-- {
		m.registry.InsertUpgrade(recs[i].bridge)
	}
}

// assignedSeams lists the capability claims that were accepted.
func assignedSeams(c wire.Capabilities) []string {
	seams := []string{}
	if c.EarlyClaim != nil {
		seams = append(seams, "early_claim")
	}
	if c.UpgradeClaim != nil {
		seams = append(seams, "upgrade_claim")
	}
	if c.InjectionTarget != nil {
		seams = append(seams, "injection_target")
	}
	return seams
}
