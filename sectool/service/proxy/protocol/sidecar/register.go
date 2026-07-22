package sidecar

import (
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/google/uuid"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// handleRegister validates and stores a registration, returning the new record
// and the result, or an error.
func (m *Manager) handleRegister(peer *wire.Peer, p *wire.RegisterParams) (*Record, *wire.RegisterResult, *wire.Error) {
	if p.Name == "" {
		return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: name is required")
	}
	if p.ProtocolVersion.Major != wire.VersionMajor {
		return nil, nil, wire.NewError(wire.CodeVersionUnsupported,
			fmt.Sprintf("contract major mismatch: sectool %d, sidecar %d", wire.VersionMajor, p.ProtocolVersion.Major)).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	if p.ProtocolVersion.Minor > wire.VersionMinor {
		return nil, nil, wire.NewError(wire.CodeVersionUnsupported,
			fmt.Sprintf("contract minor too new: sectool %d.%d, sidecar %d.%d",
				wire.VersionMajor, wire.VersionMinor, p.ProtocolVersion.Major, p.ProtocolVersion.Minor)).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	effMinor := p.ProtocolVersion.Minor // Older-or-equal minor is supported
	if effMinor < 0 {
		effMinor = 0
	}
	if p.InstanceID != "" {
		if _, err := uuid.Parse(p.InstanceID); err != nil {
			return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: instance_id must be a valid UUID").
				WithData(&wire.ErrorData{Adapter: p.Name})
		}
	}
	early, err := compileEarlyClaims(p.Capabilities.EarlyClaims)
	if err != nil {
		return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: "+err.Error()).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	upgrade, err := compileUpgradeClaims(p.Capabilities.UpgradeClaims)
	if err != nil {
		return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: "+err.Error()).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// classify a name collision before mutating anything
	existing, hasExisting := m.records[p.Name]
	var reconnect bool
	if hasExisting {
		reconnect = p.InstanceID != "" && existing.InstanceID == p.InstanceID
		switch {
		case reconnect && existing.peer == peer:
			// second register on this connection would close our own peer
			return nil, nil, wire.NewError(wire.CodeDuplicateRegistration,
				"adapter already registered on this connection: "+p.Name).
				WithData(&wire.ErrorData{Adapter: p.Name})
		case reconnect, !existing.alive():
			// replaceable: validated below, removed only on success
		default:
			return nil, nil, wire.NewError(wire.CodeDuplicateRegistration,
				"adapter name already registered: "+p.Name).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: existing.Name})
		}
	}

	// validate before any destructive mutation, excluding the record being replaced
	if rpcErr := m.checkConflicts(p, early, upgrade); rpcErr != nil {
		return nil, nil, rpcErr
	}

	// commit: consume resume state and replace the old record only now
	var carried *resumeEntry
	if p.InstanceID != "" {
		if st, ok := m.resumeState[p.InstanceID]; ok {
			if p.Resume {
				carried = st
			}
			delete(m.resumeState, p.InstanceID) // discard stale stash even on a fresh reconnect
		}
	}
	if hasExisting {
		if reconnect && p.Resume && carried == nil {
			owned, inFlight := existing.snapshotOwnership()
			carried = &resumeEntry{ownedFlows: owned, inFlight: inFlight}
		}
		m.removeLocked(existing)
	}

	now := m.now()
	rec := &Record{
		Name:         p.Name,
		ProtoVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: effMinor},
		Protocols:    p.Protocols,
		Capabilities: p.Capabilities,
		MCPTools:     p.MCPTools,
		InstanceID:   p.InstanceID,
		early:        early,
		upgrade:      upgrade,
		peer:         peer,
		resume:       p.Resume,
		liveness:     Liveness{LastPongRecv: now},
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

	instanceTag := p.InstanceID
	if instanceTag == "" {
		instanceTag = "-"
	}
	log.Printf("sidecar[%s]: registered instance_id=%s", p.Name, instanceTag)

	return rec, &wire.RegisterResult{
		ProtocolVersion: rec.ProtoVersion,
		ServerTime:      now.Format(time.RFC3339Nano),
	}, nil
}

// activateClaims opens the claim seam for a freshly registered record. Call once
// the record is seeded, so no stream is routed to a sidecar without its rules.
func (m *Manager) activateClaims(rec *Record) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.records[rec.Name] != rec {
		return // replaced or disconnected while seeding
	}
	if len(rec.early) > 0 {
		m.registry.InsertEarly(rec.bridge)
	}
	if len(rec.upgrade) > 0 {
		m.reorderUpgradeClaims()
	}
}

// reorderUpgradeClaims re-inserts every upgrade-claiming sidecar bridge so the
// most-specific matchers are evaluated first (ahead of the built-in adapters). A
// record with several upgrade claims is ranked by its most-specific one. Callers
// hold mu.
func (m *Manager) reorderUpgradeClaims() {
	recs := bulk.SliceFilter(func(r *Record) bool { return len(r.upgrade) > 0 }, bulk.MapValuesSlice(m.records))
	slices.SortStableFunc(recs, func(a, b *Record) int {
		ac, bc := mostSpecificUpgrade(a.upgrade), mostSpecificUpgrade(b.upgrade)
		switch {
		case dominates(ac, bc):
			return -1
		case dominates(bc, ac):
			return 1
		default:
			return 0
		}
	})
	for _, r := range recs {
		m.registry.RemoveUpgrade(r.Name)
	}
	// InsertUpgrade prepends: insert least-specific first to leave most-specific at front
	for i := len(recs) - 1; i >= 0; i-- {
		m.registry.InsertUpgrade(recs[i].bridge)
	}
}
