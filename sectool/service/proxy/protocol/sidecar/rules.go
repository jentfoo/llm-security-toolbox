package sidecar

import (
	"context"
	"sync"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// PushRules sends each connected sidecar its scoped rule snapshot via sync_rules and
// records the acked version. Snapshots are read under mu (lock order mu -> rule store,
// matching handleRegister) so a concurrent rule change can't be lost. It waits for every
// push so the caller's ctx stays valid for the duration and acks are recorded before it returns.
func (m *Manager) PushRules(ctx context.Context) {
	type job struct {
		rec     *Record
		version uint64
		rules   []wire.Rule
	}
	m.mu.Lock()
	jobs := make([]job, 0, len(m.records))
	for _, rec := range m.records {
		version, rules := m.rules.RuleSnapshot(rec.Name)
		jobs = append(jobs, job{rec, version, rules})
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			if !j.rec.alive() {
				return
			}
			var res wire.SyncRulesResult
			if err := j.rec.peer.Call(ctx, wire.MethodSyncRules,
				wire.SyncRulesParams{SnapshotVersion: j.version, Rules: j.rules}, &res); err == nil {
				j.rec.appliedVersion.Store(res.AppliedVersion)
			}
		}(j)
	}
	wg.Wait()
}
