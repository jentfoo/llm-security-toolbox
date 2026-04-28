package orchestrator

import (
	"context"
	"sync/atomic"
)

// Shutdown phase constants.
const (
	ShutdownPhaseRunning         int32 = 0
	ShutdownPhaseVerifyOnly      int32 = 1
	ShutdownPhaseDumpUnvalidated int32 = 2
	ShutdownPhaseKill            int32 = 3
)

// Shutdown coordinates a graceful, multi-stage termination of a Run.
//
// Stage 1 (verify-only): non-validation goroutines (workers + directors)
// are cancelled via WorkersCtx; the controller exits its iteration loop and
// runs the verifier once on every still-pending candidate.
//
// Stage 2 (dump unvalidated): the verifier is cancelled via VerifierCtx;
// the controller writes every still-pending candidate to disk under an
// UNVALIDATED banner.
//
// Stage 3 (kill): the signal handler is responsible for terminating the
// process; this type only records the request so peers can short-circuit.
type Shutdown struct {
	phase atomic.Int32

	// WorkersCtx is the context handed to workers, decision/synthesis
	// directors, and any other "non-validation" work. Cancelled at stage 1.
	WorkersCtx    context.Context
	workersCancel context.CancelFunc

	// VerifierCtx is the context handed to the verifier loop. Cancelled at
	// stage 2 so a verifier mid-Drain bails out before continuing.
	VerifierCtx    context.Context
	verifierCancel context.CancelFunc

	// RootCtx is the parent context — used for teardown work that should
	// outlive both the worker- and verifier-level cancellations (sectool
	// subprocess termination, log close, etc.).
	RootCtx context.Context

	log *Logger
}

// NewShutdown derives Workers and Verifier child contexts from parent and
// returns a Shutdown in the running state.
func NewShutdown(parent context.Context, log *Logger) *Shutdown {
	wctx, wcancel := context.WithCancel(parent)
	vctx, vcancel := context.WithCancel(parent)
	return &Shutdown{
		WorkersCtx:     wctx,
		workersCancel:  wcancel,
		VerifierCtx:    vctx,
		verifierCancel: vcancel,
		RootCtx:        parent,
		log:            log,
	}
}

// Phase returns the current shutdown phase.
func (s *Shutdown) Phase() int32 {
	if s == nil {
		return ShutdownPhaseRunning
	}
	return s.phase.Load()
}

// RequestVerifyOnly transitions to phase 1 and cancels WorkersCtx. Idempotent.
// Calling this when already in phase 2 or 3 is a no-op (those are stricter).
func (s *Shutdown) RequestVerifyOnly() {
	if s == nil {
		return
	}
	if s.phase.CompareAndSwap(ShutdownPhaseRunning, ShutdownPhaseVerifyOnly) {
		s.workersCancel()
		if s.log != nil {
			s.log.Log("shutdown", "verify-only requested", map[string]any{"phase": ShutdownPhaseVerifyOnly})
		}
	}
}

// RequestDumpUnvalidated transitions to phase 2 and cancels VerifierCtx.
// Also cancels WorkersCtx if we somehow skipped phase 1. Idempotent.
func (s *Shutdown) RequestDumpUnvalidated() {
	if s == nil {
		return
	}
	for {
		cur := s.phase.Load()
		if cur >= ShutdownPhaseDumpUnvalidated {
			return
		}
		if s.phase.CompareAndSwap(cur, ShutdownPhaseDumpUnvalidated) {
			s.workersCancel()
			s.verifierCancel()
			if s.log != nil {
				s.log.Log("shutdown", "dump-unvalidated requested", map[string]any{"phase": ShutdownPhaseDumpUnvalidated})
			}
			return
		}
	}
}

// DumpUnvalidatedCandidates writes every pending candidate to disk under the
// UNVALIDATED banner via writer.WriteUnvalidated. Returns the number of
// successfully written files. Errors are logged and skipped so a single
// failed write doesn't drop the rest.
func DumpUnvalidatedCandidates(pending []FindingCandidate, writer *FindingWriter, log *Logger) int {
	written := 0
	for _, c := range pending {
		path, err := writer.WriteUnvalidated(c)
		if err != nil {
			if log != nil {
				log.Log("unvalidated", "write failed", map[string]any{
					"candidate_id": c.CandidateID, "title": c.Title, "err": err.Error(),
				})
			}
			continue
		}
		written++
		if log != nil {
			log.Log("unvalidated", "written", map[string]any{
				"candidate_id": c.CandidateID, "path": path, "title": c.Title,
			})
		}
	}
	if log != nil {
		log.Log("shutdown", "dumped unvalidated", map[string]any{
			"written": written, "pending": len(pending),
		})
	}
	return written
}

// RequestKill transitions to phase 3. The caller is responsible for
// terminating the process; this method only updates state and cancels
// any still-live child contexts so peers unblock.
func (s *Shutdown) RequestKill() {
	if s == nil {
		return
	}
	for {
		cur := s.phase.Load()
		if cur >= ShutdownPhaseKill {
			return
		}
		if s.phase.CompareAndSwap(cur, ShutdownPhaseKill) {
			s.workersCancel()
			s.verifierCancel()
			if s.log != nil {
				s.log.Log("shutdown", "kill requested", map[string]any{"phase": ShutdownPhaseKill})
			}
			return
		}
	}
}
