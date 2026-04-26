package orchestrator

import (
	"context"
	"strconv"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/go-appsec/secagent/agent"
)

// StatusSummaryInterval controls how often the orchestrator should ask
// each agent for a one-sentence summary of its current focus. 0 disables.
// This is a package-level variable so tests can tweak it; production reads
// from config.ProgressLogInterval and sets it before Run.
var StatusSummaryInterval int = 0

// emitStatusIfDue asks the agent for a one-line status summary when the
// agent is an OpenAIAgent and its turn count mod interval == 0.
func emitStatusIfDue(ctx context.Context, a agent.Agent, tag string, turn int, log *Logger) {
	if StatusSummaryInterval <= 0 || turn == 0 || turn%StatusSummaryInterval != 0 {
		return
	}
	oa, ok := a.(*agent.OpenAIAgent)
	if !ok {
		return
	}
	line, err := agent.SummarizeStatus(ctx, oa, 80)
	if err != nil {
		if log != nil {
			log.Log(tag, "status-failed", map[string]any{"err": err.Error()})
		}
		return
	}
	if line != "" && log != nil {
		log.Log(tag, "status", map[string]any{"line": line})
	}
}

// drainOne runs a single agent Drain, classifies the resulting turn against
// the candidate pool, records it on the worker, logs it, and emits the
// periodic status summary if due. Shared by the normal loop and the
// post-retry recovery path (spec §7.7).
func drainOne(
	ctx context.Context,
	w *WorkerState,
	candidates *CandidatePool,
	log *Logger,
) (agent.TurnSummary, error) {
	before := candidates.Counter()
	summary, err := w.Agent.Drain(ctx)
	if err != nil {
		if log != nil {
			log.Log("worker", "drain error", map[string]any{
				"worker_id": w.ID, "err": err.Error(),
			})
		}
		return summary, err
	}
	if newIDs := candidates.IDsSinceForWorker(before, w.ID); len(newIDs) > 0 {
		summary.EscalationReason = "candidate"
	} else {
		summary.EscalationReason = agent.ClassifyEscalation(summary, false)
	}
	w.AutonomousTurns = append(w.AutonomousTurns, summary)
	updateToolErrorSignatures(w, summary)
	if log != nil {
		log.Log("worker", "turn", map[string]any{
			"worker_id":        w.ID,
			"turn":             len(w.AutonomousTurns),
			"escalation":       summary.EscalationReason,
			"tokens_in":        summary.TokensIn,
			"tokens_out":       summary.TokensOut,
			"tool_calls":       len(summary.ToolCalls),
			"flow_ids_touched": len(summary.FlowIDs),
		})
	}
	emitStatusIfDue(ctx, w.Agent, "worker."+strconv.Itoa(w.ID), len(w.AutonomousTurns), log)
	return summary, nil
}

// updateToolErrorSignatures records each error-producing tool call from a
// turn as a rolling signature on WorkerState. A single successful tool call
// in the same turn clears CoachedErrorSig so the next distinct failure can
// be coached again.
func updateToolErrorSignatures(w *WorkerState, summary agent.TurnSummary) {
	sawSuccess := false
	for _, tc := range summary.ToolCalls {
		if !tc.IsError {
			sawSuccess = true
			continue
		}
		sig := tc.ResultSummary
		if len(sig) > ErrorSignatureMaxLen {
			sig = sig[:ErrorSignatureMaxLen]
		}
		if sig == "" {
			continue
		}
		w.RecentToolErrors = append(w.RecentToolErrors, sig)
		if len(w.RecentToolErrors) > MaxRecentToolErrors {
			w.RecentToolErrors = w.RecentToolErrors[len(w.RecentToolErrors)-MaxRecentToolErrors:]
		}
	}
	if sawSuccess {
		w.CoachedErrorSig = ""
	}
}

// intraPhaseContinuePrompt is the bare resumption directive injected
// between worker turns within a single autonomous phase. The cross-iteration
// directive lives in the worker's freshly composed history at phase entry,
// so this only needs to nudge the model into producing the next turn — the
// full task context is already established.
const intraPhaseContinuePrompt = "Continue your current testing plan. Take the next concrete step."

// RunWorkerUntilEscalation drains up to w.AutonomousBudget turns or until
// the worker escalates. Each escalation reason is set on the worker.
// Note: first-turn Query is NOT injected here; the caller is responsible
// for installing the worker's per-iteration composed history (which itself
// ends with the directive) before invoking.
func RunWorkerUntilEscalation(
	ctx context.Context,
	w *WorkerState,
	candidates *CandidatePool,
	log *Logger,
) ([]agent.TurnSummary, error) {
	budget := min(max(w.AutonomousBudget, 1), 20)

	var runs []agent.TurnSummary
	for attempt := 0; attempt < budget; attempt++ {
		if attempt > 0 {
			w.Agent.Query(intraPhaseContinuePrompt)
		}
		summary, err := drainOne(ctx, w, candidates, log)
		if err != nil {
			w.EscalationReason = EscalationError
			return runs, err
		}
		runs = append(runs, summary)
		if summary.EscalationReason != "" {
			w.EscalationReason = summary.EscalationReason
			return runs, nil
		}
	}
	w.EscalationReason = EscalationBudget
	return runs, nil
}

// RunAllWorkersUntilEscalation runs every alive worker concurrently.
// On mid-iteration drain error (after the agent's own retry budget) the
// controller makes exactly one further recovery attempt: interrupt the
// agent, re-queue LastInstruction, and run a single Drain before marking
// the worker's iteration result errored (spec §7.7).
func RunAllWorkersUntilEscalation(
	ctx context.Context,
	workers []*WorkerState,
	candidates *CandidatePool,
	log *Logger,
) map[int][]agent.TurnSummary {
	results := map[int][]agent.TurnSummary{}
	var mu sync.Mutex
	eg, ectx := errgroup.WithContext(ctx)
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		w.EscalationReason = ""
		w.AutonomousTurns = nil
		eg.Go(func() error {
			runs, err := RunWorkerUntilEscalation(ectx, w, candidates, log)
			if err != nil && w.LastInstruction != "" {
				if log != nil {
					log.Log("worker", "recover", map[string]any{
						"worker_id": w.ID, "attempt": 1, "err": err.Error(),
					})
				}
				w.Agent.Interrupt()
				w.Agent.Query(w.LastInstruction)
				summary, err2 := drainOne(ectx, w, candidates, log)
				if err2 != nil {
					w.EscalationReason = EscalationError
				} else {
					runs = append(runs, summary)
					if summary.EscalationReason != "" {
						w.EscalationReason = summary.EscalationReason
					}
				}
			}
			mu.Lock()
			results[w.ID] = runs
			mu.Unlock()
			return nil
		})
	}
	_ = eg.Wait()
	return results
}
