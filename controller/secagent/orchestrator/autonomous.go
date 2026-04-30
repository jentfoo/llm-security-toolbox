package orchestrator

import (
	"context"
	"strconv"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/go-appsec/secagent/agent"
)

// StatusSummaryInterval is the turn count between periodic status summaries
// per agent. 0 disables.
var StatusSummaryInterval int = 0

// emitStatusIfDue logs a one-line status summary when turn is a non-zero
// multiple of StatusSummaryInterval and a is an *agent.OpenAIAgent.
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

// drainOne runs one agent Drain, classifies the turn against candidates,
// appends it to w.AutonomousTurns, and returns the summary.
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

// updateToolErrorSignatures appends each error tool call's signature to
// w.RecentToolErrors and clears w.CoachedErrorSig if any call succeeded.
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

// intraPhaseContinuePrompt is queued between worker turns within a single
// autonomous phase to nudge the model to its next turn.
const intraPhaseContinuePrompt = "Continue your current testing plan. Take the next concrete step."

// RunWorkerUntilEscalation drains up to w.AutonomousBudget turns (capped
// at 20) or until the worker escalates, returning the turn summaries.
// w.EscalationReason is set on return. The caller must install the
// worker's per-iteration history before invoking.
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

// runOneWorker drains one alive worker for one iteration with one
// recovery attempt on mid-iter error, returning the turn summaries.
// w.EscalationReason and w.AutonomousTurns are reset before draining.
func runOneWorker(
	ctx context.Context,
	w *WorkerState,
	candidates *CandidatePool,
	log *Logger,
) []agent.TurnSummary {
	w.EscalationReason = ""
	w.AutonomousTurns = nil
	runs, err := RunWorkerUntilEscalation(ctx, w, candidates, log)
	if err != nil && w.LastInstruction != "" {
		if log != nil {
			log.Log("worker", "recover", map[string]any{
				"worker_id": w.ID, "attempt": 1, "err": err.Error(),
			})
		}
		w.Agent.Interrupt()
		w.Agent.Query(w.LastInstruction)
		summary, err2 := drainOne(ctx, w, candidates, log)
		if err2 != nil {
			w.EscalationReason = EscalationError
		} else {
			runs = append(runs, summary)
			if summary.EscalationReason != "" {
				w.EscalationReason = summary.EscalationReason
			}
		}
	}
	return runs
}

// RunAllWorkersUntilEscalation runs every alive worker concurrently and
// returns each one's turn summaries keyed by worker ID.
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
		eg.Go(func() error {
			runs := runOneWorker(ectx, w, candidates, log)
			mu.Lock()
			results[w.ID] = runs
			mu.Unlock()
			return nil
		})
	}
	_ = eg.Wait()
	return results
}
