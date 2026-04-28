package orchestrator

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/go-appsec/secagent/agent"
)

// FireWorkerFunc starts one worker's iter+1 autonomous run as a goroutine
// and returns a join function the caller invokes at iter boundary to
// collect the resulting TurnSummaries. Used by RunDecisionPhase to fire
// the next-iter run the moment a decision lands, so workers run
// concurrently with the remaining per-worker decisions.
type FireWorkerFunc func(ctx context.Context, w *WorkerState) (joinFn func() []agent.TurnSummary)

// SpawnChildFunc spawns a forked child worker by id with the steering
// instruction. The parent's chronicle is copied into the child by the
// caller (handled in controller.go); this fn just provisions the
// agent + MCP client.
type SpawnChildFunc func(ctx context.Context, id int, instruction string) (*WorkerState, error)

// DecisionPhaseInput bundles everything RunDecisionPhase needs.
type DecisionPhaseInput struct {
	Director        agent.Agent
	DirChat         *DirectorChat
	Decisions       *DecisionQueue
	Workers         []*WorkerState // current alive set + dead (for completed-roster context)
	WorkerRuns      map[int][]agent.TurnSummary
	IterationStatus string
	Iter            int
	MaxWorkers      int
	TakenIDs        func() map[int]bool
	Fire            FireWorkerFunc
	SpawnChild      SpawnChildFunc
	Retire          func(w *WorkerState, reason string, iter int)
}

// DecisionPhaseResult carries the join handles for fired worker runs.
// Caller must invoke Wait() at iter boundary to collect iter+1
// TurnSummaries (and merge them into the next iter's workerRuns map).
type DecisionPhaseResult struct {
	mu    sync.Mutex
	joins map[int]func() []agent.TurnSummary
}

// Wait blocks on every fired worker run, returns the per-worker iter+1
// turn-summary map. Safe to call once.
func (r *DecisionPhaseResult) Wait() map[int][]agent.TurnSummary {
	if r == nil {
		return nil
	}
	out := map[int][]agent.TurnSummary{}
	r.mu.Lock()
	joins := r.joins
	r.mu.Unlock()
	for id, j := range joins {
		out[id] = j()
	}
	return out
}

// RunDecisionPhase makes one per-worker decision call per alive worker
// (in deterministic ID order). For each worker:
//
//  1. Append the worker's iter activity (assistant turns + tool calls +
//     tool results from this iter's autonomous run) to the canonical
//     director chat, tagged with the worker's id.
//  2. Render a selectively-compacted view of the director chat (current
//     worker raw, other workers compacted, director-owned raw).
//  3. Append a per-worker decision prompt asking for exactly one
//     decide_worker tool call; install on the director agent and drain.
//  4. Append the decision narration to director chat (tagged with the
//     worker's id) so subsequent per-worker prompts see the peer state.
//  5. Apply the decision: continue/expand sets LastInstruction and fires
//     the worker's iter+1 run as a goroutine; stop enqueues async retire;
//     fork (alongside) spawns a child + copies the chronicle + fires the
//     child's first iter run.
//
// The per-worker calls are SEQUENTIAL (so each decision sees the prior
// decisions' effect on the canonical chat — coordination context), but
// the worker iter+1 runs they trigger are CONCURRENT with the remaining
// decision calls. The returned DecisionPhaseResult.Wait() blocks on
// every fired run.
func RunDecisionPhase(
	ctx context.Context,
	in DecisionPhaseInput,
	log *Logger,
) *DecisionPhaseResult {
	in.Decisions.BeginPhase(agent.PhaseDirection)
	res := &DecisionPhaseResult{joins: map[int]func() []agent.TurnSummary{}}

	// Sort alive workers by ID for deterministic order.
	alive := make([]*WorkerState, 0, len(in.Workers))
	for _, w := range in.Workers {
		if w.Alive {
			alive = append(alive, w)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].ID < alive[j].ID })

	for _, w := range alive {
		// Append this worker's iter activity to the canonical chat.
		// Activity = whatever was added to the worker agent's history
		// from the iteration boundary onward (assistant turns + tool
		// calls + tool results). Snapshot BEFORE the agent runs its
		// next iter run (which we'll fire after the decision lands).
		activity := snapshotWorkerIterActivity(w)
		in.DirChat.AppendWorkerActivity(w.ID, in.Iter, activity)

		decisionsBefore := len(in.Decisions.WorkerDecisions)
		askWorker(ctx, in, w, log)
		if len(in.Decisions.WorkerDecisions) == decisionsBefore {
			// The director failed to record a decision (drain error or
			// model didn't call the tool). Default to continue with the
			// existing instruction so the worker doesn't silently lose
			// its directive.
			if log != nil {
				log.Log("decision", "no-decision-defaulting-to-continue", map[string]any{
					"worker_id": w.ID,
				})
			}
			in.Decisions.AddDecision(WorkerDecision{
				Kind:        "continue",
				WorkerID:    w.ID,
				Instruction: w.LastInstruction,
			})
		}

		d := in.Decisions.WorkerDecisions[len(in.Decisions.WorkerDecisions)-1]
		// Mirror the decision into the director chat so the next worker's
		// per-worker prompt sees the decision in its peer-context.
		appendDecisionToChat(in.DirChat, w.ID, in.Iter, d)

		applyDecisionAndFire(ctx, in, w, d, res, log)
	}
	in.Decisions.BeginPerWorkerDecision(0) // clear the asked-worker hint
	return res
}

// askWorker installs the selectively-compacted view + per-worker prompt
// onto the director agent, sets the asked-worker hint on the decision
// queue, and drains (bounded by decisionDrainMaxRounds). The
// decide_worker handler validates the worker_id match and appends one
// WorkerDecision. If the bounded drain exits without a decision (e.g.
// the model loops on rejected tool calls), RunDecisionPhase's
// no-decision-defaulting-to-continue fallback takes over.
func askWorker(ctx context.Context, in DecisionPhaseInput, w *WorkerState, log *Logger) {
	view := in.DirChat.RenderForWorker(w.ID)
	peer := FormatPeerSummary(in.Workers, w.ID)
	taken := map[int]bool{}
	if in.TakenIDs != nil {
		taken = in.TakenIDs()
	}
	prompt := BuildPerWorkerDecisionPrompt(
		w.ID, w, in.WorkerRuns[w.ID], peer, in.IterationStatus, taken,
	)
	in.Director.ReplaceHistory(view)
	in.Director.Query(prompt)
	in.Decisions.BeginPerWorkerDecision(w.ID)
	if _, err := in.Director.DrainBounded(ctx, decisionDrainMaxRounds); err != nil && log != nil {
		log.Log("decision", "drain error", map[string]any{
			"worker_id": w.ID, "err": err.Error(),
		})
	}
}

// applyDecisionAndFire applies the decision to the worker (continue /
// expand → set instruction + budget then fire next-iter run, stop →
// enqueue retire, fork → spawn + fire child) and records a join handle
// in res for any fired iter run.
func applyDecisionAndFire(
	ctx context.Context,
	in DecisionPhaseInput,
	w *WorkerState,
	d WorkerDecision,
	res *DecisionPhaseResult,
	log *Logger,
) {
	switch d.Kind {
	case decideActionStop:
		if log != nil {
			log.Log("decision", decideActionStop, map[string]any{"worker_id": w.ID, "reason": d.Reason})
		}
		if in.Retire != nil {
			in.Retire(w, d.Reason, in.Iter)
		} else {
			w.Alive = false
			_ = w.Agent.Close()
		}
	case decideActionContinue, decideActionExpand:
		budget := d.AutonomousBudget
		if budget <= 0 {
			budget = defaultAutonomousBudget
		}
		if budget > 20 {
			budget = 20
		}
		w.AutonomousBudget = budget
		w.LastInstruction = d.Instruction
		// Reset per-iter state and fire the next-iter run as a goroutine.
		// installChronicle puts the (compacted) chronicle + new directive
		// onto the worker agent; the join captures the result for caller
		// wait at iter end.
		if in.Fire != nil {
			installChronicle(w, w.LastInstruction)
			join := in.Fire(ctx, w)
			res.mu.Lock()
			res.joins[w.ID] = join
			res.mu.Unlock()
		}
		if log != nil {
			log.Log("decision", d.Kind, map[string]any{
				"worker_id": w.ID, "autonomous_budget": budget,
			})
		}
	}
	// Fork (optional): spawn the child, copy parent chronicle, fire its
	// first iter run. Parent's own decision (continue/expand) already
	// landed above; stop+fork is meaningless (spawning a child off a
	// worker we're retiring) and we silently skip the fork in that case.
	if d.Fork != nil && d.Kind != "stop" && in.SpawnChild != nil {
		nw, err := in.SpawnChild(ctx, d.Fork.NewWorkerID, d.Fork.Instruction)
		if err != nil {
			if log != nil {
				log.Log("fork", "spawn failed", map[string]any{
					"parent": w.ID, "new": d.Fork.NewWorkerID, "err": err.Error(),
				})
			}
			return
		}
		// Inherit parent's chronicle: deep-copy slices, prepend an
		// inheritance header so the next install reads cleanly.
		nw.Chronicle = make([]agent.Message, 0, 1+len(w.Chronicle))
		nw.Chronicle = append(nw.Chronicle, agent.Message{
			Role:    "user",
			Content: forkInheritanceHeader(w.ID, in.Iter, nw.ID),
		})
		nw.Chronicle = append(nw.Chronicle, w.Chronicle...)
		nw.ChronicleIter = make([]int, 0, 1+len(w.ChronicleIter))
		nw.ChronicleIter = append(nw.ChronicleIter, in.Iter)
		nw.ChronicleIter = append(nw.ChronicleIter, w.ChronicleIter...)
		// Append child to the workers slice via the shared callback so
		// the controller can see it. We don't mutate Workers here
		// directly because the slice is owned by the controller. Instead,
		// rely on the spawn callback to do the append.
		// Fire the child's iter run.
		if in.Fire != nil {
			installChronicle(nw, nw.LastInstruction)
			join := in.Fire(ctx, nw)
			res.mu.Lock()
			res.joins[nw.ID] = join
			res.mu.Unlock()
		}
		if log != nil {
			log.Log("fork", "spawn", map[string]any{
				"parent": w.ID, "new": nw.ID,
				"inherited_msgs": len(nw.Chronicle),
			})
		}
	}
}

// snapshotWorkerIterActivity reads the worker agent's history from the
// iteration boundary onward — i.e. exactly the messages produced by the
// iter's autonomous run. Returns nil for agents that don't expose
// Snapshot/IterationBoundary (test fakes), in which case the director
// chat just gets no activity for that worker this iter.
//
// Empty Content on user/system/tool messages is normalized before
// return so the canonical director chat never holds a message that
// would 400 on the wire (see NormalizeEmptyContent).
func snapshotWorkerIterActivity(w *WorkerState) []agent.Message {
	s, ok := w.Agent.(snapshotter)
	if !ok {
		return nil
	}
	full := s.Snapshot()
	boundary := boundaryOf(w.Agent)
	if boundary < 0 || boundary >= len(full) {
		return nil
	}
	out := slices.Clone(full[boundary:])
	NormalizeEmptyContent(out)
	return out
}

// appendDecisionToChat mirrors a per-worker decision into the canonical
// director chat as a single tagged user message. The decision's full
// content (action, instruction/reason, fork) is preserved so subsequent
// per-worker prompts (and the synthesis prompt) can read what the
// director already decided this iter.
//
// We render as a user-role message rather than try to faithfully replay
// the director's tool-call assistant message — the chat is a controller-
// owned record, not a faithful agent transcript, and a clear synthetic
// summary is more readable for the next decision call.
func appendDecisionToChat(c *DirectorChat, workerID, iter int, d WorkerDecision) {
	body := "[director decision recorded for worker " + intToStr(workerID) + ": " +
		d.Kind
	switch d.Kind {
	case "continue", "expand":
		body += " — " + short(d.Instruction, 400)
		if d.AutonomousBudget > 0 {
			body += " (budget=" + intToStr(d.AutonomousBudget) + ")"
		}
	case "stop":
		body += " — " + short(d.Reason, 400)
	}
	if d.Fork != nil {
		body += " | fork worker " + intToStr(d.Fork.NewWorkerID) + ": " +
			short(d.Fork.Instruction, 400)
	}
	body += "]"
	c.Append(agent.Message{Role: "user", Content: body}, workerID, iter)
}

// intToStr is a small helper to avoid importing strconv just for this
// file — keeps imports tight.
func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// forkInheritanceHeader is the synthetic chronicle header inserted at the
// front of a forked child's chronicle so the model sees a clear handoff
// point ("you are worker N now, picking up the thread") when it reads
// inherited parent turns later.
func forkInheritanceHeader(parentID, iter, newID int) string {
	return "[Inherited investigative history from worker " + intToStr(parentID) +
		" at iter " + intToStr(iter) +
		". The remainder of this chronicle records that worker's prior turns; you are now worker " +
		intToStr(newID) + ", picking up the thread under a new directive.]"
}

// SynthesisPhaseInput bundles inputs for the post-decision synthesis call.
type SynthesisPhaseInput struct {
	Director        agent.Agent
	DirChat         *DirectorChat
	Decisions       *DecisionQueue
	Workers         []*WorkerState
	Completed       []CompletedWorker
	VerifierSummary string
	FindingsSummary string
	StallWarnings   string
	FollowUpHints   string
	IterationStatus string
	MaxWorkers      int
}

// RunSynthesisPhase is the post-decision synthesis call. Renders a
// uniformly-compacted view (all worker activity stubbed; director-owned
// raw) plus the synthesis prompt, drains, and lets the synthesis tools
// (plan_workers / direction_done / end_run) populate the decision queue.
//
// Returns true when direction_done OR end_run landed; false if the
// director failed to close the phase (controller treats as direction_done
// for safety).
func RunSynthesisPhase(
	ctx context.Context,
	in SynthesisPhaseInput,
	log *Logger,
) bool {
	in.Decisions.BeginPhase(agent.PhaseDirection)
	view := in.DirChat.RenderForSynthesis()
	prompt := BuildSynthesisPrompt(
		in.Workers, in.Completed,
		in.VerifierSummary, in.FindingsSummary, in.StallWarnings, in.FollowUpHints,
		in.IterationStatus, in.MaxWorkers,
	)
	in.Director.ReplaceHistory(view)
	in.Director.Query(prompt)
	if _, err := in.Director.Drain(ctx); err != nil {
		if log != nil {
			log.Log("synthesis", "drain error", map[string]any{"err": err.Error()})
		}
	}
	closed := in.Decisions.HasDirectionDone || in.Decisions.HasEndRun
	if !closed {
		// The synthesis call didn't close the phase. Auto-close so the
		// controller doesn't wedge — director_done is the safe default.
		in.Decisions.SetDirectionDone("auto: synthesis did not call direction_done")
		if log != nil {
			log.Log("synthesis", "auto-direction-done", nil)
		}
	}
	return true
}

// RunIter1ReconReviewCall is the FIRST half of the iter-1 recon
// synthesis. The director reads the recon summary in dirChat and
// produces a free-form text response describing the scope understanding
// and proposed iter-2 worker assignments. NO tools are registered for
// this call so the model focuses on understanding the problem space
// before planning. The text response is appended to dirChat as a
// director-owned message so the subsequent plan call sees it.
//
// The caller is responsible for tool registration: SetTools(nil) before
// this call, then SetTools(synthesisTools) before RunIter1ReconPlanCall.
func RunIter1ReconReviewCall(
	ctx context.Context,
	director agent.Agent,
	dirChat *DirectorChat,
	iterationStatus string,
	iter, maxWorkers int,
	log *Logger,
) {
	view := dirChat.RenderForSynthesis()
	prompt := BuildIter1ReconReviewPrompt(iterationStatus, maxWorkers)
	director.ReplaceHistory(view)
	director.Query(prompt)
	turn, err := director.Drain(ctx)
	if err != nil && log != nil {
		log.Log("synthesis", "iter1-review drain error", map[string]any{"err": err.Error()})
	}
	text := strings.TrimSpace(agent.StripThinkBlocks(turn.AssistantText))
	if text == "" {
		if log != nil {
			log.Log("synthesis", "iter1-review empty response", nil)
		}
		return
	}
	dirChat.Append(agent.Message{
		Role:    "assistant",
		Content: text,
	}, 0, iter)
	if log != nil {
		log.Log("synthesis", "iter1-review captured", map[string]any{
			"chars":   len(text),
			"preview": short(text, 600),
		})
	}
}

// RunIter1ReconPlanCall is the SECOND half of the iter-1 recon
// synthesis. The director reads its own review response (now in dirChat)
// and is asked to call plan_workers + direction_done to formalize the
// iter-2 roster. If plan_workers wasn't called, this function re-prompts
// the director ONCE with a pointed reminder. If the retry still produces
// no plan, the function returns with HasPlan=false; the caller logs a
// critical warning and the run terminates at iter 2's alive-check
// because there are no workers to run.
//
// Caller is responsible for SetTools(synthesisTools) before this call.
func RunIter1ReconPlanCall(
	ctx context.Context,
	director agent.Agent,
	dirChat *DirectorChat,
	decisions *DecisionQueue,
	iterationStatus string,
	iter, maxWorkers int,
	log *Logger,
) {
	decisions.BeginPhase(agent.PhaseDirection)
	view := dirChat.RenderForSynthesis()
	director.ReplaceHistory(view)
	director.Query(BuildIter1ReconPlanPrompt(iterationStatus, maxWorkers))
	if _, err := director.Drain(ctx); err != nil && log != nil {
		log.Log("synthesis", "iter1-plan drain error", map[string]any{"err": err.Error()})
	}
	// Mandatory retry: if plan_workers wasn't called, re-prompt once with
	// a pointed reminder. The director's own previous response is still
	// in its agent history (no ReplaceHistory between drains) so it can
	// see what it just emitted.
	if !decisions.HasPlan {
		if log != nil {
			log.Log("synthesis", "iter1-plan missing-retry", nil)
		}
		director.Query(BuildIter1ReconPlanRetryPrompt())
		if _, err := director.Drain(ctx); err != nil && log != nil {
			log.Log("synthesis", "iter1-plan retry drain error", map[string]any{"err": err.Error()})
		}
	}
	if !decisions.HasDirectionDone && !decisions.HasEndRun {
		decisions.SetDirectionDone("auto: iter-1 plan call did not call direction_done")
		if log != nil {
			log.Log("synthesis", "iter1-plan auto-direction-done", nil)
		}
	}
	if log != nil {
		log.Log("synthesis", "iter1-plan result", map[string]any{
			"has_plan":    decisions.HasPlan,
			"plan_count":  len(decisions.Plan),
			"closed_done": decisions.HasDirectionDone,
		})
	}
}
