package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-analyze/bulk"
	"golang.org/x/sync/errgroup"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/config"
	"github.com/go-appsec/secagent/mcp"
	"github.com/go-appsec/secagent/prompts"
)

// AgentFactory builds a new Agent for a given role. It's parameterized so
// tests can inject FakeAgent.
type AgentFactory interface {
	NewWorker(id, numWorkers int) (agent.Agent, error)
	NewVerifier() (agent.Agent, error)
	NewDirector() (agent.Agent, error)
	Close() error
}

// OpenAIFactory builds OpenAIAgent instances against the configured pools.
type OpenAIFactory struct {
	Cfg        *config.Config
	WorkerPool *agent.ClientPool
	OrchPool   *agent.ClientPool
	Malformed  *MalformedCounter
	Log        *Logger
	// WorkerReasoning / OrchReasoning hold the reasoning handlers detected
	// at startup for their respective models. Nil falls back to inline.
	WorkerReasoning agent.ReasoningHandler
	OrchReasoning   agent.ReasoningHandler
}

// slowToolThreshold is the elapsed time at which [tool] done is mirrored
// to stderr; below it, tool lifecycle stays in the JSON file only.
const slowToolThreshold = 5 * time.Second

func (f *OpenAIFactory) malformedCallback(model string) func(name string, err error) {
	if f.Malformed == nil {
		return nil
	}
	return func(name string, err error) { f.Malformed.Observe(model, name, err) }
}

// requestCallbacks returns start/end hooks that record each chat-completion
// HTTP call. Model is dropped from per-call fields — it is logged once at
// startup — but role stays so operators can tell calls apart in the JSON log.
func (f *OpenAIFactory) requestCallbacks(role string) (func(int), func(int, time.Duration, int, int, error)) {
	if f.Log == nil {
		return nil, nil
	}
	start := func(attempt int) {
		fields := map[string]any{"role": role}
		if attempt > 0 {
			fields["attempt"] = attempt
		}
		f.Log.Log("agent", "request", fields)
	}
	end := func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error) {
		fields := map[string]any{
			"role":       role,
			"elapsed":    elapsed.Round(time.Millisecond).String(),
			"tokens_in":  tokensIn,
			"tokens_out": tokensOut,
		}
		if attempt > 0 {
			fields["attempt"] = attempt
		}
		msg := "response"
		if err != nil {
			fields["err"] = err.Error()
			switch {
			case errors.Is(err, context.Canceled):
				msg = "response cancelled"
			case errors.Is(err, context.DeadlineExceeded):
				msg = "response timeout"
			default:
				msg = "response error"
			}
		}
		f.Log.Log("agent", msg, fields)
	}
	return start, end
}

// toolCallbacks returns start/end hooks for individual tool dispatches. Only
// slow/error/timeout outcomes mirror to stderr; the rest stay in the JSON log.
func (f *OpenAIFactory) toolCallbacks(role string) (func(string, json.RawMessage), func(string, json.RawMessage, time.Duration, bool, bool, string)) {
	if f.Log == nil {
		return nil, nil
	}
	start := func(name string, _ json.RawMessage) {
		f.Log.Log("tool", "start", map[string]any{"role": role, "name": name})
	}
	end := func(name string, _ json.RawMessage, elapsed time.Duration, isErr, timedOut bool, errText string) {
		fields := map[string]any{
			"role":    role,
			"name":    name,
			"elapsed": elapsed.Round(time.Millisecond).String(),
			"error":   isErr,
		}
		if errText != "" {
			fields["error_text"] = errText
		}
		msg := toolMsgDone
		switch {
		case timedOut:
			msg = toolMsgTimeout
		case elapsed >= slowToolThreshold && !isErr:
			msg = toolMsgSlow
		}
		f.Log.Log("tool", msg, fields)
	}
	return start, end
}

// buildAgent assembles an OpenAIAgent for a role. Workers and verifiers set
// a FlowIDExtractor so their turn summaries can link reported flow IDs;
// directors don't dispatch sectool tools, so their extractor stays nil.
func (f *OpenAIFactory) buildAgent(
	role, model, systemPrompt string,
	pool *agent.ClientPool,
	maxContext int,
	reasoning agent.ReasoningHandler,
	setFlowExtractor bool,
) agent.Agent {
	onReqStart, onReqEnd := f.requestCallbacks(role)
	onToolStart, onToolEnd := f.toolCallbacks(role)
	cfg := agent.OpenAIAgentConfig{
		Model:        model,
		SystemPrompt: systemPrompt,
		Pool:         pool,
		MaxContext:   maxContext,
		Compaction: agent.CompactionOptions{
			HighWatermark: f.Cfg.HighWatermark,
			LowWatermark:  f.Cfg.LowWatermark,
			KeepTurns:     f.Cfg.KeepTurns,
		},
		TurnTimeout:      f.Cfg.TurnTimeout,
		PerToolTimeout:   f.Cfg.PerToolTimeout,
		MaxParallelTools: f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent: f.Cfg.MaxTurnsPerAgent,
		KeepThinkTurns:   f.Cfg.EffectiveKeepThinkTurns(maxContext),
		Reasoning:        reasoning,
		OnMalformedCall:  f.malformedCallback(model),
		OnRequestStart:   onReqStart,
		OnRequestEnd:     onReqEnd,
		OnToolStart:      onToolStart,
		OnToolEnd:        onToolEnd,
	}
	if setFlowExtractor {
		cfg.FlowIDExtractor = ExtractFlowIDs
	}
	return agent.NewOpenAIAgent(cfg)
}

// NewWorker builds a worker agent with the given role-sizing.
func (f *OpenAIFactory) NewWorker(id, numWorkers int) (agent.Agent, error) {
	return f.buildAgent(
		fmt.Sprintf("worker-%d", id),
		f.Cfg.WorkerModel,
		prompts.BuildWorkerSystemPrompt(id, numWorkers),
		f.WorkerPool,
		f.Cfg.WorkerMaxContext,
		f.WorkerReasoning,
		true,
	), nil
}

// NewVerifier builds a verifier agent.
func (f *OpenAIFactory) NewVerifier() (agent.Agent, error) {
	return f.buildAgent(
		"verifier",
		f.Cfg.OrchestratorModel,
		prompts.BuildVerifierSystemPrompt(f.Cfg.MaxWorkers),
		f.OrchPool,
		f.Cfg.OrchestratorMaxContext,
		f.OrchReasoning,
		true,
	), nil
}

// NewDirector builds a director agent.
func (f *OpenAIFactory) NewDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director",
		f.Cfg.OrchestratorModel,
		prompts.BuildDirectorSystemPrompt(f.Cfg.MaxWorkers),
		f.OrchPool,
		f.Cfg.OrchestratorMaxContext,
		f.OrchReasoning,
		false,
	), nil
}

// Close is a no-op (pools outlive the factory in typical use).
func (f *OpenAIFactory) Close() error { return nil }

// buildClientPool constructs n distinct ChatClient instances against baseURL
// and wraps them in a bounded-concurrency ClientPool.
func buildClientPool(baseURL, apiKey string, n int) *agent.ClientPool {
	if n < 1 {
		n = 1
	}
	clients := make([]agent.ChatClient, 0, n)
	for i := 0; i < n; i++ {
		clients = append(clients, agent.NewOpenAIChatClient(baseURL, apiKey))
	}
	return agent.NewClientPoolWithClients(clients)
}

// resolveFormat probes (baseURL, model) via pool-acquired client through the
// shared cache and emits a [server] reasoning-format log entry on the real
// detection path (cache hits are silent). Returns the resolved format.
func resolveFormat(
	ctx context.Context,
	cache *agent.ReasoningFormatCache,
	pool *agent.ClientPool,
	role, baseURL, model string,
	log *Logger,
) agent.ReasoningFormat {
	client, err := pool.Acquire(ctx)
	if err != nil {
		if log != nil {
			log.Log("server", "reasoning-format probe aborted", map[string]any{
				"role": role, "model": model, "err": err.Error(),
			})
		}
		return agent.ReasoningFormatUnknown
	}
	defer pool.Release(client)
	return cache.Resolve(ctx, client, baseURL, model,
		func(f agent.ReasoningFormat, elapsed time.Duration, err error) {
			if log == nil {
				return
			}
			fields := map[string]any{
				"role":     role,
				"model":    model,
				"base_url": baseURL,
				"format":   f.String(),
				"elapsed":  elapsed.Round(time.Millisecond).String(),
			}
			if err != nil {
				fields["err"] = err.Error()
			}
			log.Log("server", "reasoning-format", fields)
		},
	)
}

// workerSpawnFunc produces a ready-to-run worker (MCP client connected,
// tools registered, assignment queued). Injected into applyPlanDiff so
// tests can stub provisioning without touching the real MCP server.
type workerSpawnFunc func(ctx context.Context, id, numWorkers int, assignment string) (*WorkerState, error)

// newWorkerSpawner returns a workerSpawnFunc that provisions workers
// against a live MCP endpoint. Each call opens a fresh mcp.Client so each
// worker has its own transport state per spec §6.
func newWorkerSpawner(
	mcpURL string,
	toolResultMaxBytes int,
	factory AgentFactory,
	candidates *CandidatePool,
	autonomousBudget int,
) workerSpawnFunc {
	return func(ctx context.Context, id, numWorkers int, assignment string) (*WorkerState, error) {
		m, err := mcp.Connect(ctx, mcpURL)
		if err != nil {
			return nil, fmt.Errorf("mcp connect (worker %d): %w", id, err)
		}
		defs, err := m.BuildToolDefs(ctx, "mcp__sectool__", toolResultMaxBytes)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("list sectool tools (worker %d): %w", id, err)
		}
		a, err := factory.NewWorker(id, numWorkers)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("new worker %d: %w", id, err)
		}
		tools := append(slices.Clone(defs), WorkerToolDefs(candidates, id)...)
		a.SetTools(tools)
		a.Query(assignment)
		return &WorkerState{
			ID:               id,
			Agent:            a,
			MCP:              m,
			Alive:            true,
			Assignment:       assignment,
			LastInstruction:  assignment,
			AutonomousBudget: autonomousBudget,
		}, nil
	}
}

// Run is the main entrypoint. Starts sectool, connects agents, and runs
// the main iteration loop until max-iterations or a director `done`.
func Run(ctx context.Context, cfg *config.Config, repoRoot string, log *Logger) error {
	var srv *SectoolServer
	if !cfg.External {
		var err error
		srv, err = StartSectool(repoRoot, cfg.ProxyPort, cfg.MCPPort, cfg.Workflow, cfg.SkipBuild, log)
		if err != nil {
			return fmt.Errorf("sectool start: %w", err)
		}
		defer srv.Terminate()
	} else if log != nil {
		log.Log("server", "external mode: attaching to running sectool", map[string]any{"mcp_port": cfg.MCPPort})
	}

	mcpURL := fmt.Sprintf("http://127.0.0.1:%d/mcp", cfg.MCPPort)

	// ProgressLogInterval is the deprecated per-turn status summary; when the
	// narrator is active it subsumes that channel, so force-disable it.
	if cfg.NarrateInterval > 0 {
		StatusSummaryInterval = 0
	} else {
		StatusSummaryInterval = cfg.ProgressLogInterval
	}

	if log != nil {
		log.Log("server", "models", map[string]any{
			"worker":       cfg.WorkerModel,
			"orchestrator": cfg.OrchestratorModel,
			"summary":      cfg.EffectiveSummaryModel(),
		})
	}

	workerPool := buildClientPool(cfg.EffectiveWorkerBaseURL(), cfg.APIKey, cfg.OpenAIPoolSize)
	orchPool := workerPool
	if cfg.OrchestratorPool > 0 ||
		(cfg.OrchestratorBaseURL != "" && cfg.OrchestratorBaseURL != cfg.EffectiveWorkerBaseURL()) {
		sz := cfg.OrchestratorPool
		if sz <= 0 {
			sz = cfg.OpenAIPoolSize
		}
		orchPool = buildClientPool(cfg.EffectiveOrchestratorBaseURL(), cfg.APIKey, sz)
	}
	// Build the summary pool alongside worker/orch so all three reasoning-
	// format probes can run in parallel below, rather than waiting until
	// narrator construction time to start the third probe.
	summaryPool := orchPool
	if cfg.EffectiveSummaryBaseURL() != cfg.EffectiveOrchestratorBaseURL() {
		summaryPool = buildClientPool(cfg.EffectiveSummaryBaseURL(), cfg.APIKey, 1)
	}

	// Probe each unique (baseURL, model) in parallel. Reasoning-format
	// detection on qwen3-class models takes ~30s per probe; sequential
	// probes add up to ~60-90s of startup latency. errgroup + the shared
	// cache dedups identical pairs (so if orchestrator model == worker
	// model, the second probe is a cache hit rather than a duplicate call).
	formatCache := agent.NewReasoningFormatCache()
	var (
		workerFmt  agent.ReasoningFormat
		orchFmt    agent.ReasoningFormat
		summaryFmt agent.ReasoningFormat
	)
	probeGroup, probeCtx := errgroup.WithContext(ctx)
	probeGroup.Go(func() error {
		workerFmt = resolveFormat(probeCtx, formatCache, workerPool, "worker",
			cfg.EffectiveWorkerBaseURL(), cfg.WorkerModel, log)
		return nil
	})
	probeGroup.Go(func() error {
		orchFmt = resolveFormat(probeCtx, formatCache, orchPool, "orchestrator",
			cfg.EffectiveOrchestratorBaseURL(), cfg.OrchestratorModel, log)
		return nil
	})
	probeGroup.Go(func() error {
		summaryFmt = resolveFormat(probeCtx, formatCache, summaryPool, "summary",
			cfg.EffectiveSummaryBaseURL(), cfg.EffectiveSummaryModel(), log)
		return nil
	})
	_ = probeGroup.Wait()
	workerReasoning := agent.NewReasoningHandler(workerFmt)
	orchReasoning := agent.NewReasoningHandler(orchFmt)
	summaryReasoning := agent.NewReasoningHandler(summaryFmt)

	malformed := NewMalformedCounter(log)
	defer malformed.Flush()
	factory := &OpenAIFactory{
		Cfg: cfg, WorkerPool: workerPool, OrchPool: orchPool,
		Malformed: malformed, Log: log,
		WorkerReasoning: workerReasoning,
		OrchReasoning:   orchReasoning,
	}

	candidates := NewCandidatePool()
	decisions := NewDecisionQueue()
	writer := NewFindingWriter(cfg.FindingsDir)
	dedupReviewer := &OpenAIDedupReviewer{
		Pool:  orchPool,
		Model: cfg.OrchestratorModel,
		Log:   log,
	}

	verifier, err := factory.NewVerifier()
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	defer func() { _ = verifier.Close() }()
	director, err := factory.NewDirector()
	if err != nil {
		return fmt.Errorf("new director: %w", err)
	}
	defer func() { _ = director.Close() }()

	// per spec §6 each agent gets its own MCP client; workers get theirs in spawnWorker
	verifierMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (verifier): %w", err)
	}
	defer func() { _ = verifierMCP.Close() }()

	verifierSectoolDefs, err := verifierMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list verifier sectool tools: %w", err)
	}

	verifierTools := append(slices.Clone(verifierSectoolDefs), VerifierToolDefs(decisions)...)
	verifier.SetTools(verifierTools)

	// guardIteration is updated by the main loop below; the closure captures
	// its address so DirectorToolDefs' end_run guard sees live state instead
	// of a stale snapshot. writer.RunCount is read directly — the FindingWriter
	// is race-safe (internal mutex).
	var guardIteration int
	director.SetTools(DirectorToolDefs(decisions, func() (int, int) {
		return guardIteration, writer.RunCount
	}))

	spawn := newWorkerSpawner(mcpURL, cfg.ToolResultMaxBytes, factory, candidates, cfg.AutonomousBudget)

	workers := make([]*WorkerState, 0, cfg.MaxWorkers)
	defer func() {
		for _, w := range workers {
			w.Close()
		}
	}()
	w1, err := spawn(ctx, 1, 1, cfg.Prompt)
	if err != nil {
		return err
	}
	workers = append(workers, w1)
	if log != nil {
		log.Log("worker", "seeded", map[string]any{"id": 1, "assignment": cfg.Prompt})
	}

	// currentPhase drives which agents the narrator summarizes per firing.
	// Mutated only on the main loop goroutine (phaseTransition); snapshots
	// are pushed to the narrator via SetActiveAgents so the narrator's
	// goroutine never dereferences controller-owned state directly.
	currentPhase := "idle"

	// computeActiveAgents returns the agents active for currentPhase. Called
	// only from the main loop goroutine. Fake agents used in tests are
	// interface-only and skipped.
	computeActiveAgents := func() []NamedAgent {
		switch currentPhase {
		case "autonomous":
			var out []NamedAgent
			for _, w := range workers {
				if !w.Alive {
					continue
				}
				if oa, ok := w.Agent.(*agent.OpenAIAgent); ok {
					out = append(out, NamedAgent{
						Name:  fmt.Sprintf("worker-%d", w.ID),
						Agent: oa,
					})
				}
			}
			return out
		case "verification":
			if oa, ok := verifier.(*agent.OpenAIAgent); ok {
				return []NamedAgent{{Name: "verifier", Agent: oa}}
			}
		case "direction":
			if oa, ok := director.(*agent.OpenAIAgent); ok {
				return []NamedAgent{{Name: "director", Agent: oa}}
			}
		}
		return nil
	}

	// summaryPool and summaryReasoning were constructed earlier alongside
	// worker/orch pools so all three reasoning-format probes could run in
	// parallel at startup. Narration routes through the shared orchestrator
	// pool when the summary endpoint matches; a distinct summary URL gets
	// its own size-1 pool so the "one summary in flight" invariant holds by
	// construction.
	narrator := NewNarrator(NarratorConfig{
		Interval:   cfg.NarrateInterval,
		Model:      cfg.EffectiveSummaryModel(),
		Pool:       summaryPool,
		CallBudget: cfg.NarrateTimeout,
		Summarizer: summaryReasoning,
		// Parent ctx — ctrl+c propagates to in-flight summary HTTP calls
		// so shutdown doesn't wait on narration that the operator doesn't
		// care about anymore.
		Parent: ctx,
	}, log)
	log.AttachNarrator(narrator)
	defer func() {
		log.AttachNarrator(nil)
		narrator.Close()
	}()
	if log != nil {
		fields := map[string]any{}
		if narrator == nil {
			fields["enabled"] = false
			fields["reason"] = "disabled by config"
		} else {
			fields["enabled"] = true
			fields["interval"] = cfg.NarrateInterval.String()
			fields["timeout"] = cfg.NarrateTimeout.String()
			fields["pool_size"] = summaryPool.Size()
			fields["shared_pool"] = summaryPool == orchPool
		}
		log.Log("server", "narrator", fields)
	}

	// phaseTransition logs a phase change, republishes the narrator's
	// active-agent snapshot for the new phase, and force-fires a summary
	// so the operator always gets a fresh sentence at phase boundaries.
	phaseTransition := func(from, to string) {
		currentPhase = to
		narrator.SetActiveAgents(computeActiveAgents())
		if log != nil {
			log.Log("controller", "transition phase "+from+" to "+to, nil)
		}
		narrator.TriggerNow()
	}

	var iteration int
	for iteration = 1; iteration <= cfg.MaxIterations; iteration++ {
		guardIteration = iteration
		if err := ctx.Err(); err != nil {
			if log != nil {
				log.Log("controller", "cancelled", map[string]any{"iter": iteration, "err": err.Error()})
			}
			break
		}
		alive := aliveWorkers(workers)
		if len(alive) == 0 {
			if log != nil {
				log.Log("controller", "no alive workers, stopping", map[string]any{"iter": iteration})
			}
			break
		}

		if log != nil {
			log.Log("controller", "iteration start", map[string]any{
				"iter":          iteration,
				"alive_workers": len(alive),
			})
		}
		phaseTransition("idle", "autonomous")
		narrator.Tick()

		candidatesBefore := candidates.Counter()
		workerRuns := RunAllWorkersUntilEscalation(ctx, alive, candidates, log)
		UpdateStallStreaks(alive)

		// stall-force-stop happens before verification so the stalled worker's
		// run still feeds the verifier (spec §7.3). Both silent and error
		// escalations count toward ProgressNoneStreak (see UpdateStallStreaks),
		// so a worker that consistently times out or crashes terminates at
		// the same threshold as one that goes silent by choice.
		for _, w := range workers {
			if w.Alive && w.ProgressNoneStreak >= cfg.StallStopAfter {
				if log != nil {
					log.Log("controller", "stall-force-stop", map[string]any{
						"worker_id": w.ID, "streak": w.ProgressNoneStreak,
					})
				}
				w.Alive = false
				w.Close()
			}
		}

		// Dead-iteration short-circuit: if every worker produced zero tool
		// calls AND no new candidates were filed this iteration, there is
		// nothing for the verifier to process and nothing new for the
		// director to plan against. Skip both phases to save orchestrator
		// LLM budget. The stall mechanism above still retires dead workers
		// naturally; once all workers stop, the alive-check ends the run.
		// Each still-alive worker gets a continuePrompt queued so the next
		// iteration's Drain has a user message to respond to — otherwise
		// the chat history would end on an assistant role and the next
		// request would be rejected or degenerate.
		if isDeadIteration(workerRuns, candidatesBefore, candidates.Counter()) {
			if log != nil {
				log.Log("controller", "dead-iteration", map[string]any{"iter": iteration})
			}
			for _, w := range workers {
				if w.Alive {
					w.Agent.Query(continuePrompt)
				}
			}
			narrator.TriggerNow()
			continue
		}

		decisions.Reset()

		phaseTransition("autonomous", "verification")
		verificationSummary := RunVerificationPhase(
			ctx, verifier, decisions, candidates, writer, dedupReviewer,
			workerRuns, workers, iteration, cfg.MaxIterations, log,
		)

		phaseTransition("verification", "direction")
		stallWarnings := FormatStallWarnings(workers, cfg.StallWarnAfter)
		followUpHints := FormatFollowUpHints(decisions.Findings, decisions.Dismissals)
		RunDirectionPhase(
			ctx, director, decisions, workers, workerRuns,
			verificationSummary, writer.SummaryForOrchestrator(), stallWarnings, followUpHints,
			iteration, cfg.MaxIterations, writer.RunCount, cfg.MaxWorkers, log,
		)
		LatchStallWarnings(workers, cfg.StallWarnAfter)

		if decisions.HasEndRun {
			// The end_run tool handler already enforced MinIterationsForDone /
			// RunCount; by the time HasEndRun is true the director has met the
			// bar, so the controller just honors it.
			if log != nil {
				log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
			}
			break
		}

		if decisions.HasPlan {
			applyPlanDiff(ctx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, log)
		}

		// apply per-worker decisions
		decidedWIDs := map[int]bool{}
		for _, d := range decisions.WorkerDecisions {
			w := findWorker(workers, d.WorkerID)
			if w == nil || !w.Alive {
				if log != nil {
					log.Log("controller", "decision for unknown/dead worker", map[string]any{"worker_id": d.WorkerID})
				}
				continue
			}
			applyDecision(d, w, log)
			decidedWIDs[d.WorkerID] = true
		}

		// implicit continue for undirected alive workers
		for _, w := range workers {
			if !w.Alive || decidedWIDs[w.ID] {
				continue
			} else if decisions.HasPlan && slices.ContainsFunc(decisions.Plan, func(p PlanEntry) bool {
				return p.WorkerID == w.ID
			}) {
				continue
			}
			if log != nil {
				log.Log("controller", "implicit continue", map[string]any{"worker_id": w.ID})
			}
			w.Agent.Query(continuePrompt)
		}

		// End-of-iteration: coalesce any events since the last phase transition
		// into a summary firing so the operator sees a sentence per iteration.
		narrator.TriggerNow()
	}

	if log != nil {
		log.Log("summary", "run complete", map[string]any{
			"iterations":     iteration,
			"findings_count": writer.RunCount,
			"workers":        len(workers),
		})
		for _, p := range writer.Paths {
			log.Log("summary", "finding", map[string]any{"path": filepath.Clean(p)})
		}
	}
	return nil
}

func aliveWorkers(ws []*WorkerState) []*WorkerState {
	return bulk.SliceFilter(func(w *WorkerState) bool { return w.Alive }, ws)
}

// isDeadIteration reports whether the autonomous phase produced nothing
// actionable — no tool calls across any worker and no new candidates filed.
// These iterations shouldn't feed verification/direction; doing so lets the
// director hallucinate plans over workers that silently failed LLM-side.
func isDeadIteration(workerRuns map[int][]agent.TurnSummary, candidatesBefore, candidatesAfter int) bool {
	if candidatesAfter != candidatesBefore {
		return false
	}
	for _, runs := range workerRuns {
		for _, r := range runs {
			if len(r.ToolCalls) > 0 {
				return false
			}
		}
	}
	return true
}

func findWorker(ws []*WorkerState, id int) *WorkerState {
	idx := slices.IndexFunc(ws, func(w *WorkerState) bool { return w.ID == id })
	if idx < 0 {
		return nil
	}
	return ws[idx]
}

func applyDecision(d WorkerDecision, w *WorkerState, log *Logger) {
	if d.Kind == "stop" {
		if log != nil {
			log.Log("decision", "stop", map[string]any{"worker_id": w.ID, "reason": d.Reason})
		}
		w.Alive = false
		_ = w.Agent.Close()
		return
	}
	budget := d.AutonomousBudget
	if budget <= 0 {
		budget = defaultAutonomousBudget
	}
	budget = min(budget, 20)
	w.AutonomousBudget = budget
	w.LastInstruction = d.Instruction
	w.Agent.Query(d.Instruction)
	if log != nil {
		log.Log("decision", d.Kind, map[string]any{
			"worker_id":         w.ID,
			"autonomous_budget": budget,
		})
	}
}

func applyPlanDiff(
	ctx context.Context,
	plan []PlanEntry,
	workers *[]*WorkerState,
	spawn workerSpawnFunc,
	maxWorkers int,
	log *Logger,
) {
	byID := map[int]*WorkerState{}
	existing := 0
	for _, w := range *workers {
		byID[w.ID] = w
		if w.Alive {
			existing++
		}
	}
	for _, p := range plan {
		if w, ok := byID[p.WorkerID]; ok && w.Alive {
			w.Assignment = p.Assignment
			w.LastInstruction = p.Assignment
			// Only reset the stall counter when the worker actually produced
			// something this iteration. A fresh assignment doesn't bring a
			// dead LLM back to life, so the streak must keep climbing until
			// force-stop fires.
			if hasProductiveTurn(w.AutonomousTurns) {
				w.ProgressNoneStreak = 0
				w.StallWarned = false
			}
			w.Agent.Query(p.Assignment)
			if log != nil {
				log.Log("plan", "retarget", map[string]any{"worker_id": p.WorkerID})
			}
			continue
		}
		if existing >= maxWorkers {
			if log != nil {
				log.Log("plan", "spawn skipped: max_workers", map[string]any{"worker_id": p.WorkerID})
			}
			continue
		}
		nw, err := spawn(ctx, p.WorkerID, existing+1, p.Assignment)
		if err != nil {
			if log != nil {
				log.Log("plan", "spawn failed", map[string]any{"worker_id": p.WorkerID, "err": err.Error()})
			}
			continue
		}
		*workers = append(*workers, nw)
		existing++
		if log != nil {
			log.Log("plan", "spawn", map[string]any{"worker_id": p.WorkerID})
		}
	}
}
