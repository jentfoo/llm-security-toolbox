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
func (f *OpenAIFactory) toolCallbacks(role string) (func(string, json.RawMessage), func(string, json.RawMessage, time.Duration, bool, bool)) {
	if f.Log == nil {
		return nil, nil
	}
	start := func(name string, _ json.RawMessage) {
		f.Log.Log("tool", "start", map[string]any{"role": role, "name": name})
	}
	end := func(name string, _ json.RawMessage, elapsed time.Duration, isErr, timedOut bool) {
		fields := map[string]any{
			"role":    role,
			"name":    name,
			"elapsed": elapsed.Round(time.Millisecond).String(),
			"error":   isErr,
		}
		msg := "done"
		switch {
		case timedOut:
			msg = "timeout"
		case elapsed >= slowToolThreshold && !isErr:
			msg = "slow"
		}
		f.Log.Log("tool", msg, fields)
	}
	return start, end
}

// NewWorker builds a worker agent with the given role-sizing.
func (f *OpenAIFactory) NewWorker(id, numWorkers int) (agent.Agent, error) {
	role := fmt.Sprintf("worker-%d", id)
	onReqStart, onReqEnd := f.requestCallbacks(role)
	onToolStart, onToolEnd := f.toolCallbacks(role)
	return agent.NewOpenAIAgent(agent.OpenAIAgentConfig{
		Model:        f.Cfg.WorkerModel,
		SystemPrompt: prompts.BuildWorkerSystemPrompt(id, numWorkers),
		Pool:         f.WorkerPool,
		MaxContext:   f.Cfg.WorkerMaxContext,
		Compaction: agent.CompactionOptions{
			HighWatermark: f.Cfg.HighWatermark,
			LowWatermark:  f.Cfg.LowWatermark,
			KeepTurns:     f.Cfg.KeepTurns,
		},
		TurnTimeout:      f.Cfg.TurnTimeout,
		PerToolTimeout:   f.Cfg.PerToolTimeout,
		MaxParallelTools: f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent: f.Cfg.MaxTurnsPerAgent,
		FlowIDExtractor:  ExtractFlowIDs,
		OnMalformedCall:  f.malformedCallback(f.Cfg.WorkerModel),
		OnRequestStart:   onReqStart,
		OnRequestEnd:     onReqEnd,
		OnToolStart:      onToolStart,
		OnToolEnd:        onToolEnd,
	}), nil
}

// NewVerifier builds a verifier agent.
func (f *OpenAIFactory) NewVerifier() (agent.Agent, error) {
	onReqStart, onReqEnd := f.requestCallbacks("verifier")
	onToolStart, onToolEnd := f.toolCallbacks("verifier")
	return agent.NewOpenAIAgent(agent.OpenAIAgentConfig{
		Model:        f.Cfg.OrchestratorModel,
		SystemPrompt: prompts.BuildVerifierSystemPrompt(f.Cfg.MaxWorkers),
		Pool:         f.OrchPool,
		MaxContext:   f.Cfg.OrchestratorMaxContext,
		Compaction: agent.CompactionOptions{
			HighWatermark: f.Cfg.HighWatermark,
			LowWatermark:  f.Cfg.LowWatermark,
			KeepTurns:     f.Cfg.KeepTurns,
		},
		TurnTimeout:      f.Cfg.TurnTimeout,
		PerToolTimeout:   f.Cfg.PerToolTimeout,
		MaxParallelTools: f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent: f.Cfg.MaxTurnsPerAgent,
		FlowIDExtractor:  ExtractFlowIDs,
		OnMalformedCall:  f.malformedCallback(f.Cfg.OrchestratorModel),
		OnRequestStart:   onReqStart,
		OnRequestEnd:     onReqEnd,
		OnToolStart:      onToolStart,
		OnToolEnd:        onToolEnd,
	}), nil
}

// NewDirector builds a director agent.
func (f *OpenAIFactory) NewDirector() (agent.Agent, error) {
	onReqStart, onReqEnd := f.requestCallbacks("director")
	onToolStart, onToolEnd := f.toolCallbacks("director")
	return agent.NewOpenAIAgent(agent.OpenAIAgentConfig{
		Model:        f.Cfg.OrchestratorModel,
		SystemPrompt: prompts.BuildDirectorSystemPrompt(f.Cfg.MaxWorkers),
		Pool:         f.OrchPool,
		MaxContext:   f.Cfg.OrchestratorMaxContext,
		Compaction: agent.CompactionOptions{
			HighWatermark: f.Cfg.HighWatermark,
			LowWatermark:  f.Cfg.LowWatermark,
			KeepTurns:     f.Cfg.KeepTurns,
		},
		TurnTimeout:      f.Cfg.TurnTimeout,
		PerToolTimeout:   f.Cfg.PerToolTimeout,
		MaxParallelTools: f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent: f.Cfg.MaxTurnsPerAgent,
		OnMalformedCall:  f.malformedCallback(f.Cfg.OrchestratorModel),
		OnRequestStart:   onReqStart,
		OnRequestEnd:     onReqEnd,
		OnToolStart:      onToolStart,
		OnToolEnd:        onToolEnd,
	}), nil
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

	// Narrator runs on its own dedicated ChatClient so narration never queues
	// behind worker/verifier/director HTTP traffic.
	narrator := NewNarrator(NarratorConfig{
		Interval:   cfg.NarrateInterval,
		Model:      cfg.EffectiveSummaryModel(),
		Client:     agent.NewOpenAIChatClient(cfg.EffectiveSummaryBaseURL(), cfg.APIKey),
		CallBudget: cfg.NarrateTimeout,
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
		}
		log.Log("server", "narrator", fields)
	}

	malformed := NewMalformedCounter(log)
	defer malformed.Flush()
	factory := &OpenAIFactory{
		Cfg: cfg, WorkerPool: workerPool, OrchPool: orchPool,
		Malformed: malformed, Log: log,
	}

	candidates := NewCandidatePool()
	decisions := NewDecisionQueue()
	writer := NewFindingWriter(cfg.FindingsDir)

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
	director.SetTools(DirectorToolDefs(decisions))

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

	// phaseTransition logs a phase change and force-fires a narrator summary,
	// so the operator always gets a fresh sentence when the agent switches
	// between autonomous / verification / direction phases.
	phaseTransition := func(from, to string) {
		if log != nil {
			log.Log("controller", "phase", map[string]any{"from": from, "to": to})
		}
		narrator.TriggerNow()
	}

	var iteration int
	for iteration = 1; iteration <= cfg.MaxIterations; iteration++ {
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

		workerRuns := RunAllWorkersUntilEscalation(ctx, alive, candidates, log)
		UpdateStallStreaks(alive)

		// stall-force-stop happens before verification so the stalled worker's
		// run still feeds the verifier (spec §7.3)
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

		decisions.Reset()

		phaseTransition("autonomous", "verification")
		verificationSummary := RunVerificationPhase(
			ctx, verifier, decisions, candidates, writer,
			workerRuns, workers, iteration, cfg.MaxIterations, log,
		)

		phaseTransition("verification", "direction")
		stallWarnings := FormatStallWarnings(workers, cfg.StallWarnAfter)
		RunDirectionPhase(
			ctx, director, decisions, workers, workerRuns,
			verificationSummary, writer.SummaryForOrchestrator(), stallWarnings,
			iteration, cfg.MaxIterations, writer.Count, cfg.MaxWorkers, log,
		)
		LatchStallWarnings(workers, cfg.StallWarnAfter)

		if decisions.HasDone {
			// Guardrail: local models routinely confuse `done` with `direction_done`
			// on early iterations. Only accept `done` once the run has made
			// meaningful progress (filed findings, or exhausted several iterations).
			if iteration < MinIterationsForDone && writer.Count == 0 {
				if log != nil {
					log.Log("controller", "done ignored: premature", map[string]any{
						"iter":           iteration,
						"findings_count": writer.Count,
						"summary":        decisions.DoneSummary,
					})
				}
				decisions.HasDone = false
				decisions.DoneSummary = ""
			} else {
				if log != nil {
					log.Log("controller", "director done", map[string]any{"summary": decisions.DoneSummary})
				}
				break
			}
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
			"findings_count": writer.Count,
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
			w.ProgressNoneStreak = 0
			w.StallWarned = false
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
