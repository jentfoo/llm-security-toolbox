package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	NewVerifier(onContextOverflow func()) (agent.Agent, error)
	NewDirector() (agent.Agent, error)
	Close() error
}

// OpenAIFactory builds OpenAIAgent instances against the shared pool.
type OpenAIFactory struct {
	Cfg       *config.Config
	Pool      *agent.ClientPool
	Malformed *MalformedCounter
	Log       *Logger
	// Reasoning is the reasoning handler detected at startup for cfg.Model.
	// Nil falls back to inline.
	Reasoning agent.ReasoningHandler
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

// summarizeErrorCallback returns a hook that logs failed boundary-summarize
// attempts. The agent fails open regardless; this just records the failure
// so operators can see it in the JSON log.
func (f *OpenAIFactory) summarizeErrorCallback(role string) func(error) {
	if f.Log == nil {
		return nil
	}
	return func(err error) {
		f.Log.Log("agent", "summarize-error", map[string]any{
			"role": role,
			"err":  err.Error(),
		})
	}
}

// buildAgent assembles an OpenAIAgent for a role. Workers and verifiers set
// a FlowIDExtractor so their turn summaries can link reported flow IDs;
// directors don't dispatch sectool tools, so their extractor stays nil.
//
// onContextOverflow, when non-nil, fires once per chat-completion call that
// the model rejected as over-context. The verifier wires this to a captured
// bool so the controller can auto-dismiss in-flight candidates after a
// freshly composed phase still overflows.
func (f *OpenAIFactory) buildAgent(
	role, model, systemPrompt string,
	pool *agent.ClientPool,
	maxContext int,
	reasoning agent.ReasoningHandler,
	setFlowExtractor bool,
	onContextOverflow func(),
) agent.Agent {
	onReqStart, onReqEnd := f.requestCallbacks(role)
	onToolStart, onToolEnd := f.toolCallbacks(role)
	cfg := agent.OpenAIAgentConfig{
		Model:        model,
		SystemPrompt: systemPrompt,
		Pool:         pool,
		MaxContext:   maxContext,
		Compaction: agent.CompactionOptions{
			HighWatermark:          f.Cfg.HighWatermark,
			LowWatermark:           f.Cfg.LowWatermark,
			KeepTurns:              f.Cfg.KeepTurns,
			HardTruncateOnOverflow: true,
		},
		TurnTimeout:       f.Cfg.TurnTimeout,
		PerToolTimeout:    f.Cfg.PerToolTimeout,
		MaxParallelTools:  f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent:  f.Cfg.MaxTurnsPerAgent,
		KeepThinkTurns:    f.Cfg.EffectiveKeepThinkTurns(maxContext),
		Reasoning:         reasoning,
		OnMalformedCall:   f.malformedCallback(model),
		OnRequestStart:    onReqStart,
		OnRequestEnd:      onReqEnd,
		OnToolStart:       onToolStart,
		OnToolEnd:         onToolEnd,
		OnContextOverflow: onContextOverflow,
		OnSummarizeError:  f.summarizeErrorCallback(role),
	}
	if setFlowExtractor {
		cfg.FlowIDExtractor = ExtractFlowIDs
	}
	return agent.NewOpenAIAgent(cfg)
}

// withMission appends the run's mission (cfg.Prompt) to a role's system
// prompt as a non-negotiable anchor. The system prompt is preserved across
// every ReplaceHistory and every compaction pass, so anchoring the mission
// here means it survives every context-management operation. Empty mission
// renders nothing — keeps tests and bare-bones invocations clean.
func (f *OpenAIFactory) withMission(systemPrompt string) string {
	mission := strings.TrimSpace(f.Cfg.Prompt)
	if mission == "" {
		return systemPrompt
	}
	return systemPrompt + "\n\n## Mission (original assignment for this run — do not lose sight of this)\n\n" + mission
}

// NewWorker builds a worker agent with the given role-sizing.
func (f *OpenAIFactory) NewWorker(id, numWorkers int) (agent.Agent, error) {
	return f.buildAgent(
		fmt.Sprintf("worker-%d", id),
		f.Cfg.Model,
		f.withMission(prompts.BuildWorkerSystemPrompt(id, numWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		nil,
	), nil
}

// NewVerifier builds a verifier agent. onContextOverflow is wired through
// to OpenAIAgentConfig so the controller can detect a budget-stuck verifier
// after a fresh compose and auto-dismiss its in-flight candidates.
func (f *OpenAIFactory) NewVerifier(onContextOverflow func()) (agent.Agent, error) {
	return f.buildAgent(
		"verifier",
		f.Cfg.Model,
		f.withMission(prompts.BuildVerifierSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		onContextOverflow,
	), nil
}

// NewDirector builds a director agent.
func (f *OpenAIFactory) NewDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director",
		f.Cfg.Model,
		f.withMission(prompts.BuildDirectorSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		false,
		nil,
	), nil
}

// Close is a no-op (pools outlive the factory in typical use).
func (f *OpenAIFactory) Close() error { return nil }

// buildClientPool constructs n distinct ChatClient instances against baseURL
// and wraps them in a bounded-concurrency ClientPool. httpTimeout is a
// belt-and-suspenders outer bound for wedged keep-alives; 0 disables it
// (context deadlines still apply per call). Pass TurnTimeout + a small
// headroom so context cancellation, not the HTTP deadline, is the normal
// termination path.
func buildClientPool(baseURL, apiKey string, n int, httpTimeout time.Duration) *agent.ClientPool {
	if n < 1 {
		n = 1
	}
	clients := make([]agent.ChatClient, 0, n)
	for i := 0; i < n; i++ {
		clients = append(clients, agent.NewOpenAIChatClientWithTimeout(baseURL, apiKey, httpTimeout))
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
//
// Workers do NOT install an OnSummarizeBoundary callback — the per-iter
// install in installChronicle already produces a fresh summary from the
// canonical raw chronicle, so any in-iter boundary summarize would be
// summary-of-summary. In-iter context pressure is bounded by the iter's
// tool calls; the existing Compact passes handle that.
func newWorkerSpawner(
	mcpURL string,
	toolResultMaxBytes int,
	factory AgentFactory,
	candidates *CandidatePool,
	writer *FindingWriter,
	candidateDedup CandidateDedupReviewer,
	merger MergeSubmitter,
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
		tools := append(slices.Clone(defs), WorkerToolDefs(candidates, writer, id, candidateDedup, merger)...)
		a.SetTools(tools)
		ws := &WorkerState{
			ID:               id,
			Agent:            a,
			MCP:              m,
			Alive:            true,
			Assignment:       assignment,
			LastInstruction:  assignment,
			AutonomousBudget: autonomousBudget,
		}
		return ws, nil
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
			"model":     cfg.Model,
			"log_model": cfg.LogModel,
		})
	}

	// HTTP timeout is TurnTimeout + 2m headroom so context cancellation is
	// the normal termination path — the HTTP deadline only catches wedged
	// keep-alives that survive context cancellation.
	httpTimeout := cfg.TurnTimeout + 2*time.Minute
	pool := buildClientPool(cfg.BaseURL, cfg.APIKey, cfg.AgentPoolSize, httpTimeout)
	mainReasoning, logReasoning := probeReasoningHandlers(ctx, cfg, pool, log)

	malformed := NewMalformedCounter(log)
	defer malformed.Flush()
	factory := &OpenAIFactory{
		Cfg: cfg, Pool: pool,
		Malformed: malformed, Log: log,
		Reasoning: mainReasoning,
	}

	candidates := NewCandidatePool()
	decisions := NewDecisionQueue()
	writer := NewFindingWriter(cfg.FindingsDir)
	dedupReviewer := &OpenAIDedupReviewer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	// candidateDedup runs at the worker hot path: every report_finding_candidate
	// classifies the incoming candidate against existing finding digests via
	// the log model. Lighter than the verifier-side pair-wise reviewer above
	// and shares the same pool — different model identifier per request.
	candidateDedup := &OpenAIDedupReviewer{
		Pool:  pool,
		Model: cfg.LogModel,
		Log:   log,
	}
	// summarizer runs the on-demand boundary-summarize callback for workers
	// and the oldest-iters compression for the director. Routed through the
	// main pool/model — these summaries are load-bearing (they determine what
	// the worker remembers across long runs and how the director's planning
	// history compacts) so they get the main model, not the cheap log model.
	// Fires only when context pressure trips the watermark, not every iter.
	summarizer := &Summarizer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	// asyncMerger schedules merge-into-existing-finding goroutines when the
	// worker tool's dedup verdict is "merge". Bounded concurrency (cap=4) so
	// a flurry of candidates can't saturate the shared pool. Run() waits on
	// in-flight merges at shutdown so the user doesn't lose work mid-merge.
	asyncMerger := newAsyncMerger(ctx, candidateDedup, writer, log, 4)
	defer asyncMerger.Wait()

	// completed accumulates retired workers as the run progresses. The
	// director sees these in BuildDirectorPrompt as historical reference
	// (IDs are gone, not eligible for planning/forking/narration). retire
	// is invoked from applyDecision (kind=stop) and enforceStallStops; it
	// generates the canonical summary synchronously from the worker's
	// chronicle (the canonical raw record) so the summary is one-shot from
	// the source — never from a prior summary — preserving fidelity.
	var completed []CompletedWorker
	retire := func(rctx context.Context, w *WorkerState, reason string, iter int) {
		entry := CompletedWorker{ID: w.ID, StoppedAt: iter, Reason: reason}
		if len(w.Chronicle) > 0 {
			summary, sErr := summarizer.SummarizeCompletedWorker(rctx, w.Chronicle, cfg.Prompt, reason, w.ID)
			if sErr != nil {
				if log != nil {
					log.Log("summarize", "completed-worker fallback", map[string]any{
						"worker_id": w.ID, "err": sErr.Error(),
					})
				}
				entry.Summary = ""
			} else {
				entry.Summary = summary
			}
		}
		completed = append(completed, entry)
		w.Alive = false
		_ = w.Agent.Close()
		if log != nil {
			log.Log("controller", "worker retired", map[string]any{
				"worker_id": w.ID, "reason": reason, "iter": iter,
				"summary_chars": len(entry.Summary),
			})
		}
	}

	// verifierOverflowed is set true by the OpenAIAgent OnContextOverflow
	// callback when a chat-completion request was rejected as over-context.
	// The controller resets it before each verification phase compose and
	// reads it after the phase to drive the auto-dismiss-on-budget-exhaust
	// path. The write happens inside Drain on the agent's request goroutine
	// and the read happens after Drain returns on the controller goroutine,
	// so the goroutine join is the synchronizing event.
	var verifierOverflowed bool
	verifier, err := factory.NewVerifier(func() {
		verifierOverflowed = true
	})
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	defer func() { _ = verifier.Close() }()
	director, err := factory.NewDirector()
	if err != nil {
		return fmt.Errorf("new director: %w", err)
	}
	defer func() { _ = director.Close() }()
	// Wire director's boundary-summarize callback. The director's history
	// is long-lived; when watermark fires, this collapses the oldest
	// contiguous block of director messages into one concise recap and
	// returns it as the replacement slice. Different prompt variant from
	// worker (no goal/directive bias).
	if oa, ok := director.(*agent.OpenAIAgent); ok {
		oa.SetOnSummarizeBoundary(func(cctx context.Context, snapshot []agent.Message) ([]agent.Message, error) {
			out, sErr := summarizer.SummarizeDirectorOldest(cctx, snapshot)
			if sErr != nil {
				return nil, sErr
			}
			return []agent.Message{{Role: "user", Content: out}}, nil
		})
	}

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

	spawn := newWorkerSpawner(mcpURL, cfg.ToolResultMaxBytes, factory, candidates, writer, candidateDedup, asyncMerger, cfg.AutonomousBudget)

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

	// Narration runs through the shared pool with the log model. The
	// narrator's internal fireMu serializes calls so the "one summary in
	// flight" invariant holds without a dedicated pool slot.
	narrator := NewNarrator(NarratorConfig{
		Interval:   cfg.NarrateInterval,
		Model:      cfg.LogModel,
		Pool:       pool,
		CallBudget: cfg.NarrateTimeout,
		Summarizer: logReasoning,
		// Parent ctx — ctrl+c propagates to in-flight narration HTTP calls
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
			fields["pool_size"] = pool.Size()
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

		// Phase entry: summarize each alive worker's chronicle fresh and
		// install the result as the worker's pre-iter context. Always
		// summarized from canonical raw bytes — never from a prior
		// summary — so worker focus doesn't drift across iterations.
		installWorkerChroniclesAtIterStart(ctx, alive, summarizer.SummarizeWorkerFromChronicle, cfg.Prompt, iteration, log)

		phaseTransition("idle", "autonomous")
		narrator.Tick()

		candidatesBefore := candidates.Counter()
		// Snapshot angles BEFORE applyDecision mutates LastInstruction at the
		// end of the iteration so history reflects what the worker actually
		// worked on.
		angleAt, aliveAtStart := snapshotIterationStart(alive)
		workerRuns := RunAllWorkersUntilEscalation(ctx, alive, candidates, log)
		UpdateStallStreaks(alive)

		// Extract this iter's new content into each worker's chronicle so the
		// next iter's install sees verbatim turns.
		extractWorkerChroniclesAtIterEnd(alive, iteration, log)

		// stall-force-stop happens before verification so the stalled worker's
		// run still feeds the verifier (spec §7.3). Both silent and error
		// escalations count toward ProgressNoneStreak (see UpdateStallStreaks),
		// so a worker that consistently times out or crashes terminates at
		// the same threshold as one that goes silent by choice.
		enforceStallStops(ctx, workers, cfg.StallStopAfter, retire, iteration, log)

		// Dead-iteration short-circuit: if every worker produced zero tool
		// calls AND no new candidates were filed this iteration, there is
		// nothing for the verifier to process and nothing new for the
		// director to plan against. Skip both phases to save orchestrator
		// LLM budget. With v3, no follow-up Query is needed — the next
		// iteration's compose layer rebuilds each worker's history from
		// scratch.
		if isDeadIteration(workerRuns, candidatesBefore, candidates.Counter()) {
			if log != nil {
				log.Log("controller", "dead-iteration", map[string]any{"iter": iteration})
			}
			// Record a history entry even on dead iterations so the director
			// still sees the streak next time around.
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			narrator.TriggerNow()
			continue
		}

		decisions.Reset()

		// Verification phase entry: install fresh history with the iter's
		// directive. Reset overflow watchdog for the phase. Mission lives
		// in the verifier's system prompt and is re-prepended automatically
		// by ReplaceHistory.
		verifierOverflowed = false
		verifierDirective := BuildVerifierPrompt(
			workers, workerRuns, candidates.Pending(),
			writer.SummaryForOrchestrator(),
			iteration, cfg.MaxIterations, writer.RunCount,
		)
		verifier.ReplaceHistory(ComposeVerifier(verifierDirective))
		if log != nil {
			log.Log("compose", "installed", map[string]any{"role": "verifier", "iter": iteration})
		}

		phaseTransition("autonomous", "verification")
		verificationSummary := RunVerificationPhase(
			ctx, verifier, decisions, candidates, writer, dedupReviewer, log,
		)
		// If the verifier overflowed even after a fresh compose, the model
		// can't reproduce its candidates under the current budget. Drop
		// them so the next iteration doesn't re-burn the same tokens.
		if verifierOverflowed && !decisions.HasVerificationDone && len(candidates.Pending()) > 0 {
			AutoDismissOnContextOverflow(candidates, decisions, log)
		}

		// Direction phase entry: director uses a long-lived chat history
		// that grows naturally across iterations. Mark the iteration
		// boundary BEFORE the directive Query so the boundary-summarize
		// callback (configured at director-construction time) can collapse
		// older director iterations into a single concise recap when
		// context pressure trips the watermark, leaving this iter's work
		// verbatim.
		stallWarnings := FormatStallWarnings(workers, cfg.StallWarnAfter)
		followUpHints := FormatFollowUpHints(decisions.Findings, decisions.Dismissals)
		directorDirective := BuildDirectorPrompt(
			workers, workerRuns, verificationSummary, writer.SummaryForOrchestrator(),
			stallWarnings, followUpHints, completed,
			iteration, cfg.MaxIterations, writer.RunCount, cfg.MaxWorkers,
		)
		director.MarkIterationBoundary()
		director.Query(directorDirective)

		phaseTransition("verification", "direction")
		RunDirectionPhase(ctx, director, decisions, workers, log)
		LatchStallWarnings(workers, cfg.StallWarnAfter)

		if decisions.HasEndRun {
			// The end_run tool handler already enforced MinIterationsForDone /
			// RunCount; by the time HasEndRun is true the director has met the
			// bar, so the controller just honors it. Skip summarization —
			// the next iteration won't run.
			if log != nil {
				log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
			}
			break
		}

		if decisions.HasPlan {
			applyPlanDiff(ctx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, log)
		}

		if decisions.HasForks {
			applyForkDiff(ctx, decisions.Forks, &workers, spawn, cfg.MaxWorkers, iteration, log)
		}

		// apply per-worker decisions, after coalescing director duplicates
		effective := coalesceDecisions(decisions.WorkerDecisions, decisions.Plan)
		if log != nil && len(effective) != len(decisions.WorkerDecisions) {
			log.Log("decision", "coalesced", map[string]any{
				"original":  len(decisions.WorkerDecisions),
				"effective": len(effective),
			})
		}
		applyEffectiveDecisions(ctx, effective, workers, retire, iteration, log)

		// Record per-worker history for this iteration now that autonomous,
		// verification, and direction have all landed. Outcome derivation
		// uses decisions + candidates, so it must run after decisions are
		// applied.
		appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)

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

// retireFunc summarizes a worker's full investigation and retires it.
// Implementations append a CompletedWorker entry to the run's registry,
// then close the worker's agent. The iter parameter is the iteration in
// which the retirement decision was taken — recorded as StoppedAt on the
// CompletedWorker so the director prompt can show "stopped iter N".
// Synchronous so the next director prompt renders the new entry. Pass
// nil from test contexts where summarization is undesirable; the caller
// then becomes responsible for closing the agent.
type retireFunc func(ctx context.Context, w *WorkerState, reason string, iter int)

func applyDecision(ctx context.Context, d WorkerDecision, w *WorkerState, retire retireFunc, iter int, log *Logger) {
	if d.Kind == "stop" {
		if log != nil {
			log.Log("decision", "stop", map[string]any{"worker_id": w.ID, "reason": d.Reason})
		}
		if retire != nil {
			retire(ctx, w, d.Reason, iter)
		} else {
			w.Alive = false
			_ = w.Agent.Close()
		}
		return
	}
	budget := d.AutonomousBudget
	if budget <= 0 {
		budget = defaultAutonomousBudget
	}
	budget = min(budget, 20)
	w.AutonomousBudget = budget
	w.LastInstruction = d.Instruction
	// v4: no Query here — the next iteration's installChronicle will
	// re-install the chronicle (wiping any pending Query) and Query
	// w.LastInstruction itself. Pre-Query'ing would be a no-op at best
	// and could create transient two-user-message states at worst.
	if log != nil {
		log.Log("decision", d.Kind, map[string]any{
			"worker_id":         w.ID,
			"autonomous_budget": budget,
		})
	}
}

// applyForkDiff spawns a new worker per ForkEntry, copying the parent's
// chronicle so the child reads parent's prior investigation on first
// install. Validation that already happened in the tool handler:
// parent_worker_id != new_worker_id, instruction non-empty, both >=1. We
// re-verify at apply time because director state may have shifted between
// tool call and apply (e.g. parent stopped in the same direction phase).
//
// Rules:
//   - Parent must be alive at apply time. If retired since the tool call,
//     log and skip — the inheritance contract is no longer meaningful.
//   - new_worker_id must not collide with an alive worker.
//   - Hitting maxWorkers cap skips the fork (logged).
//
// Inheritance framing: the child's chronicle is prepended with a synthetic
// inheritance header so the next install's summarizer reads the parent's
// turns under the correct frame ("you are now worker N picking up the
// thread") rather than mistakenly treating them as the child's own work.
func applyForkDiff(
	ctx context.Context,
	forks []ForkEntry,
	workers *[]*WorkerState,
	spawn workerSpawnFunc,
	maxWorkers int,
	iter int,
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
	for _, f := range forks {
		parent, ok := byID[f.ParentWorkerID]
		if !ok || !parent.Alive {
			if log != nil {
				log.Log("fork", "skipped: parent unavailable", map[string]any{
					"parent": f.ParentWorkerID, "new": f.NewWorkerID,
				})
			}
			continue
		}
		if w, exists := byID[f.NewWorkerID]; exists && w.Alive {
			if log != nil {
				log.Log("fork", "skipped: new id collides with alive worker", map[string]any{
					"parent": f.ParentWorkerID, "new": f.NewWorkerID,
				})
			}
			continue
		}
		if existing >= maxWorkers {
			if log != nil {
				log.Log("fork", "skipped: max_workers", map[string]any{
					"parent": f.ParentWorkerID, "new": f.NewWorkerID,
				})
			}
			continue
		}
		nw, err := spawn(ctx, f.NewWorkerID, existing+1, f.Instruction)
		if err != nil {
			if log != nil {
				log.Log("fork", "spawn failed", map[string]any{
					"parent": f.ParentWorkerID, "new": f.NewWorkerID, "err": err.Error(),
				})
			}
			continue
		}
		header := agent.Message{
			Role: "user",
			Content: fmt.Sprintf(
				"[Inherited investigative history from worker %d at iter %d. The remainder of this chronicle records that worker's prior turns; you are now worker %d, picking up the thread under a new directive.]",
				parent.ID, iter, nw.ID,
			),
		}
		nw.Chronicle = make([]agent.Message, 0, 1+len(parent.Chronicle))
		nw.Chronicle = append(nw.Chronicle, header)
		nw.Chronicle = append(nw.Chronicle, parent.Chronicle...)
		*workers = append(*workers, nw)
		byID[nw.ID] = nw
		existing++
		if log != nil {
			log.Log("fork", "spawn", map[string]any{
				"parent": f.ParentWorkerID, "new": f.NewWorkerID,
				"inherited_msgs": len(nw.Chronicle),
			})
		}
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
			// v4: no Query here — the next iter's installChronicle re-installs
			// the chronicle and Queries w.LastInstruction (= the new assignment).
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

// probeReasoningHandlers detects reasoning-format support for the main and
// log models. When both names match, a single resolveFormat call covers
// both; otherwise the two probes run concurrently and share a cache so
// identical (baseURL, model) pairs only fire one detection call.
func probeReasoningHandlers(
	ctx context.Context, cfg *config.Config, pool *agent.ClientPool, log *Logger,
) (mainR, logR agent.ReasoningHandler) {
	cache := agent.NewReasoningFormatCache()
	if cfg.LogModel == cfg.Model {
		f := resolveFormat(ctx, cache, pool, "main", cfg.BaseURL, cfg.Model, log)
		h := agent.NewReasoningHandler(f)
		return h, h
	}
	var mainFmt, logFmt agent.ReasoningFormat
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		mainFmt = resolveFormat(gctx, cache, pool, "main", cfg.BaseURL, cfg.Model, log)
		return nil
	})
	g.Go(func() error {
		logFmt = resolveFormat(gctx, cache, pool, "log", cfg.BaseURL, cfg.LogModel, log)
		return nil
	})
	_ = g.Wait()
	return agent.NewReasoningHandler(mainFmt), agent.NewReasoningHandler(logFmt)
}

// installWorkerChroniclesAtIterStart summarizes each alive worker's
// chronicle fresh and installs the result as that worker's pre-iter
// context. Workers run concurrently (bounded by the shared LLM pool) so
// per-iter latency is dominated by the slowest summary, not the sum.
func installWorkerChroniclesAtIterStart(
	ctx context.Context,
	alive []*WorkerState,
	summarize chronicleSummarizeFn,
	mission string,
	iteration int,
	log *Logger,
) {
	if len(alive) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, w := range alive {
		wg.Add(1)
		go func(w *WorkerState) {
			defer wg.Done()
			installChronicle(ctx, w, w.LastInstruction, summarize, mission, log)
			if log != nil {
				log.Log("chronicle", "install", map[string]any{
					"worker_id":      w.ID,
					"iter":           iteration,
					"chronicle_msgs": len(w.Chronicle),
				})
			}
		}(w)
	}
	wg.Wait()
}

// snapshotIterationStart records each worker's current angle before the
// autonomous phase mutates LastInstruction. Returns the angle map and an
// alive-set used by appendIterationHistory.
func snapshotIterationStart(alive []*WorkerState) (angleAt map[int]string, aliveAtStart map[int]bool) {
	angleAt = map[int]string{}
	aliveAtStart = map[int]bool{}
	for _, w := range alive {
		angleAt[w.ID] = w.LastInstruction
		aliveAtStart[w.ID] = true
	}
	return
}

// extractWorkerChroniclesAtIterEnd reads each alive worker's iteration
// boundary onward off its agent and appends it to the worker's chronicle.
// Called after the autonomous phase so the next iter's installChronicle
// sees the iter's verbatim turns.
func extractWorkerChroniclesAtIterEnd(alive []*WorkerState, iteration int, log *Logger) {
	for _, w := range alive {
		extractAndAppend(w)
		if log != nil {
			log.Log("chronicle", "extract", map[string]any{
				"worker_id":      w.ID,
				"iter":           iteration,
				"chronicle_msgs": len(w.Chronicle),
			})
		}
	}
}

// enforceStallStops retires every still-alive worker whose
// ProgressNoneStreak has reached stopAfter. Runs before verification so the
// stalled worker's run still feeds the verifier (spec §7.3).
func enforceStallStops(ctx context.Context, workers []*WorkerState, stopAfter int, retire retireFunc, iter int, log *Logger) {
	for _, w := range workers {
		if w.Alive && w.ProgressNoneStreak >= stopAfter {
			if log != nil {
				log.Log("controller", "stall-force-stop", map[string]any{
					"worker_id": w.ID, "streak": w.ProgressNoneStreak,
				})
			}
			if retire != nil {
				retire(ctx, w, "stall-force-stop", iter)
			} else {
				w.Alive = false
				w.Close()
			}
		}
	}
}

// applyEffectiveDecisions applies each coalesced WorkerDecision onto its
// target worker. Decisions referencing dead or unknown workers are
// dropped (and logged when a logger is attached).
func applyEffectiveDecisions(ctx context.Context, effective []WorkerDecision, workers []*WorkerState, retire retireFunc, iter int, log *Logger) {
	for _, d := range effective {
		w := findWorker(workers, d.WorkerID)
		if w == nil || !w.Alive {
			if log != nil {
				log.Log("controller", "decision for unknown/dead worker", map[string]any{"worker_id": d.WorkerID})
			}
			continue
		}
		applyDecision(ctx, d, w, retire, iter, log)
	}
}
