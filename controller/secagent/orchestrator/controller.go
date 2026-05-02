package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-analyze/bulk"
	"golang.org/x/sync/errgroup"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/config"
	"github.com/go-appsec/secagent/history"
	"github.com/go-appsec/secagent/mcp"
	"github.com/go-appsec/secagent/prompts"
)

// AgentFactory builds Agent instances per role. NewReconWorker omits
// report_finding_candidate so recon cannot file findings.
type AgentFactory interface {
	NewWorker(id, numWorkers int) (agent.Agent, error)
	NewReconWorker(reconMission string) (agent.Agent, error)
	NewVerifier(onContextOverflow func()) (agent.Agent, error)
	NewDecisionDirector() (agent.Agent, error)
	NewSynthesisDirector() (agent.Agent, error)
	Close() error
}

// OpenAIFactory builds OpenAIAgent instances against the shared pool.
type OpenAIFactory struct {
	Cfg       *config.Config
	Pool      *agent.ClientPool
	Malformed *MalformedCounter
	Log       *Logger
	// Reasoning handler for cfg.Model; nil falls back to inline.
	Reasoning agent.ReasoningHandler
	// Summarizer drives worker model-driven compaction callbacks; nil disables.
	Summarizer *history.Summarizer
	// ReconSummary is anchored into every subsequent worker's system prompt.
	ReconSummary string
}

// slowToolThreshold is the elapsed time at which a successful tool call
// is mirrored to stderr instead of staying in the JSON log.
const slowToolThreshold = 5 * time.Second

func (f *OpenAIFactory) malformedCallback(model string) func(name string, err error) {
	if f.Malformed == nil {
		return nil
	}
	return func(name string, err error) { f.Malformed.Observe(model, name, err) }
}

// requestCallbacks returns start/end hooks that log each chat-completion
// call tagged with role. Returns (nil, nil) when f.Log is nil.
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

// toolCallbacks returns start/end hooks for tool dispatches tagged with
// role. Returns (nil, nil) when f.Log is nil.
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

// fuzzyToolMatchCallback returns a hook that logs each fuzzy tool-name
// match. Returns nil when f.Log is nil.
func (f *OpenAIFactory) fuzzyToolMatchCallback(role string) func(received, resolved string) {
	if f.Log == nil {
		return nil
	}
	return func(received, resolved string) {
		f.Log.Log("tool", "fuzzy-name-match", map[string]any{
			"role":     role,
			"received": received,
			"resolved": resolved,
		})
	}
}

// callbackErrorCallback returns a hook that logs failures from the
// model-driven aux compaction passes (self-prune, distill). Returns nil
// when f.Log is nil.
func (f *OpenAIFactory) callbackErrorCallback(role string) func(error) {
	if f.Log == nil {
		return nil
	}
	return func(err error) {
		f.Log.Log("agent", "compact-callback-error", map[string]any{
			"role": role,
			"err":  err.Error(),
		})
	}
}

// compactCallback returns a hook that logs each completed compaction event
// tagged with role. phase is the deepest pass the compactor had to reach
// to relieve pressure (last entry in PassesApplied). Returns nil when
// f.Log is nil.
func (f *OpenAIFactory) compactCallback(role string) func(agent.CompactionReport) {
	if f.Log == nil {
		return nil
	}
	return func(r agent.CompactionReport) {
		fields := map[string]any{
			"role":   role,
			"before": r.Before,
			"after":  r.After,
		}
		if n := len(r.PassesApplied); n > 0 {
			fields["phase"] = r.PassesApplied[n-1]
		}
		f.Log.Log("agent", "compact", fields)
	}
}

// buildAgent assembles an OpenAIAgent for a role.
//
// setFlowExtractor wires ExtractFlowIDs onto the agent's turn summaries.
// onContextOverflow fires once per chat-completion call rejected as
// over-context. retireOnPressure stops compaction so the agent retires at
// the high watermark instead. wireCompactionAssist installs the
// model-driven self-prune and distill callbacks (workers only).
func (f *OpenAIFactory) buildAgent(
	role, model, systemPrompt string,
	pool *agent.ClientPool,
	maxContext int,
	reasoning agent.ReasoningHandler,
	setFlowExtractor bool,
	onContextOverflow func(),
	retireOnPressure bool,
	wireCompactionAssist bool,
) agent.Agent {
	onReqStart, onReqEnd := f.requestCallbacks(role)
	onToolStart, onToolEnd := f.toolCallbacks(role)
	compactionOpts := agent.CompactionOptions{
		HighWatermark:          f.Cfg.HighWatermark,
		LowWatermark:           f.Cfg.LowWatermark,
		KeepTurns:              f.Cfg.KeepTurns,
		HardTruncateOnOverflow: true,
	}
	compactorOpts := history.CompactorOptions{
		Compaction:       compactionOpts,
		RetireOnPressure: retireOnPressure,
		OnCallbackError:  f.callbackErrorCallback(role),
		OnCompact:        f.compactCallback(role),
	}
	if wireCompactionAssist && f.Summarizer != nil {
		compactorOpts.OnSelfPruneCandidates = history.SelfPruneCallback(f.Summarizer)
		compactorOpts.OnDistillResults = history.DistillCallback(f.Summarizer)
	}
	cfg := agent.OpenAIAgentConfig{
		Model:             model,
		SystemPrompt:      systemPrompt,
		Pool:              pool,
		MaxContext:        maxContext,
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
		OnFuzzyToolMatch:  f.fuzzyToolMatchCallback(role),
		OnContextOverflow: onContextOverflow,
		OnHardTruncate:    f.compactCallback(role),
		Compactor:         history.NewLayeredCompactor(compactorOpts),
	}
	if setFlowExtractor {
		cfg.FlowIDExtractor = ExtractFlowIDs
	}
	return agent.NewOpenAIAgent(cfg)
}

// withMission appends cfg.Prompt and ReconSummary (when non-empty) to
// systemPrompt as anchored sections.
func (f *OpenAIFactory) withMission(systemPrompt string) string {
	mission := strings.TrimSpace(f.Cfg.Prompt)
	out := systemPrompt
	if mission != "" {
		out += "\n\n## Mission (original assignment for this run — do not lose sight of this)\n\n" + mission
	}
	recon := strings.TrimSpace(f.ReconSummary)
	if recon != "" {
		out += "\n\n## Recon (iter-1 scope mapping by retired worker 1 — anchored context for every subsequent worker)\n\n" + recon
	}
	return out
}

// withRecon appends reconMission to systemPrompt as an anchored section.
// Empty reconMission returns systemPrompt unchanged.
func (f *OpenAIFactory) withRecon(systemPrompt, reconMission string) string {
	out := systemPrompt
	if recon := strings.TrimSpace(reconMission); recon != "" {
		out += "\n\n## Recon goal (this run's surface-mapping objective — observation only)\n\n" + recon
	}
	return out
}

// NewWorker returns a worker agent with the given id out of numWorkers.
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
		false,
		true, // wire model-driven compaction assist (workers only)
	), nil
}

// NewReconWorker returns the iter-1 recon worker agent anchored to
// reconMission. The agent retires at the high watermark instead of
// compacting (preserving the chronicle for the retire summary).
func (f *OpenAIFactory) NewReconWorker(reconMission string) (agent.Agent, error) {
	return f.buildAgent(
		"worker-1-recon",
		f.Cfg.Model,
		f.withRecon(prompts.BuildReconWorkerSystemPrompt(), reconMission),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		nil,
		true,  // RetireOnPressure: recon stops cleanly at high watermark
		false, // RetireOnPressure short-circuits maybeCompact, so callbacks are unreachable; skip wiring
	), nil
}

// NewVerifier returns a verifier agent. onContextOverflow fires when a
// chat-completion call is rejected as over-context.
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
		false,
		true, // wire model-driven compaction assist (parity with workers)
	), nil
}

// NewDecisionDirector returns the per-worker decision director agent.
func (f *OpenAIFactory) NewDecisionDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director-review",
		f.Cfg.Model,
		f.withMission(prompts.BuildDirectorDecisionSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		false,
		nil,
		false,
		false, // director compaction stays mechanical
	), nil
}

// NewSynthesisDirector returns the iteration-end synthesis director agent.
func (f *OpenAIFactory) NewSynthesisDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director-plan",
		f.Cfg.Model,
		f.withMission(prompts.BuildDirectorSynthesisSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		false,
		nil,
		false,
		false, // director compaction stays mechanical
	), nil
}

// Close is a no-op.
func (f *OpenAIFactory) Close() error { return nil }

// buildClientPool returns a bounded-concurrency ClientPool of n distinct
// ChatClient instances against baseURL. httpTimeout caps each HTTP call;
// 0 disables it.
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

// resolveFormat returns the reasoning format for (baseURL, model) via cache,
// probing through a pool-acquired client on cache miss.
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

// workerSpawnFunc returns a ready-to-run worker provisioned with id,
// numWorkers and the assignment as its initial LastInstruction.
type workerSpawnFunc func(ctx context.Context, id, numWorkers int, assignment string) (*WorkerState, error)

// newWorkerSpawner returns a workerSpawnFunc that provisions workers
// against the MCP endpoint at mcpURL.
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
			LastInstruction:  assignment,
			AutonomousBudget: autonomousBudget,
		}
		// Buffer self-prune drops so RunDecisionPhase can mirror them onto
		// DirectorChat and the chronicle.
		if oa, ok := a.(*agent.OpenAIAgent); ok {
			oa.SetOnSelfPruneApplied(ws.BufferSelfPrunes)
		}
		return ws, nil
	}
}

// spawnReconWorker returns the iter-1 recon worker (id=1) provisioned
// against mcpURL. report_finding_candidate is not registered, so the
// worker cannot file findings.
func spawnReconWorker(
	ctx context.Context,
	mcpURL string,
	toolResultMaxBytes int,
	factory AgentFactory,
	reconMission, assignment string,
	autonomousBudget int,
) (*WorkerState, error) {
	m, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return nil, fmt.Errorf("mcp connect (recon worker): %w", err)
	}
	defs, err := m.BuildToolDefs(ctx, "mcp__sectool__", toolResultMaxBytes)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("list sectool tools (recon worker): %w", err)
	}
	a, err := factory.NewReconWorker(reconMission)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("new recon worker: %w", err)
	}
	a.SetTools(defs)
	return &WorkerState{
		ID:               1,
		Agent:            a,
		MCP:              m,
		Alive:            true,
		LastInstruction:  assignment,
		AutonomousBudget: autonomousBudget,
	}, nil
}

// Run starts sectool and drives the iteration loop until cfg.MaxIterations
// is reached or the director ends the run. A nil sd is replaced with a
// fresh Shutdown derived from ctx.
func Run(ctx context.Context, cfg *config.Config, log *Logger, sd *Shutdown) error {
	if sd == nil {
		sd = NewShutdown(ctx, log)
	}
	srv, err := StartSectool(cfg.ProxyPort, cfg.MCPPort, log)
	if err != nil {
		return fmt.Errorf("sectool start: %w", err)
	}
	defer srv.Terminate()

	mcpURL := srv.URL

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
	// Dedicated log pool isolates narrator + log-model probes from main-pool
	// contention, so worker turns can't starve operator-facing narration.
	logPool := buildClientPool(cfg.BaseURL, cfg.APIKey, cfg.LogPoolSize(), httpTimeout)
	mainReasoning, logReasoning := probeReasoningHandlers(ctx, cfg, pool, logPool, log)

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
	// dedupReviewer is shared between the verifier-side filed-finding dedup
	// pipeline, the worker-hot-path candidate classifier, and the async
	// merger. All three feed verdicts back into agent context (worker tool
	// results, merged finding bodies the director reads), so they run on
	// the main model — the cheaper log model produced too many false-merge
	// verdicts that silently dropped distinct findings.
	dedupReviewer := &OpenAIDedupReviewer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	// summarizer runs the on-demand boundary-summarize callback for workers
	// and the oldest-iters compression for the director. Routed through the
	// main pool/model — these summaries are load-bearing (they determine what
	// the worker remembers across long runs and how the director's planning
	// history compacts) so they get the main model, not the cheap log model.
	// Fires only when context pressure trips the watermark, not every iter.
	summarizer := &history.Summarizer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	// Wire the summarizer onto the factory so subsequent NewWorker calls
	// install the model-driven self-prune and distill callbacks.
	factory.Summarizer = summarizer
	// asyncMerger schedules merge-into-existing-finding goroutines when the
	// worker tool's dedup verdict is "merge". Bounded concurrency (cap=4) so
	// a flurry of candidates can't saturate the shared pool. Run() waits on
	// in-flight merges at shutdown so the user doesn't lose work mid-merge.
	asyncMerger := newAsyncMerger(ctx, dedupReviewer, writer, log, 4)
	defer asyncMerger.Wait()

	// completed is the controller-side registry of retired workers — used
	// for plan_workers ID-collision validation and synthesis-prompt
	// rendering. Mutated on the main goroutine when DrainCompleted picks
	// up async retire summaries; read by closures handed to the tools
	// layer.
	var completed []CompletedWorker
	// retireQueue summarizes retired workers in the background so the
	// controller's main loop never blocks on the LLM call.
	retireQueue := newRetireQueue(ctx, summarizer, cfg.Prompt, log, 4)
	defer retireQueue.Wait()

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
	// Two phase-scoped director agents share the canonical DirectorChat.
	// The decision agent's system prompt only describes decide_worker; the
	// synthesis agent's only describes plan_workers / direction_done /
	// end_run. Splitting them keeps the model from hallucinating tools that
	// aren't registered for the current phase.
	decisionDirector, err := factory.NewDecisionDirector()
	if err != nil {
		return fmt.Errorf("new decision director: %w", err)
	}
	defer func() { _ = decisionDirector.Close() }()
	synthesisDirector, err := factory.NewSynthesisDirector()
	if err != nil {
		return fmt.Errorf("new synthesis director: %w", err)
	}
	defer func() { _ = synthesisDirector.Close() }()

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

	// Both directors get full sectool access so they can spot-check worker
	// claims directly instead of either spawning a verification worker or
	// hallucinating tool calls from worker history. Each director gets its
	// own MCP client per spec §6. Decision and synthesis directors run
	// sequentially per phase, but separate clients keep tool dispatch state
	// cleanly scoped per agent and match the existing one-client-per-agent
	// pattern.
	decisionDirectorMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (decision director): %w", err)
	}
	defer func() { _ = decisionDirectorMCP.Close() }()
	decisionDirectorSectoolDefs, err := decisionDirectorMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list decision director sectool tools: %w", err)
	}
	synthesisDirectorMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (synthesis director): %w", err)
	}
	defer func() { _ = synthesisDirectorMCP.Close() }()
	synthesisDirectorSectoolDefs, err := synthesisDirectorMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list synthesis director sectool tools: %w", err)
	}

	verifierTools := append(slices.Clone(verifierSectoolDefs), VerifierToolDefs(decisions)...)
	verifier.SetTools(verifierTools)

	spawn := newWorkerSpawner(mcpURL, cfg.ToolResultMaxBytes, factory, candidates, writer, dedupReviewer, asyncMerger, cfg.AutonomousBudget)

	workers := make([]*WorkerState, 0, cfg.MaxWorkers)
	defer func() {
		for _, w := range workers {
			w.Close()
		}
	}()
	// Iter 1 spawn: either the recon worker (default) or a normal
	// testing worker (--skip-recon). The recon worker is anchored to a
	// recon-mission summary, not cfg.Prompt, and has no
	// report_finding_candidate registered; its retirement summary
	// becomes the anchored context for every subsequent worker
	// (factory.ReconSummary). With --skip-recon the iter-1 worker is a
	// regular testing worker against cfg.Prompt — useful for A/B
	// comparing the value of the recon iter on a given target.
	var w1 *WorkerState
	if cfg.SkipRecon {
		if log != nil {
			log.Log("server", "recon", map[string]any{"enabled": false, "reason": "--skip-recon"})
		}
		w1, err = spawn(ctx, 1, 1, cfg.Prompt)
		if err != nil {
			return err
		}
		if log != nil {
			log.Log("worker", "seeded testing worker (skip-recon)", map[string]any{"id": 1})
		}
	} else {
		reconMission, rerr := summarizer.SummarizeReconMission(ctx, cfg.Prompt)
		if rerr != nil || reconMission == "" {
			// Fail-soft: if the recon-mission summary fails (model
			// error, empty output), use cfg.Prompt verbatim. The recon
			// worker is still tool-restricted so the worst case is it
			// reads the full mission and tries to test — better than
			// blocking the entire run on a one-shot summarize call.
			if log != nil {
				fields := map[string]any{"fallback": "cfg.Prompt verbatim"}
				if rerr != nil {
					fields["err"] = rerr.Error()
				}
				log.Log("recon", "mission-summary failed", fields)
			}
			reconMission = cfg.Prompt
		}
		if log != nil {
			log.Log("recon", "start", map[string]any{
				"mission_chars":   len(reconMission),
				"mission_preview": history.Short(reconMission, 240),
			})
		}
		w1, err = spawnReconWorker(ctx, mcpURL, cfg.ToolResultMaxBytes, factory, reconMission, ReconDirective, cfg.AutonomousBudget)
		if err != nil {
			return err
		}
		if log != nil {
			log.Log("worker", "seeded recon", map[string]any{"id": 1})
		}
	}
	workers = append(workers, w1)

	// Canonical director chat — the long-lived record of every worker's
	// activity, every per-worker decision, the recon summary, retired-
	// worker summaries, verifier reports. The director agent is stateless
	// per call; each per-worker decision call and each synthesis call
	// installs a selectively-compacted view via ReplaceHistory.
	dirChat := NewDirectorChat()

	// guardIteration is updated by the main loop below; the closure captures
	// its address so end_run / takenIDs see live state instead of a stale
	// snapshot. writer.RunCount is read directly — the FindingWriter is
	// race-safe (internal mutex).
	var guardIteration int
	guardStateFn := func() (int, int) { return guardIteration, writer.RunCount }
	takenIDsFn := func() map[int]bool {
		out := map[int]bool{}
		for _, w := range workers {
			out[w.ID] = true // alive AND dead — both are taken
		}
		for _, c := range completed {
			out[c.ID] = true
		}
		return out
	}
	completedIDsFn := func() map[int]bool {
		out := map[int]bool{}
		for _, c := range completed {
			out[c.ID] = true
		}
		// Also include retired workers still in the workers slice (Alive=false)
		// — they may not yet be in `completed` (summary still in flight).
		for _, w := range workers {
			if !w.Alive {
				out[w.ID] = true
			}
		}
		return out
	}
	aliveWorkerIDsFn := func() []int {
		var out []int
		for _, w := range workers {
			if w.Alive {
				out = append(out, w.ID)
			}
		}
		return out
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
			var out []NamedAgent
			if oa, ok := decisionDirector.(*agent.OpenAIAgent); ok {
				out = append(out, NamedAgent{Name: "director-review", Agent: oa})
			}
			if oa, ok := synthesisDirector.(*agent.OpenAIAgent); ok {
				out = append(out, NamedAgent{Name: "director-plan", Agent: oa})
			}
			return out
		}
		return nil
	}

	// Narration runs through its own logPool so worker traffic on the main
	// pool can't starve operator-facing summaries. Pool capacity itself is
	// the only cap on concurrent narration calls.
	narrator := NewNarrator(NarratorConfig{
		Interval:   cfg.NarrateInterval,
		Model:      cfg.LogModel,
		Pool:       logPool,
		CallBudget: cfg.NarrateTimeout(),
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
			fields["timeout"] = cfg.NarrateTimeout().String()
			fields["pool_size"] = logPool.Size()
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

	// Closure: fire one worker's iter run as a goroutine, returning a
	// blocking join function. Used both to start iter-1 (worker 1) and to
	// fire each worker's iter+1 run from RunDecisionPhase / applyPlanAndFire
	// the moment its decision lands.
	fire := func(fctx context.Context, w *WorkerState) func() []agent.TurnSummary {
		resultCh := make(chan []agent.TurnSummary, 1)
		go func() {
			resultCh <- runOneWorker(fctx, w, candidates, log)
		}()
		return func() []agent.TurnSummary { return <-resultCh }
	}

	// Closure: spawn a forked child worker (used by RunDecisionPhase when
	// a decide_worker call carries a fork sub-action). The child gets its
	// inherited chronicle copied in by direct.go; we just provision the
	// agent + MCP client here. Always treats numWorkers as len(alive)+1
	// for the multi-worker addendum.
	spawnChild := func(sctx context.Context, id int, instruction string) (*WorkerState, error) {
		var alive int
		for _, w := range workers {
			if w.Alive {
				alive++
			}
		}
		nw, err := spawn(sctx, id, alive+1, instruction)
		if err != nil {
			return nil, err
		}
		workers = append(workers, nw)
		return nw, nil
	}

	// Closure: enqueue a worker for async retire. Workers go Alive=false
	// immediately; the LLM summarize call runs in the background and the
	// summary lands on retireQueue's results channel for the main loop
	// to drain at iter boundaries.
	retire := func(w *WorkerState, reason string, iter int) {
		retireQueue.Submit(w, reason, iter)
	}

	// applyRetiredSummaries drains every completed retire result from the
	// queue, replaces the worker's messages in dirChat with the summary
	// when one exists, and appends to the controller-side completed
	// registry. Idempotent / safe to call repeatedly.
	applyRetiredSummaries := func() {
		for _, r := range retireQueue.DrainCompleted() {
			if r.Summary != "" {
				dirChat.ReplaceWorkerWithSummary(r.WorkerID, r.Summary, r.Iter)
			}
			completed = append(completed, CompletedWorker{
				ID: r.WorkerID, StoppedAt: r.Iter, Reason: r.Reason, Summary: r.Summary,
			})
			if log != nil {
				if r.Summary != "" {
					log.Log("retire", "summary-applied", map[string]any{
						"worker_id": r.WorkerID, "iter": r.Iter, "summary_chars": len(r.Summary),
					})
				} else {
					log.Log("retire", "empty summary — keeping raw worker activity in dirChat", map[string]any{
						"worker_id": r.WorkerID, "iter": r.Iter,
					})
				}
			}
		}
	}

	// Iter-1 fire: kick off worker 1's recon run before the loop so the
	// loop's wait-for-in-flight pattern works uniformly from iter 1.
	w1.Chronicle.Install(w1.Agent, w1.LastInstruction)
	inflight := map[int]func() []agent.TurnSummary{}
	inflight[1] = fire(sd.WorkersCtx, w1)

	var iteration int
	for iteration = 1; iteration <= cfg.MaxIterations; iteration++ {
		guardIteration = iteration

		// Wait for in-flight worker iter runs (fired at end of iter-1 seed
		// or end of prior iter's decision/synthesis phase). workerRuns is
		// the iter's autonomous-phase output map.
		phaseTransition("idle", "autonomous")
		narrator.Tick()
		workerRuns := harvestInflight(inflight)
		inflight = map[int]func() []agent.TurnSummary{}

		// Cancellation checks AFTER harvest so any in-flight workers from
		// the previous iter are cleanly reaped first. Root-ctx cancellation
		// (parent died) takes the existing fast path; shutdown stage ≥ 1
		// breaks out so the post-loop block can run final verification.
		if err := ctx.Err(); err != nil {
			if log != nil {
				log.Log("controller", "cancelled", map[string]any{"iter": iteration, "err": err.Error()})
			}
			break
		}
		if sd.Phase() >= ShutdownPhaseVerifyOnly {
			if log != nil {
				log.Log("controller", "shutdown — exiting iteration loop", map[string]any{
					"iter": iteration, "phase": sd.Phase(),
				})
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

		candidatesBefore := candidates.Counter()
		angleAt, aliveAtStart := snapshotIterationStart(alive)

		UpdateStallStreaks(alive)
		// Extract iter's content into each alive worker's chronicle (and
		// run in-place compaction so older iters' bulk folds into stubs).
		extractWorkerChroniclesAtIterEnd(alive, iteration, log)

		// stall-force-stop: workers that have hit the silent-streak
		// threshold get retired. The retire enqueues async summarization;
		// the worker is Alive=false immediately so subsequent phases skip it.
		enforceStallStopsAsync(workers, cfg.StallStopAfter, retire, iteration, log)

		// Dead-iteration short-circuit: nothing happened, no candidates
		// filed. Skip verification/direction; record history; continue.
		if isDeadIteration(workerRuns, candidatesBefore, candidates.Counter()) {
			if log != nil {
				log.Log("controller", "dead-iteration", map[string]any{"iter": iteration})
			}
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			// Re-fire still-alive workers' next-iter runs with their existing
			// LastInstruction so the loop doesn't wedge on no-in-flight.
			refireAlive(sd.WorkersCtx, workers, fire, inflight, log)
			narrator.TriggerNow()
			continue
		}

		decisions.Reset()

		// Verification phase: fresh compose with the iter's directive.
		// Reset overflow watchdog. Mission and recon summary live in the
		// verifier's system prompt anchor; the per-iter directive includes
		// the recon summary as a header from iter 2+ (BuildVerifierPrompt).
		verifierOverflowed = false
		verifierDirective := BuildVerifierPrompt(
			workers, workerRuns, candidates.Pending(),
			writer.SummaryForOrchestrator(), factory.ReconSummary,
			iteration, cfg.MaxIterations, writer.RunCount,
		)
		verifier.ReplaceHistory([]agent.Message{{Role: "user", Content: verifierDirective}})
		if log != nil {
			log.Log("compose", "installed", map[string]any{"role": "verifier", "iter": iteration})
		}
		phaseTransition("autonomous", "verification")
		verificationSummary := RunVerificationPhase(
			sd.VerifierCtx, verifier, decisions, candidates, writer, dedupReviewer, log,
		)
		if verifierOverflowed && !decisions.HasVerificationDone && len(candidates.Pending()) > 0 {
			AutoDismissOnContextOverflow(candidates, decisions, log)
		}

		// Drain any retire summaries that have completed since last drain
		// (e.g. workers retired at iter N-1 that finished summarizing).
		applyRetiredSummaries()

		phaseTransition("verification", "direction")
		stallWarnings := FormatStallWarnings(workers, cfg.StallWarnAfter)
		followUpHints := FormatFollowUpHints(decisions.Findings, decisions.Dismissals)
		iterStatus := statusLine(iteration, cfg.MaxIterations, writer.RunCount)

		if iteration == 1 && !cfg.SkipRecon {
			// Iter-1 recon flow:
			//   1. Append worker 1's iter activity to dirChat.
			//   2. Retire worker 1, block on summary. ReplaceWorkerWithSummary
			//      ONLY when the summary is non-empty — an empty summary
			//      (summarize timeout / model error) would otherwise
			//      collapse the worker's evidence into nothing, leaving
			//      the director with no recon context.
			//   3. Review call: SetTools(nil); director reads the recon
			//      and produces free-form text proposing iter-2 worker
			//      assignments. Response is appended to dirChat.
			//   4. Plan call: SetTools(synthesis); director formalizes
			//      via plan_workers + direction_done, with one mandatory
			//      retry if plan_workers wasn't called.
			//   5. Fallback plan: if plan_workers still missing after
			//      retry, inject a single-worker plan with the original
			//      cfg.Prompt as the directive so iter 2 runs. Without
			//      this fallback the run terminates at iter 2's alive-
			//      check whenever the director can't commit to a plan.
			dirChat.AppendWorkerActivity(w1.ID, iteration, snapshotWorkerIterActivity(w1))
			retire(w1, "recon complete", iteration)
			if r, ok := retireQueue.WaitOne(ctx); ok {
				if r.Summary != "" {
					dirChat.ReplaceWorkerWithSummary(r.WorkerID, r.Summary, r.Iter)
					factory.ReconSummary = r.Summary
				} else if log != nil {
					log.Log("recon", "empty summary — keeping raw worker activity in dirChat", map[string]any{
						"worker_id": r.WorkerID,
					})
				}
				completed = append(completed, CompletedWorker{
					ID: r.WorkerID, StoppedAt: r.Iter, Reason: r.Reason, Summary: r.Summary,
				})
				if log != nil {
					// summary_tokens_est: calibrated estimate of the recon
					// summary anchored into every subsequent worker/director
					// system prompt — so this is the recurring per-call cost
					// the summary imposes on the rest of the run.
					log.Log("recon", "end", map[string]any{
						"worker_id":          r.WorkerID,
						"summary_chars":      len(r.Summary),
						"summary_tokens_est": agent.EstimateStringTokens(r.Summary),
					})
				}
				// Discard the recon worker's chronicle now that we have
				// the canonical summary in factory.ReconSummary. The
				// worker agent is already closed by retire; resetting
				// the chronicle releases the backing storage so it
				// doesn't sit around for the rest of the run.
				w1.Chronicle.Reset()
			}
			LatchStallWarnings(workers, cfg.StallWarnAfter)

			synthesisDirector.SetTools(nil)
			RunIter1ReconReviewCall(sd.WorkersCtx, synthesisDirector, dirChat, iterStatus, iteration, cfg.MaxWorkers, log)

			synthesisDirector.SetTools(append(slices.Clone(synthesisDirectorSectoolDefs),
				SynthesisToolDefs(decisions, guardStateFn, takenIDsFn, completedIDsFn, aliveWorkerIDsFn)...))
			RunIter1ReconPlanCall(sd.WorkersCtx, synthesisDirector, dirChat, decisions, iterStatus, iteration, cfg.MaxWorkers, log)

			if decisions.HasEndRun {
				if log != nil {
					log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
				}
				appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
				break
			}
			if !decisions.HasPlan {
				// Fallback: synthesis failed to commit to a plan even
				// after the retry. Inject a default single-worker plan
				// using the original mission so iter 2 still has work to
				// do. Surfacing the failure prominently so the operator
				// can tune the prompts; the run continues regardless.
				fallback := []PlanEntry{{WorkerID: 2, Assignment: cfg.Prompt}}
				decisions.SetPlan(fallback)
				if log != nil {
					log.Log("recon", "synthesis produced no plan — injecting fallback worker 2", map[string]any{
						"hint":            "director did not call plan_workers after retry; iter 2 spawns one worker with the original mission",
						"fallback_worker": 2,
						"fallback_assign": history.Short(cfg.Prompt, 200),
						"recon_summary":   history.Short(factory.ReconSummary, 200),
					})
				}
			}
			applyPlanAndFire(sd.WorkersCtx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, fire, inflight, log)
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			narrator.TriggerNow()
			continue
		}

		// Iter 2+: per-worker decision loop, then synthesis. Both directors
		// get sectool tools alongside their phase-primary tools so the
		// model can spot-check worker activity instead of either spawning
		// a verification worker or hallucinating tool calls from the
		// worker history that's already in its rendered view.
		decisionDirector.SetTools(append(slices.Clone(decisionDirectorSectoolDefs),
			DecisionToolDefs(decisions, takenIDsFn, log)...))
		decRes := RunDecisionPhase(sd.WorkersCtx, DecisionPhaseInput{
			Director: decisionDirector, DirChat: dirChat, Decisions: decisions,
			Workers: workers, WorkerRuns: workerRuns,
			IterationStatus: iterStatus, Iter: iteration, MaxWorkers: cfg.MaxWorkers,
			TakenIDs:   takenIDsFn,
			Fire:       fire,
			SpawnChild: spawnChild,
			Retire:     retire,
		}, log)
		LatchStallWarnings(workers, cfg.StallWarnAfter)
		// Drain retires that completed during the decision loop (stops).
		applyRetiredSummaries()

		// Synthesis call.
		synthesisDirector.SetTools(append(slices.Clone(synthesisDirectorSectoolDefs),
			SynthesisToolDefs(decisions, guardStateFn, takenIDsFn, completedIDsFn, aliveWorkerIDsFn)...))
		RunSynthesisPhase(sd.WorkersCtx, SynthesisPhaseInput{
			Director: synthesisDirector, DirChat: dirChat, Decisions: decisions,
			Workers: workers, Completed: completed,
			VerifierSummary: verificationSummary, FindingsSummary: writer.SummaryForOrchestrator(),
			StallWarnings: stallWarnings, FollowUpHints: followUpHints,
			IterationStatus: iterStatus, MaxWorkers: cfg.MaxWorkers,
		}, log)

		if decisions.HasEndRun {
			if log != nil {
				log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
			}
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			break
		}

		// Per-worker decisions may already have fired iter+1 runs. Publish them
		// before synthesis-plan apply so retargeting the same worker can cancel
		// and replace that in-flight run instead of launching a concurrent second
		// Drain on the same WorkerState.
		for id, j := range decRes.joins {
			inflight[id] = j
		}
		// Apply plan_workers (spawn fresh / retarget alive) and fire
		// iter+1 runs for the affected workers. Merge their joins into
		// inflight alongside the per-worker decision-fired runs.
		if decisions.HasPlan {
			applyPlanAndFire(sd.WorkersCtx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, fire, inflight, log)
		}

		appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
		narrator.TriggerNow()
	}

	// Wait for any in-flight runs the loop may have fired but never
	// harvested (e.g. end_run break path).
	for _, j := range inflight {
		_ = j()
	}

	// Multi-stage shutdown finalization. Runs only when the operator
	// requested a graceful shutdown via *Shutdown (Ctrl+C path). Stage 1
	// runs the verifier once on every still-pending candidate; stage 2
	// (or stage 1 followed by an in-flight 2nd Ctrl+C) dumps whatever's
	// still pending under the UNVALIDATED banner.
	if sd.Phase() >= ShutdownPhaseVerifyOnly {
		if sd.Phase() == ShutdownPhaseVerifyOnly && len(candidates.Pending()) > 0 {
			verifierOverflowed = false
			finalDirective := BuildVerifierPrompt(
				workers, map[int][]agent.TurnSummary{}, candidates.Pending(),
				writer.SummaryForOrchestrator(), factory.ReconSummary,
				iteration, cfg.MaxIterations, writer.RunCount,
			)
			verifier.ReplaceHistory([]agent.Message{{Role: "user", Content: finalDirective}})
			if log != nil {
				log.Log("shutdown", "final-verification start", map[string]any{
					"pending": len(candidates.Pending()),
				})
			}
			RunVerificationPhase(
				sd.VerifierCtx, verifier, decisions, candidates, writer, dedupReviewer, log,
			)
			if verifierOverflowed && len(candidates.Pending()) > 0 {
				AutoDismissOnContextOverflow(candidates, decisions, log)
			}
		}
		if sd.Phase() >= ShutdownPhaseDumpUnvalidated {
			DumpUnvalidatedCandidates(candidates.Pending(), writer, log)
		}
	}

	// Drain any retire summaries still pending so logs are complete.
	retireQueue.Wait()
	applyRetiredSummaries()

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

// isDeadIteration reports whether the autonomous phase produced no tool
// calls across any worker and no new candidates.
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

// applyPlanAndFire applies a plan_workers list (spawn fresh / retarget
// alive) and fires each affected worker's iter+1 run via fire, recording
// the join in inflight. Entries that exceed maxWorkers or collide with
// retired IDs are skipped with a log entry.
func applyPlanAndFire(
	ctx context.Context,
	plan []PlanEntry,
	workers *[]*WorkerState,
	spawn workerSpawnFunc,
	maxWorkers int,
	fire func(context.Context, *WorkerState) func() []agent.TurnSummary,
	inflight map[int]func() []agent.TurnSummary,
	log *Logger,
) {
	byID := map[int]*WorkerState{}
	var existing int
	planned := map[int]bool{}
	for _, w := range *workers {
		byID[w.ID] = w
		if w.Alive {
			existing++
		}
	}
	for _, p := range plan {
		if planned[p.WorkerID] {
			if log != nil {
				log.Log("plan", "duplicate entry skipped", map[string]any{"worker_id": p.WorkerID})
			}
			continue
		}
		planned[p.WorkerID] = true
		if w, ok := byID[p.WorkerID]; ok && w.Alive {
			stopInflightWorkerRun(w, inflight, log)
			w.LastInstruction = p.Assignment
			if hasProductiveTurn(w.AutonomousTurns) {
				w.ProgressNoneStreak = 0
				w.StallWarned = false
			}
			if log != nil {
				log.Log("plan", "retarget", map[string]any{"worker_id": p.WorkerID})
			}
			w.Chronicle.Install(w.Agent, w.LastInstruction)
			inflight[w.ID] = fire(ctx, w)
			continue
		}
		// Defense-in-depth: an ID present in workers (Alive=false) belongs
		// to a retired worker. The plan_workers handler already rejects
		// these, but reorderings (e.g. iter-1 path retires worker 1
		// between handler-time and apply-time) could in principle let one
		// slip through. Skip explicitly so we never spawn a duplicate ID
		// that would shadow the dead entry in findWorker-style lookups.
		if w, ok := byID[p.WorkerID]; ok && !w.Alive {
			if log != nil {
				log.Log("plan", "spawn skipped: id taken by retired worker", map[string]any{"worker_id": p.WorkerID})
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
		byID[nw.ID] = nw
		existing++
		nw.Chronicle.Install(nw.Agent, nw.LastInstruction)
		inflight[nw.ID] = fire(ctx, nw)
		if log != nil {
			log.Log("plan", "spawn", map[string]any{"worker_id": p.WorkerID})
		}
	}
}

func stopInflightWorkerRun(w *WorkerState, inflight map[int]func() []agent.TurnSummary, log *Logger) {
	if w == nil || inflight == nil {
		return
	}
	join, exists := inflight[w.ID]
	if !exists {
		return
	}
	if w.Agent != nil {
		w.Agent.Interrupt()
	}
	_ = join()
	delete(inflight, w.ID)
	if log != nil {
		log.Log("plan", "replaced in-flight run", map[string]any{"worker_id": w.ID})
	}
}

// refireAlive fires an iter+1 run for every alive worker that doesn't
// already have a join in inflight.
func refireAlive(
	ctx context.Context,
	workers []*WorkerState,
	fire func(context.Context, *WorkerState) func() []agent.TurnSummary,
	inflight map[int]func() []agent.TurnSummary,
	log *Logger,
) {
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		if _, exists := inflight[w.ID]; exists {
			continue
		}
		w.Chronicle.Install(w.Agent, w.LastInstruction)
		inflight[w.ID] = fire(ctx, w)
		if log != nil {
			log.Log("refire", "alive worker", map[string]any{"worker_id": w.ID})
		}
	}
}

// harvestInflight blocks on every join in inflight and returns the
// per-worker turn-summary map.
func harvestInflight(inflight map[int]func() []agent.TurnSummary) map[int][]agent.TurnSummary {
	out := map[int][]agent.TurnSummary{}
	for id, j := range inflight {
		out[id] = j()
	}
	return out
}

// probeReasoningHandlers returns reasoning handlers for cfg.Model and
// cfg.LogModel. The main probe goes through pool; the log probe through
// logPool so the two probes don't contend on a single shared slot.
func probeReasoningHandlers(
	ctx context.Context, cfg *config.Config, pool, logPool *agent.ClientPool, log *Logger,
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
		logFmt = resolveFormat(gctx, cache, logPool, "log", cfg.BaseURL, cfg.LogModel, log)
		return nil
	})
	_ = g.Wait()
	return agent.NewReasoningHandler(mainFmt), agent.NewReasoningHandler(logFmt)
}

// snapshotIterationStart returns each alive worker's current LastInstruction
// (angleAt) and an alive-set keyed by worker ID.
func snapshotIterationStart(alive []*WorkerState) (angleAt map[int]string, aliveAtStart map[int]bool) {
	angleAt = map[int]string{}
	aliveAtStart = map[int]bool{}
	for _, w := range alive {
		angleAt[w.ID] = w.LastInstruction
		aliveAtStart[w.ID] = true
	}
	return
}

// extractWorkerChroniclesAtIterEnd appends each alive worker's iter
// content to its chronicle and runs in-place compaction.
func extractWorkerChroniclesAtIterEnd(alive []*WorkerState, iteration int, log *Logger) {
	for _, w := range alive {
		w.Chronicle.ExtractAndAppend(w.Agent, iteration)
		stripped, stubbed := w.Chronicle.Compact(iteration, history.ChronicleKeepRecentIters)
		if log != nil {
			log.Log("chronicle", "extract", map[string]any{
				"worker_id":      w.ID,
				"iter":           iteration,
				"chronicle_msgs": w.Chronicle.Len(),
				"think_stripped": stripped,
				"tool_stubbed":   stubbed,
			})
		}
	}
}

// enforceStallStopsAsync calls retire for every alive worker whose
// ProgressNoneStreak has reached stopAfter.
func enforceStallStopsAsync(workers []*WorkerState, stopAfter int, retire func(*WorkerState, string, int), iter int, log *Logger) {
	for _, w := range workers {
		if w.Alive && w.ProgressNoneStreak >= stopAfter {
			if log != nil {
				log.Log("controller", "stall-force-stop", map[string]any{
					"worker_id": w.ID, "streak": w.ProgressNoneStreak,
				})
			}
			retire(w, "stall-force-stop", iter)
		}
	}
}
