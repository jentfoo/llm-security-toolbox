// Package config holds the secagent runtime configuration and flag parsing.
package config

import (
	"errors"
	"flag"
	"time"
)

// Config is the full runtime configuration parsed from flags.
type Config struct {
	// Connection
	BaseURL             string
	APIKey              string
	WorkerBaseURL       string
	OrchestratorBaseURL string
	SummaryBaseURL      string
	WorkerModel         string
	OrchestratorModel   string
	SummaryModel        string
	OpenAIPoolSize      int
	OrchestratorPool    int

	// Context / compaction
	WorkerMaxContext       int
	OrchestratorMaxContext int
	ToolResultMaxBytes     int
	HighWatermark          float64
	LowWatermark           float64
	KeepTurns              int
	KeepThinkTurns         int

	// Sectool
	ProxyPort int
	MCPPort   int
	Workflow  string
	External  bool
	SkipBuild bool

	// Loop
	Prompt           string
	MaxIterations    int
	MaxWorkers       int
	AutonomousBudget int
	TurnTimeout      time.Duration
	PerToolTimeout   time.Duration
	MaxParallelTools int
	MaxTurnsPerAgent int
	FindingsDir      string

	// Stall
	StallWarnAfter int
	StallStopAfter int

	// Logging
	ProgressLogInterval int
	NarrateInterval     time.Duration
	NarrateTimeout      time.Duration
	LogFile             string
}

// Bounds used for clamping.
const (
	MinWorkers          = 1
	MaxWorkers          = 5
	MaxAutonomousBudget = 20
	DefaultAutoBudget   = 8
)

// Parse parses os.Args (via the default flag set) and returns a Config.
// Any validation error causes os.Exit via flag.CommandLine.
func Parse(fs *flag.FlagSet, args []string) (*Config, error) {
	c := &Config{}

	fs.StringVar(&c.BaseURL, "base-url", "", "default OpenAI-compatible base URL for both roles")
	fs.StringVar(&c.APIKey, "api-key", "", "optional API key")
	fs.StringVar(&c.WorkerBaseURL, "worker-base-url", "", "override base URL for worker role")
	fs.StringVar(&c.OrchestratorBaseURL, "orchestrator-base-url", "", "override base URL for orchestrator role")
	fs.StringVar(&c.SummaryBaseURL, "summary-base-url", "", "override base URL for narration summary model")
	fs.StringVar(&c.WorkerModel, "worker-model", "", "model ID for worker role")
	fs.StringVar(&c.OrchestratorModel, "orchestrator-model", "", "model ID for verifier + director")
	fs.StringVar(&c.SummaryModel, "summary-model", "", "model ID for narrator; defaults to orchestrator then worker")
	fs.IntVar(&c.OpenAIPoolSize, "openai-client-pool-size", 4, "concurrent model request bound (worker pool)")
	fs.IntVar(&c.OrchestratorPool, "orchestrator-pool-size", 0, "orchestrator pool size; 0 reuses worker pool")

	fs.IntVar(&c.WorkerMaxContext, "worker-max-context", 32768, "worker context window (tokens)")
	fs.IntVar(&c.OrchestratorMaxContext, "orchestrator-max-context", 32768, "orchestrator context window (tokens)")
	fs.IntVar(&c.ToolResultMaxBytes, "tool-result-max-bytes", 8192, "per-tool-result truncation cap")
	fs.Float64Var(&c.HighWatermark, "compaction-high-watermark", 0.80, "compaction trigger fraction")
	fs.Float64Var(&c.LowWatermark, "compaction-low-watermark", 0.40, "compaction target fraction")
	fs.IntVar(&c.KeepTurns, "compaction-keep-turns", 4, "turns never compacted")
	fs.IntVar(&c.KeepThinkTurns, "keep-think-turns", 0, "assistant messages to preserve <think> blocks on when replaying history (0 = auto: 4 if max-context ≤ 128k, else 8)")

	fs.IntVar(&c.ProxyPort, "proxy-port", 8181, "sectool proxy port")
	fs.IntVar(&c.MCPPort, "mcp-port", 9119, "sectool MCP port")
	fs.StringVar(&c.Workflow, "workflow", "explore", "sectool workflow mode")
	fs.BoolVar(&c.External, "external", false, "attach to running MCP; skip build+start")
	fs.BoolVar(&c.SkipBuild, "skip-build", false, "skip make build")

	fs.StringVar(&c.Prompt, "prompt", "", "initial task prompt (required)")
	fs.IntVar(&c.MaxIterations, "max-iterations", 30, "hard iteration cap")
	fs.IntVar(&c.MaxWorkers, "max-workers", 4, "max parallel workers")
	fs.IntVar(&c.AutonomousBudget, "autonomous-budget", DefaultAutoBudget, "turns per worker per iteration")
	// Defaults sized for slow local models: a turn that chains many tool
	// calls against a heavy backend easily exceeds 5 minutes, and a 5-min
	// turn timeout produced repeated forced escalations in past runs before
	// the agent could emit its final response. 15 min per turn / 5 min per
	// tool gives breathing room without hiding genuinely stuck operations.
	fs.DurationVar(&c.TurnTimeout, "turn-timeout", 15*time.Minute, "per-turn ctx timeout")
	fs.DurationVar(&c.PerToolTimeout, "per-tool-timeout", 5*time.Minute, "per-tool-call ctx timeout")
	fs.IntVar(&c.MaxParallelTools, "max-parallel-tools", 4, "max concurrent in-flight tool calls per assistant response")
	fs.IntVar(&c.MaxTurnsPerAgent, "max-turns-per-agent", 100, "hard cap per Drain chain")
	fs.StringVar(&c.FindingsDir, "findings-dir", "./findings", "finding report directory")

	fs.IntVar(&c.StallWarnAfter, "stall-warn-after", 3, "silent runs before director warning")
	fs.IntVar(&c.StallStopAfter, "stall-stop-after", 4, "silent runs before force-stop")

	fs.IntVar(&c.ProgressLogInterval, "progress-log-interval", 3, "turns per agent between status summaries (0 disables; deprecated — superseded by narrator)")
	fs.DurationVar(&c.NarrateInterval, "narrate-interval", 2*time.Minute, "min interval between async narrator summaries (0 disables)")
	// Narrator shares the pool with workers/orchestrator; a too-tight cap
	// here just abandons in-flight summaries without freeing the slot
	// sooner. Align with TurnTimeout.
	fs.DurationVar(&c.NarrateTimeout, "narrate-timeout", 15*time.Minute, "per-summary narrator call timeout")
	fs.StringVar(&c.LogFile, "log-file", "secagent.log", "structured log destination")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.Prompt == "" {
		return nil, errors.New("--prompt is required")
	}
	c.MaxWorkers = min(max(c.MaxWorkers, MinWorkers), MaxWorkers)
	c.AutonomousBudget = min(max(c.AutonomousBudget, 1), MaxAutonomousBudget)
	return c, nil
}

// EffectiveWorkerBaseURL returns WorkerBaseURL if set, otherwise BaseURL.
func (c *Config) EffectiveWorkerBaseURL() string {
	if c.WorkerBaseURL != "" {
		return c.WorkerBaseURL
	}
	return c.BaseURL
}

// EffectiveOrchestratorBaseURL returns OrchestratorBaseURL if set, otherwise BaseURL.
func (c *Config) EffectiveOrchestratorBaseURL() string {
	if c.OrchestratorBaseURL != "" {
		return c.OrchestratorBaseURL
	}
	return c.BaseURL
}

// EffectiveSummaryBaseURL returns SummaryBaseURL if set, otherwise the
// orchestrator URL, otherwise worker URL.
func (c *Config) EffectiveSummaryBaseURL() string {
	if c.SummaryBaseURL != "" {
		return c.SummaryBaseURL
	}
	return c.EffectiveOrchestratorBaseURL()
}

// EffectiveSummaryModel returns SummaryModel if set, otherwise OrchestratorModel, otherwise WorkerModel.
func (c *Config) EffectiveSummaryModel() string {
	if c.SummaryModel != "" {
		return c.SummaryModel
	}
	if c.OrchestratorModel != "" {
		return c.OrchestratorModel
	}
	return c.WorkerModel
}

// EffectiveKeepThinkTurns returns the number of recent assistant messages
// that should retain their `<think>` blocks when replaying history to the
// model. An explicit positive KeepThinkTurns takes precedence; otherwise
// auto-resolves based on maxContext — small contexts get a tighter window
// (4) since think blocks can be large, larger contexts keep 8.
func (c *Config) EffectiveKeepThinkTurns(maxContext int) int {
	if c.KeepThinkTurns > 0 {
		return c.KeepThinkTurns
	}
	if maxContext <= 128_000 {
		return 4
	}
	return 8
}
