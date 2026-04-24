# sectool Controller - secagent (OpenAI-compatible)

Autonomous security exploration controller written in Go that runs multiple
LLM agents against an OpenAI-compatible chat-completions endpoint. The agents
share a sectool MCP server and split responsibilities:

- **Worker(s)** - agents connected to sectool's MCP server plus a small
  in-process tool (`report_finding_candidate`). Workers execute security tests
  with sectool (proxy, replay, crawl, OAST, analysis tools) and, when they
  find something suspicious, call `report_finding_candidate(...)` to flag it.
- **Verifier** - dedicated agent whose only job is to reproduce
  worker-reported candidates using the full sectool tool surface (`flow_get`,
  `replay_send`, `request_send`, `diff_flow`, `find_reflected`,
  `proxy_rule_*`, `crawl_*`, `oast_*`, …) and either `file_finding` or
  `dismiss_candidate`. Runs over multiple substeps per iteration so it can
  reflect between reproductions.
- **Director** - dedicated agent whose only job is to decide what each alive
  worker should do next (`continue_worker`, `expand_worker`, `stop_worker`,
  `plan_workers`, `done`) and how long it may run autonomously before
  escalating back (`autonomous_budget`). Also runs over multiple substeps
  per iteration.

Splitting verification and direction into separate clients with separate
system prompts forces each role to do its job thoroughly - a single-turn
orchestrator tends to short-circuit both.

Any OpenAI-compatible endpoint works: OpenAI, Azure OpenAI, vLLM, llama.cpp
server, LM Studio, OpenRouter, Together, Groq, etc. No Claude subscription
is required.

## Prerequisites

- Go 1.25+ (for building secagent and sectool)
- An OpenAI-compatible chat-completions endpoint (with tool-calling support)
- The endpoint's API key (when required)

## Installation

From the toolbox repo root:

```bash
make build         # builds bin/sectool and bin/secagent
# or:
make build-secagent
```

## Usage

```bash
bin/secagent \
  --base-url https://api.openai.com/v1 \
  --api-key "$OPENAI_API_KEY" \
  --worker-model gpt-4.1-mini \
  --orchestrator-model gpt-4.1 \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30
```

Single-endpoint local example (vLLM / llama.cpp / LM Studio):

```bash
bin/secagent \
  --base-url http://127.0.0.1:8000/v1 \
  --worker-model qwen2.5-coder:32b \
  --orchestrator-model qwen2.5-coder:32b \
  --prompt "Explore https://target.example.com for auth issues."
```

Split worker/orchestrator endpoints (e.g. fast cheap worker, smarter
orchestrator):

```bash
bin/secagent \
  --worker-base-url http://127.0.0.1:8000/v1 --worker-model qwen2.5-coder:7b \
  --orchestrator-base-url https://api.openai.com/v1 --orchestrator-model gpt-4.1 \
  --api-key "$OPENAI_API_KEY" \
  --prompt "Explore https://target.example.com."
```

## CLI Arguments

**Connection**

| Flag | Default | Description |
|------|---------|-------------|
| `--base-url` | - | Default OpenAI-compatible base URL for both roles |
| `--api-key` | - | Optional API key |
| `--worker-base-url` | - | Override base URL for worker role |
| `--orchestrator-base-url` | - | Override base URL for verifier + director |
| `--worker-model` | - | Model ID for worker role |
| `--orchestrator-model` | - | Model ID for verifier + director |
| `--openai-client-pool-size` | `4` | Concurrent model request bound (worker pool) |
| `--orchestrator-pool-size` | `0` | Orchestrator pool size; `0` reuses worker pool |

**Context / compaction**

| Flag | Default | Description |
|------|---------|-------------|
| `--worker-max-context` | `32768` | Worker context window in tokens |
| `--orchestrator-max-context` | `32768` | Orchestrator context window in tokens |
| `--tool-result-max-bytes` | `8192` | Per-tool-result truncation cap |
| `--compaction-high-watermark` | `0.80` | Fraction of context that triggers compaction |
| `--compaction-low-watermark` | `0.40` | Compaction target fraction |
| `--compaction-keep-turns` | `4` | Trailing turns never compacted |

**Sectool**

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-port` | `8181` | Port for sectool's native proxy |
| `--mcp-port` | `9119` | Port for sectool's MCP server |
| `--workflow` | `explore` | Sectool workflow mode |
| `--external` | `false` | Attach to a running MCP server; skips build, start, and teardown |
| `--skip-build` | `false` | Skip `make build-sectool` (use existing binary) |

**Loop**

| Flag | Default | Description |
|------|---------|-------------|
| `--prompt` | - | **Required.** Initial task prompt for the first worker |
| `--max-iterations` | `30` | Hard cap on outer loop iterations |
| `--max-workers` | `4` | Maximum parallel workers (capped at 5) |
| `--autonomous-budget` | `8` | Turns per worker per iteration (1–20) |
| `--turn-timeout` | `5m` | Per-turn context timeout |
| `--max-turns-per-agent` | `100` | Hard cap per Drain chain |
| `--findings-dir` | `./findings` | Directory for finding report files |

**Stall detection**

| Flag | Default | Description |
|------|---------|-------------|
| `--stall-warn-after` | `3` | Silent runs before director warning |
| `--stall-stop-after` | `4` | Silent runs before force-stop |

**Logging**

| Flag | Default | Description |
|------|---------|-------------|
| `--progress-log-interval` | `3` | Turns per agent between status summaries (0 disables) |
| `--log-file` | `secagent.log` | Structured JSON log destination |

## Using with an Existing MCP Server

```bash
# Start the MCP server separately
bin/sectool mcp --proxy-port 8181 --workflow=explore

# In another terminal, run secagent against it
bin/secagent \
  --base-url https://api.openai.com/v1 --api-key "$OPENAI_API_KEY" \
  --worker-model gpt-4.1-mini --orchestrator-model gpt-4.1 \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --external --proxy-port 8181 --mcp-port 9119
```

## How It Works

1. **Build & launch MCP** - unless `--external`, runs `make build-sectool`,
   then starts `bin/sectool mcp` as a child process on `--mcp-port` and waits
   for HTTP readiness.
2. **Build client pools & connect agents** - bounded-concurrency client pools
   are constructed for each base URL. The verifier and director each open
   their own MCP connection; each worker opens its own MCP connection on
   spawn.
3. **Initial prompt** - the user's `--prompt` is sent to worker 1 for
   discovery.
4. **Per-iteration anatomy** (three phases):

   **Phase 1: Autonomous worker run.** Each alive worker runs concurrently
   for up to its `autonomous_budget` turns (default 8). Between turns the
   controller sends a terse resumption prompt via
   `BuildWorkerContinuePrompt` - no orchestrator intervention. At iteration
   boundaries (implicit-continue, dead-iteration recovery) the prompt is
   prefixed with a short "findings filed so far" recap so workers avoid
   re-investigating already-filed vulnerabilities. A worker **escalates back** early
   if it reports a finding candidate, produces a silent turn (no tool
   calls, no new flow IDs), or hits an error. Each turn's summary (tool
   calls, flow IDs touched, candidates raised) is recorded on the worker.
   On a mid-iteration drain error the controller makes one recovery
   attempt: interrupt, re-queue the worker's last instruction, run a
   single Drain. Controller waits until every worker has escalated.

   **Phase 2: Verification (multi-substep).** The verifier receives the
   pending candidates + every worker's full autonomous-run transcript and
   reproduces each candidate using sectool tools. It may take up to
   `VerificationMaxSubsteps` (6) query/drain substeps - between substeps
   the controller applies any `file_finding` / `dismiss_candidate`
   decisions and prompts again with the updated pending list. Phase ends
   on `verification_done(summary)`, when no pending candidates remain, or
   at the cap.

   **Phase 3: Direction (multi-substep).** The director receives the
   verification summary + every worker's autonomous-run transcript and
   issues `continue_worker` / `expand_worker` / `stop_worker` /
   `plan_workers` decisions - each with an `autonomous_budget` for the
   next iteration. Up to `DirectionMaxSubsteps` (4) substeps. Phase ends
   on `direction_done(summary)`, on `done(summary)` to end the run, when
   every alive worker has a decision, or at the cap.

   **Apply.** Controller applies the plan diff (spawn/retarget), sends each
   worker its instruction + updated budget, and starts the next iteration.
   Workers with no explicit decision get an implicit `continue` prompt.

5. **Phase gating.** Each orchestrator tool checks the current phase and
   rejects calls made in the wrong phase. Verification phase may call
   `file_finding`, `dismiss_candidate`, and `verification_done` (plus the
   sectool read/replay tools). Direction phase may call `plan_workers`,
   `continue_worker`, `expand_worker`, `stop_worker`, `direction_done`,
   and `done`.
6. **Stall detection** - controller-observed via each worker's
   `escalation_reason`. Silent escalations increment
   `progress_none_streak`; candidate escalations or turns that touched new
   flow IDs reset it. `--stall-warn-after` (default 3) consecutive silent
   escalations triggers a stall warning in the director prompt;
   `--stall-stop-after` (default 4) forces the worker stopped before the
   next iteration.
7. **Context compaction** - when an agent's context exceeds
   `--compaction-high-watermark` it compacts older turns down to
   `--compaction-low-watermark`, preserving the last
   `--compaction-keep-turns` turns verbatim.
8. **Teardown** - terminates the MCP child server (unless `--external`)
   and writes a final summary line to the log.

## Orchestrator Tools (phase-gated decision surface)

**Verification phase tools:**

| Tool | Purpose |
|------|---------|
| `file_finding(...)` | Record a *verified* finding; `verification_notes` must describe how the issue was reproduced. |
| `dismiss_candidate(candidate_id, reason)` | Mark a worker candidate as not-a-finding. |
| `verification_done(summary)` | Signal verification complete; transitions to direction. |

Plus the **full sectool tool surface** (same as workers): `flow_get`,
`proxy_poll`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`,
`cookie_jar`, `jwt_decode`, `encode`, `decode`, `hash`, `crawl_*`,
`oast_*`, `proxy_rule_*`, `proxy_respond_*`, `notes_save`, `notes_list`.
The verifier prompt directs it to prefer non-destructive reproduction and
clean up any rules/responders/sessions it introduces.

**Direction phase tools:**

| Tool | Purpose |
|------|---------|
| `plan_workers(plans)` | Spawn or retarget workers. |
| `continue_worker(worker_id, instruction, progress, autonomous_budget?)` | Keep worker N going with the specified budget. |
| `expand_worker(worker_id, instruction, progress, autonomous_budget?)` | Pivot worker N's plan. |
| `stop_worker(worker_id, reason)` | Retire worker N. |
| `direction_done(summary)` | Signal that all alive workers have a decision. |
| `done(summary)` | End the run. |

Calling a tool in the wrong phase returns an `is_error=true` response
directing the orchestrator to transition phases first.

### `autonomous_budget` parameter

`continue_worker` and `expand_worker` accept an optional `autonomous_budget`
(integer, 1–20, default 8) that sets how many consecutive autonomous turns
the worker may run before escalating back. Typical values:

- **8–15** - productive workers on a clear exploitation path.
- **5–8** - general exploration (default).
- **2–4** - exploratory/uncertain assignments where you want to review sooner.

## Worker Tool

| Tool | Purpose |
|------|---------|
| `report_finding_candidate(...)` | Flag a potential vulnerability with proof flow IDs. The verifier will reproduce and, if confirmed, file the formal finding. |

Workers do not write finding documents themselves - that's the verifier's
job (after reproduction).

## Findings

Filed findings are written as markdown files to `--findings-dir`:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file has Title, Severity, Affected Endpoint, Description, Reproduction
Steps, Evidence, Impact, and a **Verification** section in which the
verifier records how it reproduced the issue. Findings are deduplicated by
title-slug and canonicalized endpoint before write.

## Logs

`--log-file` (default `secagent.log`) receives a structured JSON event per
line covering server lifecycle, agent turns, phase transitions, decisions,
stalls, and findings. The child sectool MCP server's stdout/stderr go to
`sectool-mcp.log` in the working directory.

## Safety Bounds

- **Max iterations**: `--max-iterations` caps the outer loop (default 30).
  Each iteration runs one autonomous worker phase + verification +
  direction, so an iteration involves many underlying model turns.
- **Autonomous budget per worker**: 1–20 turns, default 8, settable per
  worker by the director via `continue_worker` / `expand_worker`.
- **Phase substep caps**: `VerificationMaxSubsteps=6`,
  `DirectionMaxSubsteps=4`.
- **Per-agent turn cap**: `--max-turns-per-agent` (default 100) bounds any
  single Drain chain.
- **Stall detection**: configurable via `--stall-warn-after` /
  `--stall-stop-after`.
- **Per-turn timeout**: `--turn-timeout` (default 5m) bounds each model
  call.
- **Max workers**: capped at 5 by `config.Parse`.
- **Verification required**: findings are only filed after the verifier
  calls `file_finding` with non-empty `verification_notes`.

## Running the tests

From the repo root:

```bash
make test            # short tests
make test-all        # full tests with -race and coverage
```

Or directly inside the secagent module:

```bash
cd controller/secagent && go test ./...
```

The tests do not touch the network or any real LLM endpoint - they exercise
the orchestrator phases, candidate/decision queues, finding writer,
flow-ID extractor, autonomous-run loop, stall logic, compaction, and the
verification/direction phase drivers against a scripted `FakeAgent`.
