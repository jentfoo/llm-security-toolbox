# sectool Controller - secagent (OpenAI-compatible)

Autonomous security exploration controller written in Go that runs multiple LLM agents against an OpenAI-compatible chat-completions endpoint. The agents share a sectool MCP server and split responsibilities:

- **Worker(s)** - agents connected to sectool's MCP server plus a small in-process tool (`report_finding_candidate`). Workers execute security tests with sectool (proxy, replay, crawl, OAST, analysis tools) and, when they find something suspicious, call `report_finding_candidate(...)` to flag it. Each worker carries a private investigative chronicle that persists across iterations.
- **Verifier** - dedicated agent whose only job is to reproduce worker-reported candidates using the full sectool tool surface (`flow_get`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `proxy_rule_*`, `crawl_*`, `oast_*`, …) and either `file_finding` or `dismiss_candidate`. Runs over multiple substeps per iteration so it can reflect between reproductions. Composed fresh each iteration.
- **Director** - dedicated agent whose only job is to decide what each alive worker does next via a single `decide_worker(action: continue|expand|stop, instruction?, reason?, autonomous_budget?, fork?)` tool call per worker, then close the iteration via a separate synthesis call (`plan_workers`, `direction_done`, `end_run`). The controller maintains the director's canonical chat at the orchestrator level (worker activity tagged by id, retired-worker summaries replace dead workers' messages in place); per-worker decision calls install a selectively-compacted view (current worker raw, others compacted) so the director coordinates without drowning in peer detail.

By default, the run begins with an **initial recon** pass — a dedicated recon worker that maps the target's surface area, retires at the end of iteration 1, and whose summary is anchored into every subsequent worker's system prompt and the verifier's per-iter compose. Pass `--skip-recon` to disable this and have the run start with a regular testing worker against `--prompt` (no recon summary anchor for downstream workers). See "How It Works" step 3 for the full mechanics.

A separate **log model** can be configured (`--log-model`) for cheap LLM operations that don't need the main flagship model: the narrator, candidate-dedup classification, and async-merge classification. It shares the main client pool — only the model identifier on each request differs. Defaults to `--model` when unset. Boundary-summarize stays on the main model since those recaps are load-bearing.

Splitting verification and direction into separate clients with separate system prompts forces each role to do its job thoroughly - a single-turn orchestrator tends to short-circuit both.

Any OpenAI-compatible endpoint works: OpenAI, Azure OpenAI, vLLM, llama.cpp server, LM Studio, OpenRouter, Together, Groq, etc. No Claude subscription is required.

## Prerequisites

- Go 1.25+ (for building secagent and sectool)
- `sectool` available on `$PATH` — secagent shells out to `sectool mcp` when no MCP server is already running on `--mcp-port`
- An OpenAI-compatible chat-completions endpoint (with tool-calling support)
- The endpoint's API key (when required)

## Installation

From the toolbox repo root:

```bash
make build         # builds bin/sectool and bin/secagent
# or:
make build-secagent
```

Make sure `sectool` is on your `$PATH` (e.g. add `bin/` to `$PATH`, or copy/symlink `bin/sectool` into a directory that already is) so secagent can launch its MCP server.

## Usage

```bash
bin/secagent \
  --base-url https://api.openai.com/v1 \
  --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30
```

Single-endpoint local example (vLLM / llama.cpp / LM Studio):

```bash
bin/secagent \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen2.5-coder:32b \
  --prompt "Explore https://target.example.com for auth issues."
```

Cheaper log-tier model (narrator + candidate dedup) on the same endpoint:

```bash
bin/secagent \
  --base-url https://api.openai.com/v1 --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 --log-model gpt-4.1-mini \
  --prompt "Explore https://target.example.com."
```

## CLI Arguments

**Connection**

| Flag | Default | Description |
|------|---------|-------------|
| `--base-url` | - | OpenAI-compatible base URL |
| `--api-key` | - | Optional API key |
| `--model` | - | Main model ID (workers, verifier, director, boundary-summarize) |
| `--log-model` | (= `--model`) | Model ID for narrator, candidate dedup, async-merge classify |
| `--agent-pool-size` | `4` | Concurrent model-request bound (shared pool) |

**Context / compaction**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-context` | `32768` | Main-model context window in tokens |
| `--log-max-context` | (= `--max-context`) | Log-model context window in tokens |
| `--tool-result-max-bytes` | `8192` | Per-tool-result truncation cap |
| `--compaction-high-watermark` | `0.80` | Fraction of context that triggers compaction |
| `--compaction-low-watermark` | `0.40` | Compaction target fraction |
| `--compaction-keep-turns` | `4` | Trailing turns never compacted |
| `--keep-think-turns` | `0` (auto) | Assistant messages to preserve `<think>` blocks on when replaying history. `0` auto-picks 4 if max-context ≤ 128k else 8 |

**Sectool**

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-port` | `8181` | Port for sectool's native proxy |
| `--mcp-port` | `9119` | Port for sectool's MCP server (auto-attaches when one is already running) |

**Loop**

| Flag | Default | Description |
|------|---------|-------------|
| `--prompt` | - | **Required.** Initial task prompt for the first worker |
| `--max-iterations` | `30` | Hard cap on outer loop iterations |
| `--max-workers` | `4` | Maximum parallel workers (capped at 5) |
| `--autonomous-budget` | `8` | Turns per worker per iteration (1–20) |
| `--turn-timeout` | `15m` | Per-turn (per chat-completion call) context timeout |
| `--per-tool-timeout` | `5m` | Per-tool-call context timeout |
| `--max-parallel-tools` | `4` | Max concurrent in-flight tool calls per assistant response |
| `--max-turns-per-agent` | `100` | Hard cap per Drain chain |
| `--findings-dir` | `./findings` | Directory for finding report files |
| `--skip-recon` | `false` | Skip the initial recon pass; the run starts with a normal testing worker against `--prompt`. See "How It Works" step 3 |

**Stall detection**

| Flag | Default | Description |
|------|---------|-------------|
| `--stall-warn-after` | `3` | Silent runs before director warning |
| `--stall-stop-after` | `4` | Silent runs before force-stop |

**Logging / narration**

| Flag | Default | Description |
|------|---------|-------------|
| `--progress-log-interval` | `3` | Turns per agent between status summaries (0 disables; deprecated — superseded by narrator) |
| `--narrate-interval` | `2m` | Min interval between async narrator summaries (0 disables) |
| `--narrate-timeout` | `15m` | Per-summary narrator call timeout |
| `--log-file` | `secagent.log` | Structured JSON log destination |

## Using with an Existing MCP Server

secagent probes `--mcp-port` at startup. If a sectool MCP server is already serving on that port, secagent attaches to it (no child process started, no teardown on exit). Otherwise it launches `sectool mcp` from `$PATH` and tears it down at exit.

```bash
# Start the MCP server separately
sectool mcp --proxy-port 8181

# In another terminal, run secagent against it — no special flag required
bin/secagent \
  --base-url https://api.openai.com/v1 --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --proxy-port 8181 --mcp-port 9119
```

## How It Works

```
   --prompt
      │
      ▼
   ┌──► workers explore ──► candidates ──► verifier ──► file_finding ──► findings/
   │                                          │
   │                                          └──► dismiss
   │                                                  │
   └──────────────── director steers ◄────────────────┘
                     continue / expand / stop / spawn — or end_run to exit
```

Each loop around the cycle is one **iteration**. The controller keeps iterating until the director calls `end_run` or `--max-iterations` is hit.

Operational details:

1. **Launch or attach to MCP** - probes `http://127.0.0.1:<mcp-port>/mcp` first; if a server is already responding, secagent attaches to it. Otherwise it launches `sectool mcp` from `$PATH` as a child process on `--mcp-port` and waits for HTTP readiness.
2. **Build client pool & connect agents** - a single bounded-concurrency client pool is constructed against `--base-url` and shared by every role; the narrator and candidate-dedup classifier issue requests through it with the log-model identifier. The verifier and director each open their own MCP connection; each worker opens its own MCP connection on spawn. Mission text from `--prompt` is appended to every role's system prompt as a non-negotiable anchor that survives every history replace and compaction pass.
3. **Initial prompt & initial recon** - by default, the user's `--prompt` is first run through an LLM `SummarizeReconMission` pass that distills it into a recon-scoped goal, and worker 1 is spawned as a dedicated **recon worker**: anchored to that recon mission, given the hardcoded `ReconDirective` (scope-mapping, observation-only), and registered with the sectool tool surface but **without** `report_finding_candidate` so it structurally cannot file candidates. At the end of iteration 1 the recon worker is retired, its chronicle is summarized, and the result is held as `factory.ReconSummary` — anchored into every subsequent worker's system prompt and the verifier's per-iter compose. If `SummarizeReconMission` fails (model error / empty output) the controller fails soft and uses `--prompt` verbatim as the recon mission. With `--skip-recon`, the run instead starts with a regular testing worker against `--prompt` (no recon directive, full tool surface including `report_finding_candidate`, no anchored `ReconSummary` for downstream workers) — useful for A/B comparing the value of recon on a given target, or when the target is small enough that recon is overhead.
4. **Per-iteration anatomy** (three phases):

   **Phase 1: Autonomous worker run.** At iteration start the controller installs each worker's accumulated chronicle (its own prior tool calls, candidate reports, and verifier verdicts) via `ReplaceHistory`, marks the iteration boundary, and queries the worker with its current instruction. Workers then run concurrently for up to their `autonomous_budget` turns (default 8). Between turns the controller queues a terse continue prompt — no orchestrator intervention. A worker **escalates back** early if it reports a finding candidate, produces a silent turn (no tool calls, no new flow IDs), or hits an error. On a mid-iteration drain error the controller makes one recovery attempt: interrupt, re-queue the worker's last instruction, run a single Drain. Each turn's summary (tool calls, flow IDs, candidates raised) is recorded on the worker. The controller waits until every alive worker has escalated, then extracts the new turns and appends them to the worker's chronicle for next iteration.

   **Phase 2: Verification (multi-substep).** The verifier is composed fresh each iteration: `ReplaceHistory` installs a single user message containing the pending candidates, every worker's autonomous-run transcript, and a recap of findings filed so far. The verifier reproduces each candidate using sectool tools. Up to `VerificationMaxSubsteps` (6) query/drain substeps — between substeps the controller applies any `file_finding` / `dismiss_candidate` decisions and prompts again with the updated pending list. Phase ends on `verification_done(summary)`, when no pending candidates remain, or at the cap. If the verifier overflows context even after the fresh compose, all still-pending candidates are auto-dismissed for the iteration so they don't re-burn the same tokens next time.

   **Phase 3: Direction (multi-substep).** The director's history is long-lived — across iterations it accumulates planning context, with older blocks compressed by the boundary-summarize callback when context pressure trips. The controller marks the iteration boundary and queries with the verification summary, every worker's autonomous-run transcript, the per-worker iteration history block (see "What the director sees" below), stall warnings, and any verifier follow-up hints. The director issues `continue_worker` / `expand_worker` / `stop_worker` / `plan_workers` decisions — each with an `autonomous_budget` for the next iteration. Up to `DirectionMaxSubsteps` (4) substeps plus one mandatory self-review round. Phase ends on `direction_done(summary)`, on `end_run(summary)` to end the run, when every alive worker has a decision, or at the cap.

   **Apply.** Controller applies the plan diff (spawn/retarget) and records each worker decision onto `WorkerState`. No agent queries happen during apply — the next iteration's chronicle install does the queueing. Workers with no explicit decision get an implicit `continue` instruction.

5. **Phase gating.** Each orchestrator tool checks the current phase and rejects calls made in the wrong phase. Verification phase may call `file_finding`, `dismiss_candidate`, and `verification_done` (plus the sectool tools). Direction phase may call `plan_workers`, `continue_worker`, `expand_worker`, `stop_worker`, `direction_done`, and `end_run`.
6. **Stall detection** - controller-observed via each worker's `escalation_reason`. Silent escalations increment `progress_none_streak`; candidate escalations or turns that touched new flow IDs reset it. `--stall-warn-after` (default 3) consecutive silent escalations triggers a stall warning in the director prompt; `--stall-stop-after` (default 4) forces the worker stopped before the next iteration.
7. **Context management** - three-pass: existing structural compaction (drop oldest turn-triples, stub stale tool results) → boundary-summarize when an iteration boundary has been marked (LLM-compresses pre-iteration messages into one concise recap, leaving the in-flight iteration verbatim) → final compaction pass. The mission anchor in the system prompt is preserved across every step. Workers and the director both have boundary-summarize wired; the verifier doesn't (it's already fresh per iteration).
8. **Teardown** - terminates the MCP child server if secagent started it (no-op when attached to a pre-existing one), waits on any in-flight async finding merges, and writes a final summary line to the log.

## Worker Tool

| Tool | Purpose |
|------|---------|
| `report_finding_candidate(...)` | Flag a potential vulnerability with proof flow IDs. The verifier will reproduce and, if confirmed, file the formal finding. |

Workers do not write finding documents themselves — that's the verifier's job (after reproduction).

### Candidate dedup pipeline

Every `report_finding_candidate` call runs through a cheap LLM dedup check (log model) against the digests of already-filed findings before the candidate enters the pool. Three outcomes:

- **unique** — candidate enters the pool and is presented to the verifier next phase.
- **duplicate** — rejected at the tool boundary; the worker is told which finding already covers it and to pivot to a different angle.
- **merge** — acknowledged synchronously to the worker; the candidate's evidence is queued onto a bounded background goroutine pool that opens the matched finding, calls the log model again to merge the new evidence in, and writes the result. The controller waits on outstanding merges at shutdown so no work is lost.

Findings filed by the verifier go through a similar dedup pass before being written to disk (`writer.MatchesFiled` deterministic match plus an LLM review for soft matches), and pending candidates that aren't explicitly linked via `supersedes_candidate_ids` are tier-matched (title+endpoint, then endpoint-only, then title-only) so the verifier can leave the linkage implicit when the relationship is obvious.

## Orchestrator Tools (phase-gated decision surface)

**Verification phase tools:**

| Tool | Purpose |
|------|---------|
| `file_finding(...)` | Record a *verified* finding; `verification_notes` must describe how the issue was reproduced. Optional `supersedes_candidate_ids` explicitly links the finding to the candidate(s) it covers. Optional `follow_up_hint` advises the director on adjacent angles to probe. |
| `dismiss_candidate(candidate_id, reason)` | Mark a worker candidate as not-a-finding. Optional `follow_up_hint` advises the director. |
| `verification_done(summary)` | Signal verification complete; transitions to direction. |

Plus the **full sectool tool surface** (same as workers): `flow_get`, `proxy_poll`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `cookie_jar`, `jwt_decode`, `encode`, `decode`, `hash`, `crawl_*`, `oast_*`, `proxy_rule_*`, `proxy_respond_*`, `notes_save`, `notes_list`. The verifier prompt directs it to prefer non-destructive reproduction and clean up any rules/responders/sessions it introduces.

**Direction phase tools:**

| Tool | Purpose |
|------|---------|
| `plan_workers(plans)` | Spawn or retarget workers (additive to the per-worker decisions below — use both in the same phase). |
| `continue_worker(worker_id, instruction, progress, autonomous_budget?)` | Keep worker N going with the specified budget. |
| `expand_worker(worker_id, instruction, progress, autonomous_budget?)` | Pivot worker N's plan. |
| `stop_worker(worker_id, reason)` | Retire worker N. |
| `direction_done(summary)` | Signal that the direction phase is complete. **Use this to close almost every iteration.** |
| `end_run(summary)` | End the entire run. Rejected as premature when called before iteration `MinIterationsForDone` (5) with zero findings filed — local models that conflate `end_run` with `direction_done` get a clear error pointing them at the right tool. |

Calling a tool in the wrong phase returns an `is_error=true` response directing the orchestrator to transition phases first.

### `autonomous_budget` parameter

`continue_worker` and `expand_worker` accept an optional `autonomous_budget` (integer, 1–20, default 8) that sets how many consecutive autonomous turns the worker may run before escalating back. Typical values:

- **8–15** - productive workers on a clear exploitation path.
- **5–8** - general exploration (default).
- **2–4** - exploratory/uncertain assignments where you want to review sooner.

## What the director sees

Per iteration the director receives the verification summary, every worker's autonomous-run transcript for the iteration, a findings-so-far recap, optional verifier follow-up hints, optional stall warnings, and a **recent worker history block** rendered from a per-worker ring (last 6 iterations). Each entry includes the angle, an outcome token, tool-call count, and flow count. Outcome tokens (precedence top-to-bottom):

| Token | Meaning |
|-------|---------|
| `stopped` | Worker was stopped this iteration (no longer alive). |
| `finding` | Verifier explicitly linked a filed finding to one of this worker's candidates via `supersedes_candidate_ids`. |
| `possible-finding` | Verifier filed a finding that heuristically matches one of this worker's candidates (title+endpoint tier match) but didn't explicitly link it. The director should follow up rather than assume coverage — a finding outcome should be explicit. |
| `dismissed` | Verifier dismissed a candidate from this worker. |
| `candidate` | Worker reported a candidate that's still pending at iter end. |
| `silent` / `error` / `budget` | Escalation reason from a worker that didn't produce a candidate. |

The director's system prompt also defines an **angle exhaustion** rule: when a worker's history shows the same or near-identical angle across 2+ iterations with no finding filed, treat it as exhausted and pivot or stop — don't re-issue a lightly-reworded variant.

## Findings

Filed findings are written as markdown files to `--findings-dir`:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file has Title, Severity, Affected Endpoint, Description, Reproduction Steps, Evidence, Impact, and a **Verification** section in which the verifier records how it reproduced the issue. Findings are deduplicated by title-slug and canonicalized endpoint plus an LLM soft-match review before write; merges from later iterations re-open and rewrite the matched file via the log model.

## Logs

`--log-file` (default `secagent.log`) receives a structured JSON event per line covering server lifecycle, agent turns, phase transitions, decisions, stalls, candidate dedup verdicts, async-merge outcomes, summarize callbacks, and findings. The child sectool MCP server's stdout/stderr go to `sectool-mcp.log` in the working directory.

## Safety Bounds

- **Max iterations**: `--max-iterations` caps the outer loop (default 30). Each iteration runs one autonomous worker phase + verification + direction, so an iteration involves many underlying model turns.
- **Autonomous budget per worker**: 1–20 turns, default 8, settable per worker by the director via `continue_worker` / `expand_worker`.
- **Phase substep caps**: `VerificationMaxSubsteps=6`, `DirectionMaxSubsteps=4` plus one mandatory self-review substep (`DirectionSelfReviewMaxRounds=2`).
- **Per-agent turn cap**: `--max-turns-per-agent` (default 100) bounds any single Drain chain.
- **Stall detection**: configurable via `--stall-warn-after` / `--stall-stop-after`.
- **Per-turn timeout**: `--turn-timeout` (default 15m) bounds each model call. `--per-tool-timeout` (default 5m) bounds each tool dispatch.
- **Max workers**: capped at 5 by `config.Parse`.
- **Verification required**: findings are only filed after the verifier calls `file_finding` with non-empty `verification_notes`.
- **Premature end_run guard**: rejected before iteration 5 when zero findings have been filed.

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

The tests do not touch the network or any real LLM endpoint - they exercise the orchestrator phases, candidate/decision queues, finding writer, dedup pipeline, async merger, chronicle/iteration-history derivation, flow-ID extractor, autonomous-run loop, stall logic, compaction, retry classification, and the verification/direction phase drivers against a scripted `FakeAgent`.
