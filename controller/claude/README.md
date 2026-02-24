# sectool Controller — Claude Agent SDK

Autonomous security exploration controller that runs two (or more) Claude
instances with different responsibilities:

- **Worker(s)** — Claude Code connected to sectool's MCP server and a small
  in-process `worker_tools` MCP server. Workers execute security tests with
  sectool (proxy, replay, crawl, OAST, analysis tools) and, when they find
  something suspicious, call `report_finding_candidate(...)` to flag it.
- **Orchestrator** — Claude Code connected to sectool's MCP server and an
  in-process `orch_tools` MCP server. The orchestrator **independently
  verifies** every worker-reported candidate by using sectool tools itself
  (`flow_get`, `replay_send`, `request_send`, `diff_flow`, etc.) before
  filing a formal finding. It directs workers via tool calls
  (`continue_worker`, `expand_worker`, `stop_worker`, `plan_workers`,
  `file_finding`, `dismiss_candidate`, `done`).

Both instances authenticate via Claude Code's built-in OAuth — no API key
required.

## Prerequisites

- Python 3.10+
- Claude Code CLI installed and authenticated (`claude` must be on PATH)
- Go toolchain (for building sectool)

## Installation

```bash
cd controller/claude
pip install -r requirements.txt
```

## Usage

```bash
python controller.py \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30 \
  --model sonnet \
  --verbose
```

## CLI Arguments

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--prompt` | yes | — | Initial task prompt for the worker |
| `--proxy-port` | no | `8181` | Port for sectool's native proxy |
| `--mcp-port` | no | `9119` | Port for sectool's MCP server |
| `--findings-dir` | no | `./findings` | Directory for finding report files |
| `--max-iterations` | no | `30` | Hard cap on orchestrator loop iterations |
| `--max-cost` | no | none | USD cost ceiling; halts loop if exceeded |
| `--model` | no | `sonnet` | Model for the orchestrator (sonnet, opus, haiku) |
| `--worker-model` | no | none | Override model for the Claude Code worker |
| `--max-workers` | no | `4` | Maximum parallel workers the orchestrator can assign |
| `--verbose` | no | false | Print full worker and orchestrator outputs |
| `--skip-build` | no | false | Skip `make build` (use existing binary) |
| `--workflow` | no | `explore` | Sectool workflow mode |
| `--external` | no | false | Connect to an already-running MCP server; skips build, server start, and teardown |

## Using with an Existing MCP Server

```bash
# Start the MCP server separately
bin/sectool mcp --proxy-port 8181 --workflow=explore

# In another terminal, run the controller against it
python controller.py \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --external \
  --proxy-port 8181 \
  --mcp-port 9119
```

## How It Works

1. **Build & launch MCP** — unless `--external`, runs `make build`, then
   starts `bin/sectool mcp` as a subprocess on `--mcp-port`.
2. **Connect worker 1 and the orchestrator** — both share the sectool MCP
   server; each gets its own in-process SDK MCP server for control tools
   (`worker_tools` for workers, `orch_tools` for the orchestrator).
3. **Initial prompt** — the user's prompt is sent to worker 1 for
   discovery.
4. **Iteration loop**:
   - Workers run until they stop producing output this turn.
   - The controller builds a structured summary per worker: assistant
     text, tool calls made (with truncated inputs/results), flow IDs
     referenced, and any candidates raised this turn.
   - All summaries + a status line (iter, cost, findings) + pending
     candidates + stall warnings are sent to the orchestrator.
   - The orchestrator may call any number of tools in response:
     - Verification tools (`flow_get`, `replay_send`, `diff_flow`, …) —
       used to independently reproduce candidate behavior.
     - Decision tools — every per-worker decision and every finding is
       expressed as a tool call; the controller consumes them
       deterministically (no prose parsing).
   - The controller then applies decisions: files/dismisses candidates,
     dispatches worker instructions, spawns or retargets workers per
     `plan_workers`, or ends the run on `done`.
5. **Stall detection** — every worker-directed decision carries a
   `progress` tag (`none`/`incremental`/`new`) chosen by the
   orchestrator. Three consecutive `none` tags triggers a stall warning
   in the next orchestrator prompt; one more forces `stop_worker` (or
   ends single-worker runs).
6. **Teardown** — terminates the MCP server (unless `--external`) and
   prints a summary.

## Orchestrator Tools (decision surface)

| Tool | Purpose |
|------|---------|
| `plan_workers(plans)` | Spawn/retarget workers. Callable any turn. |
| `continue_worker(worker_id, instruction, progress)` | Keep worker N going. |
| `expand_worker(worker_id, instruction, progress)` | Pivot worker N's plan. |
| `stop_worker(worker_id, reason)` | Retire worker N. |
| `file_finding(...)` | Record a *verified* finding; must cite verification flows. |
| `dismiss_candidate(candidate_id, reason)` | Mark a worker candidate as not-a-finding. |
| `done(summary)` | End the run. |

The orchestrator also has read/reproduce access to the sectool MCP server
for verification (proxy history, replay, diff, reflection detection, etc.).
Destructive sectool tools (`proxy_rule_*`, `crawl_stop`, `oast_delete`)
are **not** exposed to the orchestrator to prevent unintentional
disruption of running workers.

## Worker Tool

| Tool | Purpose |
|------|---------|
| `report_finding_candidate(...)` | Flag a potential vulnerability with proof flow IDs. The orchestrator will verify and, if confirmed, file the formal finding. |

Workers do not write finding documents themselves — that's the
orchestrator's job (after verification).

## Findings

Filed findings are written as markdown files to the `--findings-dir`
directory:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file has Title, Severity, Affected Endpoint, Description,
Reproduction Steps, Evidence, Impact, and a **Verification** section in
which the orchestrator records the flow IDs and tool calls it used to
confirm the issue.

## Safety Bounds

- **Max iterations**: Configurable hard cap (default 30).
- **Cost ceiling**: Optional `--max-cost` flag halts the loop if total USD
  cost is exceeded.
- **Stall detection**: Driven by the orchestrator's self-reported
  `progress` tag. Three consecutive `progress=none` decisions issue a
  warning; four force a worker stop.
- **Worker timeout**: If a worker produces no response within 5 minutes,
  it is interrupted and the orchestrator is consulted.
- **Orchestrator verification required**: findings are only filed after
  the orchestrator calls `file_finding` with non-empty
  `verification_notes`.

## Running the tests

```bash
cd controller/claude
python -m pytest tests/
```

The tests do not touch the network or the real SDK — they exercise the
queue types, the finding writer, the flow-ID extractor, and the worker-
turn collector against a scripted fake `ClaudeSDKClient`.
