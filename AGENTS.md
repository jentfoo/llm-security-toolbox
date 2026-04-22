## Project Overview

**go-appsec/toolbox (sectool)** is a CLI and MCP toolkit for human and LLM agent collaboration for application security testing.

Key characteristics:
- MCP-primary architecture: single API serves both agents and CLI
- CLI is a thin client over MCP for human interaction
- Global config at `~/.sectool/config.json` (auto-created)
- All output in markdown format for LLM consumption
- Pluggable backend architecture (native built-in proxy or Burp MCP for HTTP, Interactsh for OAST, Colly for crawling)

## Build Commands

```bash
make build          # Build to bin/sectool
make build-cross    # Cross-compile (linux/darwin, amd64/arm64)
make test           # Quick tests (-short flag)
make test-all       # Full tests with -race and coverage
make lint           # Run golangci-lint and go vet
```

## Architecture

```
CLI Command → MCP Client → MCP Server → Backends (Built-in Proxy or Burp MCP, OAST, Crawler)
MCP Agent  → MCP Server → Backends (Built-in Proxy or Burp MCP, OAST, Crawler)
```

### Core Files

- `sectool/main.go` - Entry point; routes `mcp` subcommand to server mode, else CLI command dispatch
- `sectool/config/config.go` - Config loading/saving, defaults, auto-creation
- `sectool/mcpclient/client.go` - MCP client wrapper for CLI usage
- `sectool/mcpclient/tools.go` - Typed methods for each MCP tool
- `sectool/mcpclient/types.go` - Client-specific option types (*Opts structs)
- `sectool/bundle/bundle.go` - Client-side bundle file operations for export

### Protocol

- `sectool/protocol/workflow.go` - Workflow mode constants shared between service and mcpclient
- `sectool/protocol/types.go` - Shared MCP response types (used by both service and mcpclient)

### Service Layer

- `sectool/service/server.go` - MCP server lifecycle and backend coordination
- `sectool/service/mcp_server.go` - MCP server setup, tool registration, workflow handling
- `sectool/service/mcp_proxy.go` - Proxy and flow_get tool handlers (poll, flow_get, cookie_jar, rules)
- `sectool/service/mcp_replay.go` - Replay tool handlers (send, request_send)
- `sectool/service/mcp_crawl.go` - Crawl tool handlers (create, seed, status, poll, sessions, stop)
- `sectool/service/mcp_oast.go` - OAST tool handlers (create, poll, get, list, delete)
- `sectool/service/mcp_encode.go` - Encode/decode tool handlers (url, base64, html)
- `sectool/service/mcp_hash.go` - Hash tool handler (md5, sha1, sha256, sha512, HMAC)
- `sectool/service/mcp_jwt.go` - JWT decode tool handler
- `sectool/service/mcp_diff.go` - Diff tool handler (structured flow comparison)
- `sectool/service/mcp_reflection.go` - Reflection tool handler (parameter reflection detection)
- `sectool/service/mcp_notes.go` - Notes tool handlers (save, list) and flow listing attachment
- `sectool/service/mcp_respond.go` - Proxy responder tool handlers (respond_add, respond_delete, respond_list); native backend only
- `sectool/service/flags.go` - MCP server flag parsing (`--port`, `--workflow`, `--config`, `--notes`)
- `sectool/service/backend.go` - HttpBackend, ResponderBackend, OastBackend, CrawlerBackend interfaces
- `sectool/service/backend_http_native.go` - Native built-in proxy implementation of HttpBackend
- `sectool/service/backend_http_native_respond.go` - Native backend implementation of ResponderBackend
- `sectool/service/backend_http_burp.go` - Burp MCP implementation of HttpBackend
- `sectool/service/backend_oast_interactsh.go` - Interactsh implementation of OastBackend
- `sectool/service/smtputil.go` - SMTP email header parsing utilities
- `sectool/service/backend_crawler_colly.go` - Colly-based crawler implementation
- `sectool/service/capture_filter.go` - BuildCaptureFilter: compiles proxy exclusion patterns from config
- `sectool/service/search.go` - RE2 pattern compilation with LLM-friendly double-escape correction; flow content matching
- `sectool/service/httputil.go` - HTTP request/response parsing utilities
- `sectool/service/jsonutil.go` - JSON field modification utilities
- `sectool/service/types.go` - Service-specific request and internal types

### Proxy Package

- `sectool/service/proxy/types.go` - Core types (Header, RawHTTP1Request/Response, H2RequestData/Response, HistoryEntry, Target, RuleApplier)
- `sectool/service/proxy/parser.go` - HTTP/1.1 tolerant parser with wire fidelity
- `sectool/service/proxy/validate.go` - Optional request validation
- `sectool/service/proxy/server.go` - TCP listener, accept loop, protocol detection
- `sectool/service/proxy/handler_http1.go` - Plain HTTP and HTTP-over-TLS handler
- `sectool/service/proxy/handler_connect.go` - CONNECT tunnel and TLS MITM with ALPN negotiation
- `sectool/service/proxy/handler_http2.go` - HTTP/2 stream handler with HPACK
- `sectool/service/proxy/handler_websocket.go` - WebSocket frame proxying
- `sectool/service/proxy/cert.go` - CA and per-hostname certificate management
- `sectool/service/proxy/history.go` - Thread-safe history storage
- `sectool/service/proxy/filter.go` - CaptureFilter type, SetCaptureFilter/ShouldCapture
- `sectool/service/proxy/interceptor.go` - ResponseInterceptor interface for serving canned responses in place of upstream requests
- `sectool/service/proxy/compression.go` - gzip/deflate utilities
- `sectool/service/proxy/sender.go` - Wire-fidelity request sender (H1 and H2)
- `sectool/service/proxy/httputil.go` - HTTP method extraction, header grouping, and raw query modification utilities
- `sectool/service/proxy/hpack.go` - HPACK encoder/decoder management

### Burp MCP Client

- `sectool/service/mcp/burp.go` - SSE-based Burp Suite MCP client
- `sectool/service/mcp/types.go` - MCP-specific types

### State Management

- `sectool/service/store/storage.go` - Storage interface and in-memory implementation
- `sectool/service/store/spill.go` - SpillStore: disk-paging Storage with LRU eviction, encryption, and compaction
- `sectool/service/store/serialize.go` - Msgpack serialization helpers
- `sectool/service/store/proxy_index.go` - Bidirectional flow_id ↔ proxy offset mapping
- `sectool/service/store/replay_history.go` - Replay request/response storage with meta/payload split
- `sectool/service/store/notes.go` - Note storage with reverse flow index
- `sectool/service/ids/ids.go` - Base62 random IDs using crypto/rand

### CLI Commands

- `sectool/proxy/flags.go` - Subcommand parsing (summary/list/cookies/export/rule)
- `sectool/proxy/list.go` - List/summary command implementation
- `sectool/proxy/cookies.go` - Cookies command implementation
- `sectool/proxy/export.go` - Export command implementation
- `sectool/proxy/rule.go` - Rule CRUD command implementations
- `sectool/crawl/flags.go` - Crawl subcommand parsing
- `sectool/crawl/crawl.go` - Crawl command implementations
- `sectool/replay/flags.go` - Subcommand parsing (send/get)
- `sectool/replay/replay.go` - Command implementations
- `sectool/oast/flags.go` - Subcommand parsing (create/poll/list/delete)
- `sectool/oast/oast.go` - Command implementations
- `sectool/encoding/flags.go` - Encode/decode subcommand parsing (url/base64/html)
- `sectool/encoding/encoding.go` - Encoding/decoding implementations
- `sectool/hash/flags.go` - Hash subcommand parsing
- `sectool/hash/hash.go` - Hash computation (plain and HMAC)
- `sectool/jwt/flags.go` - JWT subcommand parsing
- `sectool/jwt/jwt.go` - JWT decode and inspection
- `sectool/diff/flags.go` - Diff subcommand parsing
- `sectool/diff/diff.go` - Diff command implementation (CLI formatting and display)
- `sectool/reflected/flags.go` - Reflected subcommand parsing
- `sectool/reflected/reflected.go` - Reflected command implementation

### Shared CLI Utilities

- `sectool/cliutil/output.go` - Output writer and color mode detection (NO_COLOR/FORCE_COLOR aware)
- `sectool/cliutil/colors.go` - Status-code coloring helpers
- `sectool/cliutil/styles.go` - go-pretty table styles (light/simple)
- `sectool/cliutil/table.go` - NewTable helper and row painters
- `sectool/cliutil/hints.go` - Muted hint and summary print helpers
- `sectool/cliutil/suggest.go` - "Did you mean" levenshtein suggestions for unknown commands
- `sectool/util/strutil.go` - TruncateString and other shared string utilities

### Controllers (`controller/`)

Two sibling autonomous security exploration controllers drive a sectool MCP server with a worker/verifier/director multi-agent loop. Both share the same agent contract (workers run sectool tools and call `report_finding_candidate`; the verifier independently reproduces candidates and calls `file_finding` or `dismiss_candidate`; the director decides what each worker does next). They differ only in language and LLM backend. See `controller/README.md` for the comparison and recommendation (`secagent` is the default; `claude` is for users who want to bill the work to a Claude Code subscription).

Outer loop (both controllers): **autonomous worker turns → verification → direction**, repeated per iteration. Phases are tool-gated — calling a tool outside its phase returns an `is_error=true` response.

#### secagent — Go controller (`controller/secagent/`)

Go module (`github.com/go-appsec/secagent`) targeting any OpenAI-compatible chat-completions endpoint. Built to `bin/secagent` by `make build` / `make build-secagent`. Entry point in `cmd/secagent/main.go` resolves the repo root, parses `config.Config`, and hands off to `orchestrator.Run`.

- `controller/secagent/cmd/secagent/main.go` - CLI entry; repo-root detection, signal handling, invokes `orchestrator.Run`
- `controller/secagent/config/config.go` - `Config` struct and `Parse` (connection/pool, context/compaction, sectool, loop, stall, logging flags); caps `MaxWorkers` at 5
- `controller/secagent/agent/agent.go` - `Agent` interface, `ToolDef`/`ToolCall`/`TurnSummary`/`EscalationReason` types, role constants
- `controller/secagent/agent/openai_agent.go` - `OpenAIAgent`: OpenAI chat-completions driver, tool-call dispatch loop, `Drain` chain, truncation notice
- `controller/secagent/agent/openai_client.go` - `ChatClient` HTTP implementation against the OpenAI-compatible endpoint
- `controller/secagent/agent/pool.go` - `ClientPool`: bounded-concurrency gate; one pool per base URL, shared across workers/verifier/director
- `controller/secagent/agent/history.go` - Message history storage (system + turn messages + tool results)
- `controller/secagent/agent/compact.go` - Context compaction: high/low watermark passes, `KeepTurns` trailing guard, stubbing of old tool results
- `controller/secagent/agent/turn.go` - `TurnSummary` construction from tool calls and flow IDs
- `controller/secagent/agent/status.go` - Periodic one-line status summary prompt (`ProgressLogInterval`-gated)
- `controller/secagent/agent/think.go` - Reasoning/thinking message handling for models that emit it
- `controller/secagent/agent/repair.go` - Malformed-tool-call repair (reprompts with schema hints)
- `controller/secagent/agent/fake_agent.go` - Scripted `FakeAgent` used throughout the orchestrator test suite
- `controller/secagent/mcp/client.go` - `mark3labs/mcp-go` streamable-HTTP wrapper; converts sectool MCP tools to `agent.ToolDef`
- `controller/secagent/mcp/dispatch.go` - `TruncateResult`: per-tool-result byte cap with the instructive truncation notice
- `controller/secagent/orchestrator/controller.go` - `Run` entry + `AgentFactory` (`OpenAIFactory` builds real agents; tests inject fakes); top-level iteration loop
- `controller/secagent/orchestrator/autonomous.go` - Phase 1: runs every alive worker concurrently up to its `autonomous_budget`; emits `continuePrompt` between turns; escalates on candidate/silent/error
- `controller/secagent/orchestrator/verify.go` - Phase 2: `RunVerificationPhase` up to `VerificationMaxSubsteps` (6); applies `file_finding`/`dismiss_candidate` between substeps; ends on `verification_done` or empty pending list
- `controller/secagent/orchestrator/direct.go` - Phase 3: `RunDirectionPhase` up to `DirectionMaxSubsteps` (4) + mandatory self-review substep (`DirectionSelfReviewMaxRounds=2`); applies `plan_workers`/`continue_worker`/`expand_worker`/`stop_worker`; ends on `direction_done` or `done`
- `controller/secagent/orchestrator/tools.go` - `WorkerToolDefs` (`report_finding_candidate`) and `OrchestratorToolDefs`: phase-gated verifier/director tool set with severity + progress-tag validation
- `controller/secagent/orchestrator/candidates.go` - `FindingCandidate`, `CandidatePool` (thread-safe, pending/verified/dismissed)
- `controller/secagent/orchestrator/decisions.go` - `DecisionQueue` (per-phase accumulation, `BeginPhase`, verification/direction done summaries), `WorkerDecision`, `PlanEntry`, `FindingFiled`, `CandidateDismissal`
- `controller/secagent/orchestrator/findings.go` - `FindingWriter`: `Slugify`, `CanonicalEndpoint`, dedup by title-slug + canonical endpoint, `finding-NN-slug.md` numbering
- `controller/secagent/orchestrator/worker.go` - `WorkerState` lifecycle, `AutonomousTurns`, `EscalationReason`, `ProgressNoneStreak`
- `controller/secagent/orchestrator/stall.go` - `UpdateStallStreaks`: increments on silent escalations, resets on candidate or new-flow turns; `--stall-warn-after` / `--stall-stop-after` thresholds
- `controller/secagent/orchestrator/narrator.go` - Human-readable narration of each iteration's phases for the log
- `controller/secagent/orchestrator/flowids.go` - Flow-ID extraction regex shared with worker turn summaries
- `controller/secagent/orchestrator/prompts.go` - Per-iteration prompt assembly (worker continue, verifier substep, director substep)
- `controller/secagent/orchestrator/logging.go` - `Logger`: structured JSON events to `--log-file`
- `controller/secagent/orchestrator/server.go` - `StartSectool`: runs `make build-sectool` (unless `--skip-build`), launches `bin/sectool mcp`, waits for HTTP readiness; terminates on teardown (unless `--external`)
- `controller/secagent/orchestrator/constants.go` - Phase names, substep caps, stall defaults
- `controller/secagent/prompts/worker.go`, `prompts/verifier.go`, `prompts/director.go` - Role system prompts (phase-aware tool contracts)
- `controller/secagent/tests/` and `*_test.go` alongside each file - `FakeAgent`-driven unit/integration tests; no network or real LLM

#### claude — Python controller (`controller/claude/`)

Python 3.10+ module using the Claude Agent SDK; authenticates via the `claude` CLI's OAuth session (no API key). Same worker/verifier/director architecture as secagent, implemented in-process with SDK MCP servers.

- `controller/claude/controller.py` - Main loop: build, MCP server lifecycle, worker/verifier/director SDK clients, per-phase drain, decision application, stall detection, recovery, `MIN_ITERATIONS_FOR_DONE` guard
- `controller/claude/config.py` - `Config` dataclass, CLI arg parsing, model alias map (`sonnet`/`opus`/`haiku` → model IDs)
- `controller/claude/tools.py` - SDK MCP servers. `worker_tools` exposes `report_finding_candidate`. `orch_tools` is phase-gated by `DecisionQueue.phase`: verification-phase tools are `file_finding`/`dismiss_candidate`/`verification_done`; direction-phase tools are `plan_workers`/`continue_worker`/`expand_worker`/`stop_worker`/`direction_done`/`done`; wrong-phase calls return an `is_error=true` response with transition guidance. Hosts `CandidatePool`, `DecisionQueue` (tracks `phase`, `verification_done_summary`, `direction_done_summary`), `WorkerTurnSummary`, `ToolCallRecord`, `FindingCandidate`, `FindingFiled`, `CandidateDismissal`, `PlanEntry`, `WorkerDecision`, and `extract_flow_ids`
- `controller/claude/findings.py` - `FindingWriter`: slug-based filename generation, dedup by title/endpoint similarity, markdown template with Verification section
- `controller/claude/prompts/worker.py` - Worker system prompt (sectool tool surface + candidate reporting contract)
- `controller/claude/prompts/orchestrator_verifier.py` - Verifier system prompt (reproduce candidates with full sectool surface; file or dismiss; non-destructive + cleanup)
- `controller/claude/prompts/orchestrator_director.py` - Director system prompt (plan/continue/expand/stop workers; set per-iteration `autonomous_budget`)
- `controller/claude/tests/` - pytest suite: `test_controller_loop.py`, `test_tools.py`, `test_findings.py`, `conftest.py` (scripted fake `ClaudeSDKClient`; no real SDK or network)
- `controller/claude/requirements.txt`, `pyproject.toml` - Python deps (`claude-agent-sdk`)

The verifier gets the full sectool tool surface via the `mcp__sectool__*` glob (`controller.py:ORCH_SECTOOL_TOOLS_GLOB`) — same access as workers. Its system prompt directs it to prefer non-destructive reproduction and clean up any rules/responders/sessions it introduces. Stall thresholds: `STALL_WARN_AFTER=3`, `STALL_STOP_AFTER=4` consecutive silent escalations. Verification cap `VERIFICATION_MAX_SUBSTEPS=6`; direction cap `DIRECTION_MAX_SUBSTEPS=4` followed by one mandatory self-review substep. Max workers capped at 5 by `config.parse_args`. `done(summary)` before `MIN_ITERATIONS_FOR_DONE` (5) with zero findings is rejected as premature. See `controller/claude/README.md` for usage and `controller/README.md` for the secagent-vs-claude comparison.

### Config

Global config at `~/.sectool/config.json` (auto-created with defaults):

```json
{
  "mcp_port": 9119,
  "burp_required": false,
  "max_body_bytes": 10485760,
  "include_subdomains": true,
  "allowed_domains": [],
  "exclude_domains": [],
  "interactsh_server_url": "",
  "interactsh_auth_token": "",
  "proxy": {
    "exclude_extensions": "<RE2 alternation, see DefaultExcludeExtensions>"
  },
  "crawler": {
    "disallowed_paths": ["*logout*", "*signout*", "*sign-out*", "*delete*", "*remove*"],
    "delay_ms": 200,
    "parallelism": 2,
    "max_depth": 10,
    "max_requests": 1000,
    "extract_forms": true,
    "submit_forms": false,
    "recon": false
  }
}
```

Domain scoping rules:
- `exclude_domains`: always takes precedence, always matches subdomains
- `allowed_domains`: strict allowlist when non-empty; respects `include_subdomains` for subdomain matching
- Neither configured: no restriction (default)

Proxy capture exclusion filters (RE2 patterns, `proxy` section):
- `exclude_extensions` (`*string`): matches file extension from path (no dot), anchored. nil → default (see `DefaultExcludeExtensions`), `""` → disabled
- Matching requests are still proxied but never stored in history

### Export Bundle Layout

Bundles at `./sectool-requests/<flow_id>/`: `request.http` (headers + body placeholder), `body` (raw binary-safe), `request.meta.json` (method/URL/timestamps), `response.http`, `response.body`

## Key Types

**Backend Interfaces (`sectool/service/backend.go`):**
- `HttpBackend` - proxy history (get/regex), request sending, match/replace rules CRUD
- `ResponderBackend` - custom canned-response registration by origin/path; native proxy only
- `OastBackend` - OAST session create/delete, event polling, session listing
- `CrawlerBackend` - crawl session lifecycle and result retrieval

**Store (`sectool/service/store/`):**
- `Storage` - key-value blob interface (`memStorage`, `SpillStore` disk-paging)
- `ProxyIndex` - bidirectional flow_id ↔ proxy offset mapping
- `ReplayHistoryStore` - replay storage with meta/payload split
- `NoteStore` - note storage with reverse flow_id index

## MCP Tools

**MCP server:** `sectool mcp [--proxy-port PORT] [--burp] [--port PORT] [--workflow MODE]` (default port 9119, auto-detects backend)

- `workflow` - select mode (explore/test-report) for task-specific instructions
- `proxy_poll` - query proxy history: summary or list with filters
- `flow_get` - full request/response for any flow (proxy, replay, or crawl)
- `cookie_jar` - extract and deduplicate cookies; overview without filters, full values and JWT decode with name/domain filter
- `proxy_rule_list` - list match/replace rules
- `proxy_rule_add` - add match/replace rule
- `proxy_rule_delete` - delete rule
- `proxy_respond_add` - register a canned response for a given origin/path; native proxy only
- `proxy_respond_delete` - delete a responder by ID or label
- `proxy_respond_list` - list registered responders
- `crawl_create` - start crawl from URLs or proxy flow seeds
- `crawl_seed` - add seeds to running crawl
- `crawl_status` - crawl progress metrics
- `crawl_poll` - query results: summary, flows, forms, or errors
- `crawl_sessions` - list all crawl sessions
- `crawl_stop` - stop a running crawl session
- `replay_send` - send with modifications; returns flow_id for use with flow_get
- `request_send` - send new HTTP request from scratch; returns flow_id for use with flow_get
- `oast_create` - create OAST session for out-of-band testing; optional `redirect_target` for 307 redirect responses (server-dependent)
- `oast_poll` - poll events: summary or list
- `oast_get` - structured event details; optional `fields` filter (dest, headers, body)
- `oast_list` - list active OAST sessions
- `oast_delete` - delete OAST session
- `encode` - encode a string (url, base64, html)
- `decode` - decode a string (url, base64, html)
- `hash` - compute hash digest (md5, sha1, sha256, sha512, HMAC)
- `jwt_decode` - decode and inspect JWT tokens
- `diff_flow` - compare two captured flows with structured, content-type-aware diffing
- `find_reflected` - detect request parameter values reflected in the response
- `notes_save` - create, update, or delete notes/findings linked to flows (requires `--notes`)
- `notes_list` - list saved notes with filters (requires `--notes`)

## CLI Commands

CLI requires a running MCP server. Maps to MCP tools via `sectool <module> <sub>` pattern.

- `proxy`: `summary`, `list`, `cookies`, `export`, `rule {add,delete,list}`
- `crawl`: `create`, `seed`, `status`, `summary`, `list`, `export`, `sessions`, `stop`
- `replay`: `send`, `get`
- `oast`: `create`, `summary`, `poll`, `get`, `list`, `delete`
- `encode`: `url`, `base64`, `html`
- `decode`: `url`, `base64`, `html`
- `hash`: compute hash digests
- `jwt`: decode JWT tokens
- `diff`: `<flow_a> <flow_b> --scope <scope>`
- `reflected`: `<flow_id>`
- `version`

## Development Guidelines

### CLI and MCP Parity

- CLI commands map to MCP tools (e.g., `proxy list` → `proxy_list`)
- CLI is a thin client - all logic lives in MCP tool handlers
- New features should be implemented in MCP handlers first, CLI wraps them

### CLI Conventions

- All list operations must support `--limit` flag
- Flatten `--help` details at the first subcommand level
- CLI requires running MCP server; error message guides user to start it

### Code Style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context, not a single line of code
- Godocs should only describe the inputs and outputs, not how the function works
- Follow existing naming conventions and neighboring code style

### Collection handling

Reach for stdlib `slices`/`maps`/`strings` and `github.com/go-analyze/bulk` before writing a manual loop. The patterns below come up often:

- **Clone a slice or map**: `slices.Clone(src)` / `maps.Clone(src)`. Do not `make([]T, len(src))` + `copy(dst, src)` for whole-slice clones (`copy` is still correct for sub-slice writes into an existing buffer).
- **Filter a slice (same element type, no transformation)**: `bulk.SliceFilter(predicate, s)`. Use `bulk.SliceFilterInPlace` when the caller doesn't reuse the input backing array. Use instead of `for _, v := range s { if cond { out = append(out, v) } }`.
- **Slice → map set**: `bulk.SliceToSet(s)` (returns `map[T]struct{}`). Membership tests use the comma-ok form: `if _, ok := set[k]; ok`.
- **Map → slice of keys / values**: `bulk.MapKeysSlice(m)` and `bulk.MapValuesSlice(m)`. Don't write `for k := range m { keys = append(keys, k) }`.
- **Membership check on a slice**: `slices.Contains(s, x)` for comparable element types, `slices.ContainsFunc(s, predicate)` for everything else.

### Testing

Structure and conventions:
- One `_test.go` file per implementation file that requires testing
- One `func Test<FunctionName>` per target function, using table-driven tests or `t.Run` cases
- Test case names should be at most 3 to 5 words and in lower case with underscores
- Use `t.Parallel()` at test function start when no shared state, but not in the test cases
- Isolated temp directories via `t.TempDir()` when needed
- Context timeouts via `t.Context()` for tests with I/O

Assertions and validation:
- Assertions rely on `testify` (`require` for setup, `assert` for assertions)
- Don't include messages unless the message provides context outside of the test point
- Do NOT use time.Sleep for tests, instead use require.Eventually or deterministic triggers

Test helpers:
- Mock MCP server available via `service.NewTestMCPServer()`
- Test utilities in `sectool/service/testutil/`

Verification:
- Always verify with `make test-all` and `make lint` before considering changes complete
