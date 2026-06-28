# Sidecar Phase 1 — Foundation refactor (non-sidecar)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

None — this is the first phase and everything else builds on it. Split internally
into two independent merges that should land in order:

- **1a — `Flow` data model** (do first; adapters in 1b produce `Flow` values).
- **1b — adapter registry + dispatch seam**.

## Goal

Generalize sectool's internal capture model so it can host protocol adapters, with
**no behavior change**. Two outcomes:

1. The unioned `HistoryEntry` is replaced by a generalized `Flow` across the proxy
   package and the store, with transparent migration of pre-existing records.
2. The three built-in HTTP handlers become adapters dispatched through a
   claim/registry seam instead of the hardcoded protocol switch.

No sidecar exists yet. The agent-facing MCP surface and all HTTP/1.1, HTTP/2, and
WebSocket behavior stay byte-identical (spec §9.1); all existing tests pass
unchanged.

## Background & assumed state

sectool is an MCP-primary security toolkit: a single MCP server serves both agents
and a thin CLI. The native proxy (`sectool/service/proxy/`) owns the capture
pipeline — TCP accept, CONNECT tunneling, TLS MITM via a fake CA, HTTP framing —
and feeds captured exchanges into a key-value store (`sectool/service/store/`,
msgpack-serialized, with a disk-paging encrypted `SpillStore`).

Today the capture record is `HistoryEntry` in `sectool/service/proxy/types.go`: a
union carrying `Request`/`Response` (`*RawHTTP1Request`/`*RawHTTP1Response`),
`H2Request`/`H2Response`, `WSFrames []WSFrame`, plus `Protocol`, `H2StreamID`,
`Timestamp`, `Duration`. It is created in three places —
`handler_http1.go` (HTTP/1.1), `handler_http2.go` (HTTP/2), `handler_websocket.go`
(WS frames) — and stored/retrieved centrally in `proxy/history.go`. Critically,
external consumers (MCP tool handlers, CLI) never touch `HistoryEntry` directly:
they read a formatted `ProxyEntry` produced by the native backend
(`backend_http_native.go`). This firewall keeps the real blast radius of the swap
inside the proxy package plus the store.

Connection dispatch lives in `proxy/server.go` (`handleConnection`): it peeks the
opening bytes, rejects the HTTP/2 cleartext preface ("H2C not supported"), routes a
`CONNECT ` prefix to the connect handler, and otherwise hands off to the HTTP/1.1
handler. The WebSocket takeover is decided after a full HTTP request parse via
`isWebSocketUpgrade` in `handler_websocket.go` (called from `handler_http1.go` and
the CONNECT tunnel path). Rules are applied on the hot path through a
`RuleApplier` interface, decoupled from storage.

The spec's target model (§2–§3): a generalized `Flow` with per-side
`{method, path, headers, body, status}` envelopes and flow-level `adapter` /
`protocol_tag` / `direction` / `parent_flow_id` fields; an **adapter registry**
(§2.2) that selects, per connection, which adapter claims the byte stream; and the
three built-in handlers re-expressed as in-process adapters (§2.4 — "the validating
test of the abstraction").

The adapter registry and its claim/dispatch seam live **within the native proxy**
(the in-process HTTP adapters *are* the native proxy) and are not consulted under
the Burp backend (spec §8 Burp row). This keeps the whole adapter mechanism — and,
in Phase 2, the out-of-process sidecar surface — scoped to the native backend.

## Spec references

- §2.2 Adapter registry, §2.3 Connection lifecycle and handoff seams, §2.4 Refactor
  scope for built-in adapters.
- §3.1 Flow, §3.1.1 HistoryEntry → Flow migration, §3.2 session/tunnel envelope,
  §3.3 streams (data-model shapes the `Flow` type must support).
- §3.5 Rule targeting (only the parts needed to keep existing rules working; the full
  tuple/`owner` generalization is **Phase 7**).

## Scope — toolbox (server side)

**1a — `Flow` replaces `HistoryEntry`:**

- Define `Flow` in `sectool/service/proxy/types.go` per spec §3.1: a `request` and/or
  `response` sub-object (each `{method, path, headers, body, status?}`) plus flow-level
  `flow_id`, `adapter`, `protocol_tag`, `direction`, `parent_flow_id`, `started_at`,
  `completed_at`, `annotations`, `size_hint`. Carry the existing wire-fidelity types
  (`Header`, `Wire`, `ChunkFrame`, `LineEnding`) verbatim for HTTP/1.1 fidelity.
- Populate `Flow` from each built-in handler using the §3.1.1 mapping table
  (`Protocol`→`adapter`/`protocol_tag`; `H2StreamID`→header `X-Sectool-Stream-Id`;
  WS frames→child flows with `parent_flow_id` = handshake flow, `method=FRAME`).
- Update `proxy/history.go` (store/get/page) and the native backend's `ProxyEntry`
  formatting (`backend_http_native.go`) to read from `Flow`. Keep `ProxyEntry`'s
  external shape identical — it is the regression firewall.
- **Lazy v0→v1 migration** in the store read path (`proxy/history.go` `Get`, see
  spec §3.1.1): records have no per-record version tag today, so detect a v0
  (`HistoryEntry`) msgpack record on read and rewrite it to `Flow` inline. No startup
  migration, no double storage. Preserve all `SpillStore` behavior (hot cache,
  eviction, compaction, zstd+AES).

**1b — adapter registry + dispatch seam:**

- Introduce a **minimal** in-process adapter interface and registry (e.g.
  `sectool/service/adapter/`). Sized only to what the three built-in adapters need:
  per-connection claim selection and dispatch. A representative shape:

  ```go
  type Adapter interface {
      Name() string
      Claim(opening ConnContext) bool   // does this adapter take the connection?
      Handle(conn Stream) error          // drive framing + emit Flows
  }
  ```

- Replace the hardcoded peek-switch in `proxy/server.go` `handleConnection` with a
  registry claim: iterate registered adapters, the first to claim wins, with the
  HTTP/1.1 adapter as the default fallthrough (preserves today's behavior).
- Refactor `handler_http1.go`, `handler_http2.go`, `handler_websocket.go` to
  implement the adapter interface (spec §2.4). Generalize the WebSocket-101 takeover
  and the h2c-preface handling into the claim model rather than the special-cased
  switch — without changing observable behavior (h2c still rejected, WS still taken
  over after the handshake).

## Scope — `sidecar` package

None. Phase 1 is entirely internal to sectool; the `sidecar` client package is
introduced in **Phase 2** with the transport.

## Out of scope / deferred

- Rule generalization to the §3.5 tuple form and the `owner` field → **Phase 7**.
  Existing 7-type rules keep working unchanged on the refactored adapters.
- MCP tool composition / adapter-typed tool split → **Phase 9**.
- All sidecar-only registry fields (`capabilities`, `mutation_ops`, `owned_rules`,
  `liveness`) → declared/stored in **Phase 2**, fired in later phases. The Phase 1
  registry holds only claim/dispatch.
- Any out-of-process transport, RPC, or wire types → **Phase 2**. The registry (and
  the sidecar surface built atop it) is native-backend-only; gating it off under the
  Burp backend is carried by **Phase 2**.

## Test fixture

None — Phase 1 has no sidecar. Validation is via existing suites plus new
store-migration tests.

## Verification

- Existing HTTP/1.1, HTTP/2, and WebSocket proxy suites pass **byte-identical**.
- New unit test: feed real captured v0 (`HistoryEntry`) spill records through the
  store read path and assert correct v1 (`Flow`) rewrite, with `SpillStore`
  semantics intact.
- Golden-output regression: snapshot `proxy_poll` and `flow_get` output across a
  fixture capture set before and after the swap; assert no diff. This is the primary
  tripwire that the `ProxyEntry` firewall held.
- `make test-all` and `make lint` clean.

## Definition of done

- [ ] `Flow` replaces `HistoryEntry` in the proxy package and store; no remaining
      union-field access outside the migration shim.
- [ ] Lazy v0→v1 migration verified against real records.
- [ ] Three built-in handlers implement the adapter interface; dispatch goes through
      the registry claim; HTTP/2 cleartext and WS-101 behavior unchanged.
- [ ] Golden `proxy_poll`/`flow_get` output unchanged; all existing tests green.
- [ ] `make test-all` + `make lint` pass.
