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

1. The unioned `HistoryEntry` is replaced by a generalized `Flow` — a single common
   envelope type shared by the store today and the out-of-process sidecar API in
   later phases — across the proxy package and the store. sectool's history store is
   ephemeral (in-memory, spilling only to a temp file under a per-startup encryption
   key; never persisted across restarts), so this is a pure in-code type swap with
   **no record migration**.
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
- §3.1 Flow, §3.1.1 HistoryEntry → Flow field mapping (used here only as the
  field-correspondence guide for the in-code swap — there is no runtime migration,
  the store is ephemeral), §3.2 session/tunnel envelope, §3.3 streams (data-model
  shapes the `Flow` type must support).
- §3.5 Rule targeting (only the parts needed to keep existing rules working; the
  optional `adapter` scope and rule push to sidecars are **Phase 7**).

## Scope — toolbox (server side)

**1a — `Flow` replaces `HistoryEntry`:**

- Define `Flow` in `sectool/service/proxy/types.go` per spec §3.1: a `request` and/or
  `response` sub-object plus flow-level `flow_id`, `adapter`, `protocol_tag`,
  `direction`, `parent_flow_id`, `started_at`, `completed_at`, `annotations`,
  `size_hint`. Each side is a **single common `Message` envelope** —
  `{method, path, query, status, headers, body}` plus the existing wire-fidelity
  fields (`Header`, `Wire`, `ChunkFrame`, `LineEnding`, trailers, line endings)
  carried verbatim for HTTP/1.1. `Message` is the structural union of today's
  near-identical `RawHTTP1Request` + `RawHTTP1Response`; HTTP/2 pseudo-headers fold
  into `headers` (`:authority`, `:status`, …). This one type is the storage
  representation today and the sidecar-API representation in later phases (see
  "Envelope representation" below).
- **Adapters stay protocol-specific on the hot path; the common type is a boundary.**
  The HTTP/1.1, HTTP/2, and WebSocket handlers keep parsing, applying rules, and
  serializing in their precise wire types (`RawHTTP1Request`/`RawHTTP1Response`,
  `h2Stream` state); they convert to the common `Message`/`Flow` **only at store
  time**. The wire/rules/serialization hot paths are therefore untouched
  (byte-identical), and the generic representation lives only where flows are stored,
  listed, diffed, and replayed.
- Populate `Flow` from each built-in handler using the §3.1.1 mapping table
  (`Protocol`→`adapter`/`protocol_tag`; `H2StreamID`→header `X-Sectool-Stream-Id`).
  **WebSocket frames become child flows now** (laying the §3.3 stream foundation):
  one child `Flow` per frame with `parent_flow_id` = the handshake flow,
  `method=FRAME`, `path=/ws/<opcode>`, `body` = unmasked payload, `direction` set.
  Children are stored payload-only and excluded from the `proxy_poll` listing /
  `flowOrder`, so external output is unchanged (frames are not surfaced today).
- Update `proxy/history.go` (store/get/page) and the native backend's `ProxyEntry`
  formatting (`backend_http_native.go`) to read from `Flow`. `ProxyEntry` stays the
  boundary external consumers read (not `Flow` directly), so the swap stays inside the
  proxy package plus the store — but byte-identity of `ProxyEntry`/`HistoryMeta` field
  values is *not* a goal; only the agent-visible output must not regress. The
  `protocol_tag` is carried through verbatim: HTTP/2 surfaces as `"http/2"` (the
  internal selector was renamed from the old `"h2"`), `websocket` / `http/1.1`
  unchanged. `ProxyEntry.Protocol` / `HistoryMeta.Protocol` are internal plumbing
  (the value feeds replay's protocol selection and is not rendered in `proxy_poll` —
  `FlowEntry` has no protocol field — nor in `flow_get`, which emits raw bytes via the
  unchanged `formatH2*`), so the `"h2"`→`"http/2"` rename is not agent-visible.
- **No record migration.** The history store is ephemeral — every record in a run is
  written by the current build, so there are no prior `HistoryEntry` records to
  convert and no version tag is needed. `HistoryEntry` and the H2/WS stored sub-types
  are deleted outright. All `SpillStore` behavior (hot cache, eviction, compaction,
  zstd+AES) is preserved unchanged.

> **Envelope representation (decided).** A single common `Message`/`Flow` struct — not
> a Go interface with per-protocol implementations. An interface would force a custom
> msgpack codec carrying a type discriminator (re-hiding the very union being removed)
> and a setter-heavy interface for in-place rule mutation. The single struct loses no
> wire fidelity; its only cost is a few unused fields per side (a response carries an
> empty `method`, a request an empty `status`). Protocol-specific richness is kept
> where it belongs — in the adapters' hot-path wire types — and flattened to the
> common type at the store-time boundary.

**1b — adapter registry + dispatch seam:**

- Introduce a **minimal** in-process adapter interface and registry (the
  `sectool/service/proxy/protocol` package — see "Implementation outcome"). Sized only
  to what the three built-in adapters need: per-connection claim selection and dispatch.
  A representative shape (realized as-built as two seams, `EarlyAdapter` /
  `UpgradeAdapter`):

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

## Implementation outcome (as built)

Decisions taken during implementation that refine the scope above:

- **Package layout.** The data model was relocated into a new `sectool/service/proxy/types`
  package (`Flow`, `Message`, `RawHTTP1Request/Response`, `Header(s)`, `ChunkFrame`,
  `WireFormat`, `LineEnding`, `Target`, `HistoryMeta`, `RuleApplier`, and the
  `SerializeRaw`/`format*` helpers). The adapter registry lives in a separate
  `sectool/service/proxy/protocol` package — **not** `sectool/service/adapter/`. Both choices
  break the import cycle one-directionally (`proxy/types` ← `proxy/protocol` ← `proxy`, and
  `proxy/types` ← `proxy`); a sibling/nested package without the type relocation would cycle
  against `proxy` for `Target`/`RawHTTP1Request`/handler structs. References were re-qualified
  to `types.X` directly (no re-export aliases). `HistoryStore`, the handlers, the parser, and
  the sender stay in `proxy`.
- **Two claim seams, not one.** Instead of a single `Adapter{Claim, Handle}`, `proxy/protocol`
  defines `EarlyAdapter` (`Name`/`ClaimEarly`/`ServeEarly`) for accept-time claims and
  `UpgradeAdapter` (`Name`/`ClaimUpgrade`/`ServeUpgrade`) for post-HTTP-upgrade claims, plus
  `EarlyClaimCtx` / `UpgradeClaimCtx` / `UpgradeConns` context structs and a `Registry`
  (`DispatchEarly` / `ClaimUpgrade`, first-claim-wins). The ALPN-h2 post-CONNECT path is
  modeled as an `early_claim` on the decrypted stream (`TLSTerminated` + `ALPN`), unifying raw
  accept and post-CONNECT into one seam.
- **Handlers wrapped by thin shims.** `http1Adapter` / `http2Adapter` / `wsAdapter`
  (`adapter_shims.go`) implement the interfaces over the existing handler structs; the handler
  bodies (`handler_http2.go`, `handler_websocket.go`) are unchanged. `handler_http1.go` swapped
  its `wsHandler` field for `reg *protocol.Registry` and routes the two WS-upgrade sites through
  `ClaimUpgrade`.
- **h2c reject and CONNECT stay as transport guards.** `handleConnection` keeps the
  h2c-cleartext reject and the `CONNECT ` detection as pre-seam guards; the claim seam only
  chooses among the three real capture adapters. `routeByProtocol` feeds the decrypted stream
  back through `DispatchEarly`. (`http1` is the unconditional fallthrough, registered last.)

## Scope — `sidecar` package

None. Phase 1 is entirely internal to sectool; the `sidecar` client package is
introduced in **Phase 2** with the transport.

## Out of scope / deferred

- The optional rule `adapter` scope (§3.5) and rule push to sidecars → **Phase 7**.
  Existing 7-type rules keep working unchanged on the refactored adapters.
- MCP tool composition / adapter-typed tool split → **Phase 9**.
- All sidecar-only registry fields (`capabilities`, `mcp_tools`, `liveness`) →
  declared/stored in **Phase 2**, fired in later phases. The Phase 1 registry holds
  only claim/dispatch.
- Any out-of-process transport, RPC, or wire types → **Phase 2**. The registry (and
  the sidecar surface built atop it) is native-backend-only; gating it off under the
  Burp backend is carried by **Phase 2**.

## Test fixture

None — Phase 1 has no sidecar, and the store is ephemeral (no record migration).
Validation is via the existing proxy suites plus new golden-output regression
(`proxy_poll` / `flow_get`) around the `HistoryEntry`→`Flow` swap.

## Verification

- Existing HTTP/1.1, HTTP/2, and WebSocket proxy suites pass **byte-identical**.
- Golden-output regression: snapshot `proxy_poll` and `flow_get` output across a
  fixture capture set before and after the swap; assert no diff. This is the primary
  tripwire that the `ProxyEntry` firewall held.
- New unit tests for the store-time conversion: `Message`/`Flow` round-trips through
  the store; HTTP/2 pseudo-header folding reproduces identical `formatH2*` bytes; WS
  child flows are stored, retrievable by id, and absent from `Page` / `PageMeta`.
- `make test-all` and `make lint` clean.

## Definition of done

- [x] `Flow` (with the single common `Message` envelope) replaces `HistoryEntry` in
      the proxy package and store; no remaining protocol-union fields; `HistoryEntry`
      and the H2/WS stored sub-types deleted.
- [x] Adapters convert to the common type only at store time; wire/rules/serialization
      hot paths untouched.
- [x] WebSocket frames stored as child flows (`parent_flow_id`, `method=FRAME`),
      excluded from the default listing.
- [x] Three built-in handlers implement the adapter interface (via thin shims); dispatch
      goes through the registry claim; HTTP/2 cleartext and WS-101 behavior unchanged. *(1b)*
- [x] Golden `proxy_poll`/`flow_get` output unchanged; all existing tests green.
- [x] `make test-all` + `make lint` pass.
