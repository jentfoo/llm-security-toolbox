# Sidecar Phase 3 — Flow emission & core read access

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 2** (a registered sidecar over the RPC channel). Prerequisite for
Phase 7 (rule push references emitted flows) and Phase 9 (`core_query`). Independent
of the byte-interception chain (Phases 4–6), so it can be built before them.

## Goal

Let a registered sidecar publish captured exchanges into sectool's unified history and
read sectool's own state. After this phase a sidecar can emit single
request/response flows, two-phase (incremental) flows, streams (parent + ordered
children), and session/tunnel envelopes — all appearing in `proxy_poll`/`flow_get`/
`diff_flow` exactly like HTTP flows — and can read history and rules via `core_query`.
This is the first phase where non-HTTP flows become real, exercised purely over the
RPC channel with no socket interception.

## Background & assumed state

After Phase 2, a sidecar is a registered adapter on the JSON-RPC connection; sectool
knows its declared protocols and capabilities but receives no flows from it. The
generalized `Flow` model from Phase 1 (spec §3.1) already backs the store and the
`proxy_poll`/`flow_get` tools, with `ProxyEntry` formatting as the external view.

The spec models everything a sidecar emits as a `Flow` via one method, `push_flow`
(§6a.2). There is no separate primitive for sessions or streams:

- A **session/tunnel envelope** (§3.2) is an ordinary `Flow` with
  `direction=bidirectional`, `protocol_tag` ending `.tunnel`, `method=TUNNEL`,
  handshake metadata in `headers`; its `flow_id` is the grouping key children point
  at via `parent_flow_id`.
- A **stream** (§3.3) is a parent `Flow` plus child `Flow`s, each with
  `parent_flow_id` set. Children are persisted and replayed **in emission order** —
  the single ordered RPC connection preserves order and sectool never reorders, so
  there is no per-chunk sequence number.
- **Two-phase completion** (§6a.2): the request side may be emitted first (sectool
  returns a `flow_id`), with the response side attached later by re-invoking
  `push_flow` with that `flow_id`. The same form records session/stream teardown
  (same `flow_id`, `completed_at` set).

When the wire form is not natively decodable by sectool (protobuf, custom framing),
the sidecar also supplies `body_raw` (post-decryption wire bytes) and `body_codec`
(transform chain + logical content-type), per §3.1; sectool stores both, every tool
operates on the logical `body`, and replay later uses `body_raw`/`body_codec`.

`core_query` (§6a.9) is read-only access to sectool's read-side core tools so a
sidecar can inspect captured traffic and the rule list while implementing its logic.

## Spec references

- §3.1 Flow, §3.2 session/tunnel envelope, §3.3 streams.
- §6a.2 `push_flow`, §6a.3 `log`, §6a.4 `report_metrics`, §6a.9 `core_query`.
- §8 Feature parity (the `adapter` / `protocol_tag` / `parent_flow_id` filter fields;
  `find_reflected` / `diff_flow` generalization).
- §10 Security considerations (sidecar identity in flow metadata).

## Scope — toolbox (server side)

- **`push_flow` handler** (§6a.2): accept a `Flow` object on a request side and/or
  response side, assign a `flow_id` on first emission, persist via the Phase 1 store.
  Support:
  - single request/response flows;
  - **two-phase completion** — re-invocation with an existing `flow_id` attaches the
    response side (or marks `completed_at` for session/stream close);
  - **streams** — a parent flow whose `flow_id` is the stream id, plus child flows
    carrying `parent_flow_id`; persist children in emission order, never reorder;
  - **session/tunnel envelopes** — the §3.2 bidirectional shape (no special casing,
    just a `Flow`);
  - `body_raw` + `body_codec` storage when supplied (both retained; tools use `body`).
  - Attribute every flow to the emitting sidecar (§10 sidecar identity): record the
    emitting **adapter name**, the sidecar **version**, and its **instance_id** on the
    flow. This populates the per-flow attribution the Phase 2 ownership/in-flight
    bookkeeping (and §5.5 `resume`) relies on.
- **`log` and `report_metrics`** (§6a.3, §6a.4): structured diagnostic logging and
  counter/gauge intake (notifications).
- **`core_query`** (§6a.9): dispatch the named read-side core tool (`proxy_poll`,
  `flow_get`, `proxy_rule_list`, `cookie_jar`, `diff_flow`, `find_reflected`,
  `notes_list`, `oast_poll`, …) with the supplied params and return its normal
  result. Read/inspection only — no write access to another adapter's flows.
- **Filter surfacing** (§8): expose `adapter`, `protocol_tag`, and `parent_flow_id`
  as filterable fields in `proxy_poll`/`flow_get`, now that non-HTTP flows exist to
  exercise them. Host/path filters resolve against the HTTP-shaped `Flow` fields every
  adapter populates.
- **Read-side tool generalization** (§8): generalize the analysis tools now that
  non-HTTP flows exist. `find_reflected` pairs flows on the **same adapter** or
  **sharing a `parent_flow_id`** (searching request-side params reflected in
  response-side body); its default HTTP behavior is unchanged and the variant
  *encodings* (`url_query`, `js_unicode`, `html_*`, …) remain HTTP-specific. Confirm
  `diff_flow` content-type detection (JSON/text/binary) operates on adapter flows via
  the `headers`/`body` of both flows. These are the §8 behaviors with no prior owner;
  they belong here because Phase 3 is when non-HTTP flows first exist to exercise them.

## Scope — `sidecar` package

- `PushFlow` helper(s): emit a single flow, attach a response (two-phase), open a
  stream parent, and emit ordered stream children — modeling the §3.2/§3.3
  conventions so adapter authors do not hand-build envelopes.
- `Log` and `ReportMetrics` helpers.
- `CoreQuery` helper returning the core tool's result.

## Out of scope / deferred

- Byte interception / `stream_*` events → Phase 4. `push_flow` here is driven by the
  sidecar's own logic over RPC, not by intercepted sockets.
- Rule push and mutation audit pairs → Phase 7.
- Replay/origination of emitted flows → Phase 8.
- `find_reflected` **cross-flow pairing** of one-way request/response flows
  (same-adapter / shared-`parent_flow_id`, spec §8) → deferred. Phase 3 keeps the
  single-flow behavior, which already covers adapter flows that carry both sides.

## Test fixture

A flow-pusher fixture (on the `sidecar` package) that, after registering, emits each
flow shape: a plain request/response, a two-phase request-then-response, a stream
(parent + several ordered children + close), a session/tunnel envelope with nested
children, and a flow carrying `body_raw`/`body_codec`. It also issues `core_query`
calls to read back what it pushed.

## Verification

- Each emitted shape appears correctly via `proxy_poll`, `flow_get`, and `diff_flow`;
  stream children return in emission order; two-phase completion attaches the response
  to the same `flow_id`; envelope/child nesting resolves via `parent_flow_id`.
- `body`/`body_raw`/`body_codec` round-trip; tools operate on `body`.
- `core_query` returns correct read-side results and rejects write attempts.
- `proxy_poll`/`flow_get` filter on `adapter`/`protocol_tag`/`parent_flow_id`.
- Each flow records the emitting adapter name, sidecar version, and instance_id.
- `find_reflected` operates on adapter flows carrying both sides (single-flow; HTTP
  default unchanged); `diff_flow` content-type detection works on adapter flows.
- `log`/`report_metrics` intake observed. End-to-end through MCP tools, no socket.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Implementation decisions (as built)

These refine the description above where they conflict:

- **`core_query` wiring via dependency injection, not a setter.** `EnableSidecars`
  takes the `CoreQuerier` (the `*Server`, which resolves its read-side MCP tools
  lazily through an atomic pointer once the MCP server is built). All sidecar wiring
  stays inside `NativeProxyBackend.EnableSidecars`; no type assertion or post-hoc
  setter in `server.Run`.
- **`body_raw`/`body_codec` live on `Message`** (request and response sides) and are
  populated only when the logical `body` differs from the wire form; nil for HTTP and
  most flows, so no bytes are duplicated in the common case.
- **Sidecar identity** is recorded as the forced `Flow.adapter` (the registered name)
  plus `annotations.sidecar_version` / `annotations.sidecar_instance_id`.
- **Stream/session children** are surfaced via a `parent_flow_id` filter on
  `proxy_poll`, backed by a parent->children emission-order index on the history store
  (`Children`) and an `HttpBackend.GetProxyChildren` method (empty for Burp). Children
  stay excluded from the default top-level listing.
- **`find_reflected` stays single-flow** for this phase: it operates on adapter flows
  carrying both sides; cross-flow pairing of one-way messages is deferred.
- **SDK emission helpers** are `PushFlow` plus `CompleteFlow` (the two-phase /
  teardown form), with `Log`, `ReportMetrics`, and `CoreQuery`. Streams and
  session/tunnel nesting are expressed by setting `parent_flow_id` on `PushFlow`
  rather than dedicated open-stream / push-child helpers.
- **CLI parity**: `--adapter` / `--protocol-tag` / `--parent-flow-id` added to
  `proxy list`.

## Definition of done

- [x] `push_flow` supports single, two-phase, stream (ordered children), and
      session/tunnel shapes, with `body_raw`/`body_codec` storage.
- [x] `log`, `report_metrics`, `core_query` (read-only) implemented.
- [x] `adapter`/`protocol_tag`/`parent_flow_id` filters live in `proxy_poll`/
      `flow_get`; per-flow identity (adapter name, version, instance_id) recorded.
- [x] `find_reflected`/`diff_flow` generalized to non-HTTP flows (HTTP behavior
      unchanged; variant encodings stay HTTP-specific).
- [x] Flow-pusher fixture validates all shapes end-to-end through MCP tools.
- [x] `sidecar` package gains the emission + `core_query` helpers; still no
      `sectool/` dependency.
- [x] `make test-all` + `make lint` pass.
