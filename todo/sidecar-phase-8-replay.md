# Sidecar Phase 8 — Replay & origination (sidecar_send)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 5** (replay egress flows through `dial_upstream`) and **Phase 7**
(replay reuses the relocated `sidecar/mutate` helpers for the §3.4 mutation grammar).
Builds on **Phase 3** (flows it replays)
and **Phase 2** (`injection_target` declared at registration).

## Carried-forward cleanup

- `protocol.UpgradeClaimCtx.TLS` (set on the http1 TLS upgrade path in Phase 6) was
  unused: the WS adapter keys the TLS path off `UpgradeConns.UpstreamConn` and the
  sidecar bridge derives scheme from `Target.Scheme()`. Removed in this phase.

## Design decisions

- **No adapter name in the agent surface.** `replay_send` auto-routes a flow to its
  owning adapter from the captured flow's recorded `adapter` field; HTTP flows stay
  native and unchanged. `request_send` stays HTTP-native (no adapter selector).
- **No `target_override`.** The existing `replay_send` `target` param
  (`scheme://host[:port]`) is forwarded to the owning adapter as a routing-only hint
  (`destination`). The destination-adapter facet (cross-adapter / cross-tunnel replay)
  is dropped until a concrete use case; its future homes are the Phase 9 protocol
  injection tools and `invoke_adapter`.
- **No sectool-side schema validation.** `injection_target.target_schema` is
  descriptive; sectool forwards `target`/`payload`/`force` to the owning adapter, which
  validates (or not) itself, consistent with sectool's tolerance of invalid payloads
  for protocol testing.
- The originate path of `sidecar_send` (no base flow) is built in the SDK and service
  but reached in this phase only via `invoke_adapter`; agent-facing protocol
  origination tools are Phase 9.

## Goal

Make the existing `replay_send` and `request_send` MCP tools work on sidecar-owned
flows, and let a sidecar originate new outbound messages — routed internally to the
owning adapter via `sidecar_send`. Add cross-adapter origination (`invoke_adapter`) so
one adapter can drive a sibling's `injection_target`. Agents keep using the same tool
surface; the protocol-specific re-encoding/re-signing happens in the owning adapter.

## Background & assumed state

After Phase 7, sectool pushes rules and sidecars apply them on the capture hot path,
and the JSON/form mutation helpers live in the `sidecar/mutate` package. Replay is the
active counterpart: take a captured flow (or a fresh target), apply the §3.4 mutation
grammar via those helpers, and send. The captured `body` is the plaintext logical form
(already
decrypted/decompressed/de-framed by the originating adapter, Phase 3); on replay the
**owning adapter** re-applies wrapping, compression, framing, and any cryptographic
binding at the wire — sectool carries no adapter-specific crypto state across the
replay boundary.

`sidecar_send` (§6b.2) is the internal method behind `replay_send` and the destination
side of `invoke_adapter`. With `flow_id` set it replays that flow with mutations, routed
to the owning adapter keyed by the source flow's `adapter` field; sectool passes the
resolved source flow inline so the adapter has `body`/`body_raw`/`body_codec` without a
round-trip. With `flow_id` omitted it originates from `target`/`payload` (validated by
the owning adapter, not sectool). The agent's `target` (`scheme://host[:port]`) rides
through as the `destination` routing-only override. Replay sends `body_raw` verbatim
when no body mutation is requested; a mutated body is re-encoded through `body_codec`.
Where a protocol binds fields (e.g. a signature), the owning adapter re-signs when it
holds the key material (its connection-time configuration) or strips the bound fields,
surfacing the outcome in `annotations`. Egress flows through `dial_upstream`, so scope
policy applies. Stream flows replay `per_chunk` (default, stored/emission order) or
`collapsed` (the adapter rejects `collapsed` when its protocol forbids merging).

`injection_target` (§5.3): declares the adapter can originate outbound messages,
driven by a sidecar-registered tool (Phase 9) or by another adapter via
`invoke_adapter`. Its `target_schema` describes accepted target params. Scoped to the
declaring adapter's own flows — no inter-sidecar conflict possible.

`invoke_adapter` (§6a.8): a sidecar routes an outbound message through another
adapter's `injection_target` — the same path an injection tool uses. Recorded in
history with `annotations.invoked_by`; scope policy and the destination's validation
apply.

The agent-facing tools live in `sectool/service/mcp_replay.go` (`replay_send`,
`request_send`); their existing HTTP mutation execution order is preserved for HTTP and
is that adapter's convention (§8), not a cross-adapter guarantee.

## Spec references

- §5.3 Capabilities (`injection_target`).
- §6a.8 `invoke_adapter`, §6b.2 `sidecar_send`.
- §8 Feature parity (`replay_send` / `request_send` routing).

## Scope — toolbox (server side)

- **`sidecar_send`** (§6b.2): the internal method routing replay/origination to the
  owning adapter. Support `flow_id` + inline `flow` (replay) and originate
  (`target`/`payload`), `mutations` (ordered §3.4 ops), `destination` (routing-only
  `scheme://host[:port]` override), `follow_redirects` (HTTP-specific), `force`
  (forwarded to the adapter), `wait_for_response` (block for the response form), and
  `stream_strategy` (`per_chunk`/`collapsed`). Return `{new_flow_ids, writes?,
  response?}`.
- **Route `replay_send`:** a flow owned by a connected sidecar routes to that adapter
  via `sidecar_send` over RPC; HTTP flows stay native (existing behavior preserved).
  `request_send` stays HTTP-native. The mutation grammar is the fixed §3.4 set.
- **`invoke_adapter`** (§6a.8): route an outbound message through another registered
  adapter's `injection_target`; record `annotations.invoked_by`; egress scope applies
  via `dial_upstream`. Target/payload validation is the destination adapter's concern.
- Re-encoding, re-wrapping, and re-signing are the owning adapter's responsibility;
  sectool adds no core auto-prepend step and models no cryptographic binding.

## Scope — `sidecar` package

- A `SendHandler` hook (`OnSidecarSend`): receive a replay/originate request, apply
  mutations (reusing the `sidecar/mutate` helpers via `ApplyMutations`), re-encode via
  `body_codec`, re-wrap/re-sign per the adapter's configuration, emit the resulting
  flow(s) and `writes`, and report any stripped-binding outcome in `annotations`.
- An `InvokeAdapter` call for cross-adapter origination. Any target/payload validation
  is the adapter's own choice, not sectool's.

## Out of scope / deferred

- Exposing protocol-specific operations as MCP tools (`mcp_tools`/`invoke_tool`) →
  Phase 9, which is also the home for agent-facing protocol *origination* tools built
  on the `sidecar_send` originate path. This phase routes the core `replay_send` tool
  and implements `invoke_adapter`.
- Cross-adapter / cross-tunnel replay (a flow captured on one adapter replayed through
  another) — deferred with `target_override` until a concrete use case.
- `invoke_adapter` targeting the in-process HTTP adapter (e.g. an upstream `/key`
  fetch) — a follow-up mapping to the native send path; this phase routes
  `invoke_adapter` to registered sidecar destinations.

## Test fixture

An emit-only injection sidecar (on the `sidecar` package) implementing `SendHandler`
that applies mutations and pushes the resulting flow(s) on `sidecar_send`. A second
fixture/adapter pair exercises `invoke_adapter` cross-adapter origination.

## Verification

- `replay_send` on an HTTP flow is byte-identical to today; on a sidecar-owned flow it
  routes via `sidecar_send`, the adapter re-encodes/sends, and a new flow is produced.
- Unmutated replay sends `body_raw` verbatim; a mutated body is re-encoded via
  `body_codec`; stripped/re-signed bindings are surfaced in `annotations`.
- `stream_strategy` `per_chunk` replays in emission order; `collapsed` is rejected when
  the protocol forbids it.
- `invoke_adapter` originates through a sibling adapter, records `invoked_by`, and
  applies scope.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [x] `sidecar_send` supports replay and originate with the param set and return shape;
      `replay_send` routes a sidecar-owned flow to its owning adapter.
- [x] `invoke_adapter` cross-adapter origination with `invoked_by` audit.
- [x] Re-encode via `body_codec`; binding re-sign/strip surfaced in `annotations`;
      `stream_strategy` honored (adapter-side).
- [x] Injection + cross-adapter fixtures validate end-to-end.
- [x] `sidecar` package gains the `SendHandler` hook + `ApplyMutations`/`InvokeAdapter`
      helpers; no `sectool/` dep.
- [x] `make test-all` + `make lint` pass.
