# Sidecar Phase 8 — Replay & origination (sidecar_send)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 5** (replay egress flows through `dial_upstream`) and **Phase 7**
(replay applies the §3.4 mutation grammar). Builds on **Phase 3** (flows it replays)
and **Phase 2** (`injection_target` declared at registration).

## Carried-forward cleanup

- `protocol.UpgradeClaimCtx.TLS` (set on the http1 TLS upgrade path in Phase 6) is
  currently unused: the WS adapter keys the TLS path off `UpgradeConns.UpstreamConn`
  and the sidecar bridge derives scheme from `Target.Scheme()`. While touching the
  upgrade-claim/transport seam here, either remove the field or document it as
  informational only.

## Goal

Make the existing `replay_send` and `request_send` MCP tools work on sidecar-owned
flows, and let a sidecar originate new outbound messages — routed internally to the
owning adapter via `sidecar_send`. Add cross-adapter origination (`invoke_adapter`) so
one adapter can drive a sibling's `injection_target`. Agents keep using the same tool
surface; the protocol-specific re-encoding/re-signing happens in the owning adapter.

## Background & assumed state

After Phase 7, sectool pushes rules and sidecars apply mutations on the capture hot
path. Replay is the active counterpart: take a captured flow (or a fresh target),
apply mutations, and send. The captured `body` is the plaintext logical form (already
decrypted/decompressed/de-framed by the originating adapter, Phase 3); on replay the
**owning adapter** re-applies wrapping, compression, framing, and any cryptographic
binding at the wire — sectool carries no adapter-specific crypto state across the
replay boundary.

`sidecar_send` (§6b.2) is the internal method behind `replay_send`/`request_send` and
the destination side of `invoke_adapter`. With `flow_id` set it replays that flow with
mutations (routed to the destination adapter keyed by the source flow's `adapter`
field; `target_override` may name a different destination adapter able to encode the
source `protocol_tag`). With `flow_id` omitted it originates from `target`/`payload`
(validated against the adapter's `injection_target.target_schema`). Replay sends
`body_raw` verbatim when no body mutation is requested; a mutated body is re-encoded
through `body_codec`. Where a protocol binds fields (e.g. a signature), the owning
adapter re-signs when it holds the key material (its connection-time configuration) or
strips the bound fields, surfacing the outcome in `annotations`. Egress flows through
`dial_upstream`, so scope policy applies. Stream flows replay `per_chunk` (default,
stored/emission order) or `collapsed` (the adapter rejects `collapsed` when its
protocol forbids merging).

`injection_target` (§5.3): declares the adapter can originate outbound messages,
driven by a sidecar-registered tool (Phase 9) or by another adapter via
`invoke_adapter`. Its `target_schema` describes accepted target params. Scoped to the
declaring adapter's own flows — no inter-sidecar conflict possible.

`invoke_adapter` (§6a.8): a sidecar routes an outbound message through another
adapter's `injection_target` — the same path an injection tool uses. Recorded in
history with `annotations.invoked_by`; scope policy and the destination's validation
apply. **Self-loop exemption:** a flow originated via `invoke_adapter` by adapter X is
exempt from X's own `owned_rules` (matched via `annotations.invoked_by`); all other
rules still fire.

The agent-facing tools live in `sectool/service/mcp_replay.go` (`replay_send`,
`request_send`); their existing HTTP mutation execution order is preserved for HTTP and
is that adapter's convention (§8), not a cross-adapter guarantee.

## Spec references

- §5.3 Capabilities (`injection_target`).
- §6a.8 `invoke_adapter` (incl. self-loop exemption), §6b.2 `sidecar_send`.
- §8 Feature parity (`replay_send` / `request_send` routing).

## Scope — toolbox (server side)

- **`sidecar_send`** (§6b.2): the internal method routing replay/origination to the
  owning adapter. Support `flow_id` (replay) and originate (`target`/`payload`),
  `mutations` (ordered §3.4 ops), `target_override` (destination routing /
  cross-adapter destination only), `follow_redirects` (HTTP-specific), `force`
  (skip adapter validation), `wait_for_response` (block for the response form), and
  `stream_strategy` (`per_chunk`/`collapsed`). Return `{new_flow_ids, writes?,
  response?}`.
- **Route the MCP tools:** `replay_send` and `request_send` translate their existing
  parameters into `sidecar_send` invocations routed to the owning adapter — HTTP
  adapter handled natively (existing behavior preserved), sidecar-owned flows routed
  over RPC. Validate mutations against the flow's adapter `mutation_ops` (non-declared
  ops error unless `force=true`).
- **Fire `injection_target`:** validate `target`/`payload` against the declaring
  adapter's `target_schema`; originate via the adapter.
- **`invoke_adapter`** (§6a.8): route an outbound message through another registered
  adapter's `injection_target`; record `annotations.invoked_by`; apply scope policy
  and destination validation; enforce the self-loop exemption against the originating
  adapter's `owned_rules` only.
- Re-encoding, re-wrapping, and re-signing are the owning adapter's responsibility;
  sectool adds no core auto-prepend step and models no cryptographic binding.

## Scope — `sidecar` package

- A `sidecar_send` handler hook: receive a replay/originate request, apply mutations
  (reusing the Phase 7 mutation helpers), re-encode via `body_codec`, re-wrap/re-sign
  per the adapter's configuration, emit the resulting flow(s) and `writes`, and report
  any stripped-binding outcome in `annotations`.
- Injection helpers for the originate case (validate against the adapter's own
  `target_schema`) and an `InvokeAdapter` call for cross-adapter origination.

## Out of scope / deferred

- Exposing protocol-specific operations as MCP tools (`mcp_tools`/`invoke_tool`) →
  Phase 9. This phase routes the *core* `replay_send`/`request_send` tools only.

## Test fixture

An injection sidecar (on the `sidecar` package) that declares `injection_target`,
owns some flows (Phase 3), and on `sidecar_send` re-encodes and sends them via
`dial_upstream` (Phase 5). A second fixture/adapter pair exercises `invoke_adapter`
cross-adapter origination and the self-loop exemption.

## Verification

- `replay_send` on an HTTP flow is byte-identical to today; on a sidecar-owned flow it
  routes via `sidecar_send`, the adapter re-encodes/sends, and a new flow is produced.
- `request_send` originates from `target`/`payload` validated against the schema.
- Unmutated replay sends `body_raw` verbatim; a mutated body is re-encoded via
  `body_codec`; stripped/ re-signed bindings are surfaced in `annotations`.
- `stream_strategy` `per_chunk` replays in emission order; `collapsed` is rejected when
  the protocol forbids it.
- `invoke_adapter` originates through a sibling adapter, records `invoked_by`, applies
  scope, and the self-loop exemption skips only the originating adapter's `owned_rules`.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [ ] `sidecar_send` supports replay and originate with the full param set and return
      shape; `replay_send`/`request_send` route to the owning adapter.
- [ ] `injection_target` validation + origination; `invoke_adapter` cross-adapter
      origination with `invoked_by` audit and self-loop exemption.
- [ ] Re-encode via `body_codec`; binding re-sign/strip surfaced in `annotations`;
      `stream_strategy` honored.
- [ ] Injection + cross-adapter fixtures validate end-to-end.
- [ ] `sidecar` package gains `sidecar_send` handler + injection/`InvokeAdapter`
      helpers; no `sectool/` dep.
- [ ] `make test-all` + `make lint` pass.
