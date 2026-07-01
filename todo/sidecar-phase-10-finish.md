# Sidecar Finish — Annotation Surfacing & Native HTTP Origination

Two required pieces of the sectool-side sidecar contract remain before external
protocol sidecars (the Tailscale client-side MITM and server-side control
adapter, and a future MQTT adapter) can run end-to-end. Two further items are
documentation-only. No agent-facing tool schemas change in a breaking way; both
required changes are additive.

## Background

An external sidecar participates in capture/mutation/replay over a local
JSON-RPC channel. It emits captured exchanges as generalized `Flow` objects
(`sectool/service/proxy/types/flow.go`), each carrying an open-ended
`Annotations map[string]any` (flow.go:49). Annotations are the audit surface for
everything a sidecar does that isn't visible in the request/response bytes:

- Mutation pairing — a mutated message is emitted as two flows, the pre-mutation
  `captured` form and the post-mutation `mutated` form, linked by
  `annotations.phase` (`"captured"` / `"mutated"`), `annotations.fired_rules`
  (`[rule_id...]`), and `annotations.parent_flow_id` (the mutated flow points at
  the captured flow's id, distinct from the structural `parent_flow_id` used for
  stream/session nesting).
- Binding strips — when a sidecar cannot re-sign a cryptographically bound field
  on replay it strips the field and records `annotations.stripped_fields`,
  `annotations.binding`, `annotations.reason`.
- Origination attribution — `annotations.invoked_by` names the sidecar that
  originated a cross-adapter message; `annotations.dial_upstream` records a
  sidecar-requested upstream dial; `annotations.sidecar_version` /
  `annotations.sidecar_instance_id` attribute every emitted flow.

Sectool **stores** all of this correctly (it is serialized on the flow and
merged on two-phase completion). The gap is on the **read** side: none of it is
returned to an agent. Separately, a sidecar has no way to originate an outbound
HTTP request through sectool's in-process HTTP path — only through a peer
sidecar — which blocks protocols with an out-of-band HTTP bootstrap step.

---

## Item 1 — Surface flow annotations in the read tools (required)

### Problem

`flow_get` builds its result map in `handleFlowGet` (mcp_proxy.go, ~lines
475-501) from a `resolvedFlow` (`sectool/service/mcp_server.go:503`).
`resolvedFlow` has no annotations field, and `resolveFlow`
(mcp_server.go:529) never reads them off the stored `Flow`, so annotations are
dropped in the projection. The `proxy_poll` list path is the same: entries flow
through `ProxyEntryMeta` (`sectool/service/backend.go:115`) and the internal
`flowEntry` (mcp_proxy.go, ~line 687) — neither carries annotations.

Consequence: an agent cannot read the captured/mutated pairing, `fired_rules`,
`stripped_fields`, or `invoked_by` that the whole sidecar audit model depends
on. This blocks every sidecar, not just Tailscale.

### What is needed

1. **Thread annotations into `resolvedFlow`.**
   - Add `Annotations map[string]any` to the `resolvedFlow` struct.
   - Populate it in `resolveFlow` for every source (proxy, replay, crawl) from
     the underlying stored `Flow`. Where a source has no annotations leave it
     nil.

2. **Emit annotations from `flow_get`.**
   - In `handleFlowGet`, when `resolved.Annotations` is non-empty, set
     `result["annotations"] = resolved.Annotations`. Always include it (subject
     to the same scope gating as other metadata), so a plain `flow_get` on a
     mutated flow shows `phase` / `fired_rules` / `parent_flow_id`, and a
     stripped-binding replay shows `stripped_fields` / `reason`.

3. **Surface a compact annotations view in `proxy_poll` listings.**
   - Add annotations to `ProxyEntryMeta` and to the internal `flowEntry` used by
     the list/summary builders, and include them (or at least the pairing keys
     `phase`, `fired_rules`, `invoked_by`, plus `annotations.parent_flow_id`) in
     the per-entry list output. This lets an agent spot captured/mutated pairs
     and rule hits without a `flow_get` per row. `parent_flow_id` (structural)
     is already surfaced; the annotation link is additive.
   - Keep the meta path lightweight — do not load bodies to obtain annotations;
     annotations already live on the meta-level record.

### Notes / edge cases

- Annotations are an untyped `map[string]any`; serialize them through the
  existing JSON result path unchanged. Do not schema-validate or rename keys —
  sidecars own the key space (`sectool` reserves only the documented keys
  above).
- The two `parent_flow_id` notions coexist: the top-level flow field is
  structural nesting (stream child → stream parent); `annotations.parent_flow_id`
  links a mutated flow to its captured twin. Surface both; do not collapse them.
- No change to `diff_flow` is required — an agent diffs the captured vs. mutated
  flows by id once it can discover the pair from annotations.

### Acceptance

- `flow_get` on a sidecar-emitted mutated flow returns `annotations` including
  `phase="mutated"`, `fired_rules`, and the captured-twin `parent_flow_id`.
- `flow_get` on a replayed flow whose binding was stripped returns
  `stripped_fields` / `binding` / `reason`.
- `proxy_poll` list entries expose the pairing/attribution keys so a
  captured/mutated pair and an `invoked_by` origination are identifiable from the
  listing.
- No-sidecar behavior is byte-identical: HTTP flows without annotations produce
  the same output as today (the `annotations` key is omitted when empty).

---

## Item 2 — Native in-process HTTP origination via `invoke_adapter` (required)

### Problem

`invoke_adapter` (and the no-base-flow origination form of `sidecar_send`) routes
only to **registered sidecar records** that declared an `injection_target`:
`Manager.SidecarSend` (`sectool/service/proxy/protocol/sidecar/send.go:14`) does
`m.Get(adapter)` and `handleInvokeAdapter` (send.go:44) rejects a nil
`InjectionTarget`. The in-process HTTP proxy is not a registered record — its
identifiers (`http/1.1`, `h2`, `websocket`, `sectool`) are only reserved names
(`backend_http_native.go:140`) that sidecars may not claim. So a sidecar asking
sectool to originate an HTTP request through the native path gets
`CodeUnknownDestAdapter`.

This blocks any protocol with an out-of-band HTTP bootstrap. The concrete driver
is the Tailscale client-side MITM: under its default key strategy it must fetch
the **real** upstream control key with an HTTP `GET /key?v=<n>` and wants that
fetch to land in history as a normal, attributable HTTP flow (so key rotation,
server errors, and future pinning stay visible in `proxy_poll`). Routing it
through a raw upstream byte-stream dial would work but produces no clean HTTP
flow and forces the sidecar to reimplement TLS+HTTP; the correct answer reuses
the native send path.

### The primitive to reuse

`executeSend` (`sectool/service/mcp_replay.go:328`) is already *"the shared send
pipeline for replay_send and request_send"*: it applies header/body
modifications, validates, sends through the proxy sender, and **stores the
result as a history flow**. `handleRequestSend` (mcp_replay.go:266) shows the
origination entry: parse `{url, method, headers, body}`, build a raw request via
`buildRawRequestManual`, then call `executeSend(ctx, rawRequest, "http/1.1",
mods, "")`. Egress scope is applied inside the send path exactly as for any
proxied request.

### What is needed

1. **Recognize the in-process HTTP proxy as an origination destination.**
   - In `Manager.SidecarSend` / `handleInvokeAdapter`, before the registered-record
     lookup, branch when `adapter` names the reserved in-process HTTP proxy
     (accept `sectool` and/or `http/1.1`; pick one canonical value and document
     it). This branch does not require an `InjectionTarget` record.

2. **Translate the injection `target`/`payload` into a native send.**
   - The target/payload schema mirrors `request_send`: `{url, method, headers,
     body, follow_redirects?, force?}`. Map these to `sendModifications` and a
     raw request the same way `handleRequestSend` does, apply the optional
     `mutations` list (§ shared mutation grammar) before sending, then invoke the
     native send.
   - Scope policy, `Host` syncing, and history storage come for free from
     `executeSend`.

3. **Return the produced flow to the caller.**
   - `invoke_adapter` must return `{new_flow_ids, response?}` and record
     `annotations.invoked_by = <caller>` on the produced flow (the existing
     `handleInvokeAdapter` already stamps `invoked_by` on returned ids via
     `flows.Complete`; reuse that once the native branch yields the id).
   - This requires a native send entry point that returns the stored flow id and
     the response form, not only an MCP `CallToolResult`. Factor a lower-level
     helper out of `executeSend`, e.g.:

     ```
     func (m *mcpServer) executeSendFlow(ctx, rawRequest []byte, httpProtocol string,
         mods sendModifications, sourceFlowID string) (flowID string, response *ResponseForm, err error)
     ```

     and have both the existing `executeSend` (for the tool result) and the new
     `invoke_adapter` branch call it. Respect `wait_for_response` (default true):
     when false, return `new_flow_ids` without blocking on the response form.

### Notes

- Keep this generic: the branch is "originate through the native HTTP adapter,"
  not "Tailscale `/key`." Any sidecar (JWKS/OIDC discovery, token endpoints,
  cert-bundle fetch) uses the same path.
- Do not route the agent-facing `request_send` through this branch; it stays
  native and unchanged. This item only makes the native send **reachable from
  the sidecar contract**.
- A sidecar that must keep this fetch clear of a substitution rule scopes the
  rule so it does not match, or handles substitution internally — unchanged from
  today's rule-scoping semantics.

### Acceptance

- A registered sidecar issuing `invoke_adapter` at the in-process HTTP proxy with
  `{url, method, headers}` produces a real HTTP flow visible in `proxy_poll`,
  attributed with `annotations.invoked_by`, with scope policy applied.
- `wait_for_response=true` returns the decoded response form alongside
  `new_flow_ids`; `false` returns ids without blocking.
- The Tailscale upstream `GET /key?v=<n>` fetch completes through this path and
  reads the real upstream key (attributable, outside any client-facing
  substitution rule's scope).

---

## Item 3 — `stream_strategy` (documentation only, no code)

The replay path carries a `stream_strategy` field on the wire
(`sidecar/wire/params.go`) but `replay_send` never sets it, so a sidecar always
receives the empty value and defaults to `per_chunk`. This is correct for every
in-scope protocol: streamed replays that must preserve order (Tailscale
MapResponse, MQTT pub/sub, WebSocket frames) only support `per_chunk`, and
`collapsed` has no consumer.

Action: do **not** add a dedicated `stream_strategy` parameter to `replay_send`.
Keep the default `per_chunk` behavior. If a future chunked-response protocol ever
needs a merged replay, express it as a generic option/annotation on the replay
request rather than a typed enum, so the primitive stays adapter-agnostic. The
unused wire field may be left reserved or removed.

## Item 4 — `assigned_seams` (documentation only, no code)

Registration is all-or-nothing: `checkConflicts`
(`sectool/service/proxy/protocol/sidecar/register.go:67`) aborts the entire
`register` with a typed conflict error if any declared capability clashes. There
is no partial-acceptance path, so a successful `register` already implies that
every declared seam was accepted.

Action: do **not** add an `assigned_seams` field to the register response. It
would be a redundant echo. Document that a successful registration means all
declared seams are accepted and that capability conflicts are hard errors
(naming both registrations). Only revisit if partial seam acceptance is ever
introduced.

---

## Definition of done

- [ ] `resolvedFlow` carries annotations; `resolveFlow` populates them for
      proxy/replay/crawl sources.
- [ ] `flow_get` returns `annotations` (omitted when empty); no-sidecar output
      unchanged.
- [ ] `proxy_poll` list entries surface the pairing/attribution annotation keys
      without loading bodies.
- [ ] `invoke_adapter` / no-base-flow `sidecar_send` can target the in-process
      HTTP proxy, producing an attributable history flow via the factored native
      send helper, honoring `mutations`, `wait_for_response`, and scope policy.
- [ ] `request_send` remains native and unchanged; the native send helper is
      shared, not duplicated.
- [ ] Items 3 and 4 captured in the sidecar spec docs as intentional decisions.
- [ ] `make test-all` and `make lint` pass; no-sidecar behavior byte-identical.
