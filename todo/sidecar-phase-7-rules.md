# Sidecar Phase 7 — Rule push & mutation (sync_rules)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Hard-requires **Phase 3** (mutation audit emits captured/mutated flow pairs via
`push_flow`). Most meaningful with **Phase 4**'s stream model (mutation on the hot
path applies to intercepted streams). Prerequisite for **Phase 8** (replay applies
the same mutation grammar). Because it only hard-needs Phase 3, it can move earlier in
the sequence if preferred.

## Goal

Generalize the rules engine to the contract's tuple form and let sectool push the
authoritative rule list to sidecars, which apply protocol-specific mutations on their
hot path (only the sidecar knows how to mutate its bytes). Add adapter-owned rules and
the mutation audit trail. Fold the existing `proxy_respond_*` feature onto this one
rule engine so there is no duplicated rule logic. After this phase, match/replace
testing — passive capture, mutate via rules, iterate — works for sidecar-owned flows
exactly as it does for HTTP.

## Background & assumed state

Phase 1 deliberately left the rules engine on its existing 7-type enum
(`request_header`, `request_body`, `response_header`, `response_body`, `ws:to-server`,
`ws:to-client`, `ws:both`) so HTTP/WS behavior stayed byte-identical. Rules are stored
by the native backend (`sectool/service/backend_http_native.go`, keys `http_rules` /
`ws_rules`, msgpack) and applied on the hot path via a `RuleApplier` interface,
decoupled from storage. This phase performs the generalization the spec describes.

Rule targeting generalizes (§3.5) to the tuple `(adapter, message_type, op, params,
scope_filter, label, rule_id, owner)`: `adapter`/`message_type` accept `*`; `op` is a
declared mutation op (shared or adapter-declared); `scope_filter` narrows by host/path/
`parent_flow_id`/`protocol_tag`/byte-length; `label` is unique across the whole list;
`owner` is `user` or `adapter:<name>`. Existing rules map deterministically onto the
tuple — a labeling change, not a semantic one — and keep applying to HTTP/1.1 and
HTTP/2 as today.

The shared mutation grammar (§3.4) is a small typed op set (`regex_replace`,
`set_header`/`remove_header`, `set_json`/`remove_json`, `set_form`/`remove_form`,
`set_query`/`remove_query`/`set_query_string`, `set_method`/`set_path`/`set_target`,
`set_body`). Adapters may declare extra named ops via `mutation_ops` (§6a.1) with a
JSON-Schema param shape and applicable `protocol_tag`s. The owning adapter applies the
list in its own order and runs rebind/finalizer ops (e.g. signature recompute) **after**
all content mutations.

`sync_rules` (§6b.1) pushes the full ordered rule list to a sidecar, which replaces its
local cache atomically — mirroring the native backend's RWMutex-protected slice model.
A monotonic `snapshot_version` and the sidecar's `applied_version` ack give sectool
authoritative knowledge of which snapshot each sidecar runs.

Adapter-owned rules (`owned_rules`, declared at registration in Phase 2 and stored in
the registry) are merged into the central list with `owner=adapter:<name>`, may target
any adapter, are written to the audit log at registration, cannot be deleted via
`proxy_rule_delete`, and release on unregister.

## Spec references

- §3.4 Mutation grammar, §3.5 Rule targeting.
- §5.3 (derived rule-provider / mutation-provider roles; `owned_rules`).
- §6b.1 `sync_rules`.
- §8 Feature parity (`proxy_respond_*` re-expressed as rules).
- §10 Security considerations (mutation audit via paired flows; advisory mutation-op
  validation; owned-rules-fixed-at-registration).

## Scope — toolbox (server side)

- **Generalize rule storage** to the §3.5 tuple form + `owner`. Convert existing
  `http_rules`/`ws_rules` storage in place, mapping the 7 types onto the tuple
  (`owner=user`). Preserve label uniqueness across the whole list.
- **`proxy_rule_add/list/delete` generalization** (spec §8): keep the existing 7-type
  surface working identically (each maps to a tuple with `owner=user`); accept the new
  `adapter`/`message_type`/`op`/`params` form for adapter-typed ops. `proxy_rule_list`
  shows `owner`; `proxy_rule_delete` refuses adapter-owned rules with an error naming
  the owning adapter.
- **`owned_rules` merge:** merge a sidecar's declared `owned_rules` into the central
  list at registration with `owner=adapter:<name>`; allow cross-adapter targeting;
  write each cross-adapter rule to the audit log naming owning + target adapter;
  release on unregister.
- **`mutation_ops` validation** (§3.4): validate every rule's `op`/`params` against the
  owning adapter's declared `mutation_ops` schema before pushing; reject unknown/
  inapplicable ops (errors in the §11 mutation/rule range).
- **`sync_rules` push** (§6b.1): maintain a monotonic `snapshot_version`, push the full
  ordered list (rules for `adapter` not naming this sidecar or `*` may be omitted; the
  sidecar's own `owned_rules` always included), and record the returned
  `applied_version` ack. Re-push on every add/edit/delete with an incremented version.
- **Mutation audit paired flows** (§10): the sidecar emits two flows per mutated
  message — `annotations.phase=captured` (pre-mutation) and `phase=mutated`
  (post-mutation, with `fired_rules` and `annotations.parent_flow_id` → the captured
  flow). For stream children the structural `parent_flow_id` still points at the stream
  parent (order preserved) while `annotations.parent_flow_id` links the pair. sectool
  surfaces a warning when a sidecar reports an op it did not declare.
- **Responder unification — single rule engine** (§8): re-express
  `proxy_respond_add/delete/list` on the unified rule list so there is **one rule store
  and one application path**, eliminating duplicated logic. Retire the parallel
  responder store — `nativeStoredResponder`, the `"responders"` storage key,
  `respondersMu`, and the `ResponderBackend` CRUD interface
  (`backend_http_native_respond.go`) — and back the three tools by responder-class
  rules with `owner=user`. The existing tool surface and matcher schema are preserved
  (`mcp_respond.go`); the tools become thin wrappers that CRUD those rules.
  - **Responder-as-rule design nuance:** a responder is **not** a match/replace on an
    upstream response — it **synthesizes a response and short-circuits the upstream
    dial**, and needs a status code (not just body/headers). Represent it as a
    responder-class rule scoped by host+port+path+method (a dedicated HTTP-adapter op /
    `respond` marker carrying status + headers + body), distinct from `set_body`/
    `set_header`. The §8 wording "op=set_body/set_header" is approximate and is
    superseded by this.
  - **Executor unchanged:** the existing `ResponseInterceptor` seam
    (`proxy/interceptor.go`, `BuildInterceptedH1Response`) **remains** as the mechanism
    that serves the canned response in place of upstream. What changes is its source of
    truth: the HTTP adapter's rule applier drives the interceptor when a responder-class
    rule matches, instead of reading the retired responder slice. This is execution of a
    rule, not a second rule system.

## Scope — `sidecar` package

- A local rule cache and a `sync_rules` handler that replaces the cache atomically and
  returns the `applied_version` ack.
- Mutation-application helpers implementing the shared §3.4 op set against a logical
  message (headers/body/query/form/routing), plus a hook for adapter-declared ops and
  the rebind/finalizer-last ordering rule.
- A helper to emit the captured/mutated audit pair via `push_flow` (Phase 3).

## Out of scope / deferred

- Replay/origination (`sidecar_send`) and `invoke_adapter` → Phase 8 (they consume the
  same mutation grammar defined here).

## Test fixture

A mutator sidecar (on the `sidecar` package) that declares `mutation_ops` and
`owned_rules` at registration, claims a stream (Phase 4), receives a pushed rule list
via `sync_rules`, applies mutations on the hot path, and emits captured/mutated pairs.

## Verification

- Existing HTTP/WS rules continue to apply byte-identically after the tuple migration.
- `proxy_rule_add/list/delete` work for both the legacy 7-type form and the new
  adapter-typed form; adapter-owned rules cannot be deleted; `owner` shown in lists.
- `sync_rules` pushes the ordered list; `applied_version` ack tracked; re-push on
  changes increments `snapshot_version`.
- A sidecar applies pushed rules and emits captured/mutated flow pairs; `diff_flow`
  shows the change; `fired_rules` populated; undeclared-op warning surfaced.
- Cross-adapter `owned_rules` audit-logged at registration.
- Responder unification is byte-identical to today: `proxy_respond_add/delete/list`
  work unchanged, canned responses are still served in place of upstream and recorded
  in history, and existing responder tests pass against the rule-backed implementation;
  `proxy_respond_list` reflects responder-class rules (`owner=user`); the parallel
  responder store is gone.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [ ] Rules generalized to the tuple form + `owner`; legacy rules migrated in place
      and byte-identical in effect.
- [ ] `owned_rules` merge with cross-adapter targeting + audit log; delete protection.
- [ ] `mutation_ops` validation before push; `sync_rules` with `snapshot_version`/ack.
- [ ] Mutation audit captured/mutated pairs (incl. stream-child linking).
- [ ] `proxy_respond_*` re-expressed as responder-class rules on the single rule
      engine; parallel responder store retired; `ResponseInterceptor` retained as
      executor; behavior byte-identical.
- [ ] Mutator fixture validates hot-path mutation end-to-end.
- [ ] `sidecar` package gains rule cache + mutation helpers; no `sectool/` dep.
- [ ] `make test-all` + `make lint` pass.
