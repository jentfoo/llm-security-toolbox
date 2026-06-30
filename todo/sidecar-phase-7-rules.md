# Sidecar Phase 7 — Rule push & optional adapter scope (sync_rules)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Hard-requires **Phase 3** (mutation audit emits captured/mutated flow pairs via
`push_flow`). Most meaningful with **Phase 4**'s stream model (rules on the hot path
apply to intercepted streams). Prerequisite for **Phase 8** (replay reuses the
relocated mutation helpers). Because it only hard-needs Phase 3, it can move earlier in
the sequence if preferred.

## Goal

Let sectool push the authoritative rule list to sidecars so they apply rules on their
hot path **exactly as the in-process HTTP proxy does today** — regex/literal
find-replace on headers and body. The rule model is unchanged from `origin/main` (the
7-type enum) except for **one optional `adapter` field** that scopes a rule to a named
adapter. No new rule operations, no rule ownership, no responder changes.

Separately, relocate the shared JSON/form mutation helpers into the `sidecar/mutate`
package so the existing request-mutation grammar (`replay_send`/`request_send`) is
performed the same way for in-process and sidecar-owned flows. Structured mutations are
a replay/origination concern and are **not** part of rules.

## Background & assumed state

The rules engine stays on its existing 7-type enum (`request_header`, `request_body`,
`response_header`, `response_body`, `ws:to-server`, `ws:to-client`, `ws:both`). Rules
are stored by the native backend (`sectool/service/backend_http_native.go`, keys
`http_rules` / `ws_rules`, msgpack) and applied on the hot path via a `RuleApplier`
interface, decoupled from storage. HTTP/1.1 and HTTP/2 behavior is byte-identical to
`origin/main`.

The **only** model change is an optional `adapter` field on a rule (spec §3.5): empty
means the rule applies to all adapters (today's behavior); a named adapter scopes the
rule to flows on that adapter only. The user-facing `proxy_rule_add/list/delete`
surface, find/replace/`is_regex` semantics, and label uniqueness are otherwise
unchanged.

`sync_rules` (§6b.1) pushes the full ordered rule list to a sidecar, which replaces its
local cache atomically — mirroring the native backend's RWMutex-protected slice model.
A monotonic `snapshot_version` and the sidecar's `applied_version` ack give sectool
authoritative knowledge of which snapshot each sidecar runs. A sidecar applies only the
rules it is capable of applying (regex/literal find-replace matching its adapter scope),
ignoring the rest — the same way the HTTP proxy ignores WebSocket rules.

The shared request-mutation grammar (`set_json`/`remove_json`, `set_form`/`remove_form`,
header/query/body/method/path/target ops) is the existing `replay_send`/`request_send`
surface. It is **not** carried by rules. Its JSON and form helpers move from
`sectool/service/{jsonutil,formutil}.go` into a new `sidecar/mutate` package (no
`sectool/` dependency) so replay and origination share one implementation.

## Spec references

- §3.5 Rule targeting (7-type enum + optional `adapter`).
- §6b.1 `sync_rules`.
- §8 Feature parity (`proxy_rule_*` unchanged + optional `adapter`; `proxy_respond_*`
  unchanged; `replay_send` mutation grammar unchanged).
- §10 Security considerations (mutation audit via paired flows).

## Scope — toolbox (server side)

- **Optional `adapter` on rules:** add an optional `adapter` field to `RuleEntry`
  (`sectool/protocol/types.go`) and `nativeStoredRule`
  (`sectool/service/backend_http_native.go`). Empty = all adapters (unchanged
  in-process behavior); a named adapter scopes the rule. In-process application
  (`ApplyRequestRules`/`ApplyResponseRules`/`ApplyWSRules`) applies rules with empty
  adapter as today; a rule naming a non-HTTP/WS adapter is simply not applied
  in-process.
- **`proxy_rule_add/list/delete`:** keep the existing 7-type surface working
  identically; accept an optional `adapter` argument on add; show `adapter` in
  `proxy_rule_list`. CRUD logic and label uniqueness are otherwise unchanged. CLI
  (`sectool/proxy/`) mirrors the optional argument.
- **`sync_rules` push** (§6b.1): maintain a monotonic `snapshot_version`; push the full
  ordered list (rules whose `adapter` does not name this sidecar or is empty may be
  omitted as an optimization); record the returned `applied_version` ack. Re-push on
  every add/edit/delete with an incremented version. Populate `RegisterResult`'s initial
  rule snapshot at registration the same way.
- **Mutation audit paired flows** (§10): when a sidecar mutates a message by applying a
  rule on its hot path, it emits two flows — `annotations.phase=captured`
  (pre-mutation) and `phase=mutated` (post-mutation, with `fired_rules` and
  `annotations.parent_flow_id` → the captured flow). For stream children the structural
  `parent_flow_id` still points at the stream parent (order preserved) while
  `annotations.parent_flow_id` links the pair.
- **Relocate mutation helpers:** move the JSON/form mutation functions from
  `sectool/service/{jsonutil,formutil}.go` into a new `sidecar/mutate` package
  (`mutate.JSON`, `mutate.Form`; stdlib + `go-analyze/bulk` only). Rewire
  `mcp_replay.go` and `backend_http_native.go`'s `JSONModifier` to call it. Keep the
  read/analysis helpers (`flattenJSON`, `parseStringList`) in `service`; leave the
  HTTP-wire header/query helpers in place.

## Scope — `sidecar` package

- A local rule cache and a `sync_rules` handler that replaces the cache atomically and
  returns the `applied_version` ack.
- A rule applier doing regex/literal find-replace on a logical message's headers/body
  for rules whose type and adapter scope it supports — mirroring the native backend's
  `ApplyRequestRules`/`ApplyResponseRules`.
- A helper to emit the captured/mutated audit pair via `push_flow` (Phase 3).
- The relocated `sidecar/mutate` package (no `sectool/` dependency) hosting the shared
  JSON/form request-mutation helpers consumed by replay (Phase 8).

## Out of scope / deferred

- Adapter-declared mutation ops, adapter-owned rules, rule ownership, and the
  responder-as-rule unification are **not** part of this contract; the responder store
  (`proxy_respond_*`) is unchanged.
- Replay/origination (`sidecar_send`) and `invoke_adapter` → Phase 8 (they consume the
  relocated `sidecar/mutate` helpers).

## Test fixture

A mutator sidecar (on the `sidecar` package) that claims a stream (Phase 4), receives a
pushed rule list via `sync_rules`, applies regex find-replace on its hot path, and emits
captured/mutated pairs.

## Verification

- Existing HTTP/WS rules continue to apply byte-identically; no-sidecar behavior
  unchanged.
- `proxy_rule_add/list/delete` work with the existing 7-type form plus the optional
  `adapter` argument; `adapter` shown in lists.
- `sync_rules` pushes the ordered list; `applied_version` ack tracked; re-push on
  changes increments `snapshot_version`.
- A sidecar applies pushed rules and emits captured/mutated flow pairs; `diff_flow`
  shows the change; `fired_rules` populated.
- JSON/form mutation moved to `sidecar/mutate`; `replay_send`/`request_send` remain
  byte-identical; `sidecar` has no `sectool/` import.
- `make test-all` + `make lint` pass.

## Definition of done

- [ ] Optional `adapter` field added to rules; legacy rules byte-identical in effect.
- [ ] `sync_rules` with `snapshot_version`/ack; re-push on changes.
- [ ] Mutation audit captured/mutated pairs (incl. stream-child linking).
- [ ] JSON/form mutation helpers relocated to `sidecar/mutate`; service rewired;
      `replay_send`/`request_send` byte-identical.
- [ ] `sidecar` package gains rule cache + applier + `sync_rules` handler; no `sectool/`
      dep.
- [ ] Mutator fixture validates hot-path rule application end-to-end.
- [ ] `make test-all` + `make lint` pass.
