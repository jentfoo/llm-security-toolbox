# Sidecar Phase 2 — Transport & lifecycle

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 1** (the adapter registry the sidecar plugs into, and the `Flow`
model). Prerequisite for every later sidecar phase.

## Goal

Bring an out-of-process sidecar to life as a registered adapter: it connects over a
local socket, performs the registration handshake, negotiates contract version,
heartbeats, and shuts down cleanly. Establish the reusable `sidecar` Go package as
the client SDK future adapter authors import. After this phase a sidecar can connect
and be tracked in the registry, but performs no capture, claiming, or mutation yet —
those land in later phases. With no sidecar connected, sectool behaves exactly as
today.

## Background & assumed state

After Phase 1, sectool routes connections through an adapter registry (§2.2) and the
three built-in HTTP adapters are registered in-process. This phase adds the
**out-of-process** path: an external process connects to sectool over local IPC and
registers as an adapter through a JSON-RPC bridge. From the registry's perspective an
out-of-process sidecar is just another adapter, fronted by an in-process **bridge**
that marshals the Go adapter interfaces (`EarlyAdapter` / `UpgradeAdapter`, in
`sectool/service/proxy/protocol`) to/from the wire.

**The sidecar IPC server is owned by the native proxy backend.** The registry, the
bridge, and the local-socket listener all live under the native proxy — they exist
only when the native backend is selected and running, never under Burp (spec §8 Burp
row). Concretely (confirmed in `sectool/service/server.go` /
`backend_http_native.go`): the native backend is constructed in
`Server.startBuiltinProxy()` via `NewNativeProxyBackend(...)`, started by
`NativeProxyBackend.Serve()` (goroutine), and stopped by `NativeProxyBackend.Close()`
(during `Server.shutdown()`). The sidecar listener is created, started, and shut down
**as part of that same `NativeProxyBackend` lifecycle** — so it comes up with the
native proxy and tears down with it. When Burp is the active backend the native proxy
is never constructed, so no sidecar listener exists; if a `sidecars:` launch config is
present in that case, sectool logs a warning that sidecars are unavailable under the
Burp backend and continues normally (matching sectool's existing fall-back
philosophy).

The spec fixes the transport (§4.1): a single local socket — a Unix domain socket on
unix-like OSes (performance + filesystem-permission access control), a loopback TCP
socket on Windows (Go lacks named-pipe support) — selected at build time behind build
tags. On top runs one connection of length-prefixed JSON-RPC 2.0 messages (§4.2):
a 4-byte big-endian `uint32` length prefix followed by the JSON-RPC payload; both
peers act as client and server (either may issue Requests; Notifications are
fire-and-forget). Binary data rides inside messages as base64 fields. Address
resolution is zero-config (§4.1): a `sidecar_socket` config value auto-set on config
creation, overridable by a `--sidecar-socket` flag.

sectool config lives at `~/.sectool/config.json` (auto-created with defaults by
`sectool/config/config.go`). This phase adds the `sidecar_socket` field and a
`sidecars:` section for launch configuration. MCP server flags are parsed in
`sectool/service/flags.go`.

## Spec references

- §4.1 Transport, §4.2 Framing and message model, §4.3 Versioning.
- §5.1 Launch models, §5.2 Registration handshake, §5.3 Capabilities (declaration
  only — see deferred), §5.3.1 Capability precedence and conflict resolution,
  §5.4 Heartbeat, §5.5 Restart and reconnection.
- §6a.1 `register`, §6a.5 `ping`/`pong`, §6b.3 `shutdown`.
- §8 Feature parity (Burp row — adapter/sidecar surface is native-backend-only).
- §10 Security considerations (local socket trust model, OS-guarded permissions).
- §11 Appendix: error codes (defined here in the shared wire package).

## Scope — toolbox (server side)

- **Listener (native-backend-owned):** a local socket listener, build-tagged for UDS
  (unix) vs loopback TCP (Windows). On unix, create the containing dir `0700` and
  socket `0600` (§10). New server-side package, e.g. `sectool/service/sidecar/` —
  distinct from the root `sidecar` client SDK package. Its lifecycle is **owned by
  `NativeProxyBackend`**: constructed in `NewNativeProxyBackend`/`startBuiltinProxy`,
  the listener started inside `Serve()`, and shut down inside `Close()`. It is created
  only on the native path; under Burp it does not exist (warn-and-skip if a `sidecars:`
  config is present, see Background). The registry + bridge from Phase 1 are likewise
  native-only.
- **Framing + dispatch:** length-prefixed (4-byte BE `uint32`) JSON-RPC 2.0 codec
  with a **dedicated drain-always reader** that dispatches each message to a separate
  goroutine, so a handler awaiting a nested Request never blocks the read loop
  (§4.2 deadlock-freedom — required, not deferred).
- **Registration handshake** (§5.2, §6a.1): handle the sidecar's first `register`
  message. Store in the registry the declared `name`, `protocols`, `capabilities`,
  `mutation_ops`, `owned_rules`, `mcp_tools`, `instance_id`, `resume`. Reject
  duplicate `name`. Return effective `protocol_version`, `assigned_seams`,
  `rules_snapshot` (may be empty until Phase 7), `server_time`. The `mcp_tools` field
  is **stored only** here; the per-tool **name-collision** check (vs core tools and
  other sidecars, §9.2) extends this same registration handler in **Phase 9** — Phase
  2 enforces only `name`/capability/`owned_rules`-label conflicts.
- **Version negotiation** (§4.3): major mismatch is a fast fail (registration
  rejected, error in the §11 range); within a shared major run at
  `min(sectool.minor, sidecar.minor)`.
- **Error-code taxonomy** (§11): this phase **defines** the sectool-specific
  JSON-RPC error codes — the reserved `-33000…-33999` range and its partitioning
  (`-33000…-33099` registration/lifecycle, `-33100…-33199` mutation/rule,
  `-33200…-33299` transport, `-33300…-33399` `dial_upstream`, `-33400…-33499`
  `invoke_adapter`) — plus the structured `data` convention (adapter name and any
  relevant `flow_id`/`rule_id`/`stream_id`/`snapshot_version`). These constants live
  in the **shared `sidecar` wire package** so both ends use one definition; later
  phases (4, 5, 7, 8) reference them rather than minting their own. Phase 2 itself
  uses the registration/lifecycle and transport ranges (major-mismatch, duplicate
  registration, capability/label conflict, framing/oversize violations).
- **Capability conflict resolution at registration** (§5.3.1): validate declared
  capability claims against already-registered sidecars and the native adapters —
  disjoint `early_claim` port ranges / non-overlapping matchers, `upgrade_claim`
  most-specific-wins with ambiguity rejected, `owned_rules` label uniqueness. Reject
  with an error naming both registrations and the specific clash. (This phase only
  *validates and stores* capabilities; firing them is later phases.)
- **Heartbeat** (§5.4): send `ping` at a configurable interval (default 10s); mark a
  sidecar unhealthy when no `pong` arrives within timeout (default 30s) and fall back
  to default behavior; answer reverse-direction `ping` with `pong`. This phase covers
  detecting unhealthy/disconnect and the **new-connection** fallback (new connections
  matching the sidecar's seams fall back to default behavior). Teardown of the
  sidecar's **active** claimed/dialed byte-streams on death is owned by **Phase 4**
  (the byte-stream lifecycle), cross-linked there.
- **Ownership & in-flight bookkeeping** (supports §5.5): the registry tracks, per
  sidecar, the ownership needed to route and resume — the emitting-adapter attribution
  recorded on each flow (populated in **Phase 3**) and the set of open/incomplete
  two-phase `flow_id`s (in-flight flows). Phase 2 establishes this bookkeeping plus the
  `liveness` record (heartbeat/last-activity, PID + socket fingerprint, §2.2); `resume`
  reattaches against it. (Routing those flows for `sidecar_send` and tool delegation is
  Phases 8/9; here only the bookkeeping exists.)
- **Lifecycle:** `shutdown` (§6b.3, drain then close); restart/reconnect keyed by
  `instance_id` (§5.5) — reattach flow-ownership metadata when `resume=true`, treat a
  differing `instance_id` as a distinct instance and close the old one's flows.
- **Launch models** (§5.1): managed subprocess (sectool spawns from configured launch
  command, monitors, restarts per policy) and attached (operator starts it, it dials
  the resolved socket). Configuration under a new `sidecars:` section in
  `sectool/config/config.go`; add `sidecar_socket` (auto-set default per OS) and the
  `--sidecar-socket` override flag. Managed-subprocess spawn is part of the native
  backend lifecycle (it starts with the proxy, see Background); under Burp it is not
  spawned.
- **Config migration:** adding `sidecar_socket` and the `sidecars:` section relies on
  the existing schema-version migration in `config.go` (`LoadOrCreatePath` re-saves
  with defaults when `cfg.Version != Version`), so existing `~/.sectool/config.json`
  files gain the new fields with defaults on next load. Bump `Config.Version`
  accordingly.

## Scope — `sidecar` package

Create the root `sidecar` package — the client SDK. **It must depend on nothing under
`sectool/`** (this discipline lets it later split into its own Go module). Wire
param/return structs defined here are imported by the sectool-side bridge too, so the
two ends share one definition. This phase contributes:

- Connection + length-prefix framing + JSON-RPC 2.0 peer (both-directions), with the
  same drain-always reader discipline.
- A `register` helper taking the adapter's declared identity/capabilities.
- The heartbeat loop (answer `ping`, optionally originate `ping`).
- Graceful `shutdown` handling.

A representative client surface:

```go
func Dial(addr string, reg Registration) (*Conn, error)
func (c *Conn) Serve(ctx context.Context, h Handler) error // dispatch loop
```

## Out of scope / deferred

- **Firing** any capability: `early_claim`/byte streams → Phase 4; `upgrade_claim` →
  Phase 6; `injection_target` → Phase 8. Here they are declared and conflict-checked
  only.
- `push_flow`, `log`, `report_metrics`, `core_query` → Phase 3.
- `dial_upstream` → Phase 5; `sync_rules`/mutation → Phase 7; `sidecar_send`/
  `invoke_adapter` → Phase 8; `mcp_tools`/`invoke_tool` delegation → Phase 9
  (the `mcp_tools` field is *stored* at registration here, not yet exposed).

## Test fixture

A minimal fixture process built on the `sidecar` package that connects, registers
(declaring one protocol and, in variants, conflicting/over-version capabilities),
heartbeats, reconnects with a stable `instance_id`, and shuts down.

## Verification

- Fixture connects → registers → negotiates version → heartbeats → reconnects →
  shuts down; assert registry state at each step.
- Assert minor-version capping, major-mismatch rejection, capability/label conflict
  rejection (error names both parties, uses a §11 code), and heartbeat-timeout
  fallback.
- Build both transport variants (UDS and loopback TCP) under their build tags.
- The listener starts with the native proxy and stops with it; under the Burp backend
  no listener is created and a configured sidecar produces a warning, not an error.
- With no sidecar connected, the full existing test suite is byte-identical.
- `make test-all` + `make lint` pass.

## Definition of done

- [ ] Build-tagged local listener with correct permissions; both variants compile.
- [ ] Sidecar listener lifecycle owned by `NativeProxyBackend` (starts in `Serve()`,
      stops in `Close()`); never created under Burp; warn-and-skip when a `sidecars:`
      config is present under Burp.
- [ ] Length-prefixed JSON-RPC 2.0 codec with deadlock-free reader.
- [ ] §11 error-code constants + `data` convention defined in the shared wire package.
- [ ] `register` handshake stores all declared fields (incl. `mcp_tools` stored only);
      version negotiation and §5.3.1 conflict resolution enforced.
- [ ] Heartbeat, `shutdown`, and `instance_id` restart/reconnect work; ownership +
      in-flight bookkeeping established for `resume`.
- [ ] Config (`sidecar_socket`, `sidecars:`) and `--sidecar-socket` flag in place;
      `Config.Version` bumped with migration.
- [ ] Root `sidecar` package exists, depends on nothing under `sectool/`, drives the
      fixture end-to-end.
- [ ] `make test-all` + `make lint` pass; no-sidecar behavior unchanged.
