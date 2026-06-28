# Sidecar Phase 9 — Sidecar-registered MCP tools (invoke_tool)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 2** (`mcp_tools` declared at registration) and **Phase 3**
(`core_query`, which delegated tools use to read sectool state). Independent of the
claim/replay chain (Phases 4–6, 8), so it can be built any time after Phase 3.

## Goal

Let a sidecar expose protocol-specific operations as first-class MCP tools that agents
discover and call through the normal MCP mechanism. sectool composes the tool list
(core + every connected sidecar's tools) at MCP-client connect, validates arguments,
and delegates invocation to the owning sidecar via `invoke_tool`. This is how
operations beyond the shared mutation grammar reach agents — without adding new
parameters to core tools.

## Background & assumed state

Phase 1 deliberately left the MCP tool layer as-is (hardcoded core tool list in
`sectool/service/mcp_server.go`). This phase performs the deferred "tool split": core
tools register as before, and adapter-contributed tools are gathered from registered
adapters when an MCP client connects. The mechanism is general, but in practice the
contributors are sidecars (the in-process HTTP adapter "owns" HTTP-specific tools like
`cookie_jar`/`crawl_*`, which can be expressed through the same composition without
changing their behavior).

The spec (§9.1) guarantees: with no sidecar connected, the MCP surface and behavior
are identical to today — no default/global/always-on tools are added. Everything here
is contingent on a connected sidecar.

Sidecar-registered tools (§9.2): declared in the `mcp_tools` field of `register`
(stored in the registry in Phase 2), each a complete MCP tool definition
`{name, description, input_schema, annotations?}`. Because sidecars connect and
register before any MCP client session begins (§5.1), sectool composes the full list at
client-connect time — no dynamic mid-session registration. Tool names are namespaced
by the sidecar; a collision with a core tool or another sidecar's tool is rejected at
registration, naming both owners.

`invoke_tool` (§6b.7): when an MCP client invokes a sidecar-registered tool, sectool
validates the arguments against the declared `input_schema`, delegates to the owning
sidecar, and returns the sidecar's result (markdown and/or structured content)
verbatim. While handling, the sidecar has full read access to sectool state via
`core_query` (§6a.9, Phase 3) and may emit flows (`push_flow`, Phase 3).

Discoverability (§9.3): sidecar tools appear in the standard MCP `tools/list` like any
core tool, carrying their own `description`/`input_schema`; no sectool-specific
introspection tool is needed.

## Spec references

- §6a.1 `register` (`mcp_tools` field), §6b.7 `invoke_tool`.
- §9.1 No change without a sidecar, §9.2 Sidecar-registered tools, §9.3
  Discoverability.

## Scope — toolbox (server side)

- **Tool composition:** refactor `sectool/service/mcp_server.go` tool registration to
  assemble the advertised tool list from core tools plus every registered adapter's
  contributed tools at MCP-client connect. Preserve the exact existing surface when no
  sidecar is connected (§9.1).
- **Namespacing + collision rejection** (at registration, §9.2): **extend the Phase 2
  registration handler** with the per-tool name-collision check — Phase 2 *stored*
  `mcp_tools` but did not collision-check them (it only enforced `name`/capability/
  `owned_rules`-label conflicts). Reject a sidecar whose tool name collides with a core
  tool or another sidecar's tool, naming both owners (error in the §11 registration
  range).
- **`invoke_tool` delegation** (§6b.7): on an MCP client call to a sidecar tool,
  validate `arguments` against the declared `input_schema`, delegate to the owning
  sidecar, and return `{content}` verbatim to the client.
- Sidecar-registered tools appear in `tools/list` with their own metadata (§9.3).
- Extend the `workflow` instruction templates to mention any sidecar-registered tools
  present in the session (spec §8 `workflow` row).

## Scope — `sidecar` package

- Tool-registration support: declare `mcp_tools` (name/description/input_schema/
  annotations) in the registration payload.
- An `invoke_tool` handler hook: receive the validated `arguments`, run the tool's
  logic (with `core_query`/`push_flow` available from earlier phases), and return the
  result content.

## Out of scope / deferred

- No new core MCP tools are added (operations beyond the shared grammar live in
  sidecar tools, not core-tool parameters — §9.1).
- A global adapter-enumeration tool is explicitly not needed in v1 (§9.3).

## Test fixture

A sidecar (on the `sidecar` package) that registers one or more `mcp_tools`. An MCP
client lists tools (sees the sidecar tools) and invokes one; the fixture's handler
returns a result (optionally after a `core_query`/`push_flow`). A second fixture
registers a colliding tool name to exercise rejection.

## Verification

- With no sidecar connected, `tools/list` and all tool behavior are byte-identical to
  today.
- With a sidecar connected, its tools appear in `tools/list` with correct
  metadata; invocation validates against `input_schema`, delegates via `invoke_tool`,
  and returns the result verbatim.
- A delegated tool can read state via `core_query` and emit flows via `push_flow`.
- A name collision (with a core tool or another sidecar) is rejected at registration,
  naming both owners.
- `make test-all` + `make lint` pass.

## Definition of done

- [ ] Tool list composed from core + adapter-contributed tools at client connect;
      no-sidecar surface unchanged.
- [ ] `mcp_tools` namespacing + collision rejection added to the Phase 2 registration
      handler (tool-name collisions vs core + other sidecars).
- [ ] `invoke_tool` delegation with `input_schema` validation; result returned
      verbatim; `core_query`/`push_flow` usable mid-call.
- [ ] Sidecar tools discoverable via `tools/list`; `workflow` templates mention them.
- [ ] Tool-registration + `invoke_tool` fixtures validate end-to-end (incl. collision).
- [ ] `sidecar` package gains tool registration + `invoke_tool` handler; no `sectool/`
      dep.
- [ ] `make test-all` + `make lint` pass.
