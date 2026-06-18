# Sectool Protocol Sidecar Specification

## 1. Overview and goals

### 1.1 Problem statement

Sectool's capture, rule, replay, history, diff, reflection, OAST, crawler,
and analysis surface is shaped by the assumptions of HTTP/1.1, HTTP/2, and
WebSocket. The native proxy directly speaks those protocols; the data model
(`HistoryEntry` and its unioned HTTP/HTTP2/WS fields), the rule type
enumeration, and the `replay_send` mutation grammar are all keyed off HTTP
semantics. Custom and binary protocols — MQTT, Matter, proprietary RPC
frames, and tunneled control planes built on Noise or other
non-HTTP framing — cannot be tested with the same agent-facing ergonomics
today. There is no clean seam for an external component to participate in
capture, mutation, or replay.

### 1.2 Goal

Define a protocol-adapter contract that lets any protocol — HTTP today, any
binary or custom protocol tomorrow — present its traffic into sectool's
existing flow timeline and reuse the existing rule, replay, diff,
reflection, notes, OAST cross-reference, and history machinery with full
agent parity. The HTTP/1.1, HTTP/2, and WebSocket handlers re-implement
themselves on top of this contract; external sidecar processes implement
the same contract over IPC and can register entirely new protocols without
modifying sectool source.

Two design choices anchor the contract:

- **Sectool owns the transport.** All sockets — client-facing and
  upstream-facing — are opened and owned by sectool. Sidecars never open
  listening sockets and never receive socket file descriptors. They
  receive byte streams over the RPC channel. This keeps the contract
  portable across Linux, macOS, and Windows without per-platform FD-
  passing logic.
- **Flows look like HTTP.** The on-the-wire format an adapter speaks may
  be arbitrary, but the captured representation is an HTTP-shaped envelope
  (method, path, headers, body) with an adapter-defined `protocol_tag`
  replacing the HTTP version slot. This lets every existing sectool tool
  — `flow_get`, `diff_flow`, `find_reflected`, `replay_send`, `set_json`,
  `set_header`, `notes_save` — work on adapter flows without per-adapter
  schema reasoning.

### 1.3 Non-goals

- This specification does not replace the existing top-level backend choice
  (native vs. Burp). The Burp backend slot remains unchanged. Protocol
  adapters live *under* the native proxy, not in the same slot as Burp.
- This specification does not redesign the MCP transport or the agent UX
  for HTTP testing. Existing agents continue to call `proxy_poll`,
  `flow_get`, `replay_send`, etc. with no behavioral change for HTTP
  flows.
- This specification does not require any source change in target
  applications. Adapters either intercept inline (existing TLS MITM
  approach) or terminate the target's protocol with operator-provisioned
  trust material; the choice is per-adapter.

### 1.4 Two-tier adapter model

Adapters come in two flavors implementing the same contract:

- **In-process adapters** — Go packages compiled into sectool. The
  HTTP/1.1, HTTP/2, and WebSocket handlers move to this layer. They bind
  the §6 method surface directly as Go calls — no JSON-RPC framing, no
  socket, no base64 — but express the same registration, capability,
  flow-emission, and mutation semantics as out-of-process sidecars.
- **Out-of-process sidecar adapters** — standalone processes connecting to
  sectool over a local IPC channel. The contract surface is identical;
  the transport differs.

Both produce flows that land in the same unified history, are rule-target
addressable, and are replayable through the same MCP tools.

---

## 2. Architecture

### 2.1 Hosting model

The native proxy retains overall ownership of the capture pipeline. It
continues to:

- Accept TCP connections on the configured proxy port(s).
- Perform CONNECT tunneling and TLS MITM using the existing fake-CA
  mechanism.
- Drive initial HTTP framing for cleartext and TLS-decrypted HTTP
  traffic.
- Coordinate the rules engine, history store, notes, OAST, and crawler.
- Host the MCP server and CLI surface.
- Open every TCP connection — including upstream dials requested by
  sidecars.

Protocol adapters are subordinate components registered with an **adapter
registry** maintained by the native proxy. Each adapter declares the
protocols it understands and which connection-handling seams it wants to
claim.

### 2.2 Adapter registry

The registry is keyed by adapter `name` (unique, string identifier) and
stores per-adapter:

- `version` — adapter contract version it speaks.
- `protocols` — list of protocol identifiers it provides (e.g.,
  `mqtt/3`, `tailscale.control`, `custom.foo`). The built-in in-process
  adapters register `http/1.1`, `http/2`, and `websocket` the same way
  (§2.4).
- `capabilities` — declared seams the adapter subscribes to (see §5.3).
- `mutation_ops` — declared mutation operations and their parameter
  schemas, used by the rules engine and the replay grammar to expose
  the right MCP tool options to agents.
- `owned_rules` — rules the adapter pushed at registration time (§6a.1,
  `owned_rules`). Removed from the central rule list when the adapter
  unregisters.
- `liveness` — bookkeeping for heartbeat, last activity, and process
  identity (PID + local socket fingerprint for out-of-process).

The registry is consulted when:

- New connections arrive — to determine which adapter (if any) claims
  the byte stream, at which seam.
- An agent calls `replay_send`, or invokes a sidecar-registered tool
  (§9.2) — to route the operation to the adapter that owns the source
  flow or target.
- An agent calls a mutation MCP tool — to validate the requested
  mutation against the adapter's declared `mutation_ops`.
- A sidecar requests an upstream dial via `dial_upstream` (§6a.6) —
  to apply scope policy and open the TCP connection on the sidecar's
  behalf.

### 2.3 Connection lifecycle and handoff seams

Sidecars declare their connection-handling preferences at registration
(§5.3). Two seams cover every case the contract supports:

1. **Early claim.** Sidecar claims the byte stream from TCP accept on a
   port range, optionally gated by a magic-byte prefix sniff or host
   (SNI) match. Used by adapters whose protocol does not start with HTTP.
   For a cleartext port the sidecar receives raw bytes from the first
   byte the client sends. For a **TLS** port whose claim sets
   `tls.terminate` (§5.3), sectool terminates TLS first and the sidecar
   receives the **decrypted** stream — how a TLS-wrapped non-HTTP protocol
   (e.g. MQTT-over-TLS) reaches a sidecar without ever holding the CA key.
   When a fixed magic-byte prefix cannot distinguish the protocol, the
   claim instead sets `probe` (§5.3): sectool buffers the opening bytes and
   asks the sidecar to decide via `claim_probe` (§6b.8), so a fully-binary
   protocol with no stable prefix can still be claimed without routing every
   connection through the sidecar.
2. **Upgrade claim.** Sidecar claims the byte stream after sectool has
   processed an HTTP upgrade signal — most commonly HTTP/101 Switching
   Protocols (WebSocket, h2c, `/ts2021`-style upgrades), or post-CONNECT
   when `upgrade_signal=connect`. Sectool captures the HTTP request that
   triggered the upgrade as a normal HTTP flow, synthesizes the upgrade
   response itself, and then routes subsequent bytes on that TCP
   connection to the sidecar.

These two seams cover **interception**, where sectool front-ends every
connection: sectool drives all HTTP framing itself (initial and keep-alive
requests, and the upgrade request) and diverts a connection's bytes to the
sidecar only when its claim fires. Protocols that begin in a binary state
from the first byte are handled by `early_claim` with a magic-byte sniff
(or a `claim_probe` callback when no fixed prefix discriminates);
protocols that start as HTTP and switch are handled by `upgrade_claim`
after the 101 (after the switch the protocol has changed, so there are no
further HTTP requests on that connection to re-handle). A sidecar therefore
lets sectool front-end every connection on its own ports — including
protocols that initialize in a binary state — without the sidecar
participating in transport setup.

Routing is decided **per-connection and per-upgrade, never per-target**:
the claim matcher (or `claim_probe`) selects the owning adapter at accept,
and `upgrade_claim` re-selects it at an HTTP upgrade on the same
connection. A single host may therefore speak HTTP on one connection and a
custom binary protocol on another, or switch mid-connection, and each is
routed independently. The claim decision is made from the opening bytes or
the HTTP upgrade; a protocol that can only be identified after a
multi-message exchange (no discriminating opening bytes and no HTTP
upgrade) is out of scope for v1.

A third pattern exists for adapters that are themselves an endpoint
clients connect to directly (e.g., an instrumented control server): the
adapter owns its own listening socket, sectool is not in the TCP path,
and the adapter pushes flows and accepts injections. Such an adapter MUST
still apply the rules sectool pushes (§6b.1) that are relevant to its
request/response messages, in protocol-aware form — it is the only party
that can — so origination does not preclude rule-driven mutation. This
origination role is the sole exception to sectool owning the transport; it
is not interception.

Generalizing the built-in handoff is required work: today the 101
takeover is hard-wired to WebSocket (`isWebSocketUpgrade`) and h2c is
rejected at accept. `upgrade_claim` must instead match a registered
`(host, path, upgrade-token, method)` and divert post-101 bytes
regardless of the upgrade token (e.g., `tailscale-control-protocol` on
`POST /ts2021`); `early_claim` extends the existing accept-time byte
sniff.

At each seam, sectool keeps the OS socket. Bytes flow between the socket
and the sidecar as `stream_open` / `stream_deliver` events and the sidecar's
Response `writes` (§4.2). The sidecar may request upstream connectivity
via `dial_upstream` (§6a.6); sectool opens the upstream TCP connection
(subject to scope policy) and exchanges its bytes through the same
event/Response model.

This design has three consequences worth calling out:

- The sidecar never sees an OS file descriptor and never opens a
  listening socket. Cross-platform support is automatic.
- The HTTP request that triggers an upgrade is always captured by
  sectool's HTTP machinery and is available in normal history. The
  adapter sees only post-upgrade bytes.
- Sectool stays in the connection-bookkeeping path (host, port, TLS
  cert chain, IP, timing) and applies **connection-level** scope policy
  (host/port at accept and at `dial_upstream`) to every connection.
  Where sectool terminates the encoding it sees plaintext — including
  **TLS**, even for a TLS-terminated sidecar claim — so content-level
  scope applies to the decrypted stream. Where the encoding is
  **message-level** crypto the sidecar owns (e.g. Noise inside a tunnel),
  sectool sees only ciphertext, and content-level inspection of that
  traffic is the sidecar's responsibility since it alone holds the
  protocol keys.

### 2.4 Refactor scope for built-in adapters

The HTTP/1.1, HTTP/2, and WebSocket handlers currently in
`sectool/service/proxy/handler_*.go` are refactored to implement the
in-process adapter interface. Behavior visible to agents and CLI users
remains identical. After the refactor:

- `handler_http1.go` becomes the HTTP/1.1 adapter, claiming TCP accept
  for the proxy listener via the registry.
- `handler_http2.go` becomes the HTTP/2 adapter, claiming both the
  ALPN-selected HTTP/2 path and any post-HTTP/101 h2c takeover.
- `handler_websocket.go` becomes the WebSocket adapter, claiming
  post-HTTP/101 sockets where the prior request was a WebSocket
  handshake.

This refactor is the validating test of the abstraction: if any of the
three feels distorted in the contract, the contract is wrong.

---

## 3. Data model — generalizing the HistoryEntry

### 3.1 Flow

The unioned `HistoryEntry` in `sectool/service/proxy/types.go` is replaced
by a generalized `Flow`. A Flow represents one logical exchange and MAY
carry a `request` sub-object and a `response` sub-object, each an envelope
of `{method, path, headers, body}` (plus an optional `status` on the
`response` side). The envelope fields live **inside** the `request` /
`response` sub-objects, not at the Flow level. Request/response protocols
populate both sides under a single `flow_id` — exactly as `HistoryEntry`
carries `Request` and `Response` today, so `flow_get`, `diff_flow`,
`find_reflected`, and `replay_send` keep resolving their `request_*` /
`response_*` scopes against one id with no change. One-way messages
(tunnel envelopes, stream chunks, pub/sub frames) populate a single
envelope and rely on `direction`; `bidirectional` marks a tunnel
envelope describing a session rather than a directional message.

The fields below are flow-level, except `method` / `path` / `headers` /
`body` / `status`, which are the per-side envelope fields living inside
each `request` / `response` sub-object:

- `flow_id` — opaque stable identifier, base62, unique across all
  adapters and the lifetime of the history store.
- `adapter` — name of the adapter that emitted the flow.
- `protocol_tag` — protocol identifier within the adapter (e.g.,
  `http/1.1`, `http/2`, `websocket.frame`, `mqtt/3.publish`,
  `tailscale.control`, `tailscale.tunnel`). Occupies the slot HTTP
  flows use for the HTTP version.
- `method` — any string. For HTTP this is the standard verb; for
  WebSocket frames it is `FRAME`; for tunnel envelopes it is `TUNNEL`;
  adapters may define their own (`PUBLISH` for MQTT, `STREAM` for a
  long-lived RPC, etc.).
- `path` — protocol-defined addressing string. HTTP path for HTTP;
  `/ws/<opcode>` for WebSocket frames; `/<adapter>/tunnel/<id>` for
  tunnel envelopes; any meaningful identifier for custom protocols.
- `headers` — ordered list of `Header` entries (see
  `sectool/service/proxy/types.go`, the existing `Header` struct with
  `Name`, `Value`, `RawLine`, line-ending metadata). HTTP flows carry
  real HTTP headers. Non-HTTP adapters carry the same shape: name-value
  metadata about the message. A common adapter-injected header is
  `X-Sectool-Stream-Id` (the wire stream identifier, e.g. an HTTP/2
  stream id); session/stream grouping itself uses `parent_flow_id`, not
  a header.
  Post-body metadata (e.g. HTTP/2 or gRPC trailers) is carried as ordinary
  headers by adapter convention — the contract models no separate trailer
  group; an adapter that must round-trip trailers as trailers marks them
  with a reserved header name it owns.
- `body` — the logical message payload tools operate on (parsed JSON,
  decoded text, etc.). Decompressed when the adapter declares a
  content-encoding semantically equivalent to gzip/deflate/zstd. When the
  wire form is not natively decodable by sectool (protobuf, custom
  framing), the originating adapter also supplies `body_raw` (the
  post-decryption wire bytes) and `body_codec` (the declared transform
  chain plus the logical content-type); sectool stores both, every
  existing tool operates on the logical `body`, and on replay the
  unmutated path sends `body_raw` verbatim while a mutated body is
  re-encoded by the owning adapter through `body_codec` (§6b.2).
- `status` — optional, **`response` side only**. The protocol's outcome
  code (HTTP status integer, or any adapter-defined string/code).
  Omitted by protocols that have no response-status concept (one-way
  messages, fire-and-forget frames). `proxy_poll`'s status filter
  resolves against it; for HTTP/2 adapters the `:status` pseudo-header
  maps here.
- `direction` — `client_to_server` | `server_to_client` |
  `bidirectional` (the latter for session/tunnel envelopes and synthetic
  events).
- `parent_flow_id` — optional reference to a parent flow when the
  emission is logically nested: a streamed chunk belongs to a parent
  stream-open flow, and an inner flow belongs to the session/tunnel
  envelope it was carried inside (§3.2). The sole nesting reference; a
  flow forms a tree by pointing at its immediate parent.
- `started_at`, `completed_at` — monotonic + wall-clock pair.
- `annotations` — open-ended map of typed metadata: rule hits,
  notes references, OAST correlation IDs,
  crawler depth/found-on, sidecar diagnostic info, and any
  adapter-specific keys (e.g. a sidecar recording stripped fields when it
  cannot rebind a signature on replay, §6b.2).
- `size_hint` — content length when known, used for fast list
  pagination without payload deserialization.

Wire-fidelity fields already present on the existing `Header`, `Wire`,
`ChunkFrame`, and `LineEnding` types (see `proxy/types.go:10-86`) carry
over verbatim for HTTP/1.1 flows. Adapters that need to preserve
protocol-specific wire quirks (HPACK encoding choices for HTTP/2, frame
masking for WebSocket, zstd frame headers for streamed protocols) keep
that material as headers or in `annotations`. There is no separate
"payload view" representation — `body` is the source of truth, parsed
the same way sectool's HTTP tools already parse it.

### 3.1.1 HistoryEntry → Flow migration

The migration is essentially a field rename:

| HistoryEntry v0 field | Flow v1 destination |
|---|---|
| `FlowID` | `flow_id` |
| `Protocol = "http/1.1"` | `adapter = "http/1.1"`, `protocol_tag = "http/1.1"` |
| `Protocol = "h2"` | `adapter = "http/2"`, `protocol_tag = "http/2"` |
| `Protocol = "websocket"` | handshake is an HTTP/1.1 flow; frames become child flows (see below) |
| `Timestamp`, `Duration` | `started_at`, `completed_at` |
| `Request` (`*RawHTTP1Request`) | the `request` side of a single Flow; `method`, `path`, `headers`, `body` populated from the struct |
| `Response` (`*RawHTTP1Response`) | the `response` side of the **same** Flow (one `flow_id` carries both), attached when the response completes |
| `H2Request` / `H2Response` | same shape; HTTP/2 pseudo-headers carried as headers prefixed with `:` |
| `H2StreamID` | header `X-Sectool-Stream-Id` |
| `WSFrames` (`[]WSFrame`) | one child flow per frame; `parent_flow_id` set to the handshake-response flow; `method=FRAME`, `path=/ws/<opcode>`, body = unmasked payload |

**Migration strategy: lazy rewrite on access.** The spill store's read
path detects v0 records by msgpack version tag and rewrites them to v1
inline on next touch. No startup migration, no double storage, hot
records compact naturally. Cold records remain v0 until accessed or
until a background sweep promotes them. SpillStore behavior
(`store/spill.go:42-48`: 200 MiB hot cache, 50 % eviction, 100 MiB
dead-byte compaction, zstd+AES-256) is preserved.

### 3.2 Session / tunnel envelope (a Flow convention)

A session or tunnel envelope is **not a distinct primitive** — it is an
ordinary Flow, emitted via `push_flow` (§6a.2) like any other, shaped by
convention as a synthetic HTTP-like message describing one established
session:

- `direction = bidirectional`.
- `protocol_tag` ends in `.tunnel` (e.g., `tailscale.tunnel`,
  `noise.tunnel`).
- `method = "TUNNEL"`.
- `path = "/<adapter>/tunnel/<id>"`.
- `headers` carry session metadata: negotiated protocol name, handshake
  hash, peer pubkey fingerprints, endpoint sockets, trust material
  flags (operator-supplied vs. discovered). Concrete adapters populate
  the fields their handshake produces; not every adapter populates every
  header.
- `body` is usually empty (or carries the handshake transcript for
  reproducibility).

Inner flows reference the envelope by setting `parent_flow_id` to its
`flow_id`. Diff, filtering, and rule scope expressions target that
`flow_id` to operate on a single session at a time; deeper nesting (a
stream chunk under a stream-open under a session) forms a tree reachable
by walking `parent_flow_id`. When a session ends, the envelope is
re-emitted via the two-phase `push_flow` form (same `flow_id`,
`completed_at` set) to record teardown.

### 3.3 Streams

Long-lived exchanges — server-streaming responses, persistent WebSocket
sessions, MQTT pub/sub, chunked transfer with semantic boundaries — are
**not a separate primitive**. A stream is a parent Flow plus a sequence
of child Flows, all emitted through the one `push_flow` method (§6a.2):

- **Parent flow** — a `push_flow` carrying the request/initiator;
  `protocol_tag` names the streaming variant (e.g. `http2.chunked`,
  `websocket.session`, `tailscale.control.map.stream`). The returned
  `flow_id` is the stream's id.
- **Child flows** — each a `push_flow` with `parent_flow_id` set to the
  parent's `flow_id`, `direction` set, and `body` carrying the
  chunk/message payload. Children are persisted **and replayed in the
  exact order the sidecar emits them** — the single ordered RPC
  connection (§4.2) preserves emission order and sectool never reorders.
  This arrival-order guarantee is why no per-chunk sequence number is
  needed.
- **Close** — the parent is re-emitted via the two-phase `push_flow`
  form (same `flow_id`, `completed_at` set, any trailers as
  response-side headers), exactly as a session envelope closes (§3.2).

This one mechanism covers both independent-message streams (WebSocket
frames, MQTT PUBLISH — each child a complete message) and
chunked-response streams (server-streaming, MapResponse — each child a
fragment of one response); they differ only by `protocol_tag`.

Worked shape:

```
parent  = push_flow({request, protocol_tag: "...stream"})   // → flow_id P
loop:     push_flow({parent_flow_id: P, direction, body})   // one child per chunk
close:    push_flow({flow_id: P, completed_at, response:{headers: trailers}})
```

Each child flow is independently:

- Rule-targetable (rules match by `parent_flow_id` or by general body
  predicate).
- Mutatable (the sidecar rewrites a child's logical body from the rules
  sectool pushes, §6b.1).
- Replayable in `replay_send` either child-by-child in emission order or
  collapsed into a single replay where the destination accepts that
  framing (§6b.2 `stream_strategy`).

### 3.4 Mutation grammar

Mutations are a list of typed operations. The op set is small and shared
across adapters:

- `regex_replace { scope, find, replace }` — RE2 against a designated
  region. `scope` is `body`, `headers`, or `raw`.
- `set_header { name, value }` / `remove_header { name }` — operate on
  the headers list. Casing preserved as today.
- `set_json { path, value }` / `remove_json { path }` — operate on a
  JSON body using the existing dot/bracket path syntax.
- `set_form { name, value }` / `remove_form { name }` — operate on a
  form-encoded body.
- `set_query { name, value }` / `remove_query { name }` — operate on a
  single query parameter; `set_query_string { query }` replaces the whole
  query string. Matches the existing `replay_send` `set_query` /
  `remove_query` / `query` parameters.
- `set_method { method }` / `set_path { path }` / `set_target { scheme,
  host, port }` — message routing fields.
- `set_body { bytes }` — wholesale body replacement.

Adapters may declare additional named ops via the `mutation_ops` array (§6a.1)
for cases the shared set cannot express — e.g., `set_zstd_chunk` for
zstd-framed stream chunks where the adapter must recompress, or
`resign_register_request` for protocol-specific signature recomputation.
Each adapter-declared op carries a name, a JSON-Schema parameter shape,
and a list of `protocol_tag`s it applies to.

The **owning adapter applies the mutation list in its own order**, and
applies any rebind/finalizer ops (ops that recompute integrity over the
final message, such as a signature recomputation) **after** all content
mutations regardless of their position in the list — a finalizer that ran
before the fields it covers were mutated would re-bind stale content. The
fixed ordering documented for the in-process HTTP adapter (§8) is that
adapter's convention, not a universal cross-adapter guarantee.

Each operation carries an optional `label` (unique within a rule list)
and an `is_regex` flag where the operation supports both literal and
regex matching.

### 3.5 Rule targeting

Rules generalize from the current type enum (`request_header`,
`request_body`, `response_header`, `response_body`, `ws:to-server`,
`ws:to-client`, `ws:both`) to a tuple:

`(adapter, message_type, op, params, scope_filter, label, rule_id,
owner)`

- `adapter` — name. `*` matches any.
- `message_type` — `request` | `response` | `chunk` | `tunnel` |
  `frame`. `*` matches any.
- `op` — declared mutation operation name (shared or adapter-declared).
- `params` — operation-specific parameters.
- `scope_filter` — optional predicate narrowing applicability: host
  pattern, path pattern, parent_flow_id (matches the session/tunnel
  envelope or stream parent a flow nests under),
  protocol_tag, byte-length range.
- `label` — unique across the entire rule list (current behavior
  preserved).
- `rule_id` — base62 unique identifier.
- `owner` — `user` (created via `proxy_rule_add`) or
  `adapter:<name>` (pushed via `owned_rules`, §6a.1). Adapter-owned
  rules cannot be deleted via `proxy_rule_delete`; they are released
  when the adapter unregisters.

Existing rule types map onto this tuple deterministically. Migration
defaults: existing rules become `adapter=*`, `op` derived from the type
name (`request_header` → `set_header` or `regex_replace` with
`scope=headers`, etc.). The migration is a labeling change, not a
semantic change; existing rules continue to apply to both HTTP/1.1 and
HTTP/2 traffic as they do today.

---

## 4. Wire protocol for out-of-process adapters

### 4.1 Transport

Out-of-process sidecars connect to sectool over a **local socket**,
selected at **build time** behind build tags:

- **unix-like OSes** — a Unix domain socket, chosen for **performance**
  (a sidecar is tightly coupled to the request/response path it
  participates in) and because filesystem-permission access control fits
  a tool that already assumes a secured local host.
- **Windows** — a loopback TCP socket (`127.0.0.1`). Go has no standard
  named-pipe support and `AF_UNIX` on Windows carries version caveats,
  so loopback TCP is the reliable Windows transport. It is not
  filesystem-guarded, so on Windows the trust rests entirely on the
  secured-local-host assumption (§11).

The framing and JSON-RPC message model (§4.2) on top are identical across
both. Both are local-only, so there is no non-loopback opt-in to manage.

**Zero required configuration.** The address is resolved from sectool
config — a `sidecar_socket` field auto-set when `~/.sectool/config.json`
is created (default `~/.sectool/sidecar.sock` on unix — a UDS path; a
loopback `127.0.0.1:<port>` address on Windows). Sectool binds it and an
operator-attached sidecar dials it, both resolving the value from the
**same config** (the default `~/.sectool/config.json`, or whatever path
was passed via `--config`). Starting sectool and then the sidecar
therefore connects them with no custom configuration. Override precedence,
highest first:

- `--sidecar-socket <value>` CLI flag (on either process) — a path or
  `host:port` outside of what `config.json` specifies.
- The `sidecar_socket` config value (from the default `~/.sectool/config.json`,
  or the file passed via `--config`).
- The built-in per-OS default.

### 4.2 Framing and message model

A **single** connection carries a sequence of length-prefixed JSON-RPC 2.0
messages:

- 4 bytes — big-endian `uint32` payload length.
- N bytes — the JSON-RPC 2.0 message.

There is one connection and one framing. The protocol is **JSON-RPC 2.0**:
both sides act as client and server — either peer may issue a Request and
the other replies with a Response addressed by `id`; Notifications (no
`id`, no reply) carry fire-and-forget events. Binary data — captured
request/response bytes, the bytes a sidecar wants written to a socket, and
message bodies — travels **inside** these JSON-RPC messages as
base64-encoded fields. There is no separate byte channel and nothing to
correlate across connections. The `uint32` length prefix bounds a single
message; that ceiling is not an artificial limit and is ample for the
protocols in scope. `max_body_bytes` governs only what is retained in
history, never what is forwarded.

**Synchronous, sectool-driven events.** Sectool owns every socket and
drives the interaction. Each event is a Request from sectool to the
sidecar, and the sidecar's Response carries the bytes to write back:

- `stream_open` — a claim fired; `{stream_id, host, path, matched_claim,
  peer_addr}`. The sidecar sets up per-stream state.
- `stream_deliver` — inbound bytes on a stream; `{stream_id, data}` (`data`
  base64). This is the workhorse.
- `sidecar_send` — agent-initiated (MCP) replay/originate events.

Every such Response MAY carry a `writes` array — `[{stream_id, data}]`,
`data` base64 — of bytes for sectool to write to the named socket(s). A
write may target a **different** `stream_id` than the event arrived on:
that is how a request delivered on the client stream is forwarded out the
upstream stream, and how one inbound message drives a multi-message
handshake across both. While handling an event the sidecar may issue its
own Requests back to sectool — `dial_upstream` (§6a.6) to open an
upstream stream, `core_query` (§6a) to read state.

**Every sidecar output is event-driven.** There are no unsolicited writes;
a multi-message exchange still originates from one event (proxy or MCP),
with later messages arriving as Responses to subsequent `stream_deliver` events.
The single proactive control action a sidecar may take is `close_stream`
(§6a). Sectool processes a stream's events in order — it awaits the
Response before delivering that stream's next chunk — which yields
ordering and backpressure for free. Captured flows for history are emitted
separately via `push_flow` (§6a), exactly as today;
those are independent of the `writes` that forward bytes.

**V1 scope note.** The contract assumes well-behaved sidecars and
local-host deployment. *Deadlock-freedom is required, not deferred*: each
peer MUST run a dedicated reader that always drains the connection and
dispatches work to separate goroutines, so a handler awaiting a nested
Request never blocks the read loop. What v1 defers is *backpressure and
memory bounding* — per-sidecar quotas, credit schemes, and queue caps —
none of which are required for the controlled test environments this
contract targets. A v2 may add these once production-scale operational
patterns are understood.

The choice of JSON-RPC 2.0 over alternatives:

- vs. **custom binary protocol**: would offer marginally better
  performance but at the cost of debuggability and language
  portability. Bytes ride inside JSON-RPC messages as base64; the
  overhead is immaterial on a local socket for the controlled test
  environments this contract targets.
- vs. **NDJSON / line-delimited JSON**: lacks the standard
  request/response/error semantics; would require building those
  primitives. JSON-RPC 2.0 already specifies them.

### 4.3 Versioning

The contract carries a `major.minor` version. Both peers advertise theirs
at registration (§6a.1):

- **Major mismatch is a fast fail.** If the sidecar's major differs from
  sectool's, sectool rejects `register` with a version-mismatch error
  (§12); a managed sidecar exits non-zero. There is no cross-major
  compatibility.
- **Minor differences are absorbed.** Within a shared major the session
  runs at the negotiated minor `min(sectool.minor, sidecar.minor)`, and
  each peer restricts itself to methods and fields introduced at or below
  that minor. A newer sectool talking to an older sidecar simply refrains
  from using anything above the sidecar's minor; a newer sidecar must not
  require anything above sectool's minor. Minors are additive within a
  major and never remove or repurpose an existing method or field.

---

## 5. Sidecar lifecycle and registration

### 5.1 Launch models

Two launch models, both supported:

- **Managed subprocess.** Sectool spawns the sidecar at startup using
  a configured launch command (binary path, args, env). The parent
  passes the socket path (via `--sidecar-socket` or a shared `--config`).
  Sectool monitors process lifetime and restarts the sidecar according
  to a configurable policy on crash.
- **Attached process.** An operator starts the sidecar independently
  (e.g., for debugging or for sidecars that need elevated privileges);
  it resolves the same socket path from config (§4.1). Sectool accepts
  the connection and registers it.

Configuration of launch models lives in the sectool config file under
a new `sidecars:` section, with per-sidecar entries.

### 5.2 Registration handshake

On connect, the sidecar's first message is `register`
(§6a.1). It declares:

- `name` — adapter identifier, must be unique among connected
  sidecars.
- `version` — adapter version (informational; does not gate
  acceptance).
- `protocol_version` — the contract `major.minor` the sidecar speaks.
- `protocols` — list of protocol identifiers the sidecar provides.
- `capabilities` — see §5.3.
- `mutation_ops` — array of declared operations and their parameter
  schemas (when adapter declares ops beyond the shared set).
- `owned_rules` — rules the adapter wants merged into the central rule
  list for the lifetime of its registration; declaring any makes the
  adapter a rule provider (§5.3).
- `instance_id` — sidecar-supplied UUID stable across restarts when
  the sidecar wants to claim in-flight state on reconnect.

Sectool responds with:

- The effective `protocol_version` — its major, with minor capped at the
  sidecar's reported minor (§4.3).
- A snapshot of currently relevant rules (§6b.1) so the sidecar can
  pre-warm hot-path mutation filters.

### 5.3 Capabilities

A sidecar declares which of the following it wants. Each capability has
a parameter object scoping when it applies.

- **`early_claim`** — `{ port_range, tls?: { terminate, sni_match? },
  magic_bytes_prefix?, host_match?, probe?, probe_max_bytes? }`. Claim TCP
  connections matching the
  port range and optional matchers. When `tls` is absent the claim is on
  the raw stream and the sidecar receives bytes from the first byte the
  client sends. When `tls.terminate` is set, sectool MITMs TLS with the
  fake CA and the matchers — `sni_match` (server name from the
  ClientHello) and `magic_bytes_prefix` (first bytes of the decrypted
  stream) — evaluate against the terminated connection; the sidecar then
  receives the decrypted stream via `stream_open` + `stream_deliver`.
  When `probe` is set (for fully-binary protocols that no fixed
  `magic_bytes_prefix` can discriminate), sectool buffers up to
  `probe_max_bytes` of the opening stream and calls `claim_probe` (§6b.8)
  so the sidecar decides; the probe replaces `magic_bytes_prefix` as the
  discriminator on that claim. **Fallthrough:** a connection matching no
  sidecar claim (no prefix match, or every probe declined) falls back to
  the HTTP adapter (today's default), so enabling a claim — TLS-terminated
  or probe-based — on a port never silently drops HTTP traffic.
- **`upgrade_claim`** — `{ host_pattern, path_pattern, upgrade_signal,
  method_set? }`. `upgrade_signal` is one of `http_101` (after sectool
  emits `HTTP/101 Switching Protocols` in response to a matching HTTP
  request) or `connect` (after CONNECT is fully processed). Sectool
  captures the triggering HTTP request as a normal flow, synthesizes
  the upgrade response, and routes subsequent bytes to the sidecar.
- **`injection_target`** — `{ target_schema }`. Declares that the sidecar
  can originate new outbound messages, driven by a sidecar-registered tool
  (§9.2) or by another adapter via `invoke_adapter` (§6a.8). The schema
  describes which target parameters the sidecar accepts (e.g.,
  URL/host/port, tunnel ID, endpoint path, custom routing).
The three capabilities above are the only ones carrying parameters. Three
roles from earlier drafts are now **derived from the `register` payload,
not declared as capabilities**: a sidecar that declares any `mutation_ops`
(§6a.1) is a mutation provider; one that declares any `owned_rules` (§6a.1)
is a rule provider; and any sidecar may emit flows via `push_flow`.
Adapter-owned rules (`owned_rules`) are merged into sectool's central rule
list with `owner = adapter:<name>`, visible to agents but not deletable via
`proxy_rule_delete` (released when the adapter unregisters); they MAY target
any registered adapter, not only the declaring one (e.g., the Tailscale
sidecar's `/key` rule targets `adapter=http/1.1`), and every cross-adapter
rule is written to the audit log at registration with both the owning and
target adapter named. These rules are used for adapter-supplied rewrites
such as the Tailscale adapter's `/key` pubkey substitution.

`stream_takeover` (per-HTTP/2-stream claiming) is intentionally deferred
to a future version; it is unneeded for any v1 adapter and adds
implementation complexity. `response_intercept`, `post_connect_takeover`,
and `canned_response_provider` from earlier drafts are subsumed:
`response_intercept` and `canned_response_provider` are now adapter-owned
rules via `owned_rules`; `post_connect_takeover` is `upgrade_claim`
with `upgrade_signal=connect`.

#### 5.3.1 Capability precedence and conflict resolution

Capability conflicts between sidecars are resolved at **registration
time**, not at firing time. Sectool rejects a registration whose
capability claims conflict with already-registered sidecars; the
operator must adjust matchers or the set of running sidecars to resolve.
This makes runtime behavior deterministic and makes misconfiguration
loud rather than silent.

Per-capability rules:

- **`early_claim`** — port range claims must be disjoint across all
  registered sidecars (and disjoint from native-proxy-claimed ports).
  Within a single port range, only one sidecar may claim it unless the
  claims are distinguished by a non-overlapping matcher: `magic_bytes_prefix`
  prefixes that do not overlap as proper-prefix sets, or mutually-exclusive
  `sni_match` patterns. Mixing `tls.terminate` and raw claims on the same
  port range is rejected as ambiguous (sectool cannot both MITM and pass
  through the same bytes). **Probe-based claims are the deliberate
  exception to disjoint matchers:** multiple `probe` claims may share a
  port range, resolved at connection time as an ordered chain in
  registration order — sectool calls each `claim_probe` (§6b.8) in turn
  and the first to return `claim:true` wins, with fallthrough to the HTTP
  adapter if all decline. A static `magic_bytes_prefix` claim and a `probe`
  claim on the same port range are rejected as ambiguous (the static
  matcher would pre-empt the probe).
- **`upgrade_claim`** — most-specific matcher wins (literal host > glob
  > regex; literal path > glob > regex). Two registrations whose
  matchers are mutually-incomparable in specificity (e.g., one regex
  and one glob that overlap) are rejected as ambiguous; operator picks
  one or narrows the matchers.
- **`injection_target`** — scoped to the declaring adapter's own flows.
  No inter-sidecar conflict possible by construction.
- **Adapter-owned rules** (`owned_rules`) participate in the same label
  uniqueness check as user-owned rules. A label collision rejects the
  registration.

In every "rejected as ambiguous" case, the rejection error names both
registrations and the specific clash, so the operator can diagnose and
resolve.

### 5.4 Heartbeat

Bidirectional ping/pong on the connection:

- Sectool sends `ping` notification at a configurable interval
  (default 10 s).
- Sidecar replies with `pong`. Failure to receive a `pong` within a
  timeout (default 30 s) marks the sidecar unhealthy; new connections
  matching the sidecar's seams fall back to default behavior (forward
  without modification, or refuse if the sidecar's seam was
  load-bearing).

Sidecars may issue `ping` in the reverse direction; sectool replies
with `pong`. Used for adapter-driven liveness when the adapter
generates traffic in bursts.

### 5.5 Restart and reconnection

When a sidecar reconnects with the same `instance_id`:

- Sectool checks for in-flight flows owned by that sidecar.
- If the sidecar advertises `resume=true` in `register`, sectool
  reattaches metadata: flow ownership is restored for `sidecar_send`
  routing and for delegating its registered tools (§9.2).
- Protocol-level state (Noise session keys, TLS session, HTTP/2
  multiplex state) cannot be resumed across a sidecar restart —
  those live in the sidecar process and are lost on crash. Any active
  socket-takeover byte streams are closed; the sidecar starts fresh
  for new connections.
- If `resume=false` (default), the sidecar starts fresh.

When `instance_id` differs, the new sidecar is treated as a distinct
instance; the old instance's flows are closed.

---

## 6. API surface — method by method

All methods are JSON-RPC 2.0 calls. Parameters are JSON objects unless
noted. Return values are JSON objects. Error responses use the standard
JSON-RPC error structure with negative numeric codes defined in an
appendix to this document (out of scope for this section).

### 6a. Sidecar → sectool

#### 6a.1 `register`

Issued exactly once at the start of the connection.

**Params**:

- `name` (string, required) — adapter identifier.
- `version` (string, optional) — informational.
- `protocol_version` (object, required) — `{major, minor}` integers
  (§4.3).
- `protocols` (array of string, required) — protocol identifiers.
- `capabilities` (object, required) — keyed by capability name, value
  is the parameter object for that capability.
- `mutation_ops` (array, optional) — each entry `{name, params_schema,
  applies_to: [protocol_tag...]}`. Declaring any op makes the adapter a
  mutation provider (§5.3); this array is the authoritative declaration of
  the adapter's ops.
- `owned_rules` (array, optional) — rules to merge into the central rule
  list with `owner=adapter:<name>`. Declaring any rule makes the adapter a
  rule provider (§5.3); this array is the authoritative declaration of the
  adapter's rules.
- `mcp_tools` (array, optional) — MCP tool definitions the sidecar
  provides, each `{name, description, input_schema, annotations?}`.
  Sectool exposes these to MCP clients and delegates their invocation to
  this sidecar via `invoke_tool` (§6b.7). See §9.2.
- `instance_id` (string, optional) — UUID stable across restarts.
- `resume` (boolean, optional) — see §5.5.

**Returns**:

- `protocol_version` (object) — `{major, minor}` effective (§4.3).
- `assigned_seams` (array) — which capability claims were accepted.
- `rules_snapshot` (array of rule objects) — currently active rules
  relevant to this adapter (§6b.1).
- `server_time` (string, RFC3339Nano) — for clock-skew detection.

#### 6a.2 `push_flow`

Emit a single captured exchange (request and/or response side per §3.1).

**Params**: a Flow object (§3.1) carrying a `request` and/or `response`
side. `flow_id` left empty on first emission; sectool assigns. The
sidecar provides the populated side(s) (`method`, `path`, `headers`,
`body`, and `status` on the response side), plus `direction`,
`protocol_tag`, optionally `parent_flow_id`,
`started_at` / `completed_at`, `annotations`. When the wire form is not
natively decodable by sectool (§3.1), the sidecar also supplies
`body_raw` and `body_codec` so unmutated replay can resend verbatim and
mutated replay can re-encode.

**Session / tunnel envelopes** are emitted the same way — there is no
separate method. The sidecar pushes a one-time `direction=bidirectional`
Flow carrying the handshake metadata in `headers` (shape per §3.2),
usually with no body; the returned `flow_id` is the grouping key inner
flows set as their `parent_flow_id`. When the session tears down the
sidecar re-emits the envelope via the two-phase form below (same
`flow_id`, `completed_at` set) to record the close.

**Streams** (server-streaming, WebSocket, MQTT, MapResponse) are emitted
the same way too — also no separate method. A parent `push_flow` opens
the stream (its `flow_id` is the stream id); each chunk or message is a
child `push_flow` with `parent_flow_id` set to it and `direction` set;
the parent is re-emitted (two-phase) to close. Children are stored and
replayed in emission order — sectool never reorders, so there is no
sequence number. See §3.3 for the full model and worked shape.

**Two-phase completion**: a flow may be emitted incrementally — the
`request` side first (sectool returns a `flow_id`), with the `response`
side attached later by re-invoking `push_flow` with `flow_id` set to that
id and the `response` side populated. This is required for streaming and
other cases where the response is not available when the request must be
recorded or forwarded (and for the session-envelope close above). The
native HTTP adapter records request-then-response the same way.

**Returns**: `{flow_id}`.

#### 6a.3 `log`

Emit a structured log line for diagnostics.

**Params**: `{level, message, fields}` where `fields` is an
open-ended JSON object.

**Returns**: none (notification).

#### 6a.4 `report_metrics`

Emit counters / gauges.

**Params**: `{counters: {name: int}, gauges: {name: number}}`.

**Returns**: none (notification).

#### 6a.5 `ping` / `pong`

Heartbeat (§5.4). Notifications, no return.

#### 6a.6 `dial_upstream`

Request that sectool open a TCP connection to an upstream host on the
sidecar's behalf and exchange bytes with the resulting socket as a stream
(via `stream_deliver` events and Response `writes`, §4.2).

**Params**:

- `host` (string, optional) — destination host. When omitted, sectool
  dials the original destination of the connection associated with
  `parent_flow_id`. Required only when `parent_flow_id` is absent; supplying
  it overrides (redirect to a different upstream).
- `port` (integer, optional) — destination port. Same default and
  requirement as `host`.
- `tls` (object, optional) — `{enabled: bool, sni?: string,
  alpn?: [string], skip_verify?: bool}`. When `enabled`, sectool
  performs TLS termination toward the upstream and bridges cleartext
  bytes to the sidecar.
- `parent_flow_id` (string, optional) — associate the dial with an
  emitted tunnel envelope or originating flow; used for audit and, when
  `host`/`port` are omitted, to supply the default upstream destination
  (the original destination of that flow's connection).

**Returns**:

- `{stream_id}` — stream identifier; bytes flow via `stream_deliver` events and
  Response `writes` (§4.2).
- Or a JSON-RPC error if the dial is rejected by scope policy
  (`allowed_domains` / `exclude_domains`), refused by the network, or
  fails TLS.

The resulting flow is recorded as a `dial_upstream`-tagged annotation
on `parent_flow_id` when supplied; sectool surfaces all such dials in
history for audit.

#### 6a.7 `close_stream`

Notification (no reply). Sidecar closes a stream (client-facing or an
upstream dialed via §6a.6). This is the one proactive output a sidecar
may emit outside an event Response.

**Params**: `{stream_id, reason}`.

#### 6a.8 `invoke_adapter`

Request that sectool route an outbound message through another
registered adapter's `injection_target` — the same path a
sidecar-registered injection tool uses (§9.2), letting a sidecar drive a
sibling adapter, e.g., the Tailscale sidecar's upstream `/key` fetch via
the HTTP adapter.

**Params**:

- `adapter` (string, required) — destination adapter name; must have
  declared `injection_target`.
- `target` (object, required) — validated against the destination
  adapter's `injection_target.target_schema`.
- `payload` (object, required) — validated against the same schema.
- `mutations` (array, optional) — operations applied to the payload
  before send, per §3.4.
- `wait_for_response` (boolean, optional, default true) — when true,
  blocks until the destination flow completes; the response form is
  returned alongside `new_flow_ids`.

**Returns**: `{new_flow_ids, response?}`.

Every `invoke_adapter` call is recorded in history with the caller
sidecar attributed in `annotations.invoked_by`. Scope policy
(`allowed_domains` / `exclude_domains`) and the destination adapter's
own validation apply exactly as for agent-driven injection.

#### 6a.9 `core_query`

Read sectool's own state and read-side core tools, so a sidecar can
inspect captured traffic, the active rule list, and other history while
implementing its registered tools (§9.2) or its hot-path logic.

**Params**:

- `tool` (string, required) — a read-side core tool name (`proxy_poll`,
  `flow_get`, `proxy_rule_list`, `cookie_jar`, `diff_flow`,
  `find_reflected`, `notes_list`, `oast_poll`, …).
- `params` (object, required) — that tool's parameters.

**Returns**: the tool's normal result. `core_query` is read/inspection
only; a sidecar effects changes by emitting flows, by applying the rules
sectool pushes via `sync_rules` (§6b.1), or through its registered tools
(§9.2). It does not grant write access to another adapter's flows.

### 6b. Sectool → sidecar

#### 6b.1 `sync_rules`

Push the full ordered rule list to the sidecar. The sidecar is the only
party that applies protocol-specific mutations (since only it knows how
to mutate adapter-specific bytes), so sectool sends the authoritative
list and the sidecar replaces its local cache atomically. This matches
the native HTTP backend's RWMutex-protected slice model: the central
side owns ordering, the applying side iterates under a read lock.

**Params**:

- `snapshot_version` (uint64, required) — monotonic version counter
  incremented by sectool on every rule list change. Strictly
  increases.
- `rules` (array of Rule objects, required) — the full ordered rule
  list as the sidecar should apply it, in the order rules must fire.
  Rules whose `adapter` field does not name this sidecar (or `*`) may
  be omitted by sectool as an optimization. Adapter-owned rules
  (`owner = adapter:<name>`) belonging to this sidecar are always
  included.

**Returns**: `{ack: true, applied_version}` where `applied_version`
equals the `snapshot_version` from params on success; or an error if
the sidecar cannot honor a rule shape (the error names the offending
rule_id and the sidecar continues running with its previously-applied
version). This ack is sectool's authoritative confirmation of which
snapshot each sidecar has applied — sectool knows at push time whether a
sidecar accepted the latest rules, so no per-emission version bookkeeping
is needed on the flow stream.

**Semantics**:

- The sidecar replaces its local rule cache wholesale on each call.
- Rule application order on the sidecar follows the array order
  received; the sidecar does not reorder.
- Adds, edits, and deletes all result in a full re-push with an
  incremented `snapshot_version`. v1 explicitly does not optimize
  this — local deployment makes the bandwidth cost irrelevant.

#### 6b.2 `sidecar_send`

This is the internal sectool→sidecar method behind the agent-facing
`replay_send` and `request_send` MCP tools, and the destination side of
`invoke_adapter` (§6a.8). With `flow_id` set it replays that captured flow
with mutations applied (`replay_send`); with `flow_id` omitted it
originates a fresh outbound message from `target` / `payload`
(`request_send`). Agents never call `sidecar_send` directly; sectool
routes the invocation to the owning adapter via this method.

Replay (`flow_id` present) routes to a
**destination adapter** keyed by the source flow's `adapter` field
(§3.1) — by default the adapter that emitted the flow, since it recorded
which adapter handled the original. `target_override` may name a
**different** destination adapter, which must be able to encode the source
flow's `protocol_tag`. (This is what cross-adapter replay needs — e.g., a
flow captured on a server-side adapter replayed through a client-side MITM
adapter.) For an in-process HTTP flow the destination is the HTTP adapter,
handled natively; for a sidecar-owned flow it is the owning sidecar.

The captured flow's `body` is the plaintext logical form (already
decrypted, decompressed, and de-framed by the originating adapter). On
replay the destination adapter re-applies any cryptographic wrapping,
compression, and framing at the wire — sectool does not carry
adapter-specific encryption state across the replay boundary. Replay
sends `body_raw` (§3.1) verbatim when no body mutation is requested; when
a mutation changes the logical `body`, the owning adapter re-encodes it
through the declared `body_codec` before re-wrapping. Where a protocol
cryptographically binds fields (e.g. a request signature), re-establishing
the binding is likewise the owning adapter's concern: it re-signs when the
required key material is part of its connection-time configuration and
otherwise strips the bound fields, surfacing any such outcome through the
flow's `annotations` (§3.1). sectool models nothing about these bindings;
on the forward (proxy) path a rule that mutates a bound field is forwarded
as-is, so adversarial broken-binding testing is the proxy path's job.

For stateful-transport adapters (e.g., tunnels), whether a replay reuses
a live transport or establishes a fresh one is the adapter's own
decision, made from the source flow's `parent_flow_id` (the session/tunnel
envelope it nests under) and the adapter's
connection-time configuration; sectool does not model transport lifecycle
across replay and exposes no core parameter for it. Identity selection
(e.g. which machine key a tunnelling adapter replays as) is likewise the
adapter's connection-time configuration, not a replay parameter. Egress
still flows through `dial_upstream`, so scope policy applies.

**Params**:

- `flow_id` (string, optional) — source flow to replay. Omit to originate
  a fresh message, in which case `target` / `payload` supply it.
- `target` (object, optional) — for the originate case, validated against
  the adapter's `injection_target.target_schema` (§5.3); names where/what
  to send. Examples: HTTP `{url, method, headers, body, follow_redirects}`;
  session-oriented `{flow_id, endpoint, body, stream}` where its `flow_id`
  references an existing session/tunnel envelope (§3.2) whose transport the
  injection reuses (the Tailscale adapter calls this `tunnel_id`).
- `payload` (object, optional) — adapter-typed message content for the
  originate case, validated against the same schema.
- `mutations` (array, required) — ordered list of mutation operations
  (shared or adapter-declared) per §3.4, applied to the replayed or
  originated message as given. The owning adapter re-establishes any
  cryptographic binding automatically (see above); there is no core
  auto-prepend step.
- `target_override` (object, optional) — override of **destination
  routing only**: a different `scheme://host:port`, and/or a different
  destination adapter for cross-adapter replay (which must be able to
  encode the source flow's `protocol_tag`). It does not carry identity or
  other protocol-replay parameters — those are the destination adapter's
  connection-time configuration.
- `follow_redirects` (boolean, optional, HTTP-adapter-specific).
- `force` (boolean, optional) — skip adapter-side validation (e.g. for
  protocol-level tests).
- `wait_for_response` (boolean, optional, default true) — when true, blocks
  until the produced flow completes so the response form is returned
  alongside `new_flow_ids` (used by `invoke_adapter`, §6a.8).
- `stream_strategy` (string, optional, applies to stream flows) —
  `per_chunk` (default) replays the child flows in stored (emission)
  order; `collapsed` merges them into a single replay. The destination
  adapter rejects `collapsed` when its protocol forbids reordering/merging.

**Returns**: `{new_flow_ids, writes?, response?}` — the new flow(s)
produced by the replay or origination (may be multiple for streamed
replay), the optional `writes` array (§4.2) carrying the first outbound
bytes, and `response?` (the completed response form) when
`wait_for_response` was set.

#### 6b.3 `shutdown`

Request a graceful close of the sidecar.

**Params**: `{drain_seconds}`.

**Returns**: `{ack: true}`. The sidecar finishes in-flight work,
emits a final `report_metrics`, and closes the connection.

#### 6b.4 `stream_open`

Request (reply expected). Sectool tells the sidecar that one of its claims
fired and a new stream exists, so the sidecar can set up per-stream state.

**Params**: `{stream_id, host, path, matched_claim, peer_addr}`.

**Returns**: `{writes?}` — the standard optional `writes` array (§4.2);
usually empty, since the claimed (client-facing) side speaks first.

#### 6b.5 `stream_deliver`

Request (reply expected). Sectool delivers inbound bytes it read from a
stream's socket (client-side bytes for `upgrade_claim` / `early_claim`,
upstream-side bytes for a stream returned by `dial_upstream`).

**Params**: `{stream_id, data}` — `data` base64-encoded.

**Returns**: `{writes?}` — the optional `writes` array (§4.2) for sectool
to write to the named socket(s). While handling, the sidecar may emit
`push_flow` and issue nested `dial_upstream` / `core_query`
calls.

#### 6b.6 `stream_ended`

Notification (no reply). Sectool tells the sidecar a stream closed (peer
disconnected, scope policy invalidated mid-stream, sectool shutting down).
The sidecar reacts by issuing `close_stream` (§6a.7) on any paired stream.

**Params**: `{stream_id, reason}`.

#### 6b.7 `invoke_tool`

Delegate an MCP client's invocation of a sidecar-registered tool (§9.2)
to the owning sidecar.

**Params**:

- `name` (string, required) — the registered tool name.
- `arguments` (object, required) — the client-supplied arguments,
  validated by sectool against the tool's declared `input_schema` before
  delegation.

**Returns**: `{content}` — the tool result (markdown text and/or
structured content) returned verbatim to the MCP client. While handling
the call the sidecar may emit flows (`push_flow`, etc.) and read sectool
state (`core_query`, §6a.9).

#### 6b.8 `claim_probe`

Request (reply expected). Sent only for an `early_claim` that set `probe`
(§5.3). When a connection arrives on the claim's port range, sectool
buffers up to `probe_max_bytes` of the opening stream (the decrypted
stream when the claim also set `tls.terminate`) and asks the sidecar
whether the connection is its protocol, before opening a `stream_open`.

**Params**:

- `host` (string) — destination host (SNI or connect target when known).
- `port` (integer) — destination port.
- `peer_addr` (string) — client socket address.
- `sni` (string, optional) — server name from the ClientHello when TLS
  was terminated.
- `data` (string, base64) — the buffered opening bytes.

**Returns**: `{claim}` — `claim` boolean. `true` takes the connection:
sectool follows with `stream_open` and replays the buffered bytes as the
first `stream_deliver`. `false` declines: sectool tries the next probe claim on
the range in registration order (§5.3.1), falling through to the HTTP
adapter if all decline. A decline is normal control flow, not an error.

---

## 7. Forwarding model

Sidecars capture-and-forward without per-message coordination. A sidecar
emits flows via `push_flow` (a parent flow plus child flows for streams,
§3.3) and the message proceeds; there is no interactive
per-message decision step and nothing blocks a live connection while an
agent reasons.

Mutations are applied by the sidecar on the hot path from the
authoritative rule list sectool pushes via `sync_rules` (§6b.1) — the
sidecar applies them locally with no round-trip, exactly as the native
HTTP backend applies match/replace rules inline. Emissions on different
streams or flow_ids are independent. Agents test by capturing passively,
mutating via rules, and iterating with `replay_send`.

---

## 8. Feature parity with current sectool capabilities

Every current sectool MCP tool and CLI capability is preserved. This
section maps each to its post-refactor representation.

| Current capability | Post-refactor representation |
|---|---|
| `proxy_poll` (host, path, method, status, search_header, search_body, since, exclude_host, exclude_path, limit, offset, summary/flows modes) | Unchanged tool surface. Results include flows from any adapter. Filter expressions add `adapter`, `protocol_tag`, `parent_flow_id` as filterable fields. Host/path filters apply to the HTTP-shaped Flow's `path` and `headers["Host"]` fields, which every adapter populates. |
| `flow_get` (request, response, request_headers, response_headers, request_body, response_body, all; pattern regex) | Unchanged. Scopes resolve against the Flow's `method`/`path`/`headers`/`body` fields, which every adapter populates. |
| `proxy_rule_list` (type_filter http/websocket/all, limit) | Unchanged. `type_filter` accepts adapter names; `all` returns rules across all adapters. Adapter-owned rules are shown with `owner=adapter:<name>`. |
| `proxy_rule_add` (type, find, replace, label, is_regex) | Unchanged for the existing 7 type values; under the hood, each maps to the §3.5 tuple form with `owner=user`. New form accepts `adapter`, `message_type`, `op`, `params` for adapter-typed operations. Label uniqueness preserved across the entire rule list. |
| `proxy_rule_delete` (rule_id or label) | Unchanged. Adapter-owned rules cannot be deleted via this tool — the error names the owning adapter and instructs the operator to unregister the sidecar to remove them. |
| `cookie_jar` (detail mode, name/domain filters, JWT decode) | HTTP-adapter-specific tool, unchanged shape. Cookies extracted only from flows whose adapter declares HTTP semantics. |
| `_internal_history_delete` | Unchanged; respects notes references regardless of adapter. |
| `proxy_respond_add` / `proxy_respond_delete` / `proxy_respond_list` | Implemented as adapter-owned rules with `op=set_body` / `set_header` scoped by host + path. The HTTP adapter retains the current matcher schema; the same tool surface continues to work and writes user-owned rules with the responder semantics. |
| `replay_send` (full mutation grammar: set_headers, remove_headers, set_json, remove_json, set_form, remove_form, set_query, remove_query, method, body, target, path, follow_redirects, force) | Unchanged tool surface. Each parameter is translated to a §3.4 typed operation and validated against the flow's adapter `mutation_ops`. For HTTP adapter flows, the existing parameter set is supported identically. For non-HTTP flows, mutations the adapter does not declare return a validation error unless `force=true`. The mutation execution order documented in `mcp_replay.go` (remove → set → set_json/remove_json → set_form/remove_form → remove_query → set_query → body → compression) is preserved for HTTP and is that in-process adapter's convention, not a universal cross-adapter guarantee (§3.4); each adapter orders its own ops and runs rebind/finalizer ops last. The owning adapter re-establishes any cryptographic binding automatically per its connection-time configuration (§6b.2); there is no core auto-prepend step. |
| `request_send` (url, method, headers, body, follow_redirects, force) | Routed via `sidecar_send` with no base flow (§6b.2). Surface unchanged. |
| `diff_flow` (text/JSON/binary modes, max_diff_lines) | Operates on `headers` and `body` of both flows. JSON and text modes detect from Content-Type; binary mode is the default for unrecognized content. |
| `find_reflected` (variants: url_query, url_path, html_entity, js_unicode, js_hex, html_decimal, html_hex) | Generalized. Default behavior unchanged for HTTP flows. For any pair of flows on the same adapter (or sharing a `parent_flow_id`), the tool searches request-side parameters reflected in response-side body. Variant encodings remain HTTP-specific; per-adapter encoding variants may be added. |
| `oast_*` tools | Unchanged. OAST events are independent of adapters; cross-references continue to attach to flow IDs regardless of which adapter produced the flow. |
| `crawl_*` tools | Unchanged. The crawler is an HTTP-adapter-bound feature; it produces flows tagged with the HTTP adapter name. `crawl_create` `seed_flows` accepts only HTTP flows; this is enforced at parameter validation. |
| `notes_save` / `notes_list` (free-form type, flow_ids array, contains substring, after_id, limit) | Unchanged. Notes attach to any flow regardless of adapter. |
| `workflow` (explore, test-report, cli) | Unchanged. Instruction templates per task are extended to mention any sidecar-registered tools (§9) present in the session. |
| `encode` / `decode` / `hash` / `jwt_decode` / `uuid_generate` | Fully unchanged. |
| `MCP transport` (`/mcp` streamable HTTP, `/sse` legacy) | Unchanged. The bidirectional needs of the sidecar contract live on the local IPC connection, not the agent-facing MCP transport. Agents continue to poll. |
| `storage / spill / encryption` | Unchanged. The Flow type replaces HistoryEntry as the on-disk representation with a versioned migration (lazy rewrite on access, §3.1.1). SpillStore behavior is preserved. |
| `Burp backend` | Unchanged. Lives one level above the adapter registry. When Burp is selected as the top-level backend, the adapter registry is not consulted; sectool delegates capture to the Burp MCP. Custom-protocol sidecars are only available under the native top-level backend. |

---

## 9. MCP tool surface

### 9.1 No change without a sidecar

When no sidecar is connected, the MCP tool surface and its behavior are
**identical to today's**. Sectool adds **no** default, global, or
always-on tools, and existing tools (`proxy_poll`, `flow_get`,
`replay_send`, `proxy_rule_add`, …) behave exactly as they do now. The
generalized rule/replay forms that target adapter-owned flows (§3.4–§3.5)
are inert without a sidecar to own such flows. Everything in §9.2–§9.3 is
contingent on a connected sidecar.

When a sidecar is connected, existing core tools also operate on its
flows without changing their schema: `replay_send` and rules that target
a sidecar-owned flow are routed to the owning adapter internally (§6b.1,
§6b.2), and the shared op set (§3.4) works because the adapter re-encodes
the logical body to the wire (§3.1, §6b.2). Operations a protocol needs
beyond the shared set are exposed as sidecar-registered tools (§9.2), not
as new parameters on core tools.

### 9.2 Sidecar-registered tools

A sidecar declares the tools it provides in the `mcp_tools` field of
`register` (§6a.1). Each entry is a complete MCP tool definition —
`{name, description, input_schema}` (JSON Schema) plus an optional
`annotations` hint. Because sidecars connect and register before any MCP
client session begins (§5.1), sectool composes the full tool list — core
tools plus every connected sidecar's `mcp_tools` — at the time the MCP
client connects; no dynamic mid-session tool registration is required.

When an MCP client invokes a sidecar-registered tool, sectool validates
the arguments against the declared `input_schema`, delegates the call to
the owning sidecar via `invoke_tool` (§6b.7), and returns the sidecar's
result to the client unchanged. The sidecar — not sectool — owns the
tool's behavior, so protocol-specific tools are designed for the protocol
under test (e.g., a Tailscale sidecar might register
`ts_inject_map_response` or `ts_resign_register`). Tool names are
namespaced by the sidecar; a name that collides with a core tool or
another sidecar's tool is rejected at registration, naming both owners.

A sidecar handling a delegated call has full read access to sectool state
through `core_query` (§6a.9): it can list the active proxy rules, query
proxy history, fetch any flow, diff flows, and run the other read-side
core tools, so its implementations can inspect and build on captured
traffic and protocol-specific state. The rules a sidecar applies on the
hot path come from the authoritative list sectool pushes via `sync_rules`
(§6b.1); `core_query` lets it read that same state on demand.

### 9.3 Discoverability

Sidecar-registered tools appear in the standard MCP `tools/list` like any
core tool, each carrying its own `description` and `input_schema`, so
agents discover them through the normal MCP mechanism with no
sectool-specific introspection tool. Per-flow `adapter` / `protocol_tag`
identify which adapter produced each flow, so no global
adapter-enumeration tool is required in v1.

---

## 10. Phased refactor

### Phase 0 — contract design (paper only)

- Finalize the §3 data model, §4 wire protocol, §5 capability set,
  §6 method surface, §7 forwarding model.
- Validate by sketching, on paper, how the HTTP/1.1, HTTP/2, and
  WebSocket adapters express in the contract.
- Validate by sketching at least one concrete out-of-process adapter
  expression in a companion spec document (the Tailscale adapter spec
  is the first such companion).
- Fix any distortion before writing code.

### Phase 1 — internalize

- Refactor `sectool/service/proxy/handler_http1.go`, `handler_http2.go`,
  `handler_websocket.go` into in-process adapter implementations.
- Replace `HistoryEntry` with `Flow` throughout the proxy package and
  the store. Implement lazy v0→v1 migration in the spill store.
- Generalize the rules engine to the tuple form. Convert existing
  rule storage in place; introduce the `owner` field.
- Split MCP tools into a generic core and adapter-typed extensions.
  Preserve all existing agent-visible parameter shapes.
- All existing tests pass unchanged.

### Phase 2 — out-of-process binding

- Add the local socket listener (Unix domain socket on unix / Windows
  loopback TCP, build-guarded), length-prefixed framing, JSON-RPC 2.0
  dispatch, and the synchronous event model (`stream_open` / `stream_deliver` /
  Response `writes`, `close_stream` / `stream_ended`).
- Add registration handshake, capability dispatch (early_claim including
  the `probe` / `claim_probe` path, upgrade_claim, injection_target;
  mutation-op and owned-rule registration; flow emission), heartbeat,
  cancel/shutdown.
- Add `dial_upstream` mediation with scope-policy enforcement.
- Add sidecar tool registration and delegation (`mcp_tools` in
  `register`, `invoke_tool`, `core_query`); add no default MCP tools —
  the surface is unchanged when no sidecar is connected.
- Ship a trivial echo external adapter as a test fixture (it
  registers, declares one protocol, claims TCP, echoes bytes).

### Phase 3 — protocol-specific adapters

- Built outside this specification, but the contract is now complete.
  Companion specifications describe individual adapters (the Tailscale
  adapter is the first such consumer).

---

## 11. Security considerations

- **Local socket trust model, OS-guarded on unix.** There is no
  application-layer token. On unix-like OSes the single connection is a
  Unix domain socket (containing dir `0700`, socket `0600`) reachable only
  by the local user sectool runs as. On Windows it is a loopback TCP socket
  (§4.1) reachable by any local process, so trust rests entirely on the
  secured-local-host assumption. Either way that assumption is a
  precondition — the same one underlying sectool's fake-CA private key and
  captured-traffic store — so a shared secret would add ceremony without
  adding meaningful security. (A Windows named pipe could add an
  OS-enforced ACL later if a Windows-hosted sidecar ever ships; v1's only
  sidecar is Linux-only.)
- **No remote sidecars in v1.** Both transports bind local-only
  (`127.0.0.1` on Windows); cross-host sidecars are out of scope. Future
  versions may add TLS-authenticated remote registration with explicit
  operator approval per peer.
- **No socket FD passing.** Sectool never passes OS file descriptors
  to sidecars. Bytes flow over the local IPC connection only as encoded
  JSON-RPC fields. This keeps the contract portable across Linux, macOS,
  and Windows without per-platform plumbing.
- **Upstream egress is mediated.** Every sidecar-originated upstream
  connection goes through `dial_upstream` (§6a.6). Sectool applies
  the same `allowed_domains` / `exclude_domains` scope policy used
  for proxied traffic and records every dial in history. Sidecars
  cannot bypass scope policy by dialing directly because they never
  see OS sockets.
- **Sidecar identity in flow metadata.** Every flow records the
  sidecar that emitted it, including version and instance_id. Agents
  and humans can attribute every capture and every mutation.
- **Mutation audit via paired flows.** The sidecar is the only party
  that applies protocol-specific mutations. Audit trail is built by
  the sidecar emitting **two flows per mutated message**:
  - Phase `captured` — the pre-mutation form, exactly as observed on
    the wire. `annotations.phase = "captured"`.
  - Phase `mutated` — the post-mutation form actually sent.
    `annotations.phase = "mutated"`, `annotations.fired_rules =
    [rule_id...]`, `annotations.parent_flow_id` set to the
    `captured` flow's id.
  Both flows land in the unified history; agents review both via
  `flow_get` and `diff_flow`. This mirrors the Burp backend pattern
  and the native backend's request-then-response recording. The same
  pairing applies to stream children: a mutated chunk is emitted as a
  second child `push_flow`. Its structural `parent_flow_id` still points
  at the stream parent (preserving order), while
  `annotations.parent_flow_id` points at the `captured` child's flow_id
  to link the pair — the same fields used for any captured/mutated pair.
- **Adapter-declared mutations are advisory.** Sectool validates
  rule shape against the adapter's declared `mutation_ops` schema
  before pushing the rule list via `sync_rules`; a sidecar cannot
  expand its declared op set at runtime to perform unexpected
  mutations. When a sidecar reports an op it did not declare in
  `fired_rules`, sectool logs a warning and surfaces the divergence
  to the agent.
- **Adapter-owned rules cannot be added at runtime.** A sidecar's
  `owned_rules` are fixed at registration; expanding them requires
  re-registration. This prevents a compromised sidecar from quietly
  injecting new rewrite rules after the operator inspected the
  registration.
- **No execution of arbitrary code from sidecar metadata.** Schemas
  registered by sidecars are descriptive only; sectool does not eval
  or load code based on registration payload.
- **Process isolation.** Managed sidecars run as separate processes;
  a crashing sidecar cannot corrupt sectool's history store.
  Operator-attached sidecars run under whatever identity the operator
  chooses, including with elevated privileges if the protocol
  requires (rare; should be avoided).
- **TLS MITM is unchanged.** The existing fake-CA mechanism remains
  the only way sectool decrypts TLS. Sidecars do not receive raw CA
  private keys; if a sidecar needs to perform its own decryption
  (e.g., a non-TLS encrypted protocol like Noise), it carries its
  own key material independently. A `tls.terminate` early-claim (§5.3)
  does not change this: sectool terminates TLS and hands the sidecar the
  decrypted byte stream over the IPC connection, while the CA private
  key never leaves sectool.

---

## 12. Appendix: error codes

Standard JSON-RPC 2.0 error codes apply. Sectool-specific errors use
the reserved range `-33000` to `-33999`:

- `-33000` to `-33099` — registration and lifecycle: registration
  rejected, **major version mismatch** (§4.3), unknown adapter,
  capability conflict, duplicate registration.
- `-33100` to `-33199` — mutation and rule: validation failure,
  unknown op, op not applicable to flow's `protocol_tag`,
  adapter-owned-rule deletion attempt, snapshot version mismatch.
- `-33200` to `-33299` — transport: framing violation, oversized
  message, unknown `stream_id`, `claim_probe` fault (a probe that errors
  rather than returning `{claim}`). A `claim_probe` returning
  `{claim:false}` is normal control flow, not an error.
- `-33300` to `-33399` — `dial_upstream`: scope rejection, dial
  failure, TLS handshake failure.
- `-33400` to `-33499` — `invoke_adapter`: unknown destination
  adapter, missing `injection_target`, target/payload schema
  mismatch.

Each error's `data` field carries the adapter name and any relevant
identifiers (`flow_id`, `rule_id`, `stream_id`, `snapshot_version`)
to aid diagnosis.
