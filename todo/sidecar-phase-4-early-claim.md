# Sidecar Phase 4 — Connection interception (early_claim) & byte-stream model

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 2** (registration + the RPC connection). The byte-stream event model
built here is the substrate for **Phase 5** (`dial_upstream`) and **Phase 6**
(`upgrade_claim`), so it precedes both.

## Goal

Let a sidecar intercept connections from the first byte. sectool owns the socket;
when a sidecar's `early_claim` fires, sectool streams the connection's bytes to the
sidecar as events and writes the sidecar's responses back to the socket. This phase
implements the full byte-stream event model and the simplest claim (accept-time), and
proves it end-to-end with an echo sidecar. It is the first validation of the wire
**byte path** (Phase 3 validated the flow path).

## Background & assumed state

After Phase 2, capabilities are declared and conflict-checked at registration but
never fire. Phase 1 made connection dispatch go through the adapter registry; the
out-of-process bridge is registered as an adapter. This phase wires the registry's
claim decision to the out-of-process path and adds the byte-transport event model.

The spec's hosting model (§2.1, §2.3): sectool opens and owns every socket; sidecars
never receive file descriptors and never open listeners — they receive byte streams
over the RPC channel. Routing is decided **per connection** (§2.3): at TCP accept the
claim matcher selects the owning adapter; a connection matching no claim falls through
to the HTTP adapter (today's default), so enabling a claim never silently drops HTTP.

`early_claim` (§5.3) parameters: `{ port_range, tls?: { terminate, sni_match? },
magic_bytes_prefix?, host_match?, probe?, probe_max_bytes? }`. With `tls` absent the
sidecar gets the raw stream from the first client byte. With `tls.terminate` set,
sectool MITMs TLS with the fake CA and the sidecar receives the **decrypted** stream
(the CA key never leaves sectool, §10). When a fixed prefix cannot discriminate the
protocol, `probe` buffers up to `probe_max_bytes` and asks the sidecar to decide via
`claim_probe` (§6b.8).

The synchronous, sectool-driven event model (§4.2): each event is a Request from
sectool; the sidecar's Response may carry a `writes` array `[{stream_id, data}]`
(base64) of bytes for sectool to write — possibly to a *different* `stream_id` than
the event arrived on. `stream_deliver` carries raw transport chunks **not aligned to
protocol frame boundaries**: reassembly is the sidecar's responsibility (it buffers
until it holds a complete frame). sectool processes a stream's events in order — it
awaits each Response before delivering that stream's next chunk. Two proactive
outputs exist outside event Responses: `close_stream` (§6a.7) and `stream_write`
(§6a.10, for keepalives/timer-driven output only).

## Spec references

- §2.1 Hosting model, §2.3 Connection lifecycle and handoff seams (early-claim seam).
- §5.3 Capabilities (`early_claim`), §5.3.1 (port-range disjointness; probe-chain
  exception), §5.5 (active byte-streams closed on sidecar death).
- §4.2 Framing and message model (events, `writes`, ordering, reassembly).
- §6b.4 `stream_open`, §6b.5 `stream_deliver`, §6b.6 `stream_ended`,
  §6a.7 `close_stream`, §6a.10 `stream_write`, §6b.8 `claim_probe`.

## Scope — toolbox (server side)

- **Fire `early_claim`:** at TCP accept, evaluate registered `early_claim` matchers —
  `port_range`, `magic_bytes_prefix`, `host_match`, and `sni_match`/`magic_bytes` on
  the decrypted stream when `tls.terminate` is set. First match wins; no match falls
  through to the HTTP adapter. Extend the Phase 1 accept-time byte sniff in
  `proxy/server.go` to drive this.
- **TLS-terminating claims:** when a matched claim sets `tls.terminate`, MITM TLS with
  the existing fake CA, evaluate matchers against the decrypted ClientHello/stream, and
  hand the sidecar the decrypted bytes. CA private key stays in sectool.
- **Byte-stream event model:**
  - `stream_open` (§6b.4): notify the sidecar a claim fired with
    `{stream_id, host, path, matched_claim, peer_addr}`; accept an optional `writes`
    reply.
  - `stream_deliver` (§6b.5): deliver inbound socket bytes `{stream_id, data}`; apply
    the Response's `writes` to the named socket(s); preserve per-stream ordering by
    awaiting each Response before delivering the next chunk.
  - `stream_ended` (§6b.6): notify on close (peer disconnect, scope invalidation,
    shutdown, **owning-sidecar death/unhealthy**).
  - `close_stream` (§6a.7): sidecar-initiated proactive close.
  - `stream_write` (§6a.10): sidecar-initiated proactive write (keepalives/timer
    output); a write to an unknown `stream_id` is a transport error (§11).
- **Probe path** (`claim_probe`, §6b.8): for a claim with `probe`, buffer up to
  `probe_max_bytes` and call the sidecar's `claim_probe` with the buffered bytes;
  `{claim:true}` takes the connection (replay buffered bytes as the first
  `stream_deliver`), `{claim:false}` tries the next probe claim in registration order,
  falling through to HTTP if all decline (a decline is normal control flow, not an
  error). *(If this sub-feature makes the phase too large, split it as Phase 4b.)*
- Stay in the connection-bookkeeping path for every claimed stream (host, port, TLS
  chain, IP, timing) and apply connection-level scope policy at accept (§2.3).
- **Active-stream teardown on sidecar death** (§5.5): when the owning sidecar becomes
  unhealthy or disconnects (detected by the Phase 2 heartbeat / connection loss), tear
  down its in-flight byte-streams — close both the client-facing socket and any
  upstream socket dialed for it (Phase 5) — and emit `stream_ended` for paired streams.
  This is the byte-path side of §5.5's "active socket-takeover byte streams are
  closed"; Phase 2 owns detection and the new-connection fallback, this phase owns
  closing the live sockets. (For dialed upstream streams the teardown wiring lands with
  Phase 5; the client-facing teardown is here.)

## Scope — `sidecar` package

- Claim registration helpers (declare `early_claim` with its matchers, incl. `probe`).
- Stream lifecycle callbacks: `OnStreamOpen`, `OnStreamDeliver` (returning `writes`),
  `OnStreamEnded`, plus `CloseStream` and `StreamWrite` proactive calls.
- A **reassembly buffer** helper so adapter authors can accumulate `stream_deliver`
  chunks until a full protocol frame is available before parsing.
- A `ClaimProbe` callback hook.

## Out of scope / deferred

- Upstream connectivity (`dial_upstream`) → Phase 5. An echo fixture needs none.
- HTTP-upgrade interception (`upgrade_claim`) → Phase 6.
- Rule-driven mutation of intercepted bytes → Phase 7.
- Replay/origination → Phase 8.

## Test fixture

An echo sidecar (on the `sidecar` package) that declares one `early_claim` on a test
port (variants: raw, `tls.terminate`, and `probe`-based), accepts `stream_open`,
echoes each `stream_deliver` back via the Response `writes`, and emits a `push_flow`
for the exchange. A real TCP client connects to the proxy port and round-trips bytes.

## Verification

- Bytes round-trip through the echo sidecar for raw, TLS-terminated, and probe-based
  claims; the exchange is captured as a flow (Phase 3) and attributed to the sidecar.
- Per-stream ordering holds; reassembly across chunk boundaries works.
- Fallthrough: a non-matching connection on a claimed port reaches the HTTP adapter
  unchanged; all probes declining falls through.
- `tls.terminate` decrypts with the fake CA and the CA key never leaves sectool.
- `close_stream`/`stream_write`/`stream_ended` behave; unknown `stream_id` write is a
  transport error.
- On owning-sidecar death/unhealthy, active claimed streams are torn down (client
  socket closed) and `stream_ended` fires; no orphaned sockets remain.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [x] `early_claim` fires at accept with all matchers; HTTP fallthrough preserved.
- [x] TLS-terminating claim delivers decrypted bytes; CA key contained.
- [x] Full event model (`stream_open`/`stream_deliver`/`writes`/`stream_ended`/
      `close_stream`/`stream_write`) with per-stream ordering.
- [x] Owning-sidecar death tears down active claimed streams (client socket closed);
      no orphaned sockets. `stream_ended` is delivered for live-peer ends, not on death
      (the owning sidecar is gone and cannot receive it).
- [x] `claim_probe` chain works (or is cleanly split to Phase 4b).
- [x] Echo fixture round-trips bytes end-to-end over a real TCP connection.
- [x] `sidecar` package gains claim + stream + reassembly helpers; no `sectool/` dep.
- [x] `make test-all` + `make lint` pass.

## Implementation decisions (as built)

These refine the description above where they conflict:

- **Single-listener transport, no extra sockets.** Raw claims fire on the existing
  proxy accept path discriminated by `magic_bytes_prefix`/`probe`; TLS claims by
  SNI/host/dest-port in the CONNECT handler. `port_range` gates the local port at raw
  accept (an unset range matches any) and the destination port on the CONNECT/TLS
  path. Tailscale Noise is an `upgrade_claim` case (Phase 6), not `early_claim`.
- **Accept peek narrowed.** `proxy/server.go` now peeks one byte and only widens to
  24 for openings starting `P`/`C` (HTTP/2 preface, CONNECT), so a short binary
  opening no longer blocks the accept loop. Existing HTTP behavior is unchanged.
- **Registry made dynamic.** `protocol.Registry` gained a guard mutex plus
  `InsertEarly`/`RemoveEarly` (fallthrough stays last) and `MatchTLS`; bridges are
  inserted at registration and removed on disconnect.
- **TLS-terminate via the CONNECT handler.** `handler_connect.go` matches a
  `tls.terminate` claim in `GetConfigForClient` and skips the upstream dial; the
  decrypted stream is re-offered through `ServeEarly`. A decrypted matcher that
  declines dials upstream lazily and falls through to HTTP.
- **Stream event loop on the bridge.** A per-sidecar `streamSet` tracks open
  sockets; `serveClient` runs `stream_open` then ordered `stream_deliver` awaiting
  each reply, applying `writes` (which may target a different stream), and emits
  `stream_ended` on close. `close_stream`/`stream_write` notifications route to the
  set; an unknown `stream_id` write is a transport error.
- **SDK stream surface is optional.** `StreamHandler` and `ClaimProber` are
  type-asserted alongside the existing `Handler`, so `ShutdownFunc` and current
  fixtures keep compiling; callbacks use `wire` types directly as the rest of the
  SDK does. `Reassembler` accumulates chunks into whole frames.
- **No conflict-guard change needed.** The Phase 2 native-proxy-port guard already
  no-ops for an unset `port_range` and when `NativeProxyPort` is 0, so raw claims on
  the proxy port work without touching `conflict.go`.
