# Sidecar Phase 6 — Upgrade interception (upgrade_claim)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 4** (the byte-stream event model — post-upgrade bytes flow over the
same streams). Independent of **Phase 5**, so either order works.

## Goal

Let a sidecar claim a connection **after** an HTTP upgrade — the common case where a
protocol starts as HTTP and then switches (WebSocket, h2c, `/ts2021`-style control
upgrades, or post-CONNECT). sectool captures the triggering HTTP request as a normal
flow, synthesizes the upgrade response itself, and routes subsequent bytes to the
sidecar. This generalizes the WebSocket-101 takeover that Phase 1 hard-wired into the
WS adapter so any registered upgrade can be claimed.

## Background & assumed state

After Phase 4, sidecars claim connections from the first byte (`early_claim`). But
many protocols begin as HTTP and switch mid-connection; the claim for those must fire
at the upgrade point, not at accept. Today (pre-refactor) the 101 takeover was
hard-wired to WebSocket via `isWebSocketUpgrade`, and h2c was rejected at accept;
Phase 1 folded these into the registry, and this phase opens that seam to sidecars.

The spec's upgrade-claim seam (§2.3): sectool drives all HTTP framing itself
(including the upgrade request), captures the triggering request as an HTTP flow,
synthesizes the upgrade response, and diverts subsequent bytes on that TCP connection
to the sidecar — regardless of the upgrade token (e.g.
`tailscale-control-protocol` on `POST /ts2021`). After the switch the protocol has
changed, so there are no further HTTP requests on that connection to re-handle.

`upgrade_claim` (§5.3) params: `{ host_pattern, path_pattern, upgrade_signal,
method_set? }` where `upgrade_signal` is `http_101` (after sectool emits
`HTTP/101 Switching Protocols` to a matching request) or `connect` (after CONNECT is
fully processed). Conflict resolution is most-specific-matcher-wins, with ambiguous
overlaps rejected at registration (§5.3.1 — already enforced in Phase 2).

Crucially, the triggering HTTP request is consumed by sectool before handoff, so its
headers (and `flow_id`) are surfaced to the claiming sidecar on `stream_open` (§4.2):
the payload additionally carries `request_flow_id` and `request_headers`. A protocol
that embeds handshake/setup bytes in the upgrade request itself needs these to drive
the post-upgrade exchange. (Both fields are absent for `early_claim`.)

## Spec references

- §2.3 Connection lifecycle and handoff seams (upgrade-claim seam; generalizing the
  built-in 101 takeover).
- §5.3 Capabilities (`upgrade_claim`), §5.3.1 (most-specific-wins conflict rules).
- §6b.4 `stream_open` (carrying `request_flow_id` + `request_headers` for the upgrade
  case); §4.2 (event model).

## Scope — toolbox (server side)

- **Fire `upgrade_claim`:** after sectool parses an HTTP request, match registered
  `upgrade_claim`s on `(host_pattern, path_pattern, upgrade-token, method_set)`. For
  `upgrade_signal=http_101`: synthesize the `HTTP/101 Switching Protocols` response and
  divert subsequent bytes to the sidecar. For `upgrade_signal=connect`: claim after
  CONNECT is fully processed.
- **Capture the trigger:** record the triggering HTTP request as a normal HTTP flow in
  history before handoff (it remains in `proxy_poll`/`flow_get`).
- **Hand off with context:** open the post-upgrade stream via `stream_open`
  (§6b.4) carrying `request_flow_id` and `request_headers` in addition to the standard
  fields, then stream post-upgrade bytes via the Phase 4 event model.
- **Generalize the built-in takeover:** route the WebSocket-101 takeover (folded into
  the registry in Phase 1) through this same `upgrade_claim` path, so the WS adapter
  and sidecar upgrade-claims share one mechanism; divert post-101 bytes regardless of
  the upgrade token.

## Scope — `sidecar` package

- `upgrade_claim` registration helper (host/path/upgrade-signal/method matchers).
- Post-upgrade stream handling that consumes the `request_flow_id` /
  `request_headers` provided on `stream_open` (so the sidecar can read a handshake
  carried in the upgrade request).

## Out of scope / deferred

- Per-HTTP/2-stream claiming (`stream_takeover`) — explicitly deferred by the spec
  (§5.3) beyond v1.
- Rule-driven mutation of post-upgrade bytes → Phase 7.
- Replay/origination → Phase 8.

## Test fixture

A sidecar (on the `sidecar` package) that declares an `upgrade_claim` on a test path
with a custom upgrade token. An HTTP client sends a matching upgrade request; the
fixture asserts it received `request_flow_id`/`request_headers` on `stream_open` and
then echoes post-upgrade bytes.

## Verification

- The triggering HTTP request is captured as a normal flow and visible in history.
- sectool synthesizes the 101 (or processes CONNECT) and post-upgrade bytes route to
  the sidecar; `request_flow_id`/`request_headers` are present on `stream_open`.
- A custom (non-WebSocket) upgrade token is claimed and diverted.
- The built-in WebSocket takeover still works through the unified path
  (byte-identical to today).
- Most-specific-matcher conflict resolution behaves (verified at registration).
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [ ] `upgrade_claim` fires on `http_101` and `connect` signals with host/path/token/
      method matching.
- [ ] Triggering request captured as a flow; upgrade response synthesized by sectool;
      post-upgrade bytes routed.
- [ ] `stream_open` carries `request_flow_id` + `request_headers` for upgrade claims.
- [ ] WebSocket-101 takeover runs through the unified upgrade-claim path unchanged.
- [ ] Fixture validates a custom-token upgrade end-to-end.
- [ ] `sidecar` package gains upgrade-claim registration + handling; no `sectool/` dep.
- [ ] `make test-all` + `make lint` pass.
