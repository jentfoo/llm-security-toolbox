# Sidecar Phase 5 — Upstream egress (dial_upstream)

> Implements part of the protocol-adapter sidecar contract. Read alongside the
> contract spec `todo/sectool-protocol-sidecar-specs.md` (referred to below as
> "the spec"); this file is otherwise self-contained.

## Dependencies & ordering

Requires **Phase 4** (the byte-stream event model; upstream bytes flow over the same
`stream_deliver`/`writes` mechanism). Independent of **Phase 6**. Prerequisite for
**Phase 8** (replay egress flows through `dial_upstream`).

## Goal

Let a sidecar reach an upstream host **without ever opening a socket itself**: it asks
sectool to dial, sectool opens the TCP connection (subject to scope policy), and bytes
flow to the sidecar as just another stream. This turns the Phase 4 echo-only
interception into real capture-and-forward, and centralizes all sidecar egress under
sectool's scope enforcement and audit.

## Background & assumed state

After Phase 4, a sidecar can claim a client-facing connection and exchange bytes with
it, but has no way to forward traffic onward — it cannot open sockets (spec §2.1:
sectool owns every socket, including upstream dials requested by sidecars). The spec's
design consequence (§2.3) is that the sidecar requests upstream connectivity via
`dial_upstream` and sectool exchanges the upstream socket's bytes through the same
event/Response model used for client-facing streams.

`dial_upstream` (§6a.6) params: `host`/`port` (optional — default to the original
destination of the connection associated with `parent_flow_id`; supplying them
redirects), `tls` `{enabled, sni?, alpn?, skip_verify?}` (when enabled sectool
terminates TLS toward the upstream and bridges cleartext to the sidecar), and
`parent_flow_id` (associate the dial for audit and default-destination). Returns
`{stream_id}` (bytes then flow via `stream_deliver`/`writes`) or a JSON-RPC error if
rejected by scope policy, refused by the network, or TLS fails.

Scope policy already exists for proxied traffic: `allowed_domains` /
`exclude_domains` with `include_subdomains`, where `exclude_domains` always takes
precedence (see `sectool/config/config.go` and `sectool/service/capture_filter.go`).
This phase applies the same policy to sidecar-requested dials (§10 — sidecars cannot
bypass scope because they never see OS sockets).

## Spec references

- §2.1 Hosting model, §2.3 (upstream connectivity consequence).
- §6a.6 `dial_upstream`.
- §10 Security considerations (upstream egress is mediated; every dial recorded).

## Scope — toolbox (server side)

- **`dial_upstream` handler** (§6a.6): open a TCP connection to the resolved
  destination on the sidecar's behalf and bridge it as a new stream — inbound upstream
  bytes arrive at the sidecar via `stream_deliver`, the sidecar's `writes` go out the
  upstream socket. Default the destination from `parent_flow_id`'s connection when
  `host`/`port` are omitted.
- **Scope enforcement:** apply `allowed_domains` / `exclude_domains` (reuse the
  existing scope logic) before dialing; reject out-of-scope dials with the
  `dial_upstream` scope-rejection error (§11). Network refusal and TLS failure return
  their respective errors.
- **Upstream TLS termination:** when `tls.enabled`, perform TLS toward the upstream
  (honoring `sni`/`alpn`/`skip_verify`) and bridge cleartext to the sidecar.
- **Audit:** record the dial in history as a `dial_upstream`-tagged annotation on
  `parent_flow_id` when supplied; surface all such dials for audit (§10).
- **Teardown on sidecar death** (§5.5): a dialed upstream stream is torn down with its
  owning sidecar — close the upstream socket and emit `stream_ended`, the upstream-side
  counterpart of the client-facing teardown Phase 4 owns. (Phase 4 detects death and
  closes the client socket; this phase closes the paired upstream socket.)

## Scope — `sidecar` package

- `DialUpstream` call returning the upstream `stream_id`, plus handling for the
  upstream stream's `stream_deliver`/`writes` (the same callbacks as Phase 4, now also
  used for upstream streams).
- Helper to forward a client-stream message out an upstream stream and vice-versa
  (the cross-`stream_id` `writes` pattern from §4.2).

## Out of scope / deferred

- HTTP-upgrade interception → Phase 6.
- Replay/origination that *uses* `dial_upstream` for egress → Phase 8.
- Cross-adapter origination (`invoke_adapter`) → Phase 8.

## Test fixture

A forwarding sidecar (on the `sidecar` package) that claims a port (Phase 4), calls
`dial_upstream` to a local test echo server, and proxies bytes between client and
upstream streams. Variants exercise an out-of-scope destination and a TLS upstream.

## Verification

- Bytes proxy client→upstream→client through the sidecar via sectool-owned sockets.
- An out-of-scope `dial_upstream` is rejected with the scope error; the sidecar cannot
  reach it by any other means.
- TLS upstream terminates correctly and bridges cleartext.
- Every dial appears in history as an audit annotation tied to `parent_flow_id`.
- `make test-all` + `make lint` pass; no-sidecar behavior unchanged.

## Definition of done

- [ ] `dial_upstream` opens scope-checked upstream connections and bridges bytes as a
      stream; default-destination from `parent_flow_id` works.
- [ ] Scope rejection / network failure / TLS failure return the correct errors.
- [ ] Upstream TLS termination supported.
- [ ] Every dial is recorded for audit.
- [ ] Forwarding fixture proxies end-to-end; out-of-scope and TLS variants verified.
- [ ] `sidecar` package gains `DialUpstream` + upstream-stream handling; no `sectool/`
      dep.
- [ ] `make test-all` + `make lint` pass.
