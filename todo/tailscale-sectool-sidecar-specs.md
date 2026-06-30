# Tailscale Sectool Sidecar Specification

This document describes the Tailscale-specific protocol adapters that
plug into the sectool sidecar contract. It assumes the sectool side has
been refactored per `sectool-protocol-sidecar-specs.md` (referred to in
this document as **Spec 1**). All adapter-side behavior described here
maps to capabilities, methods, and lifecycle seams defined there.

## 1. Overview

### 1.1 Scope

Two adapters are in scope, both speaking the same sectool sidecar
contract:

1. **Client-side MITM sidecar.** Sits between a Tailscale client and
   the real control server, terminating Noise IK with a substituted
   trust anchor on the client side, re-initiating Noise IK to the
   upstream control server on the server side, and exposing the
   decrypted inner HTTP/2 traffic to sectool as ordinary flows.
2. **Server-side adapter.** A Tailscale-compatible control server
   implemented by the adapter (§5) emitting MapRequest, MapResponse,
   RegisterRequest, and RegisterResponse captures into sectool over the
   same contract. Drives adversarial-server scenarios without requiring a
   real Tailscale coordination server to be in the loop.

Both adapters emit HTTP-shaped flows (Spec 1 §3.1): `method`, `path`,
`headers`, `body`, with `protocol_tag` of `tailscale.control` (inner
HTTP/2 requests) or `tailscale.tunnel` (Noise tunnel envelopes). Agents
use the identical MCP tools (`replay_send`, `set_json`, `proxy_rule_add`,
`diff_flow`, `find_reflected`, `notes_save`, etc.) against flows from
either adapter or both simultaneously.

The sidecar binary is **Linux-only** (it depends on Tailscale upstream
packages whose primary deployment target is Linux); the sectool side of
the contract is fully cross-platform per Spec 1 §11.

### 1.2 Authorized testing only

This specification describes interception of an end-to-end encrypted
control protocol. The technique requires either operator control of
the client trust anchors (test deployments, fake-CA install) or
operator control of the upstream coordination server. Operators must
have explicit authorization for any deployment they target.

---

## 2. Background — Tailscale control protocol

The information in this section grounds the adapter design. File
references are to the upstream `tailscale.com` repository and were pinned
and verified against commit `ca20611d1` (v1.101.0-pre,
`CurrentCapabilityVersion` 141) — the release Headscale `v0.29.0` also
builds against. `file:line` references still drift with upstream; re-verify
each against the exact commit locked in the sidecar's `go.mod` (§4.1) on any
bump before relying on a line number.

### 2.1 Noise variant and key material

The control plane uses **Noise_IK_25519_ChaChaPoly_BLAKE2s**, with
fresh Curve25519 ephemeral keys per handshake (`control/controlbase/
handshake.go:31`). The initiator (client) knows the responder's
(server's) static public key ahead of time. The responder authenticates
the initiator's static key (the "machine key") during the handshake.

The handshake also mixes a prologue `"Tailscale Control Protocol v" +
<version>` into the hash (`control/controlbase/handshake.go:42-50`), and a
2-byte big-endian protocol version travels in the initiation header
(§2.3.1). The header version and the prologue version **must match** or
MAC verification fails. A MitM that regenerates the initiation must carry
the client's advertised version through to the upstream initiation
unchanged. This protocol version **is** the client's capability version
(`tailcfg.CurrentCapabilityVersion`, 141 at the pinned commit): the same
integer appears three times per session — the 2-byte Noise initiation
header, the `/key?v=<n>` query (§2.2), and the `Version` field of every
`MapRequest` / `RegisterRequest` (§2.4). The sidecar recovers it from the
decoded initiation (`controlbase` exposes it as the message version) and
must reuse that value both for its own upstream initiation and for its own
`/key` fetch (§4.4 step 3); the body `Version` rides through unchanged on
forwarded messages.

### 2.2 Trust bootstrap

The client does not bake the server's static public key into the
binary. It fetches it at runtime via a plain TLS HTTPS request:

- `GET https://<control-server>/key?v=<capabilityVersion>`
  (`control/controlclient/direct.go:1534`).
- Response body is JSON of type `tailcfg.OverTLSPublicKeyResponse`
  (`tailcfg/tailcfg.go:3246`), carrying the server's Noise public key in
  the `publicKey` field; `legacyPublicKey` carries the older NaCl machine
  key for very old clients and is unused here. Both marshal as
  `key.MachinePublic` text (`mkey:<hex>`, `types/key/machine.go:252-264`),
  not base64.
- The fetched pubkey is stored as `c.serverNoiseKey`
  (`control/controlclient/direct.go:717`) and reused for the lifetime
  of the in-process control client.
- The HTTP client used for `/key` is a standard `*http.Client` with
  the platform's system TLS roots. No additional pinning is performed
  at this layer.

This bootstrap is the load-bearing seam for the client-side MITM:
substitute the JSON pubkey here and the client will subsequently
initiate Noise against the sidecar's keypair.

### 2.3 Transport

After the `/key` fetch:

1. The client opens a TCP connection to the control server (port 80
   preferred; port 443 with HTTPS as fallback).
2. The client sends `POST /ts2021` with `Upgrade:
   tailscale-control-protocol`, `Connection: upgrade`, and
   **`X-Tailscale-Handshake: base64(<noise initiation>)`**
   (`control/controlhttp/client.go:543-545`,
   `control/controlhttp/controlhttpcommon/controlhttpcommon.go:10,15`).
   The Noise IK **initiation (msg 1) is carried in the HTTP upgrade
   request header — not sent on the socket**. This is the "deferred
   initiation": `controlbase.ClientDeferred` builds the 101-byte
   initiation up front so it can ride the upgrade request
   (`control/controlbase/handshake.go:57-101`).
3. The server reads the initiation from the header
   (`control/controlhttp/controlhttpserver/controlhttpserver.go:55`),
   then replies `HTTP/101 Switching Protocols` echoing `Upgrade:
   tailscale-control-protocol` / `Connection: upgrade`
   (`controlhttpserver.go:72-74`), hijacking the underlying TCP socket.
   The Noise tunnel and subsequent HTTP/2 share that same TCP
   connection.
4. The server completes the handshake by writing the **51-byte Noise
   response (msg 2)** on the raw upgraded socket; the responder consumes
   the initiation via `controlbase.Server(ctx, conn, key, optionalInit)`
   with `optionalInit` set to the header bytes rather than reading msg 1
   from the socket (`control/controlbase/handshake.go:201-258`). Only
   msg 2 and everything after it travel on the post-101 byte stream.
5. Once the handshake completes, the server MAY emit an **EarlyNoise**
   payload before the HTTP/2 SETTINGS frame to communicate side-band
   control information. Framing (`control/ts2021/conn.go:91,143-147`):
   `[5-byte magic \xff\xff\xffTS][4-byte big-endian uint32 length, ≤10
   MiB][JSON tailcfg.EarlyNoise]`. The connection then carries HTTP/2
   (RFC 7540) inside the Noise tunnel.

The upgrade reuses the same TCP connection, which is the basis for the
Spec 1 `upgrade_claim` model: sectool keeps the socket and the sidecar
receives **post-101** bytes as `stream_deliver` events. Because the
client's Noise initiation (msg 1) was consumed from the `/ts2021`
*request header*, post-101 bytes alone are insufficient: sectool's
`stream_open` for this `upgrade_claim` also delivers the captured
request headers (Spec 1 §4.2) so the sidecar can recover
`X-Tailscale-Handshake` and feed it to `controlbase.Server(...,
optionalInit)`. The sidecar must **not** try to read the initiation
from the stream.

#### 2.3.1 Noise wire framing (MitM reference)

The sidecar drives the upstream `control/controlbase` library and **must
not reimplement framing**; this table exists so the engineer can reason
about the bytes on the wire and size buffers correctly. All Noise
messages begin with a 1-byte type (the initiation prepends a 2-byte
big-endian version first). All Noise/EarlyNoise length prefixes are
**big-endian**; the inner MapResponse frame length (§2.4) is
**little-endian** — do not conflate them.

| message | type | wire layout (`control/controlbase/messages.go`) |
|---|---|---|
| initiation (msg 1) | `0x01` | 101 B: `[2B BE version][1B type][2B BE len=96][32B client ephemeral][48B enc machine-static+tag][16B tag]` |
| response (msg 2) | `0x02` | 51 B: `[1B type][2B BE len=48][32B server ephemeral][16B tag]` |
| error | `0x03` | `[1B type][2B BE len][msg bytes]`, unauthenticated (`handshake.go:217-225`) |
| transport record | `0x04` | `[1B type][2B BE ciphertext-len][ciphertext]` (`conn.go:169-171`) |

Transport records (`control/controlbase/conn.go:25-35`): max **4096 B**
per frame, max **4077 B** plaintext (4096 − 3-byte record header − 16-byte
ChaCha20Poly1305 tag).
A larger inner HTTP/2 frame is split across multiple Noise records.
Zero-byte-plaintext records are legal and must be preserved
(`conn.go:252-256`). Nonce is 12 B = 4 zero bytes + an 8-byte big-endian
counter starting at 0 (`conn.go:385-396`); there is no rekey — the
connection dies when the counter would exhaust.

Reassembly (per Spec 1 §4.2) is the sidecar's responsibility: buffer
`stream_deliver` bytes to a complete Noise record before decrypting,
then buffer cleartext to a complete inner HTTP/2 frame before parsing.

### 2.4 Inner protocol

Inside the Noise tunnel, the client speaks HTTP/2. Standard endpoints:

- `POST /machine/register` — body is JSON `tailcfg.RegisterRequest`;
  response is JSON `tailcfg.RegisterResponse`.
- `POST /machine/map` — body is JSON `tailcfg.MapRequest`. Streaming is
  requested via the **`Stream` boolean field in the request body**
  (with `Compress: "zstd"`), not a `?stream=true` query parameter
  (`tailcfg/tailcfg.go`, `MapRequest.Stream`). The response is either a
  single JSON `tailcfg.MapResponse` or a streamed sequence of
  zstd-framed JSON fragments. Each frame is a 4-byte **little-endian**
  length prefix followed by zstd-compressed JSON
  (`control/controlclient/direct.go:1303-1311,1494`).

The MapResponse stream is long-lived; sessions remain open until the
client or server tears them down. Keepalive is HTTP/2-layer (PING
frames). There is no Noise-layer keepalive.

### 2.5 Out-of-scope plane

The data plane is not covered by this specification, for two reasons.
First, its transports don't fit the sectool sidecar contract, which
front-ends TCP byte streams: the WireGuard data plane is Noise_IKpsk2 over
**UDP** (the external `github.com/tailscale/wireguard-go` dependency, not in
the tailscale tree), disco discovery uses NaCl box over UDP
(`disco/disco.go:11-14`), and DERP NaCl-boxes only its login
handshake frames (`derp/derp.go:73-74`; the relayed packets it forwards are
opaque, already-encrypted bytes) — these out-of-band transports are not
modeled by the contract's `stream_deliver` / `dial_upstream` model. Second, the data plane
carries no authorization or configuration decisions: peer config, ACLs, key
distribution, and registration all live in the control plane, which is
therefore the high-value testing surface and makes the data plane's
exclusion cheap. A DERP or WireGuard sidecar is separately specifiable if
ever needed.

---

## 3. Attack model

### 3.1 Trust-anchor substitution

The Noise IK handshake binds the responder's static public key into
the handshake transcript. A transparent on-path attacker cannot forge
the responder's identity without possessing the responder's private
key. However:

- The client fetches the responder's pubkey at runtime over TLS.
- The TLS layer can be MITMed using sectool's existing fake-CA
  mechanism (the operator has installed sectool's CA in the client's
  trust store, as is already standard for HTTP/TLS testing).
- The `/key` response body can be rewritten to substitute a different
  pubkey, and the client will use the substituted pubkey as
  `serverNoiseKey`.
- The sidecar holds the matching private key, so the Noise IK
  handshake against the sidecar completes successfully.

This is the same conceptual move as the existing TLS CA trick, applied
one layer up: replace the trust anchor at the point where the client
is willing to learn it.

### 3.2 Prerequisites

- Sectool's fake CA must be trusted by the Tailscale client (system
  trust store install). This is the existing requirement for HTTPS
  MITM and is unchanged.
- The client must route its control traffic through sectool's proxy
  port. Methods: configure the OS proxy, redirect by DNS,
  containerize the client behind a transparent-proxy network
  namespace, or use a `tsnet` test client whose control URL can be
  set programmatically.

### 3.3 First-contact requirement

The client caches `serverNoiseKey` in-process after a successful
`/key` fetch and does not refetch on the hot path. When `/key`
substitution is used, the rewrite rule must be active at the first
`/key` call. Process restarts trigger a new fetch (cached only in
memory by default). Operators should plan test sessions so that the
client process starts after sectool and the sidecar are already
running.

#### 3.3.1 Operational paths for local deployment

The target client runs alongside the sidecar on the operator's
machine. Three operational paths exist, ordered by simplicity:

1. **`tsnet` test client + programmatic `ControlURL`** (recommended
   when the test target is application code embedding tsnet). Set
   `tsnet.Server.ControlURL` (`tsnet/tsnet.go:288`) to point at either
   the server-side adapter (§5) or, when the client-side MITM is in
   play, at the sectool proxy address. This path avoids `/key`
   substitution entirely when the target server is a sectool-hosted
   adapter (the client never asks a real coordination server for its
   pubkey).
2. **Containerized `tailscaled` with `--login-server`** (used when
   testing the unmodified `tailscaled` binary against a sectool-hosted
   control server). Mount the sectool fake CA into the container's
   trust store; set `--login-server` to the adapter's URL. No `/key`
   substitution required if the adapter is the declared login server.
3. **Full `/key` substitution** (§4.3) — required only when the target
   is an unmodified `tailscaled` pointed at a real coordination URL
   (e.g., `controlplane.tailscale.com`) and the operator wants the
   client to remain unaware of the interception. This is the only
   path that supports capturing existing production-pointed installs
   without reconfiguration.

Paths 1 and 2 are the v1 development and most-test-cases paths. Path
3 is the production-fidelity path and is what §4 describes in detail.

### 3.4 Known limitations

- **Future explicit pinning.** If Tailscale pins the control pubkey
  out of band (env var, embedded constant, signed manifest), the
  `/key` substitution approach fails. The sidecar must detect the
  failure mode (handshake never completes, client logs verification
  error) and surface it as a diagnostic, not pretend interception
  succeeded.
- **Replay protection on the upstream side.** Registration is bound
  to a machine identity. Replaying captured RegisterRequest payloads
  with the original machine identity may be rejected by the upstream
  control server. Replay with a fresh identity, or against a
  controlled test server, is the safer default.
- **Handshake-hash binding.** Any inner Tailscale message that binds
  its authentication or integrity to the Noise handshake hash cannot
  be replayed across tunnels without re-binding. The sidecar tracks these
  internally (§4.6.2) and, on replay, rebinds them automatically per its
  connection-time configuration (Spec 1 §6b.2).
- **Out-of-band traffic.** Sectool only sees what passes through the
  control plane. Disco messages, peer-to-peer connectivity, and
  WireGuard data are not visible.

---

## 4. Client-side MITM sidecar

### 4.1 Process model

A standalone Go binary, distributed as `sectool-tailscale-sidecar`
(name placeholder). Depends on Tailscale's `control/controlbase`
package (for the Noise handshake state machine), `control/ts2021`
(for the EarlyNoise envelope and HTTP/2 plumbing on top of the Noise
tunnel), and `control/controlhttp/controlhttpcommon` (for the upgrade
token and `X-Tailscale-Handshake` header constants). Pinned to a
specific Tailscale commit in the sidecar's own `go.mod` so that sectool
itself does not inherit those dependencies.

Handshake API usage (§2.3): the **client-facing responder** path uses
`controlbase.Server(ctx, conn, key, optionalInit)` with `optionalInit`
set to the initiation decoded from the captured `X-Tailscale-Handshake`
request header; the **upstream initiator** path uses
`controlbase.ClientDeferred` to build its own initiation and places it
in the `X-Tailscale-Handshake` header of the sidecar's upstream
`POST /ts2021` (§4.4 step 4).

The sidecar never opens a listening socket and never receives an OS
file descriptor (Spec 1 §2.3). Client-side bytes arrive as `stream_deliver`
events on the stream sectool opens after the `upgrade_claim` for
`/ts2021` fires, and the sidecar returns bytes to write as Response
`writes`. Upstream bytes flow over a second stream (distinct
`stream_id`) sectool opens in response to the sidecar's `dial_upstream`
call.

Launch model: either sectool-managed subprocess or operator-attached,
per Spec 1 §5.1.

### 4.2 Registration

On startup, the sidecar provisions its client-facing responder key per the
configured strategy (§4.4.1): under `substitute` (default) it generates a
fresh Noise keypair (`MachinePrivate` / `MachinePublic`) as the **substitute
trust anchor** served to the client; under `borrow` it loads the real
upstream server's key. It registers with sectool per Spec 1 §6a.1 with:

- `name`: `tailscale.client.mitm` (configurable to allow multiple
  instances).
- `protocols`: `["tailscale.tunnel", "tailscale.control",
  "tailscale.control.map.stream"]`.
- `capabilities`:
  - `upgrade_claim` for `POST /ts2021` on the configured control host
    pattern (default `controlplane.tailscale.com`, configurable to
    include Headscale instances or custom coordinators) with
    `upgrade_signal=http_101`.
  - `injection_target` with the schema described in §4.7.

The sidecar emits the inner HTTP/2 captures and tunnel envelopes via
`push_flow`. The protocol-specific re-encoding and re-signing of §4.6 are
the adapter's internal concern on replay (Spec 1 §6b.2), not declared to
sectool. The `/key` substitution (§4.3) is operator-configured rather than
a pushed rule.

The sidecar's cryptographic bindings (`register_signature`,
`hardware_attestation`, `map_session`, `early_noise_challenge`) are its
own internal concern (§4.6.2), not part of registration — sectool models
nothing about them (Spec 1 §6b.2).

#### 4.2.1 Example registration payload

Illustrative excerpt (parameters elided for brevity; field names
match Spec 1 §6a.1):

```json
{
  "name": "tailscale.client.mitm",
  "version": "0.1.0",
  "protocol_version": {"major": 1, "minor": 0},
  "protocols": [
    "tailscale.tunnel",
    "tailscale.control",
    "tailscale.control.map.stream"
  ],
  "capabilities": {
    "upgrade_claim": {
      "host_pattern": "controlplane.tailscale.com",
      "path_pattern": "/ts2021",
      "upgrade_signal": "http_101",
      "method_set": ["POST"]
    },
    "injection_target": { "/* see §4.7 */": null }
  },
  "instance_id": "/* sidecar-supplied UUID, stable across restarts */"
}
```

### 4.3 /key substitution (full-substitution path only)

The sidecar does not sit in the byte path for `/key` — that is plain
JSON over HTTPS, and sectool's existing HTTP machinery handles it. Full
`/key` substitution is needed only for the production-fidelity path (§3.3.1
path 3); the development/test paths (`tsnet ControlURL`, `--login-server`)
and the `borrow` strategy (§4.4.1) avoid it. Spec 1 does not support
adapter-pushed (`owned`) rules, so substitution is operator-configured one
of two ways:

- An operator-created user rule (`proxy_rule_add`, optional
  `adapter=http/1.1`): a `response_body` `regex_replace` over the `publicKey`
  value, rewriting it to `mkey:<hex of the sidecar's substituted Noise
  pubkey>`. 7-type rules carry no host/path scope, but a regex anchored on the
  `publicKey` (`mkey:<hex>`) field matches only `/key` responses in practice.
- Or the sidecar substitutes the pubkey internally: under `substitute`
  (§4.4.1) it learns the real upstream key via its own direct fetch and serves
  its substitute trust anchor to the client directly, so no rule on the
  client-facing `/key` is required (the simpler, recommended path).

The substituted value targets `publicKey`, the Noise control-plane key in
`OverTLSPublicKeyResponse` (§2.2); its wire form is the `key.MachinePublic`
text encoding `mkey:<hex>`, not base64. The legacy NaCl field
`legacyPublicKey`, served only to very old clients, is out of scope.

The sidecar's own upstream `/key` fetch (§4.4 step 3) must read the **real**
key. Because a user rule cannot be host/path-scoped, the internal-substitution
path avoids the hazard entirely; when a user rule is used instead, the sidecar
issues its upstream fetch directly to the real control server (attributable
via `invoked_by`) and reads the response before the rule's regex would rewrite
it. Otherwise the sidecar would read back its own substitute key, initiate
Noise upstream against the wrong responder static key, and fail the handshake.

If the upstream `/key` call fails, sectool returns the failure
unchanged. The sidecar can observe the failure via `proxy_poll` if it
chooses (e.g., a watchdog goroutine), or via the `log` emission on
its own connection failures.

### 4.4 Connection takeover and Noise tunnel establishment

When the client subsequently opens `POST /ts2021` and sectool emits
`HTTP/101 Switching Protocols` (synthesized locally, not proxied
upstream), the sidecar's `upgrade_claim` fires:

1. Sectool captures the `/ts2021` request as a normal HTTP flow,
   synthesizes the 101 response, and opens a stream to the sidecar with
   `stream_open` (Spec 1 §4.2). For this `upgrade_claim` the
   `stream_open` payload **includes the captured request headers** so
   the sidecar can recover `X-Tailscale-Handshake` (the client's Noise
   initiation, §2.3). Subsequent client bytes arrive as `stream_deliver`
   events and the sidecar's Response `writes` are written back.
2. The sidecar runs Noise IK as **responder** via
   `controlbase.Server(ctx, conn, key, optionalInit)` with
   `optionalInit` set to the base64-decoded `X-Tailscale-Handshake`
   bytes (it does **not** read msg 1 from the stream), using its
   client-facing responder keypair (synthetic or borrowed, §4.4.1). The
   library writes the 51-byte response (msg 2) back as the first
   post-101 bytes. Once the handshake completes, the sidecar has
   cleartext access to the client's inner HTTP/2 stream.
3. In parallel (started as early as upgrade_claim fires for
   pipelining), the sidecar issues `invoke_adapter` (Spec 1 §6a.8)
   targeting the HTTP adapter for an upstream `GET /key?v=<capability-version>`
   (the version the client advertised, recovered from the decoded initiation
   — §2.1; a coordinator gates the response on `v` and may 400 a missing one)
   against the real control server, learning the real upstream Noise pubkey. This
   fetch is issued directly to the real control server and is attributable via
   `invoked_by`, so it is outside the scope of any client-facing `/key`
   substitution rule (§4.3) and the sidecar reads the **real** upstream key.
   The resulting flow lands in
   sectool history under the HTTP adapter and is visible in `proxy_poll` —
   preserving agent visibility into upstream pubkey rotation, server errors,
   and future pinning behavior. (This step is skipped under the borrowed-key
   strategy, §4.4.1.)
4. The sidecar issues `dial_upstream` (Spec 1 §6a.6) for
   `controlplane.tailscale.com:443` with `tls={enabled: true,
   sni: "controlplane.tailscale.com", alpn: ["http/1.1"]}`. Sectool
   opens the TCP+TLS connection (subject to scope policy) and returns
   a `stream_id`. The sidecar builds its initiation via
   `controlbase.ClientDeferred` (using a sidecar-controlled machine
   identity, §4.4.1, and the real upstream pubkey) and sends an
   HTTP/1.1 `POST /ts2021` on that stream with `Upgrade:
   tailscale-control-protocol`, `Connection: upgrade`, and
   **`X-Tailscale-Handshake: base64(<initiation>)`**. The upstream
   replies with 101; the sidecar then reads the 51-byte Noise response
   (and optional EarlyNoise) from the post-101 stream and completes the
   handshake via the `ClientDeferred` continuation.
5. The sidecar emits a tunnel envelope flow via `push_flow` (Spec 1
   §6a.2) carrying both directions' pubkeys, the negotiated Noise
   protocol name, the handshake hash on each side, and the bound
   machine identities. The returned `flow_id` is used as
   `parent_flow_id` on all inner HTTP/2 flows.
6. The sidecar drives HTTP/2 on both cleartext sides and bridges
   streams between them per §4.5.

Because sectool owns both TCP connections (client-facing and
upstream-facing) and applies scope policy on the upstream dial, the
operator's existing `allowed_domains` / `exclude_domains` configuration
governs Tailscale-related egress identically to any other proxied
traffic.

#### 4.4.1 Keys held by the sidecar vs. keys passed through

Tailscale nodes use two distinct Curve25519 keys for different
purposes (`types/key/machine.go:36-40`, `types/key/node.go:49-52`).
For a full MITM the sidecar **must hold the private form of the
client-facing responder key and of a client-side machine key** and
**passes through the node key** by default.

**Client-facing responder key — two strategies.** The static key the sidecar
presents to the client (as Noise IK *responder* — from the client's
perspective the control server's identity) is sidecar-held-private under
both; the operator picks via `key_strategy` (§7.2):

- **Strategy A — synthetic substitute (default; works against any upstream,
  including production `controlplane.tailscale.com`).** The sidecar mints a
  fresh keypair at startup (or loads a persistent one from
  `noise_keypair_path`) and serves its public half as the substitute trust
  anchor (via the §4.3 substitution path), holding the private half as
  responder. It learns the real upstream key via its own direct `/key` fetch
  (§4.4 step 3). The only strategy possible when the operator cannot obtain
  the real server's private key.
- **Strategy B — borrowed server key (operator-controlled upstream only:
  the §5 server-side adapter, Headscale, or any self-hosted coordinator).**
  The operator supplies the real upstream server's Noise private key. The
  sidecar serves the genuine `publicKey` to the client and registers **no**
  `/key` rewrite rule — the client's runtime `/key` fetch returns the real
  key, whose private half the sidecar now holds, so the handshake binds the
  real key with no substitution and no self-loop. The real upstream pubkey
  derives from the borrowed key, so the §4.4 step 3 fetch is skipped. Trades
  substitution-stealth for exact-real-key fidelity; impossible against
  servers whose private key the operator cannot get.

**Sidecar's own client-side machine key** — used as the Noise IK
static key when the sidecar acts as *initiator* talking upstream (both
strategies). The upstream control server sees this as a distinct Tailscale
machine (Noise IK binds the initiator's static key into the
transcript, so the upstream cannot be fooled into thinking it
spoke with the original client's machine key without that key's
private form).

Selection of the upstream client-side machine identity is
configurable:

- **Auto-generated** (default for fresh test sessions): sidecar mints
  a fresh `MachinePrivate` at startup. Upstream registration sees a
  new machine.
- **Replayed from capture**: when an agent is replaying a captured
  session and the operator has supplied the original machine's
  private key out of band, the sidecar uses it. Upstream then sees
  the same machine identity as the original session.
- **Operator-supplied pool**: the sidecar reads a directory of
  machine private keys and picks one per session, useful for fuzzing
  where many fresh identities are needed.

The selected machine identity is recorded in the tunnel envelope so
the agent can identify which Tailscale node identity each session
corresponds to.

**Pass-through keys (default):**

- **Node key** (`RegisterRequest.NodeKey`, `types/key/node.go:49-52`)
  — carried inside the encrypted `RegisterRequest`. The sidecar
  reads the client's `NodePublic` from the decrypted body and
  forwards it unchanged. This means upstream sees the client's real
  node identity for WireGuard / DERP purposes. An agent may mutate
  `NodeKey` via `set_json` against `body.NodeKey` if the test
  scenario requires it. The register `SignatureV2` does **not** cover
  `NodeKey` (§4.6.2), so the mutation leaves `register_signature` intact;
  what it invalidates is the tailnet-lock `NodeKeySignature` when tailnet
  lock is enabled (pass-through, unrebindable — stripped and annotated on
  replay) and, on a `MapRequest`, the `hardware_attestation` signature.
- **Disco key** and **hardware attestation key** — pass-through by
  default, mutable via `set_json` on the decoded body. Mutating the
  hardware attestation key invalidates `hardware_attestation`, which the
  sidecar rebinds on replay when configured with the key material
  (§4.6.2); the disco key carries no binding.
- **NL (tailnet-lock) `NodeKeySignature`** — pass-through by default. The
  sidecar **cannot re-sign it**: the signature is produced by the client's
  tailnet-lock key, whose private half the sidecar does not hold. Mutating
  `NodeKey` (or the signature itself) invalidates it; on replay it is
  **stripped and annotated** rather than rebound. It is intentionally not
  modeled as a rebindable binding (§4.6.2).

**Why both static keys must be sidecar-private.** The Noise IK
pattern binds each peer's static key into the handshake transcript
and uses it in the DH key exchange. A sidecar that wanted to pass
through the client's real machine key unchanged would need that
key's private half to complete the upstream handshake — which it
does not have. Holding the private half of both static keys (the
client-facing responder key, synthetic or borrowed, and the upstream
initiator key) is the only way for the sidecar to terminate both ends
of the Noise tunnel.

### 4.5 Inner HTTP/2 capture

The sidecar captures every inner HTTP/2 request generically as an
HTTP-shaped flow regardless of endpoint or method — `POST /machine/set-dns`,
`PATCH /machine/set-device-attr`, `GET /machine/ssh/action/...`,
`POST /machine/audit-log`, and any future endpoint are captured with no
per-endpoint logic. Only `/machine/register` (signature binding, §4.6.2)
and `/machine/map` (stream framing, §4.5.1) need special handling.

For each request/response pair the client issues on its side of the
tunnel:

1. The sidecar reads the HTTP/2 stream on the cleartext-client side.
2. The sidecar emits a `push_flow` (Spec 1 §6a.2) shaped as an HTTP
   flow with `protocol_tag = "tailscale.control"`,
   `method = "POST"`, `path = "/machine/register"` (or whichever
   endpoint), HTTP/2 pseudo-headers and regular headers carried in the
   `headers` array (pseudo-headers prefixed with `:` per Spec 1
   §3.1.1), and `body` set to the JSON request body.
   `parent_flow_id` is set to the tunnel envelope's `flow_id`.
3. The sidecar forwards the request on the cleartext-upstream side. If
   a rule mutation applies (delivered via Spec 1 §6b.1 `sync_rules`),
   the forwarded bytes are the mutated form. Per Spec 1 §11, the
   sidecar emits two paired flows per mutated message: `captured`
   (pre-mutation) and `mutated` (post-mutation).
4. The sidecar reads the response from the upstream side.
5. For non-streaming endpoints (`/machine/register`, non-streaming
   `/machine/map`), the sidecar emits a `push_flow` for the response
   (`direction=server_to_client`) and forwards it to the client
   (with any mutations applied).
6. For a streaming `/machine/map` (request body `Stream: true`, §2.4),
   the sidecar emits the stream parent via `push_flow` and proceeds per
   §4.5.1.

Because the captured flows are HTTP-shaped, agents use sectool's
existing tools without modification: `set_json` against
`body.Hostinfo.OS` mutates the parsed JSON body; `set_header` against
HTTP/2 headers works through the same mechanism; `diff_flow` between
two captured RegisterRequests yields a JSON-aware diff.

#### 4.5.1 MapResponse streaming

The MapResponse stream is a sequence of zstd-compressed JSON fragments
framed by 4-byte little-endian lengths
(`control/controlclient/direct.go:1303-1311,1494`). The sidecar:

1. Reads each frame as it arrives from upstream.
2. Decompresses the zstd payload to obtain the JSON fragment.
3. Applies any matching rules from the pushed rule list (Spec 1 §6b.1)
   to the decompressed JSON on the hot path, then emits a child
   `push_flow` (Spec 1 §6a.2, `parent_flow_id` set to the stream parent)
   with:
   - `direction = server_to_client`.
   - `body` containing the decompressed JSON.
   - `headers` carrying the original frame metadata
     (`X-Sectool-Compressed-Bytes` = base64 of the compressed frame,
     `X-Sectool-Compressed-Len` = original length prefix). The agent
     can inspect either form; sectool's standard tools operate on
     `body`.
   Children are emitted in arrival order; sectool preserves that order
   (Spec 1 §3.3), so no sequence number is carried. When a rule mutates
   the chunk, the sidecar emits the paired `captured` / `mutated`
   children per Spec 1 §11.
4. The sidecar re-encodes the (possibly mutated) JSON: recompress to
   zstd, prepend the updated 4-byte length, and write to the
   client-facing tunnel. This re-encoding is internal to the adapter and
   runs automatically whenever a chunk's JSON is mutated (hot-path rule or
   replay), §4.6.
5. On stream close (upstream sends end-of-stream, or either side
   tears down), the sidecar re-emits the stream parent via `push_flow`
   (two-phase, `completed_at` set) to record the close.

The MapResponse format does not permit out-of-order replay because chunks
share stateful zstd framing and incremental JSON deltas; the sidecar
forwards chunks in emission order on the hot path, and on replay rejects
`stream_strategy=collapsed` (Spec 1 §6b.2) so ordering is always
preserved.

### 4.6 Mutation surface

Agents mutate `tailscale.control` flows with the shared §3.4 request-mutation
grammar on `replay_send` — `set_header`, `remove_header`, `set_json`,
`remove_json`, `set_form`, `remove_form`, `body` — with the same UX as any
HTTP/2 flow. Spec 1 has no adapter-declared mutation ops; the
protocol-specific re-encoding and re-binding below are the adapter's
**internal** concern, applied automatically on replay (Spec 1 §6b.2) after
the logical mutations, not declared to sectool or invoked directly by agents:

- MapResponse chunk re-encode — on replay of a streamed MapResponse chunk
  the adapter re-encodes the mutated JSON to zstd and adjusts the frame
  length.
- `register_signature` rebind (§4.6.1) — recompute over the `tailscale.control`
  RegisterRequest.
- `hardware_attestation` rebind (§4.6.1).
- `map_session` rebind (§4.6.1).
- EarlyNoise pass-through (§4.6.1).

Note: machine-key selection is configured at tunnel-establishment time
(§4.4.1), not per message. Per-message machine-key references inside payloads
(e.g. the `MachineKey` field of an inner request) are mutated via the generic
`set_json` op against `body.MachineKey`.

#### 4.6.1 Concrete rebind operations

These are the sidecar's **internal** rebind operations, not ops declared to
sectool or invoked by agents (Spec 1 §6b.2). Each recomputes message
integrity after a field-level mutation or a replay-across-tunnels condition,
is referenced as the `rebind_op` for a binding in §4.6.2, and draws its key
material from the sidecar's connection-time configuration (§7.2). On replay
the sidecar runs them after all content mutations so they bind the final
message.

- **`resign_register_request`** (key material: `device_cert_path` /
  `device_key_path` from config, §7.2)
  — recomputes the SHA-256 hash over (`Timestamp`, `ServerURL`,
  `DeviceCert`, `serverPubKey`, `machinePubKey`) — server key **before**
  machine key — and re-signs with RSA-PSS/SHA-256 as `SignatureV2`
  (`control/controlclient/sign.go:24-42`,
  `control/controlclient/sign_supported.go:180-192`). `SignatureV2`
  hashes the full `key.MachinePublic` text of each key; the older
  `SignatureV1` used `ShortString` instead. With operator cert
  (`device_cert_path` and `device_key_path` set), produces a valid
  `SignatureV2` signature using the supplied device key and certificate
  chain. Without operator cert, the op **strips** `Signature`,
  `SignatureType`, and `DeviceCert` from the RegisterRequest body;
  the resulting flow annotation lists the stripped fields explicitly
  (`annotations.stripped_fields = [...]`,
  `annotations.binding = "register_signature"`,
  `annotations.reason = "no_operator_cert_configured"`). Upstream
  behavior to expect: a self-hosted control server such as Headscale
  typically accepts stripped signatures; production
  `controlplane.tailscale.com` may reject — operator picks the
  appropriate upstream for the test scenario. The hash binds the device
  cert, timestamp, and both handshake static keys but **not** `NodeKey`, so
  node-key mutations do not trigger this rebind; a cross-tunnel replay —
  which changes `serverPubKey` /
  `machinePubKey` — does. Re-signing uses RSA-PSS with
  `SaltLength = rsa.PSSSaltLengthEqualsHash` and `crypto.SHA256`; the five
  fields are concatenated with no separators and `Timestamp` is RFC3339 UTC
  at second granularity (`RegisterRequest.Timestamp` is a `*time.Time`).
- **`resign_hardware_attestation`** (key material: `hw_key_path` from
  config, §7.2) — recomputes
  `SHA256("<unix-seconds>|<nodekey:hex>")` per
  `control/controlclient/direct.go:1145-1161`, updates
  `MapRequest.HardwareAttestationKeySignatureTimestamp` to the current
  time, and re-signs with the operator-supplied hardware attestation
  private key. The attestation key is **ECDSA P-256** (not RSA-PSS);
  `<unix-seconds>` is the updated timestamp's whole-second Unix value and
  `<nodekey:hex>` the node key's full text form; the `…SignatureTimestamp`
  field stores the full-precision time while the hash binds only the
  seconds, so both must reference the same instant. Without `hw_key_path`,
  strips
  `HardwareAttestationKeySignature`,
  `HardwareAttestationKeySignatureTimestamp`, and
  `HardwareAttestationKey`; flow annotation lists the stripped fields
  and the reason.
- **`reset_map_session`** — clears `MapRequest.MapSessionHandle` and
  resets `MapRequest.MapSessionSeq` to `0`. Used when replaying a
  captured MapRequest as the start of a new session rather than
  resuming an existing one.
- **`forward_early_noise_verbatim`** — internal no-op confirming
  pass-through. Mutation of `EarlyNoise` content (including
  `NodeKeyChallenge`) is out of scope for v1; the sidecar records via
  per-flow annotations that EarlyNoise is observed but not mutated.

#### 4.6.2 Internal cryptographic bindings

The sidecar tracks the following bindings **internally** — they are not
declared to sectool (Spec 1 §6b.2); this table documents the sidecar's own
rebind map. All `bound_fields` paths reference the HTTP-shaped Flow's
`body` (JSON paths) or `headers` (named lookups).

| name | bound_fields | rebind_op |
|---|---|---|
| `register_signature` | `body.Signature`, `body.SignatureType`, `body.DeviceCert`, `body.Timestamp` (plus implicit deps on the tunnel's `serverPubKey` / `machinePubKey`, server key hashed first; `NodeKey` is **not** covered) | `resign_register_request` |
| `hardware_attestation` | `body.HardwareAttestationKeySignature`, `body.HardwareAttestationKeySignatureTimestamp`, `body.HardwareAttestationKey` (plus implicit dep on `body.NodeKey`) | `resign_hardware_attestation` |
| `map_session` | `body.MapSessionHandle`, `body.MapSessionSeq` | `reset_map_session` |
| `early_noise_challenge` | `body.NodeKeyChallenge` (on the tunnel envelope's EarlyNoise payload) | `null` (currently unused by Tailscale; future risk if Tailscale begins enforcing proof-of-possession) |

The sidecar resolves applicability per-flow while parsing each message:
`register_signature` applies to `/machine/register`, `hardware_attestation`
and `map_session` to `/machine/map`, and `early_noise_challenge` to the
tunnel envelope — so the two bindings sharing
`protocol_tag=tailscale.control` are distinguished by endpoint.

The tailnet-lock `NodeKeySignature` (§4.4.1) is deliberately **not** a row
in this table: it is pass-through only and unrebindable without the client's
tailnet-lock private key, so mutating `NodeKey` strips and annotates it
rather than triggering a rebind op.

On the forward (proxy) path a rule that mutates a bound field is forwarded
as-is (adversarial broken-binding testing). On `replay_send` the sidecar
rebinds automatically per its connection-time configuration (Spec 1 §6b.2):
re-signing when launched with the relevant key material, otherwise
stripping the bound fields and recording the strip in the flow's
`annotations`.

Worked example: an agent captures a `RegisterRequest` and replays it
through a **different** tunnel — different `serverPubKey` / `machinePubKey`,
e.g. the cross-adapter replay of §9.8. The sidecar recomputes
`register_signature` automatically — if launched with `device_cert_path` /
`device_key_path` the rebind produces a valid signature; otherwise it strips
`Signature` / `SignatureType` / `DeviceCert` and records the strip in
`annotations.stripped_fields`. Mutating `NodeKey` does **not** trigger this
rebind (the register signature does not cover the node key); it instead
invalidates the tailnet-lock `NodeKeySignature` (stripped, unrebindable) and,
on a `MapRequest`, `hardware_attestation`. To send a broken
`register_signature` deliberately, mutate `DeviceCert` or `Timestamp` on the
forward (proxy) path, where it is forwarded as-is.

### 4.7 Injection

The sidecar declares an `injection_target` schema:

- `tunnel_id` (required) — this adapter's field naming the `flow_id` of
  an active tunnel envelope (§4.8) emitted by this sidecar.
- `endpoint` (required) — one of: `/machine/register`,
  `/machine/map`, custom path.
- `method` (default `POST`) — any HTTP method is accepted; inner
  endpoints are not POST-only (e.g. `PATCH /machine/set-device-attr`,
  `GET /machine/ssh/action/...`).
- `headers` (optional).
- `body` (required) — agent-supplied JSON; the sidecar validates
  against the declared schema for the endpoint when one exists.
- `stream` (optional, default `false`) — true for streaming endpoints;
  the sidecar will emit the parent and child flows via `push_flow`
  (Spec 1 §3.3) for the response.
- `as_machine` (optional) — override the machine identity for this
  injection; sidecar opens a fresh Noise tunnel using the supplied
  identity if it differs from the tunnel's bound identity.
- `mutations` (optional) — array of mutation operations applied to the
  request before sending; useful for `set_json` on the body rather
  than constructing it whole.

Injection is driven through this `injection_target` — invoked either by a
sidecar-registered injection tool (Spec 1 §9.2) or by another adapter via
`invoke_adapter`, both dispatched to the sidecar as `sidecar_send` with no
base flow (Spec 1 §6b.2). When `tunnel_id` references an active tunnel, the
injection uses that tunnel. When the injection arrives without a matching
active tunnel, the sidecar opens a fresh Noise tunnel to the configured
upstream using the supplied (or auto-generated) machine identity
(performing the dial via `dial_upstream` as in §4.4); this is the
"fresh tunnel" mode useful for fuzzing registration.

### 4.8 Tunnel envelope details

Each tunnel envelope is a Flow (emitted via `push_flow`, Spec 1 §6a.2)
per Spec 1 §3.2 with:

- `protocol_tag = "tailscale.tunnel"`.
- `method = "TUNNEL"`.
- `path = "/tailscale.client.mitm/tunnel/<id>"`.
- `direction = bidirectional`.
- `headers` carrying:
  - `X-TS-Noise-Protocol`: e.g.,
    `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
  - `X-TS-Protocol-Version`: the negotiated 2-byte protocol version
    (§2.3.1) carried through from the client initiation to the upstream.
  - `X-TS-Handshake-Hash-Client`: BLAKE2s-256 of the client-facing
    handshake transcript.
  - `X-TS-Handshake-Hash-Server`: same for the upstream-facing tunnel.
  - `X-TS-Client-Facing-Server-Pubkey`: the substituted pubkey served
    to the client.
  - `X-TS-Server-Facing-Server-Pubkey`: the real upstream pubkey the
    sidecar handshook against.
  - `X-TS-Client-Machine-Pubkey`: the Tailscale client's declared
    static pubkey (decrypted from the IK handshake).
  - `X-TS-Sidecar-Machine-Pubkey`: the machine identity the sidecar
    used for the upstream Noise tunnel.
  - `X-TS-Client-Addr`, `X-TS-Upstream-Addr`: socket endpoints.
- `body` empty by default, or carries the EarlyNoise JSON when the
  upstream emits one. When forwarding EarlyNoise to the client the
  sidecar re-frames it with the big-endian magic/length form from
  §2.3.1 (distinct from the little-endian MapResponse frame length).

`completed_at` is set when the tunnel finally tears down: the envelope
is re-emitted via `push_flow` with the same `flow_id` (the two-phase
form, Spec 1 §6a.2).

---

## 5. Server-side control-server adapter

### 5.1 Process model

The server-side adapter is itself a sidecar process speaking the
sectool contract. It is a **standalone Tailscale-compatible control
server implemented by the adapter** — it matches the control protocol on
the wire and uses the upstream Tailscale source only as a reference, not
as a server library to extend or embed. Concretely the adapter:

- serves `GET /key?v=<n>` returning an `OverTLSPublicKeyResponse` carrying
  its own real Noise public key (§2.2); it parses the `v` capability-version
  query param (serving the Noise `publicKey` for any `v` at or above the
  Noise floor — Headscale serves it for `v ≥ 39`) and rejects a missing `v`;
- accepts the `POST /ts2021` Noise upgrade as the IK **responder** (§2.3),
  then speaks HTTP/2 inside the established tunnel;
- routes the inner `POST /machine/register` and `POST /machine/map`
  endpoints to its own handlers, plus any other inner endpoints it chooses
  to answer.

The adapter declares a minimum capability version it accepts and validates
the `Version` field on inbound `MapRequest` / `RegisterRequest` (Headscale's
reference floor is capability 113), rejecting older clients to mirror real
coordinator behavior.

It is built directly from the low-level Tailscale protocol primitives —
the `tailcfg` message types, the Noise IK handshake, the Noise-over-HTTP
accept step, and the zstd stream framing — so it stays protocol-faithful
without depending on any Tailscale or Headscale server implementation.
Because the adapter owns all of this server code, it can emit flows and
apply mutations at every protocol boundary symmetrically (§5.3); there are
no missing hook points to work around.

Unlike the client-side MITM sidecar, the server-side adapter is the actual
control endpoint clients connect to. It listens on a port the operator
configures and serves the Tailscale clients under test directly. Sectool
sits beside it for control-plane recording and mutation; sectool is not in
the TCP path between client and adapter.

Launch model: operator-attached or sectool-managed.

### 5.2 Registration

The adapter registers per Spec 1 §6a.1 with:

- `name`: `tailscale.server.control` (configurable).
- `protocols`: `["tailscale.control",
  "tailscale.control.map.stream"]`.
- `capabilities`:
  - `injection_target` — see §5.5.

The adapter is the source of truth for flows on this side (sectool does not
sit in the data path), emitting them via `push_flow`. Its protocol-specific
re-encoding/re-binding (§4.6) is internal to the adapter; tunnel-crossing
rebinds typically execute on the client-side MITM during replay.

The adapter performs no Noise MITM — clients handshake with it using its
own real keypair, well-known to the operator running the test deployment,
so it registers no tunnel envelope. Its cryptographic bindings are the
same as the client-side sidecar's (§4.6.2) and, as there, internal to the
adapter.

The server-side adapter emits flows and applies the pushed rule list: it
receives the list via `sync_rules` (Spec 1 §6b.1) and applies the rules it
can to its outbound responses inline on the hot path, and it originates
unsolicited messages via `injection_target` (§5.5). There is no interactive
per-message hold — adversarial scenarios are driven by operator-authored
rules, fault-injection config (§5.4), and injection.

### 5.3 Hook points

Because the adapter owns the server code, it emits a flow and applies the
pushed rule list at four **symmetric** protocol boundaries — there is no
asymmetry between the register and map paths, since the adapter inserts
each boundary itself rather than relying on whichever seams a third-party
server happens to expose:

- **Inbound `RegisterRequest`** — after the adapter deserializes the
  inbound request but before its business logic processes it.
- **Outbound `RegisterResponse`** — after the adapter constructs the
  response but before serialization to the wire.
- **Inbound `MapRequest`** — same pattern.
- **Outbound `MapResponse`** (single-shot or per stream chunk) — same
  pattern. For streamed responses, the hook fires per emitted MapResponse
  chunk: the adapter applies rules to the MapResponse **before it is framed
  and compressed for the wire** (it mutates the struct, then frames and
  zstd-compresses).

Each hook:

1. Builds a Flow with `protocol_tag=tailscale.control`,
   `method=POST`, `path=/machine/register` (etc.), `headers` carrying
   the HTTP/2 framing context, `body` set to the JSON form of the
   request/response struct (the JSON that *would* have been sent).
2. Applies any matching rules from the pushed rule list (Spec 1 §6b.1) to
   the `body` inline. When a rule mutates it, the adapter emits the paired
   `captured` / `mutated` flows per Spec 1 §11.
3. Calls `push_flow` per Spec 1 (parent then child flows for streams).
4. Re-decodes the (possibly mutated) `body` back into the typed struct and
   substitutes it before resuming the adapter's business logic (for
   inbound) or completing serialization (for outbound).

### 5.4 Configuration knobs

A configuration file controls per-endpoint behavior. All of these are
implemented by the adapter itself; the malformed-zstd and truncation faults
operate at the framing layer the adapter controls directly:

- `fault_injection`:
  - `dropped_response_probability` — probability of refusing to emit
    a response.
  - `response_delay_ms` — synthetic delay before responding.
  - `malformed_zstd_probability` — for MapResponse streams, emit
    structurally-invalid zstd framing at the given probability for
    error-handling testing.
  - `truncate_response_probability` — truncate response bodies at a
    configurable length.
- `acl_overrides` — operator-supplied ACL fragments injected into
  MapResponse to drive specific test scenarios.
- `peer_synth` — operator-supplied synthesized peers for the
  MapResponse `Peers` field.

### 5.5 Injection from this adapter

`injection_target.target_schema`:

- `node_id` (required) — which connected client to deliver to.
- `endpoint` (required) — which adapter endpoint's response to
  synthesize (`map`, `register`).
- `body` (required) — the response body content.
- `as_stream_chunk` (optional, default `false`) — push as a new child
  flow on an ongoing MapResponse stream rather than as a standalone
  response.
- `mutations` (optional) — applied to the body before delivery.

Use case: an agent can synthesize an unsolicited MapResponse update to
a connected client to test how the client reacts to specific
configurations it did not request.

### 5.6 Use cases

- **Adversarial peer lists.** Inject MapResponses containing invalid
  or malicious peer definitions; observe how the client validates and
  applies them.
- **ACL fuzzing.** Mutate the ACL section of MapResponse and observe
  client behavior under malformed ACLs.
- **Capability negotiation.** Mutate capability flags in
  RegisterResponse and observe client compatibility behavior.
- **Key-rotation races.** Drive multiple MapResponse updates that
  attempt to rotate keys, then observe whether the client correctly
  handles the race.
- **Stream-framing edge cases.** Use `malformed_zstd_probability` to
  test the client's framing-error recovery.

### 5.7 Combined harness

The client-side MITM sidecar and the server-side adapter can run
simultaneously against the same sectool instance:

- Tailscale client → sectool (TLS MITM + `/key` rewrite rule) →
  sectool synthesizes 101 for `/ts2021` → client-side MITM sidecar
  (Noise responder over the `stream_deliver`/`writes` stream) → client-side MITM
  sidecar (Noise initiator, dialing upstream via `dial_upstream`) →
  server-side adapter (the Tailscale-compatible control server, §5).
- Both adapters push flows; sectool unifies them in the timeline.
- Flows from either side are usable as `replay_send` bases. Useful
  for closed-loop testing: capture a MapResponse on the server-side
  adapter, mutate it, inject from the server-side, observe the
  client-side response, replay.

**Bindings are mirrored across adapters.** Both the client-side MITM and
the server-side adapter track the same bindings internally (§4.6.2 / §5.2),
because they are properties of the Tailscale protocol itself, not of a
specific capture point. A flow captured on one adapter and replayed
through the other — the destination adapter selected via `replay_send`'s
`target_override` (Spec 1 §6b.2) — is rebound by that destination adapter
automatically per its connection-time configuration. For example,
capturing a `RegisterRequest` on the server-side adapter and replaying it
through the client-side MITM crosses tunnels, so the client-side MITM
recomputes `register_signature` with its configured identity (re-signing
with the operator cert, or stripping when none is configured) before
forwarding upstream.

---

## 6. Mutation and replay semantics

### 6.1 Body-level mutations

JSON body fields on RegisterRequest, MapRequest, RegisterResponse,
and (single-shot) MapResponse are mutated via the standard `set_json`
/ `remove_json` operations against `body.<path>`. Agents specify
paths against the field names of the underlying `tailcfg` structs.

Examples (illustrative, agent-issued):

- `set_json path="Hostinfo.OS" value="darwin"` on a MapRequest.
- `set_json path="Hostinfo.Hostname" value="test-host"` on a
  MapRequest.
- `remove_json path="DNSConfig.Resolvers"` on a MapResponse.
- `set_json path="UserProfiles.0.DisplayName" value="injected"` on a
  MapResponse.

The adapter handles serialization back to JSON, recomputes the HTTP/2
body length, and adjusts headers as needed.

### 6.2 Streaming MapResponse

Two mutation paths exist, both decompressing each chunk to JSON first and
re-encoding to zstd internally (§4.5.1):

- **Hot path** — a pushed `response_body` rule (Spec 1 §6b.1) find/replaces
  over the decompressed chunk JSON; like any 7-type rule it applies to every
  chunk it matches, with no per-stream or conditional scoping.
- **Replay** — `replay_send` against a specific captured chunk flow
  (addressed by its own `flow_id`) applies the structured §3.4 grammar
  (e.g. `set_json`) to that one chunk; this is how an agent targets a single
  chunk or mutates conditionally.

Replay of a streamed MapResponse offers two strategies (Spec 1 §6b.2
`stream_strategy` parameter):

- `per_chunk` (default) — reconstruct chunk-by-chunk in emission order,
  applying mutations as they were observed; preserves the streaming
  framing as observed.
- `collapsed` — merge all chunks into a single non-streamed
  MapResponse, useful when the receiver tolerates that framing or
  when the agent wants to test framing tolerance.

### 6.3 Identity selection for replay

The machine identity the client-side MITM sidecar replays as is its
**connection-time configuration** (`machine_identity: auto|path|pool`,
§7.2), not a per-replay parameter. Whichever mode the sidecar was launched
with governs every replay it performs:

- **Original identity** (`path:<file>` holding the captured machine's
  key, supplied out of band) — the sidecar reuses the captured machine
  identity. The upstream control server may reject the replay due to
  nonce/sequence/replay-protection in its application layer; the failure
  is surfaced to the agent.
- **Fresh identity** (`auto`) — the sidecar mints a new identity. Useful
  for clean-room reproduction of a request.
- **Operator-supplied pool** (`pool:<directory>`, §4.4.1) — the sidecar
  selects from a configured identity pool.

Because identity is fixed at connection time, the consequent
`register_signature` rebind (§4.6.2) is performed automatically by the
sidecar; the agent supplies no identity parameter and makes no rebind
decision. `target_override` (Spec 1 §6b.2) carries destination routing
only.

### 6.4 Binding-aware replay

Replay across tunnels (or against a different upstream identity) goes
through the sidecar's internal bindings (§4.6.2) and their associated
rebind ops (§4.6.1). Per Spec 1 §6b.2, replay delegates to the owning
sidecar, which applies the mutation list and then rebinds each invalidated
binding automatically per its connection-time configuration — re-signing
when the required key material is configured, stripping and annotating
otherwise. sectool performs no evaluation and the agent makes no rebind
decision.

Fields not covered by any binding are assumed safe to replay verbatim. As
the Tailscale protocol evolves, the implementer updates the binding table
in §4.6.2; the sidecar's own registered introspection tools surface the
current enumeration. A binding without a `rebind_op` (e.g.,
`early_noise_challenge`) is recorded in the replayed flow's `annotations`
as unrecoverably broken so the operator sees the state explicitly rather
than as a silent corruption.

### 6.5 Replay safety knobs

The adapter exposes a `replay_safe_mode` configuration:

- `dry_run` (default for replay against production endpoints) —
  perform all local construction and emit the resulting flow, but
  do not actually transmit upstream.
- `live` — actually transmit. The operator must explicitly opt in
  per session.
- `confined` — transmit only if the destination is a configured test
  endpoint (the server-side adapter, a self-hosted Headscale, or other
  vetted control server).

---

## 7. Configuration and deployment

### 7.1 Test client setup

For the client to be MITM-able:

1. Install sectool's fake CA into the client's TLS trust store
   (existing process, unchanged).
2. Direct the client's control traffic at sectool:
   - For **tsnet** test clients: set the control URL programmatically
     via the existing `tsnet.Server` API. Point at the sectool
     listener (typically `https://controlplane.tailscale.com` with
     DNS or `/etc/hosts` redirection to the sectool host, or directly
     at sectool's listener address).
   - For **tailscaled**: set the control URL via `tailscale up
     --login-server=https://<sectool-host>` or the equivalent env
     var, or use a transparent-proxy network namespace that routes
     traffic to sectool.

### 7.2 Client-side sidecar configuration

The sidecar never opens listening sockets. All client and upstream
bytes flow via RPC from sectool as `stream_open` / `stream_deliver` events and
Response `writes` (Spec 1 §4.2). Fields in the sidecar's configuration
file:

- `sectool.socket`: resolved from sectool config (default
  `~/.sectool/config.json`, or `--config`); override with the
  `--sidecar-socket` flag. No value needed for the default case.
- `control_hosts`: list of host patterns to claim. Default
  `["controlplane.tailscale.com"]`. Configurable to include Headscale
  instances or custom coordinators.
- `upstream_overrides`: optional map of host pattern to upstream
  address. Lets the sidecar's `dial_upstream` calls go to a different
  upstream than the host the client thinks it is talking to (useful
  for routing test traffic to a controlled coordinator).
- `key_strategy`: `substitute` (default) | `borrow` (§4.4.1). Under
  `substitute` the sidecar mints/serves its own keypair and serves it to the
  client as the substitute trust anchor (operator `/key` rule or sidecar-
  internal, §4.3); under `borrow` it serves the operator-supplied real server
  key with no substitution (valid only against an operator-controlled
  upstream).
- `noise_keypair_path`: under `substitute`, optional persistent location for
  the substituted Noise keypair (default ephemeral per startup); under
  `borrow`, the path to the real upstream server's Noise private key
  (required).
- `device_cert_path` / `device_key_path`: optional device certificate and
  key used to rebind `register_signature` on replay (§4.6.1). Absent, the
  signature fields are stripped and annotated.
- `hw_key_path`: optional hardware-attestation private key used to rebind
  `hardware_attestation` on replay (§4.6.1). Absent, the attestation fields
  are stripped and annotated.
- `machine_identity`: `auto` | `path:<file>` | `pool:<directory>`.
- `replay_safe_mode`: `dry_run` | `live` | `confined`. Default
  `dry_run`.

### 7.3 Server-side adapter configuration

Fields:

- `sectool.socket`: same config-derived resolution as §7.2.
- `listen_address`: where the embedded Tailscale-style control
  server listens (this is the only socket the server-side adapter
  opens, and it is its own design boundary, not a sidecar-contract
  socket).
- `noise_keypair_path`: persistent Noise keypair for the embedded
  control server (clients must trust this key).
- `endpoint_modes`: per-endpoint fault-injection settings per §5.4.
- `peer_synth`, `acl_overrides`: per §5.4.

### 7.4 Combined harness

A one-command launcher script (or `make` target) brings up:

1. Sectool with the native proxy.
2. The client-side MITM sidecar registered against sectool.
3. The server-side adapter registered against sectool.
4. A target Tailscale client (`tsnet` for in-process testing, or a
   `tailscaled` container).

All four components share a generated set of Tailscale identities and the
sectool socket path emitted by the launcher into a session directory, and
the script prints the relevant sectool flow URLs and MCP endpoints for the
operator to begin testing.

---

## 8. Limitations and known issues

- **First-contact only.** A client that has already cached
  `serverNoiseKey` from a prior `/key` fetch will not refetch; the
  rule-based substitution must be active at the first `/key` call
  after process start. Operators should restart the target client
  after launching the harness.
- **DERP and WireGuard out of scope.** The data plane is not visible.
  Sidecars covering DERP or the WireGuard tunnel are separately
  specifiable but not part of this document.
- **Future Tailscale changes that pin the control pubkey out of
  band** (env-var-supplied, embedded constant, or signed manifest
  validated at the application layer) would defeat the `/key`
  substitution. The sidecar must detect handshake failures and
  report them to the agent rather than silently dropping
  interception.
- **Registration replay has external side effects** on the upstream
  coordination server (creates nodes, consumes auth keys, triggers
  webhooks). The `replay_safe_mode` knob (§6.5) defaults to
  `dry_run` to prevent accidental production impact.
- **Operator-supplied machine identity may conflict upstream.** When
  `machine_identity` is set to a key previously registered with a
  different node profile (hostname, capabilities), the upstream
  coordination server may reject the registration or replace the
  prior record. Use a fresh identity unless re-registering against a
  test upstream the operator controls.
- **Replay across tunnels and identities** is governed by the sidecar's
  internal bindings (§4.6.2) and their rebind ops (§4.6.1). Fields tracked
  by a binding without a usable `rebind_op` (e.g., `early_noise_challenge`,
  or `register_signature` when no operator device cert is configured) are
  stripped, and the strip path emits diagnostic annotations listing the
  affected fields and the upstream behavior to expect.
- **EarlyNoise payload.** If the upstream emits an EarlyNoise
  payload, the sidecar forwards an EarlyNoise payload to the client.
  The simplest implementation forwards the upstream payload
  verbatim. Mutation of EarlyNoise content is an explicit extension
  and is out of scope for v1.
- **Sidecar binary is Linux-only.** The sectool side of the contract
  is fully cross-platform; the Tailscale sidecar is constrained by
  its upstream Go dependencies.
- **Tailnet-lock `NodeKeySignature` is pass-through.** It is present
  only when tailnet lock is enabled on the tailnet (uncommon in test
  tailnets), the sidecar cannot re-sign it (it lacks the tailnet-lock
  private key), and mutating `NodeKey` strips it with a diagnostic
  annotation rather than rebinding (§4.4.1, §4.6.2).

---

## 9. Verification

### 9.1 Unit-level

- Noise IK responder and initiator interop tests against Tailscale's
  own `controlbase` test vectors. Confirm the sidecar can complete a
  handshake as both initiator and responder against a reference peer.
- JSON-RPC contract tests against a sectool stub: register, push
  flow (parent and child flows for streams), `dial_upstream`, and the
  `stream_open` / `stream_deliver` → Response `writes` byte echo.
- Internal rebind-operation tests (§4.6.1) against synthetic HTTP-shaped
  flows: each binding re-signs with configured key material and strips +
  annotates without it.
- `sync_rules` round-trip: receive a pushed rule list, apply a matching
  `response_body` rule on the hot path, and confirm the `applied_version`
  ack matches the `snapshot_version`.

### 9.2 End-to-end client-side

1. Stand up an unmodified open-source Headscale instance as the
   upstream control server.
2. Configure a `tsnet` test client to use the Headscale control URL
   with sectool as the HTTPS proxy.
3. Install sectool's fake CA in the test client's trust store.
4. Launch sectool with the client-side MITM sidecar under `substitute`
   (internal `/key` substitution), or add the operator `/key` rule (§4.3).
5. Start the test client; observe in sectool history:
   - The client-facing `/key` request/response flow with the response
     body's `publicKey` field substituted; the original is visible in the
     `captured` flow of the captured/mutated pair (Spec 1 §11).
   - The `POST /ts2021` request flow and synthesized 101 response.
   - The tunnel envelope flow with handshake metadata.
   - The `POST /machine/register` request and response flows as
     `protocol_tag=tailscale.control`.
   - The streaming `POST /machine/map` flow (request body `Stream:
     true`) with chunk sub-flows.
   - An upstream-side `dial_upstream` annotation noting the sidecar's
     real-pubkey fetch and upstream Noise dial.
   - The sidecar's own upstream `/key` fetch flow (`invoked_by` the
     sidecar), whose `publicKey` is the **real** upstream key, not the
     substitute — confirming the direct fetch is outside the client-facing
     substitution rule's scope.
6. Add an operator rule (regex find/replace on the request body) that
   rewrites the `Hostinfo.OS` value to `darwin`, applied to the next
   MapRequest on the sidecar hot path. (A structured `set_json` edit of the
   same field is also available via `replay_send`.)
7. Confirm Headscale's logs show the mutated `OS` field arriving on
   its side.
8. Confirm the test client subsequently registers as a `darwin` host
   in Headscale's records.

### 9.3 End-to-end server-side

1. Replace Headscale in the §9.2 setup with the server-side adapter
   from this spec.
2. Pre-register a rule via `proxy_rule_add` — `set_json path="Peers.-1"`
   (append) injecting a synthetic peer — scoped to
   `protocol_tag=tailscale.control` / `path=/machine/map`, so the adapter
   applies it inline when it builds each `MapResponse`. (Alternatively
   synthesize an unsolicited `MapResponse` via `injection_target`, §5.5.)
3. Start a real `tailscaled` (in a container) against the server-side
   adapter (no MITM sidecar in this configuration — the client trusts
   the adapter's Noise key directly).
4. When `tailscaled` issues `MapRequest`, observe the captured flow and
   the paired `captured` / `mutated` `MapResponse` flows in sectool.
5. Observe that `tailscaled` applies the mutated map (e.g., a new peer
   appears in `tailscale status`).

### 9.4 Combined

1. Bring up the combined harness from §7.4: sectool + client-side
   MITM sidecar + server-side adapter + target client.
2. Confirm the unified history contains:
   - `/key` flow with rule-driven substitution applied.
   - Tunnel envelope from the MITM sidecar.
   - HTTP/2 inner flows captured from the MITM sidecar.
   - The corresponding HTTP/2 inner flows captured on the server-side
     adapter, with matching content modulo any mid-path mutations.
3. Confirm replay of any of these flows works using `replay_send`,
   with the operator's choice of identity mode and safe mode.
4. Confirm rules applied at registration are honored by both adapters
   on the hot path (`sync_rules` reaches both).

### 9.5 Diagnostics

- Negative test: replace the sidecar's substituted pubkey with a
  malformed value (e.g., a deliberate base64 corruption) at startup.
  Observe that the subsequent Noise handshake fails and the sidecar
  emits a diagnostic flow naming the failure mode; confirm the rest
  of the pipeline degrades gracefully.
- `dial_upstream` scope rejection: configure `exclude_domains` to
  include `controlplane.tailscale.com`, attempt a connection, confirm
  the sidecar receives a JSON-RPC scope-rejection error on
  `dial_upstream` and emits a diagnostic flow.

### 9.6 Binding invalidation

1. With the client-side MITM and the server-side adapter (or any
   Tailscale-compatible upstream) running, capture a `RegisterRequest`
   from the test client.
2. Apply `set_json path="Hostinfo.OS" value="darwin"` via
   `proxy_rule_add` and re-trigger the registration. `Hostinfo.OS` is
   not a bound field (§4.6.2), so nothing is rebound. Confirm the upstream
   accepts the request and the resulting Map view reflects
   `OS = "darwin"`.
3. Apply `set_json path="NodeKey" value="<fresh node key>"` and
   re-trigger. On a tailnet **without** tailnet lock, **no** RegisterRequest
   signature binds `NodeKey` — `register_signature` does not cover it
   (§4.6.2) — so confirm the mutated request is forwarded and accepted with
   the substituted node key (node-key rotation/impersonation testing, not a
   broken-signature test). On a tailnet **with** tailnet lock, confirm the
   pass-through `NodeKeySignature` is now invalid and is stripped and
   annotated on replay (the sidecar cannot re-sign it, §4.4.1).
4. To exercise a `register_signature` rebind, mutate a field the signature
   **does** cover (`set_json path="Timestamp"` or `set_json
   path="DeviceCert"`) or replay across tunnels (§9.8), then issue
   `replay_send`. The client-side MITM recomputes `register_signature`
   automatically per its connection-time configuration — no warning and no
   agent rebind decision.
5. Confirm the replay outcome: with the sidecar configured with
   `device_cert_path` / `device_key_path`, the replay produces a valid
   `SignatureV2` signature; without it, `Signature` / `SignatureType` /
   `DeviceCert` are stripped and the flow records the strip in
   `annotations.stripped_fields`.
6. On a streaming `/machine/map` capture, apply `set_json path="NodeKey"`
   and replay: confirm the sidecar rebinds `hardware_attestation` (the
   MapRequest binding that **does** cover the node key) when launched with
   `hw_key_path`, otherwise strips and annotates it.

### 9.7 Rule sync round-trip

1. With the combined harness running, capture a few inner HTTP/2
   flows.
2. Call `proxy_rule_add` to add a `set_json` rule. Confirm both the
   client-side MITM and the server-side adapter receive an
   `sync_rules` push with an incremented `snapshot_version`.
3. Trigger a new request from the client. Confirm both adapters emit
   paired captured + mutated flows (per Spec 1 §11), the mutated
   flow's `fired_rules` includes the new rule_id, and each adapter's
   `sync_rules` ack returned `applied_version` equal to the latest
   `snapshot_version`.
4. Delete the rule, confirm `sync_rules` is re-pushed with the
   updated `snapshot_version`, and confirm subsequent requests are
   not mutated.
5. Confirm the `/key` substitution is operator-configured (a user rule
   scoped to `adapter=http/1.1`, or handled internally by the sidecar) —
   it is an ordinary user rule with no special delete protection.

### 9.8 Cross-tunnel replay with auto-rebind

1. Capture a `RegisterRequest` on the server-side adapter (path:
   client → server-side adapter, no MITM tunnel).
2. Call `replay_send` with `target_override` selecting the client-side
   MITM sidecar as the destination adapter. This crosses tunnels
   (different `serverPubKey` and `machinePubKey` on the destination
   side).
3. Confirm the client-side MITM sidecar rebinds `register_signature`
   automatically per its connection-time configuration — no sectool
   warning or agent decision.
4. Confirm the resulting upstream `RegisterRequest` has either a valid
   signature (operator cert configured) or a stripped signature plus
   diagnostic annotations listing the stripped fields and reason.
