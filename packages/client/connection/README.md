---
description: "Browser-host wire layer for the web GUI: Remote RPC, event-stream delivery with reconnect, exact Fetch routes, the /api HTTP bridge, and the browser-trust fence."
kind: "package-reference"
---

# @deepseek-ai/dsh-client-connection

English | [中文](README.zh.md)

## Summary

The package carries browser-to-Host Remote calls, exact Fetch responses, and connection generations. The Client plugin mounts `ctx.connection` with current-page loopback state, a generic RPC carrier, the active generation and its Host facts, and the registration point for one generation source. The Host plugin applies either legacy launch-token authentication or required Principal authentication consistently across each carrier. A generation becomes visible when its source reports ready; source completion, failure, withdrawal, or an explicit stop clears it before `ConnectionController` reconnects with backoff.

## Table of Contents

- [Use this package](#use-this-package)
- [Browser authentication and request trust](#browser-authentication-and-request-trust)
- [Connection generation](#connection-generation)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-package"></a>
## Use this package

The browser uses HTTP POST for Remote unary calls. API Gateway owns the `/api/remote.mux` WebSocket and its logical streams; in-process compositions provide equivalent Remote streams through `connection.rpc.open` without opening a WebSocket. The Host half owns the sole `/api` route, Fetch bridge, browser authentication, Host/Origin checks, and exact `GET`/`HEAD` route registry. Typert Gateway claims generated Remote endpoints, feature packages register non-JSON responses such as Session-log downloads, and unclaimed requests return 404. Set `principalMode: required` only in a composition that mounts `dsh-principal` and one deployment Principal Provider; the default `legacy` mode retains the launch-token flow. Loopback hostname classification remains package-internal to the browser-facing Client state.

-----

<a id="browser-authentication-and-request-trust"></a>
## Browser authentication and request trust

Connection applies one configured authentication mode to unary Remote, exact Fetch, and WebSocket upgrade requests; there is no method-specific loopback tier. In the default `legacy` mode, each process mints a random launch token. `dsh-web-app` prints and opens the ordinary root URL with `?token=...`; `frontend-static` delegates root and index requests to `ctx.connection.authorizeIndex`, which accepts that token only on `GET /`, writes an authority-bound signed cookie, and redirects to clean `/`. A missing, expired, malformed, or wrong-authority cookie returns 401 before dispatch. Static assets remain public. The HTTP carrier accepts no query token outside the root exchange and no Authorization-header token.

In `principalMode: required`, Connection delegates index authorization, physical-request authentication, and active-generation revalidation to the Host `PrincipalProvider`. It rejects a missing or failed provider with 503 and an unauthenticated caller with 401 before decoding or dispatching business payloads, then runs handlers inside the provider-created `ctx.principals` context. The legacy cookie signing secret remains the owner-scoped `client-connection/browser-session` grant record in `ctx.credentials`; the local provider persists it in `$DSH_HOME/.credentials.yaml`, and `cookieMaxAgeDays` defaults its absolute lifetime to 30 days. Legacy cookies bind normalized hostname and port, are host-only, `Path=/`, `HttpOnly`, and `SameSite=Strict`, and omit `Secure` because the shipped server uses loopback HTTP.

Before authentication, every request still passes `src/api-request-trust.ts`. Its `Host` must be loopback or match a `trustedHosts` entry: exact on `host:port`, any port on port-less entries, both sides WHATWG-normalized. An attached `Origin` must equal that Host and `sec-fetch-site: cross-site` is refused. Malformed configured authorities fail plugin load. These checks defend DNS rebinding and cross-site browser requests; they never establish identity. A failed Host/Origin check returns 403, while a trusted but unauthenticated request returns 401. `dsh web --host 0.0.0.0` remains unsupported. Decision records: [browser request trust](../../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.md) and [browser token authentication](../../../.agents/notes/implemented/architecture/2026-08-24-browser-token-authentication.md).

<a id="connection-generation"></a>
## Connection generation

API Gateway Client registers the internal `$events` logical stream as the sole generation source, independently of whether any `$on` listener exists. The Host attaches all incremental listeners in the API Remotes source factory, then sends one `{ type: 'ready', clientId, host: { home } }` item before events. `ConnectionController` publishes that generation and calls `onConnected` only after the ready item arrives, so baseline acquisition cannot race ahead of incremental observation.

An ended `$events` stream, a Remote stream error, a non-ready opening item, or a malformed event item invalidates the current generation. The controller immediately withdraws the generation, publishes `reconnecting`, and reopens `$events` after backoff. Gateway mux reconnects the physical WebSocket; Connection generation reopens the logical stream and establishes the next baseline starting point.

<a id="model-experience"></a>
## Model Experience

None, as the wire consumer layer moves already-composed messages between browser and host; nothing here reaches a model request.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

<a id="known-limitations-and-deferred-work"></a>

- **The `/api` bridge buffers each request body in memory** — `maxRequestBodyBytes` (default 300 MiB, sized for the default 200 MiB aggregate image limit after base64 expansion plus envelope headroom) is therefore also the per-request resident bound; a streaming body path would be needed to lower it without shrinking the image limits.
- **The legacy browser cookie is not marked `Secure`** — loopback HTTP is the shipped transport, so exposing the same authority over plaintext networking can expose the bearer cookie in transit.
- **Legacy mode has no logout operation** — clearing the browser cookie ends one browser session; deleting the owner credential record and restarting `dsh` revokes every legacy session. Required mode delegates logout semantics to its Principal Provider.


<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

None.

</details>
