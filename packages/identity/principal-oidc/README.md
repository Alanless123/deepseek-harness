---
description: "Host-only OpenID Connect Principal Provider with PKCE, opaque sessions, introspection, and logout invalidation."
kind: "package-reference"
---

# @deepseek-ai/dsh-principal-oidc

English | [中文](README.zh.md)

## Summary

This package implements `PrincipalProvider` with OpenID Connect Authorization Code + PKCE. It discovers one exact issuer, validates the authorization response and ID Token, introspects the access token, and stores tokens only in a bounded process-local session map. The Browser receives a random opaque `HttpOnly` cookie; Host handlers receive only the minimal verified Principal context.

## Table of Contents

- [Configuration](#configuration)
- [Security and lifecycle](#security-and-lifecycle)
- [Further Exploration](#further-exploration)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="configuration"></a>
## Configuration

| Key | Meaning |
|---|---|
| `issuer`, `clientId`, `accessTokenAudience`, `redirectUri` | Exact OIDC authority, registered client, required access-token resource audience, and callback URI |
| `clientSecret` | Required confidential-client secret; missing or empty configuration fails provider activation |
| `postLogoutRedirectUri` | Same-origin destination after RP-initiated logout |
| `scopes`, `signingAlgorithm` | Requested scopes including `openid`, and the allowed asymmetric JWS algorithm |
| `revalidateIntervalSeconds`, `sessionMaxAgeSeconds` | Introspection cache interval (capped at 60 seconds for active contexts) and absolute Host session lifetime |
| `transactionTtlSeconds`, `maxTransactions`, `maxSessions` | Bounds for one-time login state and process-local sessions |
| `logoutPath`, `backchannelLogoutPath` | Exact routes for RP and signed back-channel logout |
| `allowInsecureHttp` | Explicit development escape hatch restricted to loopback issuer and application URLs |

Load `dsh-principal` first, load this provider with all deployment values, and set Connection to `principalMode: required`. Discovery or route-registration failure aborts plugin activation. A missing or failed provider returns 503 before business dispatch.

<a id="security-and-lifecycle"></a>
## Security and lifecycle

Login transactions carry one-time state, nonce, and S256 PKCE verifier material under an opaque callback cookie. The callback requires the exact configured application authority and path, validates the ID Token against `clientId`, validates the introspected access token against the separate `accessTokenAudience` plus `client_id`, issuer, subject, and expiry, and then discards the transaction. Session cookies are host-only, `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS.

Local logout removes the opaque session and invalidates active requests before redirecting to the issuer. Signed back-channel logout validates issuer, audience, algorithm, age, event, session target, and replay-safe `jti`; matching HTTP and WebSocket contexts abort immediately, and a bounded target tombstone prevents an older in-flight callback from recreating the logged-out session. Periodic introspection failure invalidates the session and fails closed as 401 for inactive identity or 503 for provider unavailability, including transient OAuth responses and client timeout or abort failures. The Provider publishes a revalidation cadence of at most 60 seconds on each authenticated context; Gateway uses that value for logical WebSocket streams instead of coupling identity checks to the physical network heartbeat.

<a id="further-exploration"></a>
## Further Exploration

- [identity group map](../README.md) — package ownership and the anonymous identity distinction.
- [dsh-principal](../principal/README.md) — the Service Definition and request context consumed by this provider.
- [Web server subsystem](../../../docs/subsystems/web-server.md) — Principal, Connection, and WebSocket propagation API.
- [Browser launch-token authentication](../../../.agents/notes/implemented/architecture/2026-08-24-browser-token-authentication.md) — the legacy local-browser mode retained alongside required Principal mode.

<a id="model-experience"></a>
## Model Experience

None, as OIDC protocol material, cookies, tokens, and Principal claims remain outside model-visible state.

#### KV Cache effect

None; authentication changes neither prompt tokens nor the model-visible prefix.

## Known Limitations and Deferred Work

<a id="known-limitations-and-deferred-work"></a>

- **Process-local sessions** — a Host restart requires a new OIDC login; sessions are not shared across replicas.
- **Introspection is required** — the discovered issuer must expose a working introspection endpoint, including for access tokens that are JWTs.
- **No refresh-token lifecycle** — session expiry is capped by the ID Token, access token, introspection response, and configured maximum; the provider does not refresh tokens.
- **Exact public authority** — the provider does not interpret forwarding headers or define a reverse-proxy trust policy.
- **No dynamic issuer set** — one plugin instance authenticates against one exact configured issuer and client.

<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

None.

</details>
