---
description: "Host-authenticated Principal types, provider definition, and request-scoped execution context for DSH services."
kind: "package-reference"
---

# @deepseek-ai/dsh-principal

English | [中文](README.zh.md)

## Summary

This package defines the Host identity used by authenticated DSH deployments. A `Principal` is created only after an identity protocol verifies an exact issuer and subject. `PrincipalContextService` binds that identity to one asynchronous request chain, while `PrincipalProvider` lets a deployment authenticate and revalidate requests. Browser payloads, query parameters, and caller-selected headers are not Principal sources.

## Table of Contents

- [Use this package](#use-this-package)
- [Runtime contract](#runtime-contract)
- [Further Exploration](#further-exploration)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-package"></a>
## Use this package

Load this package before a Principal Provider and configure `dsh-client-connection` with `principalMode: required`. Connection authenticates the physical request before decoding Remote or Fetch payloads, then enters `ctx.principals` while the Host handler runs. Consumers call `ctx.principals.require()` at the operation that needs authenticated identity; absence, expiry, or invalidation throws a stable 401 error.

The stable `principalId` is the SHA-256 digest of the exact verified issuer, a NUL delimiter, and the verified subject. Display name and verified email are optional presentation fields and never change the id.

<a id="runtime-contract"></a>
## Runtime contract

- `PrincipalProvider.authenticate()` returns a Host-created context with an expiry and invalidation signal.
- `PrincipalProvider.authorizeIndex()` either authorizes index serving or owns the login or failure response.
- `PrincipalProvider.revalidate()` confirms that an established WebSocket generation remains active; the authenticated context's `revalidateIntervalMs` owns that cadence independently of network heartbeat timing.
- `PrincipalContextService.run()` isolates concurrent asynchronous request chains with `AsyncLocalStorage`.
- `PrincipalAuthenticationError` exposes only stable 401 or 503 status and code values; protocol claims and tokens do not enter the error.

<a id="further-exploration"></a>
## Further Exploration

- [identity group map](../README.md) — distinguishes authenticated Principal identity from anonymous installation correlation.
- [dsh-principal-oidc](../principal-oidc/README.md) — the OIDC Service Provider.
- [dsh-client-connection](../../client/connection/README.md) — authenticates carriers and propagates the Host context.
- [Web server subsystem](../../../docs/subsystems/web-server.md) — generated Principal and Connection API reference.

<a id="model-experience"></a>
## Model Experience

None, as Principal state is Host-only request metadata and adds no prompt, tool, event, or model-visible text.

#### KV Cache effect

None; authenticated request context does not alter the model-visible prefix.

## Known Limitations and Deferred Work

<a id="known-limitations-and-deferred-work"></a>

- **No identity protocol** — this package defines and scopes identity but cannot authenticate a user without a deployment Principal Provider.
- **Process-local request context** — `AsyncLocalStorage` does not cross worker, process, or network boundaries; each carrier must establish a new verified context.
- **No authorization policy** — Principal authentication proves who the caller is, not which business resources or operations that caller may access.
- **Legacy mode has no named Principal** — Connection's legacy launch-token mode remains compatible with local DSH use but does not populate `ctx.principals`.

<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

None.

</details>
