# Agent Note: OIDC Principal request context

Status: implemented

English | [中文](2026-08-29-oidc-principal-request-context.zh.md)

## Problem

The browser launch-token session authenticates one local Browser installation but does not identify a human user. A Host business service that approves, exports, administers, or separates duties cannot derive a verified person from a launch cookie, request payload, anonymous harness-home id, operating-system user, or caller-selected header. Passing identity through Remote arguments would let the Browser choose its own authority, while authenticating only unary calls would leave exact Fetch and WebSocket streams under different rules.

## Decision

DSH exposes authenticated user identity through the Host-only Principal capability. `dsh-principal` defines an immutable Principal, a deployment `PrincipalProvider`, and `PrincipalContextService`, whose `AsyncLocalStorage` scopes one verified context to an asynchronous request chain. The opaque `principalId` is derived only from the exact verified issuer, a NUL delimiter, and subject. Display name and verified email are presentation fields and do not participate in identity.

`dsh-client-connection` owns carrier authentication. Its default `legacy` mode preserves launch-token behavior. `principalMode: required` runs the Host/Origin fence first, requires both Principal services, authenticates before payload decoding, and enters the Principal context around unary Remote and exact Fetch handlers. Missing identity returns 401; a missing or failed provider returns 503. Browser payloads and identity-like headers never populate the context.

`dsh-api-gateway` binds the authenticated context to one accepted WebSocket generation. Every logical stream opens and advances inside that context. The mux combines stream cancellation with the session invalidation signal, periodically asks Connection to revalidate the same generation, and closes the socket when identity expires, is revoked, or cannot be revalidated. Reconnection performs a new physical-request authentication.

`dsh-principal-oidc` is the deployment Service Provider. It uses Authorization Code with S256 PKCE, exact issuer discovery, state and nonce, asymmetric ID Token verification, and access-token introspection against a separately configured resource audience and OAuth `client_id`, plus bounded one-time transactions and bounded process-local sessions. Tokens and original claims stay in the provider map; the Browser receives only an opaque host-only cookie, and Host consumers receive only the verified Principal projection. RP-initiated logout and signed replay-safe back-channel logout invalidate matching active contexts.

## Verification

Package tests pin exact issuer-and-subject identity derivation, display-name independence, concurrent context isolation, expiry, invalidation, discovery, PKCE, state, nonce, issuer, audience, signature, token expiry, opaque cookies, provider failure, introspection revocation, RP logout, and signed back-channel logout. Connection Host tests prove one Host-created context reaches unary and exact Fetch dispatch while forged identity fields are ignored. Gateway carrier tests prove WebSocket generation binding, periodic revalidation, active-stream cancellation, and 401/403/503 rejection without exposing handler errors.

## Alternatives considered

**Use Browser-supplied actor or role fields.** A caller could select another identity or elevate a role before the Host operation that needs the decision. Identity is established before payload decoding and remains absent from the wire request schema.

**Treat the anonymous harness-home id or launch cookie as a person.** Both identify an installation or bearer session, not a verified human subject. They remain valid for their existing local correlation and legacy-browser purposes but cannot satisfy named-user or separation-of-duty policy.

**Replace launch-token authentication globally.** Existing local DSH profiles do not require an external issuer. An explicit Connection mode preserves that supported workflow while deployments that need named identity fail closed unless their Principal Provider is present.

**Pass OIDC tokens through Connection and business handlers.** This would spread bearer credentials and provider-specific claims across transports and consumers. The provider retains protocol material and emits only the minimal Principal context plus expiry and invalidation facts.

## Consequences

One authentication result governs unary Remote, exact Fetch, WebSocket upgrade, and every logical stream. Business packages can require a Principal without importing an OIDC implementation, and provider loss cannot silently downgrade a required deployment to launch-token identity.

Sessions are process-local and require login after a Host restart. The provider requires issuer introspection and exact public application authority; it does not define reverse-proxy header trust, token refresh, multi-issuer selection, durable sessions, or authorization policy. Those omissions keep identity proof separate from deployment topology and business permissions.

This decision complements the [browser launch-token authentication](2026-08-24-browser-token-authentication.md) decision. That note remains authoritative for legacy mode and the Host/Origin fence; required Principal mode replaces only the identity mechanism selected by an explicit deployment configuration.
