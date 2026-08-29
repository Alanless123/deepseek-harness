---
description: "The identity package group: anonymous installation correlation plus Host-authenticated Principal and OIDC services."
kind: "package-group"
---

# identity/ — installation and authenticated identity

English | [中文](README.zh.md)

## Summary

The identity group owns two distinct identity domains. `anonymous-user-id` correlates records from one harness home without identifying a person. `principal` and `principal-oidc` authenticate a named Host user and bind that Principal to request execution without accepting identity from Browser payloads. Package READMEs own each domain's configuration, security properties, and limits.

## Table of Contents

- [Packages](#packages)
- [Related documentation](#related-documentation)
- [Dev Note](#dev-note)

<a id="packages"></a>
## Packages

| Package | Role |
|---|---|
| [`anonymous-user-id`](anonymous-user-id/README.md) | Gives every harness home one anonymous id that telemetry, feedback, and DeepSeek requests attach to their records, so records from one installation can be recognized without identifying the user |
| [`principal`](principal/README.md) | Defines verified Principal identity, request-scoped Host context, and the deployment Principal Provider service |
| [`principal-oidc`](principal-oidc/README.md) | Implements the Principal Provider with Authorization Code + PKCE, opaque Host sessions, introspection, and logout invalidation |

<a id="related-documentation"></a>
## Related documentation

- [Session telemetry subsystem](../../docs/subsystems/session-telemetry.md) — the telemetry feature that carries the id on exports.
- [Web server subsystem](../../docs/subsystems/web-server.md) — the Host request, Connection, and Principal services.
- [dsh-llm-deepseek](../llm/llm-deepseek/README.md) — the DeepSeek provider that carries the id on requests.
- [dsh-command-feedback](../feedback/command-feedback/README.md) — the feedback command that names the anonymous installation in its acknowledgement.

<a id="dev-note"></a>
## Dev Note

None.
