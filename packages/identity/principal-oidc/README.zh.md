---
description: "仅限 Host 的 OpenID Connect Principal Provider，支持 PKCE、不透明会话、内省与注销失效。"
kind: "package-reference"
---

# @deepseek-ai/dsh-principal-oidc

[English](README.md) | 中文

## 概述

本包使用 OpenID Connect Authorization Code + PKCE 实现 `PrincipalProvider`。它发现一个精确 issuer，验证授权响应与 ID Token，内省 access token，并且只把 token 存在有界的进程内 session map 中。Browser 只收到随机不透明 `HttpOnly` cookie；Host handler 只收到最小的已验证 Principal 上下文。

## 目录

- [配置](#configuration)
- [安全与生命周期](#security-and-lifecycle)
- [进一步探索](#further-exploration)
- [模型体验](#model-experience)
- [已知限制与延期工作](#known-limitations-and-deferred-work)
- [开发备注](#dev-note)

-----

<a id="configuration"></a>
## 配置

| 配置键 | 含义 |
|---|---|
| `issuer`, `clientId`, `accessTokenAudience`, `redirectUri` | 精确 OIDC authority、注册 client、必需的 access-token 资源 audience 与 callback URI |
| `clientSecret` | 必填 confidential-client secret；缺失或为空时提供方启动失败 |
| `postLogoutRedirectUri` | RP 发起注销后的同源目的地 |
| `scopes`, `signingAlgorithm` | 包含 `openid` 的请求 scope，以及允许的非对称 JWS algorithm |
| `revalidateIntervalSeconds`, `sessionMaxAgeSeconds` | 内省缓存间隔（活跃上下文最高 60 秒）与 Host session 绝对生命周期 |
| `transactionTtlSeconds`, `maxTransactions`, `maxSessions` | 一次性登录状态与进程内 session 的边界 |
| `logoutPath`, `backchannelLogoutPath` | RP 注销与签名 back-channel logout 的精确路由 |
| `allowInsecureHttp` | 仅限 loopback issuer 与应用 URL 的显式开发逃生口 |

先加载 `dsh-principal`，再用全部部署值加载本提供方，并把 Connection 设为 `principalMode: required`。发现或路由注册失败会中止插件激活。提供方缺失或失败时，在业务分发前返回 503。

<a id="security-and-lifecycle"></a>
## 安全与生命周期

登录 transaction 在不透明 callback cookie 下携带一次性 state、nonce 与 S256 PKCE verifier 材料。callback 要求精确的已配置应用 authority 与路径，依据 `clientId` 验证 ID Token，并依据独立的 `accessTokenAudience` 以及 `client_id`、issuer、subject 和过期时间验证内省所得 access token，随后丢弃 transaction。session cookie 为 host-only、`HttpOnly`、`SameSite=Lax`，并在 HTTPS 下设置 `Secure`。

本地注销先移除不透明 session 并使活跃请求失效，再重定向到 issuer。签名 back-channel logout 会验证 issuer、audience、algorithm、age、event、session target 与防重放 `jti`；匹配的 HTTP 与 WebSocket 上下文会立即 abort，有界 target tombstone 还会阻止较旧的进行中 callback 重建已注销 session。周期内省失败会使 session 失效，并对非活跃身份以 401、对提供方不可用以 503 快速失败，后者包括暂时性 OAuth 响应以及 client timeout 或 abort 故障。提供方在每个认证上下文上发布最高 60 秒的复核节奏；Gateway 使用该值复核 logical WebSocket stream，而不把身份检查耦合到物理网络 heartbeat。

<a id="further-exploration"></a>
## 进一步探索

- [identity 组映射](../README.zh.md)——包职责与匿名身份的区别。
- [dsh-principal](../principal/README.zh.md)——本提供方消费的 Service Definition 与请求上下文。
- [Web server 子系统](../../../docs/subsystems/web-server.zh.md)——Principal、Connection 与 WebSocket 传播 API。
- [浏览器启动令牌认证](../../../.agents/notes/implemented/architecture/2026-08-24-browser-token-authentication.zh.md)——与 required Principal 模式并存的 legacy 本地浏览器模式。

<a id="model-experience"></a>
## 模型体验

无，因为 OIDC 协议材料、cookie、token 与 Principal claim 都保持在模型可见状态之外。

#### KV Cache 影响

无；认证既不改变提示词 token，也不改变模型可见前缀。

## 已知限制与延期工作

<a id="known-limitations-and-deferred-work"></a>

- **进程内 session**——Host 重启后必须重新完成 OIDC 登录；session 不在 replica 之间共享。
- **必须支持内省**——发现所得 issuer 必须暴露可用的 introspection endpoint，即使 access token 本身是 JWT 也不例外。
- **没有 refresh-token 生命周期**——session 过期时间受 ID Token、access token、内省响应与配置上限共同约束；本提供方不刷新 token。
- **精确公开 authority**——本提供方不解释 forwarding header，也不定义 reverse-proxy 信任策略。
- **不支持动态 issuer 集合**——一个插件实例只针对一个精确配置的 issuer 与 client 进行认证。

<a id="dev-note"></a>
### 开发备注

<details>
<summary>维护者工作上下文——点击展开</summary>

无。

</details>
