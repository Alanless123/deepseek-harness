---
description: "Web GUI 的浏览器-Host 线层：Remote RPC、带重连的事件流投递、精确 Fetch 路由、/api HTTP 桥与浏览器信任栅栏。"
kind: "package-reference"
---

# @deepseek-ai/dsh-client-connection

[English](README.md) | 中文

## 概述

本包承载浏览器到 Host 的 Remote 调用、精确 Fetch 响应与 connection generation。Client 插件挂载 `ctx.connection`，其中包含当前页面的 loopback 状态、通用 RPC carrier、当前 generation 及其 Host 信息，以及单一 generation source 的注册点。Host 插件在每种载体上一致应用 legacy 启动令牌认证或 required Principal 认证。source 报告 ready 后 generation 才可见；source 结束、失败、被撤回或显式 stop 都会清空它，再由 `ConnectionController` 退避重连。

## 目录

- [使用本包](#use-this-package)
- [浏览器认证与请求信任](#browser-authentication-and-request-trust)
- [Connection generation](#connection-generation)
- [模型体验](#model-experience)
- [已知限制与暂缓事项](#known-limitations-and-deferred-work)
- [开发备注](#dev-note)

-----

<a id="use-this-package"></a>
## 使用本包

浏览器通过 HTTP POST 执行 Remote 一元调用；API Gateway 自己拥有 `/api/remote.mux` WebSocket 及其逻辑流。进程内组合通过 `connection.rpc.open` 提供等价的 Remote 流，不打开 WebSocket。Host half 拥有唯一 `/api` route、Fetch bridge、浏览器认证、Host/Origin 校验与精确 `GET`/`HEAD` 路由注册表。Typert Gateway 认领生成的 Remote endpoint，功能包注册 Session 日志下载等非 JSON 响应，未认领的请求返回 404。只有组合已挂载 `dsh-principal` 与一个部署级 Principal Provider 时，才把 `principalMode` 设为 `required`；默认 `legacy` 模式保留启动令牌流程。Loopback hostname 判定只供浏览器侧当前页面状态使用，留在包内。

-----

<a id="browser-authentication-and-request-trust"></a>
## 浏览器认证与请求信任

Connection 对 Remote 一元调用、精确 Fetch 与 WebSocket upgrade 请求应用同一个已配置认证模式，不存在按方法区分的 loopback 层。在默认 `legacy` 模式中，每个进程生成一个随机启动令牌。`dsh-web-app` 打印并打开带 `?token=...` 的普通根 URL；`frontend-static` 把根路径和 index 请求交给 `ctx.connection.authorizeIndex`，后者只在 `GET /` 接受该令牌，写入绑定 authority 的签名 cookie，再重定向到干净的 `/`。缺失、过期、畸形或 authority 不匹配的 cookie 会在分发前得到 401。静态资源保持公开。HTTP 载体不在根路径交换之外接受 query token，也不接受 Authorization header token。

在 `principalMode: required` 中，Connection 把 index 授权、物理请求认证与活跃 generation 复核委托给 Host `PrincipalProvider`。提供方缺失或失败时以 503 拒绝，调用方未认证时以 401 拒绝，且都发生在业务 payload 解码或分发之前；随后 handler 在提供方创建的 `ctx.principals` 上下文中运行。legacy cookie 签名密钥仍是 `ctx.credentials` 中由 `client-connection/browser-session` 拥有的 grant 记录；本地提供方把它持久化到 `$DSH_HOME/.credentials.yaml`，`cookieMaxAgeDays` 默认把绝对生命周期设为 30 天。legacy cookie 同时绑定规范化 hostname 与 port，是 host-only、`Path=/`、`HttpOnly`、`SameSite=Strict`；随附服务器使用 loopback HTTP，因此不设置 `Secure`。

认证之前，每个请求仍经过 `src/api-request-trust.ts`。其 `Host` 必须是 loopback，或与 `trustedHosts` 条目匹配：带端口的 `host:port` 精确匹配，不带端口的条目匹配任意端口，两侧均经 WHATWG 归一化。若附带 `Origin`，它必须等于该 Host；`sec-fetch-site: cross-site` 一律拒绝。畸形配置 authority 会让插件加载失败。这些检查防御 DNS rebinding 与跨站浏览器请求，绝不建立身份。Host/Origin 校验失败返回 403；Host 可信但未认证的请求返回 401。`dsh web --host 0.0.0.0` 仍不受支持。决策记录：[浏览器请求信任](../../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.zh.md)与[浏览器令牌认证](../../../.agents/notes/implemented/architecture/2026-08-24-browser-token-authentication.zh.md)。

<a id="connection-generation"></a>
## Connection generation

API Gateway Client 把内部 `$events` logical stream 注册为唯一 generation source，与有无 `$on` 订阅无关。Host 在 API Remotes source factory 同步挂好所有增量 listener 后，先发送唯一 `{ type: 'ready', clientId, host: { home } }` 项，再发送事件。`ConnectionController` 仅在收到该 ready 项后发布 generation 并调用 `onConnected`，因此 baseline 不会跑在增量 listener 前面。

`$events` 结束、返回 Remote stream error、收到非 ready 首项或畸形事件项，都会使当前 generation 失效。Controller 立即撤回 generation、发布 `reconnecting`，并在退避后重开 `$events`。Gateway mux 自己负责重建底层 WebSocket；Connection generation 负责重开 logical stream 并建立下一次 baseline 起点。

<a id="model-experience"></a>
## 模型体验

无。协议消费层只在浏览器与主机之间搬运已经组合好的消息；这里没有任何内容进入模型请求。

#### KV Cache 影响

无；该包既不组装也不发送提供方请求。

## 已知限制与暂缓事项

<a id="known-limitations-and-deferred-work"></a>

- **`/api` 桥把每个请求体整体缓冲在内存里**：`maxRequestBodyBytes`（默认 300 MiB，按默认 200 MiB 图片总量上限经 base64 膨胀加信封余量得出）因此同时是单请求的驻留内存上界；要降低它而不缩小图片限额，需要流式请求体路径。
- **legacy 浏览器 cookie 不带 `Secure`**：随附载体是 loopback HTTP；若部署经明文网络暴露同一 authority，bearer cookie 可能在传输中泄露。
- **legacy 模式没有 logout 操作**：清除浏览器 cookie 会结束单个浏览器会话；删除 owner 凭据记录并重启 `dsh` 会撤销所有 legacy 会话。required 模式把 logout 语义委托给 Principal Provider。


<a id="dev-note"></a>
### 开发备注

<details>
<summary>维护者工作上下文——点击展开</summary>

无。

</details>
