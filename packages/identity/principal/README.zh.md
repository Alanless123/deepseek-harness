---
description: "面向 DSH 服务的 Host 认证 Principal 类型、提供方定义与请求作用域执行上下文。"
kind: "package-reference"
---

# @deepseek-ai/dsh-principal

[English](README.md) | 中文

## 概述

本包定义认证型 DSH 部署使用的 Host 身份。只有身份协议验证精确 issuer 与 subject 后才能创建 `Principal`。`PrincipalContextService` 把该身份绑定到一条异步请求链，`PrincipalProvider` 则让部署认证并复核请求。Browser payload、query 参数与调用方选择的 header 都不是 Principal 来源。

## 目录

- [使用本包](#use-this-package)
- [运行时约定](#runtime-contract)
- [进一步探索](#further-exploration)
- [模型体验](#model-experience)
- [已知限制与延期工作](#known-limitations-and-deferred-work)
- [开发备注](#dev-note)

-----

<a id="use-this-package"></a>
## 使用本包

先加载本包，再加载 Principal Provider，并为 `dsh-client-connection` 配置 `principalMode: required`。Connection 在解码 Remote 或 Fetch payload 前认证物理请求，随后在 Host handler 运行期间进入 `ctx.principals`。消费方在需要认证身份的操作中调用 `ctx.principals.require()`；身份缺失、过期或失效时抛出稳定的 401 错误。

稳定的 `principalId` 是精确已验证 issuer、NUL 分隔符与已验证 subject 的 SHA-256 摘要。显示名与已验证邮箱是可选展示字段，永远不会改变该 id。

<a id="runtime-contract"></a>
## 运行时约定

- `PrincipalProvider.authenticate()` 返回 Host 创建且带有过期时间与失效 signal 的上下文。
- `PrincipalProvider.authorizeIndex()` 要么授权 index 服务，要么持有登录或失败响应。
- `PrincipalProvider.revalidate()` 确认已建立的 WebSocket generation 仍然有效；认证上下文的 `revalidateIntervalMs` 独立于网络 heartbeat 时序决定复核节奏。
- `PrincipalContextService.run()` 使用 `AsyncLocalStorage` 隔离并发异步请求链。
- `PrincipalAuthenticationError` 只暴露稳定的 401 或 503 status 与 code；协议 claim 和 token 不会进入错误。

<a id="further-exploration"></a>
## 进一步探索

- [identity 组映射](../README.zh.md)——区分已认证 Principal 身份与匿名安装关联。
- [dsh-principal-oidc](../principal-oidc/README.zh.md)——OIDC Service Provider。
- [dsh-client-connection](../../client/connection/README.zh.md)——认证载体并传播 Host 上下文。
- [Web server 子系统](../../../docs/subsystems/web-server.zh.md)——生成的 Principal 与 Connection API 参考。

<a id="model-experience"></a>
## 模型体验

无，因为 Principal 状态是仅限 Host 的请求元数据，不会增加提示词、工具、事件或任何模型可见文本。

#### KV Cache 影响

无；认证请求上下文不会改变模型可见前缀。

## 已知限制与延期工作

<a id="known-limitations-and-deferred-work"></a>

- **不含身份协议**——本包定义身份并限定其作用域，但没有部署级 Principal Provider 就无法认证用户。
- **请求上下文只在进程内生效**——`AsyncLocalStorage` 不跨 worker、进程或网络边界；每个载体都必须建立新的已验证上下文。
- **不含授权策略**——Principal 认证证明调用方是谁，但不决定该调用方可以访问哪些业务资源或操作。
- **legacy 模式没有具名 Principal**——Connection 的 legacy 启动令牌模式继续兼容本地 DSH 使用，但不会填充 `ctx.principals`。

<a id="dev-note"></a>
### 开发备注

<details>
<summary>维护者工作上下文——点击展开</summary>

无。

</details>
