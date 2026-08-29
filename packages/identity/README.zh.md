---
description: "identity 包组：匿名安装关联，以及经 Host 认证的 Principal 与 OIDC 服务。"
kind: "package-group"
---

# identity/ — 安装身份与认证身份

[English](README.md) | 中文

## 概述

identity 组持有两个不同的身份领域。`anonymous-user-id` 在不识别个人的前提下关联同一个 harness home 的记录。`principal` 与 `principal-oidc` 认证具名 Host 用户，并把该 Principal 绑定到请求执行，同时不接受 Browser payload 提供的身份。各包 README 分别说明所属领域的配置、安全属性与限制。

## 目录

- [包](#packages)
- [相关文档](#related-documentation)
- [开发备注](#dev-note)

<a id="packages"></a>
## 包

| 包 | 职责 |
|---|---|
| [`anonymous-user-id`](anonymous-user-id/README.zh.md) | 让每个 harness home 拥有一个匿名 id，遥测、反馈与 DeepSeek 请求把它附加到记录上，使来自同一安装的记录无需识别用户即可被辨认 |
| [`principal`](principal/README.zh.md) | 定义经验证的 Principal 身份、请求作用域 Host 上下文与部署级 Principal Provider 服务 |
| [`principal-oidc`](principal-oidc/README.zh.md) | 通过 Authorization Code + PKCE、不透明 Host 会话、内省与注销失效实现 Principal Provider |

<a id="related-documentation"></a>
## 相关文档

- [会话遥测子系统](../../docs/subsystems/session-telemetry.zh.md)——在导出中携带该 id 的遥测功能。
- [Web server 子系统](../../docs/subsystems/web-server.zh.md)——Host 请求、Connection 与 Principal 服务。
- [dsh-llm-deepseek](../llm/llm-deepseek/README.zh.md)——在请求中携带该 id 的 DeepSeek 提供方。
- [dsh-command-feedback](../feedback/command-feedback/README.zh.md)——在确认文本中点名该匿名安装的反馈命令。

<a id="dev-note"></a>
## 开发备注

无。
