# Agent Note: OIDC Principal 请求上下文

Status: implemented

[English](2026-08-29-oidc-principal-request-context.md) | 中文

## 问题

浏览器启动令牌 session 能认证一个本地 Browser 安装，却不能识别人类用户。执行审批、导出、管理或职责分离的 Host 业务服务，无法从启动 cookie、请求 payload、匿名 harness-home id、操作系统用户或调用方选择的 header 派生出已验证人员。通过 Remote 参数传递身份会让 Browser 选择自身 authority；只认证一元调用则会让精确 Fetch 与 WebSocket stream 遵循不同规则。

## 决策

DSH 通过仅限 Host 的 Principal 能力暴露已认证用户身份。`dsh-principal` 定义不可变 Principal、部署级 `PrincipalProvider` 与 `PrincipalContextService`，后者使用 `AsyncLocalStorage` 把一个已验证上下文限定到一条异步请求链。不透明 `principalId` 只由精确已验证 issuer、NUL 分隔符与 subject 派生。显示名与已验证邮箱是展示字段，不参与身份计算。

`dsh-client-connection` 持有载体认证。其默认 `legacy` 模式保留启动令牌行为。`principalMode: required` 先运行 Host/Origin 防线，再要求两个 Principal 服务，在解码 payload 前完成认证，并围绕一元 Remote 与精确 Fetch handler 进入 Principal 上下文。身份缺失返回 401；提供方缺失或失败返回 503。Browser payload 与类似身份的 header 永远不会填充该上下文。

`dsh-api-gateway` 把已认证上下文绑定到一次获准的 WebSocket generation。每个逻辑 stream 都在该上下文中打开并推进。mux 将 stream 取消与 session 失效 signal 组合，按认证到期时刻设置精确计时器，在每次打开与投递前检查上下文，并周期性请求 Connection 复核同一个 generation。Host 首帧携带由已认证 session id 派生的进程内不透明 binding，该值绝不取自 Browser 输入；物理候选连接若在 30 秒内未投递该首帧，就会被关闭。每个等待首个可用 Host 首帧的逻辑调用都有独立的 30 秒上限，包括在旧恢复窗口结束后才创建的调用。发生含糊的载体断开后，已认证 generation 进入最长 30 秒的恢复窗口。只有替代 Host 首帧证明同一个 non-null binding 后，已接受的逻辑流才可重试；任何已获准 generation 之后排队的调用都会保留其完整预期类型与 binding。身份过期、撤销、复核失败、已认证 binding 改变或缺失、legacy/authenticated 模式改变、明确的策略关闭，或者 upgrade 与首帧前失败持续到恢复截止时刻，都会让旧逻辑流及绑定的 waiter 以 `remote-stream-policy` 终止；只有替代身份获准后才开始的调用可以使用改变后的 binding。Legacy generation 会立即向领域 supervisor 报告载体断开；受监督的重试仍必须在调用上限内收到 legacy Host 首帧，且不得重放到 authenticated generation。

`dsh-principal-oidc` 是部署级 Service Provider。它使用带 S256 PKCE 的 Authorization Code、精确 issuer discovery、state 与 nonce、非对称 ID Token 校验，并依据单独配置的资源 audience 与 OAuth `client_id` 执行 access-token 内省，同时使用有界一次性 transaction 和有界进程内 session。token 与原始 claim 留在提供方 map 中；Browser 只收到不透明 host-only cookie，Host 消费方只收到已验证 Principal 投影。RP 发起注销与带签名且防重放的 back-channel logout 会让匹配的活跃上下文失效。

## 验证

包测试固定精确 issuer 与 subject 身份派生、显示名独立性、并发上下文隔离、过期、失效、discovery、PKCE、state、nonce、issuer、audience、signature、token 过期、不透明 cookie、提供方失败、内省撤销、RP 注销与带签名 back-channel logout。Connection Host 测试证明同一个由 Host 创建的上下文进入一元与精确 Fetch 分发，同时忽略伪造身份字段。Gateway 载体测试证明 Host-only WebSocket generation binding、masked close 后在已认证有界窗口内以同 binding 恢复、拒绝跨 binding 的排队调用、首个 waiter 与旧恢复截止后新 waiter 均有界、终止无首帧的静默候选连接、跨 binding 或恢复超时以 `remote-stream-policy` 终止、legacy 载体断开立即且重试有界、拒绝 legacy 到 authenticated 的重放、延迟投递前的精确与长期到期、周期复核、活跃 stream 取消，以及不暴露 handler 错误的 401/403/503 拒绝。

## 曾考虑的替代方案

**使用 Browser 提供的 actor 或 role 字段。** 调用方可以在需要作出决定的 Host 操作前选择其他身份或提升角色。身份在 payload 解码前建立，并从协议请求 schema 中保持缺席。

**把匿名 harness-home id 或启动 cookie 当作人员。** 两者识别安装或 bearer session，而非已验证的人类 subject。它们继续适用于既有本地关联与 legacy 浏览器用途，但无法满足具名用户或职责分离策略。

**全局替换启动令牌认证。** 既有本地 DSH profile 不需要外部 issuer。显式 Connection 模式保留该受支持工作流，同时让需要具名身份的部署在 Principal Provider 缺失时快速失败。

**通过 Connection 与业务 handler 传递 OIDC token。** 这会把 bearer credential 与提供方专用 claim 扩散到传输和消费方。提供方保留协议材料，只发出最小 Principal 上下文以及过期与失效事实。

## 后果

一个认证结果统辖一元 Remote、精确 Fetch、WebSocket upgrade 与每个逻辑 stream。业务包无需导入 OIDC 实现即可要求 Principal，提供方丢失也不能把 required 部署静默降级为启动令牌身份。

session 位于进程内，Host 重启后需要重新登录。提供方要求 issuer 支持内省与精确公开应用 authority；它不定义反向代理 header 信任、token refresh、多 issuer 选择、持久 session 或授权策略。这些省略让身份凭证与部署拓扑、业务权限保持分离。

本决策补充[浏览器启动令牌认证](2026-08-24-browser-token-authentication.zh.md)决策。该说明继续负责 legacy 模式与 Host/Origin 防线；required Principal 模式只替换显式部署配置选择的身份机制。
