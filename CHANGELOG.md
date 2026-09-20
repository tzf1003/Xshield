# 变更记录

## Unreleased

- 实现通用资源资格 `grant.issued` 的完整 v3 生产契约、原子 outbox 和按族发布，加入真实 PostgreSQL/ClickHouse 回归；强化锁等待过期、撤销重放及冻结时间精度检查。`GrantPersistence::new` 接受冻结 trace_id，签发事务按 JSONB 约束表示生成事件；HTTP 发行适配器继续交付。
- 实现单次 Jev 离线评估 CLI、严格 Choice/Noul 转换、固定 HTTPS、限流/超时/取消终态、加密输入输出证据与目录审计，以及中断恢复和 `model.*` 索引解析。

- 实现受保护入口缺失 WAF Cookie 时的有界匿名空会话、原子 `session.created` 审计、401 安全 Cookie 响应，以及进程内、分布式来源/站点速率和并发容量控制。
- 建立 Rust Cargo workspace 与 M0 核心领域边界。
- 实现禁用站点的可审计 `NOT_CONFIGURED` 阶段树和失败关闭测试。
- 增加独立管理身份、Mock ports 及 Rust/文档联合 CI。
- 实现 M1 认证组合强绑定、匿名空账本与不可变身份快照领域规则。
- 实现同上下文凭证刷新、身份 epoch 轮换、撤销和旧响应失效规则。
- 实现资源、操作、视图和身份 epoch 精确匹配的有界幂等资格账本。
- 增加 M1 PostgreSQL 版本化 migration、CAS/epoch/outbox 集成验证及 CI 服务。
- 增加 SQLx PostgreSQL 身份刷新适配器，原子提交 generation、凭证状态和 outbox。
- 将业务授权上下文引用纳入认证建立、刷新、切换、资格提交和 PostgreSQL CAS；同主体范围变化推进 epoch，升级时撤销无法证明上下文的旧绑定。
- 增加 PostgreSQL 资格发行事务，校验身份、动作、策略、期限与容量，并原子写入 outbox。
- 实现受验证页面证据、批准动作描述和动作资格领域校验，拒绝目标、字段、方法与路由扩张。
- 增加 M1 UI 来源 migration，以同租户外键绑定页面证据、批准动作描述和动作资格。
- 增加 UI 来源 SQLx 事务，重验身份和批准描述，原子写入页面证据、动作资格及 outbox。
- 实现 operation 入口分类与准入矩阵，精确组合方法、路由、身份、UI 动作及资源资格。
- 实现限资源只读分享与服务身份 operation 集合证明，并接入专用入口准入。
- 增加 Pingora MVP 网络入口：可信 JSON 配置编译精确操作，固定源站转发，未配置及缺少证明的受保护请求在源站前拒绝。
- 增加本地耐久审计 journal：AES-256-GCM 记录、持久 receipt、CRC32、段内哈希链、单写者锁、目录配额、私有权限及不完整尾部恢复。
- 将 Pingora 准入接入 journal 持久屏障：转发前原子记录请求、阶段、判定与转发意图；记录失败或配额不足时关闭源站转发，并在响应后写入终态事件。
- 增加受保护根入口的 PostgreSQL 身份读取端口：精确核对 WAF 会话 HMAC、Bearer HMAC、当前 credential generation、身份 epoch 与服务端期限，读取失败时审计并关闭转发；转发前剥离仅供边缘使用的 WAF Cookie。
- 接通无资源、无请求字段 UI 动作的网关闭环：按 `X-Xshield-Action-Ref` 从 PostgreSQL 重建并重验页面证据、活动描述符、策略、认证 epoch、方法、路由和期限；缺失、替换、退休均在源站前拒绝，并剥离边缘动作头。
- 接通 GET 查询资源资格闭环：策略声明资源参数后，从实际 URI 严格提取字段和值，以租户隔离带域 HMAC 匹配 PostgreSQL ResourceGrant，并对未知资源、operation/view 偏差、字段扩张和歧义编码关闭转发。
- 增加关闭 journal 段的完整验证与 Ed25519 签名清单：提交整段摘要、链头、序号和密钥标识，读取时精确匹配段内容，并以原子、不覆盖方式写入独立私有位置。
- 增加 journal 字节阈值自动轮转和独立 `xshield-audit-seal` 封存命令；封存进程可与 edge 并行验证关闭段，重复运行会重验已有清单并保持幂等。
- 增加签名关闭段的认证流式读取边界；完整段与清单先精确匹配，每条事件再重验 CRC、AEAD、序号及哈希链，并提供正文摘要支持下游检测同 ID 异内容冲突。
- MSRV 更新为 Rust 1.94；锁定 SQLx 0.9.0 与 Tokio 1.51 LTS 依赖线。

## 3.0 — 2026-09-17
项目正式命名Xshield，Rust主语言。整合前置JS/加密接管、受控回退、严格界面来源准入、资源操作账本、WAF与业务认证强绑定、分享例外与AI适配。

新增每层决策事件、置信度语义、证据库、耐久journal、ClickHouse索引、查询/案例/导出/离线回放、调查Agent与后台自身审计；增加开发规范、契约、数据库草案、运维和验收库。

不再默认要求业务SDK/Guard；不再为无资格直接URL、新浏览器、未刷新资源做隐式兼容。一天是可配置会话最大租期。历史ID不授予任意操作，UI动作来源必须经批准。普通凭证替换拒绝，合法续期和换身份区分。

当前交付为设计与合成验证资料，未交付可运行WAF、真实模型基准或生产部署。
