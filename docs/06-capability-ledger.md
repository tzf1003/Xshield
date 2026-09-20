# 06 资格账本、根入口及分享

## 6.1 授权键

```text
site_id + auth_binding_id + auth_epoch + authorization_context_ref
+ resource_type + canonical_resource_ref
+ operation_id + view_profile + scope_hash
```

action_grant_id、source_request_id、source_rule_revision、source_evidence_ids、issued_at、expires_at、revocation_version、use_policy、status 是必要证明字段。禁止只以 URL、ID 或 Cookie 为唯一授权索引。

`authorization_context_ref` 随 AuthSnapshot 捕获，并由当前 binding 的主体、上下文与 epoch 共同重验；资格表可用 binding + epoch 作为其不可变持久键，不重复存放上下文文本。

当前 GET 资源适配器由策略显式且互斥地声明 `resource_query_parameter` 或 `resource_path_parameter`。查询适配器对实际转发 URI 的查询串严格解码一次，拒绝重复字段、分号分隔、非法百分号、超限和控制字符；路径适配器只接受固定前缀后的一个最终段，严格解码一次，并拒绝额外查询、嵌套段、编码斜杠、控制字符、模板错配和路由歧义。两者均以租户、站点、资源类型和值的带域 HMAC 生成 `resource_key_hmac`，并把实际资源字段交给 ActionGrant 校验。资源值、operation、view、action、binding、auth_epoch、策略和期限精确命中活动 ResourceGrant 后才可转发；原始资源值不进入账本或审计。其他协议形态由对应版本化站点适配器冻结后接入。

观察记录 observations、有效资格 grants、模型信号 model_signals 三者隔离。全文检索、向量相似度及 Bloom 正结果不能代替精确查表。多个资源批量请求逐项检查；父子资源检查关系，不允许把独立认识的两个 ID 任意组合。

## 6.2 入口分类

| 类别 | 起点依据 | 约束 |
|---|---|---|
| PUBLIC | 明确公开 operation/视图 | 不豁免所有同路径方法 |
| AUTH_ENTRY | 登录/代码兑换/认证回调 | 成功验证前仍匿名 |
| FLOW_ROOT_AUTHENTICATED | 认证后的批准首页或受范围约束的初始列表 | 仅发行配置允许的下一步资格 |
| UI_ACTION_REQUIRED | 页面动作与精确资源资格 | 缺少来源即拒绝 |
| SHARE_ENTRY | 有效分享凭证或明确公开资源 | 资源、视图、操作与期限受限 |
| SERVICE_IDENTITY | 已验证服务凭证与操作范围 | 不由 User-Agent 触发豁免 |

所有入口继续执行内容、协议、配额和审计。WAF 内部 bootstrap/events 路径使用独立保留命名空间，只能操作本会话的受限元数据，不能代理任意 URL 或发行业务资格。

## 6.3 来源规则

列表请求中的主体/租户必须先受约束；返回经过预期上游、业务成功码、Schema 与解密校验。只从批准的结构路径提取资源，不扫描任意正文中的 ID。创建响应只有在创建操作被事先允许且业务确认成功时才发行资格。

首个 JSON 响应提取契约在来源 operation 的 `response.resource_grant` 中显式声明业务成功状态、列表 JSON Pointer、相对资源 JSON Pointer、动作引用字段、唯一目标 operation、目标 mapping revision、TTL、单响应数量与会话容量。来源只能是已认证根或已验证 UI 动作，目标必须是带精确资源适配器的 `UI_ACTION_REQUIRED` operation；operation ID 在站点配置内唯一。完整正文按无重复对象键的严格 JSON 解析，形状、类型、数量、资源长度或唯一性偏差均不产生候选资格。动作引用字段必须由源站留空；事务提交后，网关把逐项不透明 `action_ref` 注入该字段，并移除已失效的实体长度、缓存验证和 Range 元数据，以 `private, no-store` 交付改写后的响应。源站预占字段、引用数量不一致或改写失败均不释放正文。

PageEvidence 必须关联认可来源；源站返回 200 不是授权证明。若列表本身可越权，不先约束列表就会污染整个账本。来源策略应有双身份及权限范围测试。

## 6.4 事务与容量

PostgreSQL 首版在同一短事务中锁定当前 binding，重验主体、授权上下文、auth_epoch、活动策略和精确动作描述，再把完整响应证据、逐资源 ActionGrant、ResourceGrant 与 outbox 整批提交。整批任一写入失败、会话容量不足或资格变化均不留下部分授权；相同来源响应的精确重放返回原有引用，语义变化则冲突。响应证据只保存受限 artifact 引用和带域 HMAC，不保存原始资源值。普通查询永不无限续租；最长资格期限不得超过当前会话和来源证据期限。

通用 ResourceGrant 写入同样以数据库 `clock_timestamp()` 重新约束 binding、动作和候选 grant 的绝对期限；锁等待或唯一键等待跨过期限时整笔事务回滚。发行幂等键不仅逐字段比较账本语义，还要求活动状态、冻结签发时间以及同一 `grant.issued` outbox envelope 完整一致；缺失或错绑的 outbox 视为存储损坏，不回退为已发行。

`GrantPersistence::new` 校验并冻结类型化发行字段，持久化入口构建 `gateway-grant` 的完整 v3 事件，以 source_request_id 关联来源请求，event ID 作为独立 producer boot，保留冻结 trace、策略与发行时间。调用方提供批准的 constraints 对象，输入 JSON 及 PostgreSQL `jsonb::text` 表示均限制为 16 KiB；摘要使用后者 UTF-8 字节的原生 SHA-256，约束对象留在 PostgreSQL 账本。数字按 JSONB 表示参与摘要和重试，避免指数展开及负零转换影响持久化一致性；PostgreSQL 升级须复跑数字往返与精确重试测试。TTL 限制为 1–86400 秒，并在事务中受当前身份和来源动作期限进一步约束。`XSHIELD_OUTBOX_FAMILY=grant` 发布发行历史；此入口是持久化库 API，HTTP 来源发行适配器仍待交付。

网关逐资源提交 `gateway-response-grant` 生产者的完整 v3 `response_grant.issued` envelope，绑定原请求、身份代际、响应证据、动作与资源资格、目标和策略修订。批内序号从 1 开始，发行时间随事务输入冻结；`XSHIELD_OUTBOX_FAMILY=response_grant` 可独立发布这些事实，精确契约及历史稀疏行处理见 [11.8](11-audit-event-contract.md#118-已实现的按事件族-outbox-发布)。索引发布不改变资格状态、期限或响应释放屏障；后续授权继续查询当前 PostgreSQL 账本。

首版可配置每会话最多 5000 条资格、单响应 1000 条、写操作更短 TTL；这些是待测限额。超额返回重新获取/明确拒绝，不授予 wildcard。删除旧观察记录不应误删仍有效资格；撤销资格也不删除历史证据。

## 6.5 分享

分享可以是明确公开的 GET 视图，或由有资格的发行者签发限资源凭证。随机长字符串只有在发行、验证、范围和到期语义可靠时才是分享凭证。不能收到任意私有 ID 就由 WAF 自动补签名。

首个适配器通过专用 `X-Xshield-Share-Token` 请求头接收不透明凭证，只允许带一个资源查询字段的 GET。网关分别按租户、站点和固定用途域生成凭证与资源 HMAC，精确查询 PostgreSQL 中活动、未过期、`reusable_read` 的 ShareGrant，再由领域层复核资源类型、资源值、operation、view 和期限。额外查询字段、替换、跨站、过期或撤销统一拒绝为 `SHARE_SCOPE_MISMATCH`；分享头在转发前剥离。路径资源、Range、附件和写入采用独立适配器，不由该入口推断放行。

分享发行使用独立的 `share_issuance_rules` 映射发行 operation/view 到有限读取 operation/view。事务重新锁定当前认证 binding，并精确核对发行者持有的活动 ResourceGrant、资源 HMAC、auth epoch、活动策略、规则和 TTL；分享期限不得超过认证、来源资格或规则上限。幂等 key 的全部授权语义一致时返回原 share ID，任何字段变化均冲突；每个发行者的活动分享容量在同一行锁下检查。ShareGrant 与 `share.issued` outbox 事件同事务提交，任一写入失败都不产生凭证记录。

`ShareIssueApi` 库入口从已验证的发行事实构造完整 v3 事件，再执行上述事务。share ID 使用稳定 event ID 的 UUID 部分，重试必须冻结 event ID、issuance key、request/trace、发行时间和全部授权字段；数据库同时核对原 share、发行时间及原 outbox 正文，检查当前撤销状态与数据库实时时钟。来源资格的策略版本必须等于发行版本，关联界面动作须活动且完整覆盖资格的身份、操作、view 与期限；这些授权行在事务内保持锁定，精确重试也等待分享撤销事务完成。取得授权锁后与插入后提交前重新检查期限，跨期等待会回滚发行。分享凭证明文仅在提交或精确重试成功后释放，事件不包含凭证、凭证指纹或 issuance key。历史随机 share ID 或稀疏事件不自动改写，也不据此重发凭证。

网关 `response.share_issue` 已接入 HTTP 响应发行：来源必须是独立 `UI_ACTION_REQUIRED` GET 资源操作，具备获准界面动作及精确 ResourceGrant；启动时固定 `issuance_rule_id`、目标 `SHARE_ENTRY` GET 单查询资源操作和有限 view，并要求资源类型一致。此 GET 操作会创建分享资格，应映射到明确的用户分享动作；页面预取或普通读取不应指向该操作。部署前须独立批准对应数据库规则，网关配置只引用规则。

配置字段为 `success_status`、根对象 `token_field`、`target_operation_id`、`issuance_rule_id`、`ttl_seconds`（1–86400）和 `max_active_shares`（1–5000）。响应须为完整 `BUFFERED_JSON`、匹配携带实体的成功状态，且固定 token 字段不存在；严格拒绝重复 JSON 键，并在事务前预分配和检查注入后的正文不超过 `response.max_bytes`。原数据表示保留，凭证仅替换预留的固定槽。身份快照和本次准入选中的 grant ID/HMAC/期限跨源站响应保留，分享期限取配置、原身份及来源资格期限的最小值，当前规则与资格由事务复验。发行与登录、刷新、账号切换、资源批量发行及响应应用层加密规则互斥；结果设置 `private, no-store`，生产传输须使用 TLS。

`XSHIELD_SHARE_TOKEN_KEY_HEX` 提供独立 32 字节 token 派生密钥，与入口使用的 `XSHIELD_FINGERPRINT_KEY_HEX` 必须不同，配置发行时缺失或复用会阻止启动。成功正文是新增 token 的交付面，原响应证据采集发生在注入前，网关拥有的 token/响应缓冲在释放后清零。每个新 HTTP 请求独立发行并消耗容量；当前适配器不提供跨请求重交付。提交后的连接中断可能留下已提交但未送达的分享记录，保留发行事件及请求失败终态，不据此自动重放源站。

兑换后为接收者建立 LIMITED_SHARE 上下文，与分享者 Cookie 不必相同；不会扩大为完整用户身份。只读不等于可转分享，病例摘要不等于患者全量信息。附件、视频分片、Range 访问需单独或可证明收缩的子资格。重复读取与单次写请求 nonce 分离。

## 6.6 服务身份

服务身份使用独立边缘凭证，不以 User-Agent、来源 IP 或普通用户会话推断。网关以租户、站点和固定用途域生成 HMAC 指纹，只从 PostgreSQL 加载一条活动且未过期的服务身份，再由领域层检查当前 operation 是否属于其有限集合。凭证头在访问源站前剥离；服务如还需源站认证，应使用与边缘证明职责分离的业务凭证。替换、跨站、过期或撤销统一拒绝并记录 `SERVICE_IDENTITY_MISMATCH`，存储不可用记录依赖故障且不放行。

## 6.7 缺失处理

已认证且无对应流程资格：403，UI 提示重新从认可入口打开。未认证：API 401 或顶层页面跳固定登录入口。存储不可用：503，不把基础设施故障记作越权。策略可用统一 404 隐藏对象存在性。

bookmarks、手工粘贴 ID、换浏览器、未刷新共享列表，只有已有有效资格或例外入口时才通过。没有则拒绝，是预期行为。CAPABILITY_MISSING 与 CONFIRMED_BUSINESS_DENY、MODEL_SUSPECTED_ENUMERATION 分别记录。
