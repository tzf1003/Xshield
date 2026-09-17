# 06 资格账本、根入口及分享

## 6.1 授权键

```text
site_id + auth_binding_id + auth_epoch + tenant_ref
+ resource_type + canonical_resource_ref
+ operation_id + view_profile + scope_hash
```

action_grant_id、source_request_id、source_rule_revision、source_evidence_ids、issued_at、expires_at、revocation_version、use_policy、status 是必要证明字段。禁止只以 URL、ID 或 Cookie 为唯一授权索引。

当前 GET 查询适配器由策略显式声明 `resource_query_parameter`。网关对实际转发 URI 的查询串执行一次严格解码，拒绝重复字段、分号分隔、非法百分号、超限和控制字符，以租户、站点、资源类型和值的带域 HMAC 生成 `resource_key_hmac`，并把全部查询字段同时交给 ActionGrant 校验。资源值、operation、view、action、binding、auth_epoch、策略和期限精确命中活动 ResourceGrant 后才可转发；原始资源值不进入账本或审计。该适配器只覆盖 GET 查询语义，其他协议形态由对应版本化站点适配器冻结后接入。

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

PageEvidence 必须关联认可来源；源站返回 200 不是授权证明。若列表本身可越权，不先约束列表就会污染整个账本。来源策略应有双身份及权限范围测试。

## 6.4 事务与容量

PostgreSQL 首版使用短事务校验 auth_epoch 与 policy_revision，幂等写入发行事件并写 outbox。相同 source_request_id/source_rule/resource/operation 的重复消费不重复增权。普通查询永不无限续租；最长资格期限不得超过当前会话和来源证据期限。

首版可配置每会话最多 5000 条资格、单响应 1000 条、写操作更短 TTL；这些是待测限额。超额返回重新获取/明确拒绝，不授予 wildcard。删除旧观察记录不应误删仍有效资格；撤销资格也不删除历史证据。

## 6.5 分享

分享可以是明确公开的 GET 视图，或由有资格的发行者签发限资源凭证。随机长字符串只有在发行、验证、范围和到期语义可靠时才是分享凭证。不能收到任意私有 ID 就由 WAF 自动补签名。

兑换后为接收者建立 LIMITED_SHARE 上下文，与分享者 Cookie 不必相同；不会扩大为完整用户身份。只读不等于可转分享，病例摘要不等于患者全量信息。附件、视频分片、Range 访问需单独或可证明收缩的子资格。重复读取与单次写请求 nonce 分离。

## 6.6 服务身份

服务身份使用独立边缘凭证，不以 User-Agent、来源 IP 或普通用户会话推断。网关以租户、站点和固定用途域生成 HMAC 指纹，只从 PostgreSQL 加载一条活动且未过期的服务身份，再由领域层检查当前 operation 是否属于其有限集合。凭证头在访问源站前剥离；服务如还需源站认证，应使用与边缘证明职责分离的业务凭证。替换、跨站、过期或撤销统一拒绝并记录 `SERVICE_IDENTITY_MISMATCH`，存储不可用记录依赖故障且不放行。

## 6.7 缺失处理

已认证且无对应流程资格：403，UI 提示重新从认可入口打开。未认证：API 401 或顶层页面跳固定登录入口。存储不可用：503，不把基础设施故障记作越权。策略可用统一 404 隐藏对象存在性。

bookmarks、手工粘贴 ID、换浏览器、未刷新共享列表，只有已有有效资格或例外入口时才通过。没有则拒绝，是预期行为。CAPABILITY_MISSING 与 CONFIRMED_BUSINESS_DENY、MODEL_SUSPECTED_ENUMERATION 分别记录。
