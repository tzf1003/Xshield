# 11 全链路审计事件与 ID 契约

## 11.1 审计目标

输入一个请求 ID，调查者能够回答：收到什么、使用哪个身份绑定、经过哪些层、每层依据是什么、规则/模型怎么判、为什么跳过某层、是否降级、实际转发了什么、源站返回什么、给客户端返回什么、是否发行新资格、完整证据保存到哪里。

所有被 Xshield 解析接收的 HTTP 请求均有 request.accepted 和最终/补偿状态；包括正常、拒绝、静态资源、内部管理、模型调用及失败请求。连接在形成 HTTP 请求前失败时记 connection/security 事件并带 connection_id，不虚构完整请求。业务 WS 支持时，每个业务消息有 message_id，与连接握手请求分开。

## 11.2 ID 体系

| ID | 作用 | 生成与安全 |
|---|---|---|
| request_id | 一次边缘请求 | 服务器生成 req_ + UUIDv7；客户端值另存不可信引用 |
| trace_id/span_id | 分布式关联 | 采用 W3C 格式；外部 traceparent 不得覆盖内部安全 ID |
| event_id | 一条不可变审计事件 | ev_ + UUIDv7，重发不换 ID |
| decision_id | 一次决策合成 | dec_ + UUIDv7 |
| stage_execution_id | 阶段一次执行 | 区分重试、并发与取消 |
| artifact_id | 一份内容证据或 manifest | artifact_ + UUIDv7，不是公开下载凭证 |
| transform_id | 解密/标准化/重建关系 | 关联输入、输出及配置版本 |
| model_call_id | 一次实际模型调用尝试 | mdl_ + UUIDv7；另有 logical_call_id |
| agent_run_id/tool_call_id | Agent 运行及工具调用 | agt_/tool_，父子运行明确关联 |
| grant_id/page_evidence_id | 资格与界面来源 | 用于完整追溯发行链 |
| case_id/export_id/replay_id | 调查案、导出与回放 | 各自审批、权限和审计 |

UUIDv7 可提供时间局部性，但 ID 不是身份凭证或严格全局事件顺序。[S20] trace/span 使用标准互操作字段；对外传入追踪信息视为不可信，限制 baggage 且不承载秘密。[S21]

所有查询先限定操作者可访问 tenant/site，再查 ID。ID 再长也不能替代后台授权。

## 11.3 事件公共字段

schema_version、event_type、event_id、tenant_id、site_id、request_id/subject_refs、trace_id/span_id、producer_id、producer_boot_id、producer_seq、request_seq、occurred_at、observed_at、monotonic_duration_us、policy_revision、sensitivity、payload、evidence_refs、prev_event_hash、event_hash。

occurred_at 是服务器 UTC，浏览器时间另存 client_reported_at；时区只影响显示。producer_seq 用于发现本生产者序列缺口；request_seq 由单一请求协调器分配。跨服务以因果 links 和 span 树表达，不伪装为严格全局时间顺序。

原始 append-only 事件不可修改；聚合的 request summary 可以以 revision 更新，但必须能回到原事件。

## 11.4 阶段结果契约

```json
{
  "stage": "capability",
  "outcome": "DENY",
  "reason_code": "OPERATION_NOT_GRANTED",
  "proof_kind": "deterministic",
  "confidence": null,
  "confidence_status": "not_applicable",
  "rule_revision": "policy-demo-r3",
  "input_refs": ["artifact_example"],
  "facts": {"required_operation":"user.password.admin_reset"},
  "duration_us": 320
}
```

值为纯语义示例，完整机器 Schema 见 schemas。不得对规则检查硬填 100% 置信度。`severity`、`risk_score`、`probability`、`confidence`、`coverage` 不共用字段。

模型结果另存全概率、Noul 值或评分、供应商置信度、校准版本、阈值和采取的动作。可解释文本是独立 explanation，不等同于决策事实；如果来自另一个模型，必须有另一条 model_call_id。

当前阶段发布契约：`proof_kind=model` 必须带 `mdl_` UUIDv7 调用引用；其他 proof 不携带模型调用或版本。可选 `model_revision` 为 1–128 字节的 ASCII 字母、数字、`_`、`-`、`.` 标识，写入独立索引列，供时间线与有界查询使用。旧事件缺失或显式 null 时保持未知（索引空值），不从当前配置补填历史版本。`confidence_status=provided` 与非空置信度一一对应，其他状态必须为 null；确定性结果继续为 `null/not_applicable`，SKIPPED/CANCELLED 不得携带数值。

升级兼容：已有网关确定性事件无需改写。违反文档约定的 `model_` 前缀、非模型事件附带模型引用或置信度状态矛盾会被发布器以 InvalidEvent 拒绝并保持当前段水位；应检查生产者及受影响段，保留原始审计证据。阶段汇总使用同一最新事件的置信度，包括 null，避免沿用较早尝试的数值。

一次性离线评估已接入 `model.started/requested/responded/failed/timeout/cancelled` 的 typed payload 与发布解析：model_call_id、模型/模板版本、问题类型、状态、原因、置信度、耗时及可空的输入/输出/调用证据引用。模型调用终态不设置业务请求 `is_terminal`，不表示源站已执行；完整边界见 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估)。

## 11.5 必须记录的事件族

request.accepted/completed/aborted；stage.started/completed/skipped；identity.bound/refreshed/revoked/mismatch；page.accepted/rejected；grant.issued/denied/expired/revoked；crypto.decode/encode/failed/fallback；model.requested/responded/timeout/cache_hit；agent.started/tool_called/tool_result/artifact_created/finished；origin.forward_intent/response/unknown；evidence.captured/sealed/cataloged/expired/deleted/read；policy.proposed/tested/approved/published/rolled_back；audit.gap/backpressure/durability_failed；console.query/export/decrypt/replay。

恢复补偿产生的 request.aborted 允许 `status=null`，并以 cause_event_ids 指向已知的 decision、request.accepted、origin.response 或新追加的 origin.unknown；准入批次只留下 accepted 前缀时使用 `decision=UNKNOWN` 与 `reason_code=REQUEST_INCOMPLETE`。它表达审计终态，不虚构客户端实际收到的状态码。

不可采样事件：每请求最小记录、每个实际安全判定、资格变更、模型调用、Agent 工具调用、管理动作、证据访问与完整性异常。调试 span 和性能采样可独立配置，但不能让 required 审计消失。

## 11.6 可解释拒绝图

final decision 保存 cause_event_ids、required_checks、completed_checks、skipped_checks、coverage_gaps 和 origin_state。后台展示“身份通过 → 无相应页面动作 → 拒绝 → 模型未执行”，而不是“模型没有发现异常”。明确区分 WAF 策略拒绝、已验证业务拒绝、疑似攻击及内部服务失败。

审计字段的一致性、来源质量和敏感内容处理参考 OWASP 的日志设计原则；本事件格式是 Xshield 自定义契约。[S22]

## 11.7 已实现的管理访问审计发布

封存段发布器支持当前控制服务的全部管理访问事件：`console.health.read`、`console.request.read`、`console.events.read`、`console.manifest.read`、`console.model.read`、`console.query.executed`、`console.case.read`、`case.created`、`case.closed`、`case.evidence.added`、`evidence.access.requested/approved/denied` 和 `evidence.read`。按实际 `AccessPayload` 严格解析并校验生产者、事件类型/HTTP 方法/路由组合、管理主体、目标 ID、证据引用、读取字节数及查询摘要；重复字段、未知字段、目标错绑或超界会停止当前段，水位保持在上一已确认段。

索引阶段为 `control_access`，保留实际 `PASS/DENY/ERROR`、稳定原因码及方法，证明为 `deterministic`、`confidence=null/not_applicable`。管理尝试不设置业务 `is_terminal`，不推导源站结果或客户端实际收到的 HTTP 状态。可通过管理响应的 request_id 查询事件时间线，或通过有界 QueryPlan 按 event_type、stage、reason_code、outcome 检索；业务请求摘要的完整性标记不作为管理操作完成凭证。

目标 case/access/model/request、主体、query_digest 与 bytes_read 保留在受限的原始事件载荷；当前脱敏查询返回通用摘要和证据引用，不提供按案件/主体目标过滤，也不直接返回该载荷。引用可检索不扩大证据读取权限。管理 journal 描述接口访问尝试和重试；未认证请求超出限流预算时直接返回 `CONTROL_RATE_LIMITED`，不追加逐请求访问日志。PostgreSQL 同名 outbox 记录事务状态转换，两者 event_id 与载荷契约不同；journal 发布器与下述 outbox 发布器分别绑定各自来源和契约。

## 11.8 已实现的按事件族 outbox 发布

`xshield-outbox-worker` 是一次有界发布 pass，按固定 tenant/site 作用域从 `xshield.audit_outbox` 领取最多 256 行及 64 MiB JSON 字节，并以 PostgreSQL `clock_timestamp()` 设置最长一小时租约。候选行使用 `FOR UPDATE SKIP LOCKED`；ClickHouse 网络操作不持有 PostgreSQL 事务锁。确认必须携带同一 event_id、作用域和未过期 lease token，旧 token 或跨作用域确认统一拒绝。发布成功后才写 `published_at`；失败释放租约、保存 `OUTBOX_INVALID_EVENT`、`OUTBOX_INDEX_UNAVAILABLE` 或 `OUTBOX_INTEGRITY_CONFLICT` 并按有界延迟重试。

部署先应用 `0019_m3_outbox_delivery.sql`，然后运行 `xshield-outbox-worker TENANT_ID SITE_ID`。`XSHIELD_OUTBOX_FAMILY` 可设为 `case`（默认）、`evidence_catalog` 或 `evidence_access`，每次只领取该族。数据库配置为 `XSHIELD_DATABASE_URL`、`XSHIELD_OUTBOX_DATABASE_MAX_CONNECTIONS`、`XSHIELD_OUTBOX_DATABASE_ACQUIRE_TIMEOUT_MS`；索引配置为 `XSHIELD_CLICKHOUSE_URL/DATABASE/USER/PASSWORD` 和可选 `XSHIELD_CLICKHOUSE_TABLE`（默认 `audit_events`）。秘密只通过部署环境注入。

必须配置 `XSHIELD_AUDIT_METADATA_RETENTION_DAYS`（1–3650）、`XSHIELD_OUTBOX_MAX_EVENTS`（1–256）、`XSHIELD_OUTBOX_MAX_BYTES`（1–67108864）、`XSHIELD_OUTBOX_LEASE_SECONDS` 和 `XSHIELD_OUTBOX_RETRY_SECONDS`（均为 1–3600）。一条 envelope 另受 64 KiB 解析上限约束。该命令执行一次后退出；调度器按固定作用域和族再次运行，遇错误保留退出失败供告警。当前 pass 在首个错误处停止，已领取的后续行等待租约到期再处理。

当前适配器按租约领取族隔离：`case.created`、`case.closed`、`case.evidence.added` 只接受控制服务的完整 v3 envelope；`evidence.cataloged` 只接受 `gateway-evidence-catalog` 或 `model-eval` 的完整 envelope，并重新校验 UUIDv7 producer boot、单因果、`RESTRICTED` 分类以及 artifact/evidence_refs/aggregate_ref 三方一致；`evidence.access.requested/approved/denied` 接受控制服务的完整请求/独立审批 envelope，分别校验 artifact 引用、access request 目标、主体、审批决定和 TTL。三族的 producer、policy、请求/序号、确定性 proof、重复键、未知字段和列/envelope 一致性均重新校验，不会回退到通用解析。ClickHouse 插入前后均按 event_id 比对 SHA-256 content_digest；相同 ID 的不同正文保持完整性冲突，绝不确认 PostgreSQL 行。`session.*`、`binding.*`、grant 等其他事务 outbox 仍是待交付适配器，不得据此声称全量 outbox 已索引。
