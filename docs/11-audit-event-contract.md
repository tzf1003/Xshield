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
| calibration_read_capability_id | 一份目的限定的离线校准批量读取能力 | calcap_ + UUIDv7；冻结 scope，不是内容或业务授权凭证 |
| calibration_read_lease_id | 一次校准批次会话的公开关联 ID | callease_ + UUIDv7；私有 lease handle 仅在运行中会话存在 |
| calibration_report_id | 一份独立的离线校准报告元数据投影 | calr_ + UUIDv7；不是 evidence 内容读取或阈值/策略发布凭证 |
| calibration_lineage_review_id | 一份独立的校准分区声明审核投影 | calrev_ + UUIDv7；不是 corpus 内容独立性、evidence 读取或业务授权凭证 |
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

当前阶段发布契约：`proof_kind=model` 必须带 `mdl_` UUIDv7 调用引用；其他 proof 不携带模型调用或版本。可选 `model_revision` 为 1–128 字节的 ASCII 字母、数字、`_`、`-`、`.` 标识，`model_call_id` 与其一同写入独立索引列，供请求时间线与有界查询展示直接调查链接。该链接只投影强类型 ID；模型详情继续由独立 `Observer` 端点重新鉴权和审计。为兼容新增列前的历史行，查询仅在 `proof_kind=model` 且索引为空时，从同一受限 payload 的 `model_call_id` 回填，并再次验证 `mdl_` UUIDv7；空或非法值拒绝该结果，绝不从当前配置推断历史值。旧非模型事件的缺失调用/模型版本继续以 null 表示未知。provider 与 provider_model_id 必须成对出现，旧事件两者均缺失时保持兼容，查询字段序列化为 null。`confidence_status=provided` 与非空置信度一一对应，其他状态必须为 null；确定性结果继续为 `null/not_applicable`，SKIPPED/CANCELLED 不得携带数值。

升级兼容：已有网关确定性事件无需改写。违反文档约定的 `model_` 前缀、非模型事件附带模型引用或置信度状态矛盾会被发布器以 InvalidEvent 拒绝并保持当前段水位；应检查生产者及受影响段，保留原始审计证据。阶段汇总使用同一最新事件的置信度，包括 null，避免沿用较早尝试的数值。

一次性离线评估已接入 `model.started/requested/cache_hit/responded/failed/timeout/cancelled` 的 typed payload 与发布解析：model_call_id、provider、独立的 provider_model_id（例如 `typesafe-ai/jev`）、内部模型/模板版本、问题类型、状态、原因、置信度、耗时及可空的输入/输出/调用证据引用。`model.cache_hit` 仍是 requested 状态，但必须带 `reason_code=MODEL_CACHE_HIT` 和已校验的来源 `cache_source_model_call_id`；随后写入本次新的调用记录。provider_model_id 只描述实际冻结 wire 标识，不替代内部 model_revision；Gateway alias 没有精确版本证明时 resolved_model_revision 保持 null。模型调用终态不设置业务请求 `is_terminal`，不表示源站已执行；完整边界见 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估)。

## 11.5 必须记录的事件族

request.accepted/completed/aborted；stage.started/completed/skipped；identity.bound/refreshed/revoked/mismatch；page.accepted/rejected；grant.issued/denied/expired/revoked；crypto.decode/encode/failed/fallback；model.requested/responded/timeout/cache_hit；agent.started/tool_called/tool_result/artifact_created/finished；origin.forward_intent/response/unknown；evidence.captured/sealed/cataloged/expired/deleted/read；policy.proposed/tested/approved/published/rolled_back；audit.gap/backpressure/durability_failed；console.query/export/decrypt/replay；console.auth.login/callback/session.read/session.logout/reauth.start/reauth.callback/site.config.read/site.config.write。

再认证事件仅描述 OIDC step-up 的启动与验证，不携带 state、授权码、token 或原始认证上下文值；完整的路径、角色与失败审计映射见 [29.28](29-api-endpoint-catalog.md#2928-已实现的-mfa-再认证契约)。

恢复补偿产生的 request.aborted 允许 `status=null`，并以 cause_event_ids 指向已知的 decision、request.accepted、origin.response 或新追加的 origin.unknown；准入批次只留下 accepted 前缀时使用 `decision=UNKNOWN` 与 `reason_code=REQUEST_INCOMPLETE`。它表达审计终态，不虚构客户端实际收到的状态码。

不可采样事件：每请求最小记录、每个实际安全判定、资格变更、模型调用、Agent 工具调用、管理动作、证据访问与完整性异常。调试 span 和性能采样可独立配置，但不能让 required 审计消失。

## 11.6 可解释拒绝图

final decision 保存 cause_event_ids、required_checks、completed_checks、skipped_checks、coverage_gaps 和 origin_state。后台展示“身份通过 → 无相应页面动作 → 拒绝 → 模型未执行”，而不是“模型没有发现异常”。明确区分 WAF 策略拒绝、已验证业务拒绝、疑似攻击及内部服务失败。

审计字段的一致性、来源质量和敏感内容处理参考 OWASP 的日志设计原则；本事件格式是 Xshield 自定义契约。[S22]

## 11.7 已实现的管理访问审计发布

封存段发布器支持当前控制服务的全部管理访问事件：`console.health.read`、`console.request.read`、`console.events.read`、`console.manifest.read`、`console.model.read`、`console.grant.read`、`console.binding.read`、`console.query.executed`、`console.case.read`、`console.case.list`、`console.case.analyze`、`console.job.read`、`console.evidence.access.read`、`console.evidence.access.list`、`console.site.config.read`、`console.site.config.write`、`console.sites.list`、`console.site.create`、`console.site.delete`、`console.site.status.read`、`console.site.config.validate`、`console.site.config.apply`、`console.site.config.rollback`、`case.created`、`case.closed`、`case.evidence.added`、`evidence.access.requested/approved/denied` 和 `evidence.read`。站点管理事件分别固定到列表、创建、删除、配置读写、状态/健康/修订读取、校验、应用和回滚路由；事件只携带已校验的租户/站点引用和稳定原因码，不携带配置秘密或完整配置正文。按实际 `AccessPayload` 严格解析并校验生产者、事件类型/HTTP 方法/路由组合、管理主体、目标 ID、证据引用、读取字节数及查询摘要；任务读取的 `job_` 目标使用独立字段校验。重复字段、未知字段、目标错绑或超界会停止当前段，水位保持在上一已确认段。

`console.case.list` 固定对应 `GET /control/v1/cases`，成功（含空页）要求主体和 `CONTROL_CASES_READ`。全部 target 字段、query_digest、bytes_read 仅允许缺省/null，evidence_refs 为空；事件不保存案件用途、列表正文或游标。权限/输入/预算拒绝为 DENY，依赖失败为 ERROR；启用端点前先升级管理 journal 发布器。

`console.evidence.access.list` 固定对应 `GET /control/v1/evidence-access-requests`。`mine` 视图允许 `Investigator`、`SensitiveEvidenceReader` 或 `SensitiveEvidenceApprover` 查看本人申请历史；`review` 视图允许同作用域 `SensitiveEvidenceApprover` 查看其他主体的 pending 申请。每页以独立 PostgreSQL 快照观察，使用共用操作许可、含连接池等待的 15 秒总期限及 5 秒 SQL/锁等待期限；已准入查询在客户端断连后继续到数据库结果及耐久审计终态。列表元数据用于发现和复核，内容读取仍须重新验证访问资格。

列表事件沿用 `xshield-control` / `control-v1`、`request_seq=1`、`INTERNAL` 和空 cause_event_ids。成功（含空页）必须为 `PASS/CONTROL_EVIDENCE_ACCESS_LIST_READ` 且包含调用者 subject_ref；全部 target 字段、query_digest、bytes_read 仅允许缺省/null，evidence_refs 为空。载荷只保留固定方法、路由、调用者及结果原因，view、cursor、列表记录、申请/审批理由与他人主体不进入审计事件。拒绝仅允许 `CONTROL_AUTH_REQUIRED`、`CONTROL_SCOPE_DENIED`、`CONTROL_RATE_LIMITED`、`CONTROL_CURSOR_INVALID`、`CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID`、`CONTROL_EVIDENCE_ACCESS_BUSY`；故障仅允许 `ERROR` 搭配 `CONTROL_CURSOR_UNAVAILABLE`、`CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`、`CONTROL_RATE_UNAVAILABLE`、`CONTROL_CLOCK_UNAVAILABLE`。未知字段、重复键、路由或原因/outcome 偏差均阻止发布；启用端点前先升级管理 journal 发布器。

`console.evidence.access.read` 固定对应 `GET /control/v1/evidence-access-requests/{access_request_id}`，记录固定 tenant/site 作用域内的审批详情元数据观察。具备 `Investigator` 或 `SensitiveEvidenceReader` 的申请人可读取本人记录，`SensitiveEvidenceApprover` 可读取同作用域记录；案件已关闭、申请或证据已过期、证据已删除时仍可观察保留的审批历史。缺失、跨作用域和非本人且无审批角色统一返回 404 / `CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE`。该查询保持原文权限和到期时间，读取审批详情不产生内容访问、期限延长或事务 outbox 记录。

该事件由 `xshield-control` 写入独立加密管理 journal，`request_seq=1`、`policy_revision=control-v1`、`sensitivity=INTERNAL`、cause_event_ids 为空。成功为 `PASS/CONTROL_EVIDENCE_ACCESS_READ`，必须携带调用者 subject_ref，以及规范 UUIDv7 的 `target_access_request_id`、`target_case_id`、`target_artifact_id`；evidence_refs 恰为该 artifact。失败为 DENY 或 ERROR，只允许保留已完成校验的申请目标，case/artifact 目标及 evidence_refs 为空；鉴权、限流和时钟失败发生在目标解析前，全部目标为空。`CONTROL_EVIDENCE_ACCESS_ID_INVALID` 表示申请 ID 校验失败，全部目标也必须为空。其他 target、query_digest、bytes_read 仅允许缺省/null。事件只保留调用者与目标引用，申请理由、审批理由、他人主体、状态详情、秘密和内容均不得进入载荷。

输入、查找和容量失败分别使用 `CONTROL_EVIDENCE_ACCESS_ID_INVALID`、`CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID`、`CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE`、`CONTROL_EVIDENCE_ACCESS_BUSY`，并保留通用鉴权与限流原因；数据库故障和超时使用 `ERROR/CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`（503）。通用限流服务与时钟失败分别为 `ERROR/CONTROL_RATE_UNAVAILABLE`、`ERROR/CONTROL_CLOCK_UNAVAILABLE`。查询复用案件操作的有界许可，数据库总期限为含连接池等待的 15 秒、SQL/锁等待为 5 秒；已准入任务在客户端断连后继续完成数据库观察和耐久审计。管理审计写入失败时返回审计不可用，响应本身不证明事件已保存。发布摘要沿用 `control_access`、`deterministic`、`confidence=null/not_applicable` 和非业务终态语义；须先升级管理 journal 发布器再启用端点。

`console.grant.read` 仅对应 `GET /control/v1/grants/{grant_id}`；已校验的目标使用可选 `target_grant_id`，成功（含未找到）必须携带该字段。该目标只属于此路由，失败保留已完成校验的引用，其他路由保持字段缺省；不记录账本正文、资格状态或绑定快照。部署先升级管理 journal 发布器再启用新查询端点，旧发布器遇到新事件会停止推进并保留待发布段。

`console.binding.read` 对应 `GET /control/v1/auth-bindings/{binding_id}`，按相同规则使用独立可选 `target_binding_id`。成功（含未找到）必须绑定规范 `auth_` UUIDv7；其他路由不能携带该目标。事件只记录访问结果与原因，不含身份快照，evidence_refs 为空。启用端点前须升级管理 journal 发布器。

管理发布器还支持 `console.evidence.hold.created/released/read`，分别绑定保留锁创建、释放和历史查询路由（29.21）。创建/释放成功要求 case/artifact/hold 三个目标及唯一 artifact evidence ref；列表成功只要求 case，引用为本页 artifact 去重集合。失败仅保留已校验的对应目标、引用为空；成功原因精确区分创建、释放、两者重试及读取。新增 `target_hold_id` 为规范 `ev_` UUIDv7，其他管理事件只允许缺省/null。理由与期限不进入管理日志，事务 `evidence.hold.*` 继续由独立 outbox 来源发布。须先升级管理 journal 发布器再启用新路由。

索引阶段为 `control_access`，保留实际 `PASS/DENY/ERROR`、稳定原因码及方法，证明为 `deterministic`、`confidence=null/not_applicable`。管理尝试不设置业务 `is_terminal`，不推导源站结果或客户端实际收到的 HTTP 状态。可通过管理响应的 request_id 查询事件时间线，或通过有界 QueryPlan 按 event_type、stage、reason_code、outcome 检索；业务请求摘要的完整性标记不作为管理操作完成凭证。

目标 case/hold/access/model/request、主体、query_digest 与 bytes_read 保留在受限的原始事件载荷；脱敏查询返回通用摘要和证据引用，不直接返回该载荷。`case_id` 过滤按固定事件/阶段读取案件目标，`artifact_id` 按 evidence_refs 及固定管理事件的证据目标定位；`calibration_report_id` 与 `evidence_hold_id` 均要求同一主体同时具备 Investigator 与 AuditAdministrator，分别读取固定报告/保留历史及对应管理操作目标；权限拒绝使用稳定原因码并仅以 query_digest 形成既有 `console.query.executed` 的 DENY 终态。`model_call_id` 过滤以 Investigator 身份读取固定 `model.*` 生命周期事件及 `console.model.read` 目标；它不替代该详情路由的独立 Observer 重鉴权。`evidence_access_request_id` 过滤以 Investigator 身份读取固定 `evidence.access.*` 申请/决策事件及 `console.evidence.access.read` 目标；它不替代申请详情、审批或原文读取各自的重鉴权。`subject_ref` 过滤以 Investigator 身份在固定 tenant/site 范围内精确匹配 `subject_ref`、`principal_ref`、`authorization_context_ref`、`previous_principal_ref`、`previous_authorization_context_ref` 顶层字段；查询摘要对该值使用用途隔离 HMAC，结果不回显主体。完整映射见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。完整跨事件展开仍继续交付；引用可检索不扩大证据读取权限。管理 journal 描述接口访问尝试和重试；未认证请求（含携带 `X-Xshield-API-Key` 的尝试）超出限流预算时直接返回 `CONTROL_RATE_LIMITED`，不追加逐请求访问日志；预算内的每次 API Key 尝试恰好追加一条 `console.agent_api_key.use`，不再由被拒绝请求的路由追加第二条。PostgreSQL 同名 outbox 记录事务状态转换，两者 event_id 与载荷契约不同；journal 发布器与下述 outbox 发布器分别绑定各自来源和契约。

`agent_run_id` 历史检索以 Investigator 身份读取固定 `agent.started`、`agent.tool_called`、`agent.tool_result`、`agent.artifact_created`、`agent.finished` 事件及 `console.agent.read` 目标；只投影脱敏历史摘要，不读取 Agent 输入/输出或工具正文，不触发执行、回放或权限提升。`GET /control/v1/agent-runs/{agent_run_id}` 另以 Observer 重新鉴权读取固定事件族的脱敏生命周期，并独立审计 `console.agent.read`；工具参数、结果和权限快照仍隔离。完整映射见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约) 与 [29.30](29-api-endpoint-catalog.md#2930-已实现的-agent-运行脱敏详情契约)。

案件清单分析 MVP 由 `console.case.analyze` 记录案件目标，`console.job.read` 记录任务状态查询；两者仅保存确定性管理事实，不把任务状态当作 Agent 生命周期、证据读取资格或回放结果。`target_job_id` 只允许出现在任务状态查询成功或已校验的终态错误中，并按 `job_` UUIDv7 强类型解析；审计不记录幂等原文、案件正文或模型输入输出。

## 11.8 已实现的按事件族 outbox 发布

`xshield-outbox-worker` 是一次有界发布 pass，按固定 tenant/site 作用域从 `xshield.audit_outbox` 领取最多 256 行及 64 MiB JSON 字节，并以 PostgreSQL `clock_timestamp()` 设置最长一小时租约。候选行使用 `FOR UPDATE SKIP LOCKED`；ClickHouse 网络操作不持有 PostgreSQL 事务锁。确认必须携带同一 event_id、作用域和未过期 lease token，旧 token 或跨作用域确认统一拒绝。发布成功后才写 `published_at`；失败释放租约、保存 `OUTBOX_INVALID_EVENT`、`OUTBOX_INDEX_UNAVAILABLE` 或 `OUTBOX_INTEGRITY_CONFLICT` 并按有界延迟重试。

部署先应用 `0019_m3_outbox_delivery.sql`，然后运行 `xshield-outbox-worker TENANT_ID SITE_ID`。`XSHIELD_OUTBOX_FAMILY` 可设为 `case`（默认）、`evidence_catalog`、`evidence_access`、`evidence_retention`、`calibration`、`identity`、`grant`、`response_grant` 或 `share_grant`，每次只领取该族。数据库配置为 `XSHIELD_DATABASE_URL`、`XSHIELD_OUTBOX_DATABASE_MAX_CONNECTIONS`、`XSHIELD_OUTBOX_DATABASE_ACQUIRE_TIMEOUT_MS`；索引配置为 `XSHIELD_CLICKHOUSE_URL/DATABASE/USER/PASSWORD` 和可选 `XSHIELD_CLICKHOUSE_TABLE`（默认 `audit_events`）。秘密只通过部署环境注入。

必须配置 `XSHIELD_AUDIT_METADATA_RETENTION_DAYS`（1–3650）、`XSHIELD_OUTBOX_MAX_EVENTS`（1–256）、`XSHIELD_OUTBOX_MAX_BYTES`（1–67108864）、`XSHIELD_OUTBOX_LEASE_SECONDS` 和 `XSHIELD_OUTBOX_RETRY_SECONDS`（均为 1–3600）。一条 envelope 另受 64 KiB 解析上限约束。该命令执行一次后退出；调度器按固定作用域和族再次运行，遇错误保留退出失败供告警。当前 pass 在首个错误处停止，已领取的后续行等待租约到期再处理。

当前适配器按租约领取族隔离：`case.created`、`case.closed`、`case.evidence.added` 只接受控制服务的完整 v3 envelope；`evidence.cataloged` 只接受 `gateway-evidence-catalog` 或 `model-eval` 的完整 envelope，并重新校验 UUIDv7 producer boot、单因果、`RESTRICTED` 分类以及 artifact/evidence_refs/aggregate_ref 三方一致；`evidence.access.requested/approved/denied` 接受控制服务的完整请求/独立审批 envelope，分别校验 artifact 引用、access request 目标、主体、审批决定和 TTL。`identity` 精确领取 `session.created`、`binding.created`、`identity.refreshed`、`epoch.changed`、`binding.revoked`，只接受 `gateway-identity` 的完整事件，重新校验 `auth_` binding/aggregate、初始状态、代际递增、实际上下文变化以及撤销原因；包含凭证的事件再校验凭证 kind 唯一性及 HMAC 形状；计数受 PostgreSQL bigint 上限约束。

`grant` 精确领取 `grant.issued`，只接受 `gateway-grant` 的完整 v3 envelope，aggregate_ref 等于 payload.grant_id。封闭 payload 固定 `grant/PASS/GRANT_ISSUED`，包含 grant/binding/正 bigint epoch、scoped action_ref、source_request_id、资源类型与 HMAC、operation/view、策略修订、constraints_digest 和发行/到期秒数。producer_boot_id 等于 event_id，producer_seq/request_seq 均为 1；请求和策略必须与 payload 对应字段相等，occurred_at/observed_at 必须等于冻结发行秒数的规范 UTC 编码，TTL 为 1–86400 秒。事件摘要保留目标 operation，method 为空，`confidence=null/not_applicable`、`is_terminal=0`；evidence_refs/cause_event_ids 为空，敏感引用和摘要只进入 `SENSITIVE` payload_json。发行历史不授予当前访问权。

`response_grant` 精确领取 `response_grant.issued`，只接受 `gateway-response-grant` 的完整 v3 envelope，且 `aggregate_ref` 必须等于 payload 的 `grant_id`。封闭 payload 包含 `response_grant/PASS/GRANT_ISSUED`、资格/binding/epoch/响应证据/动作引用、来源与目标 operation、GET 方法与路由、资源类型与 HMAC、view、单个 field、mapping revision、2xx 且非 204 的响应状态、正文 SHA-256、candidate_count 和发行/到期秒数。解析器重新校验强类型 ID、lowercase hex、正 epoch、1–1000 个候选及 1–86400 秒 TTL；引用或形状偏差均拒绝。

`share_grant` 精确领取 `share.issued`，只接受 `gateway-share-grant` 的完整 v3 envelope，`aggregate_ref` 必须等于 payload 的 `share_id`，share ID 的 UUID 部分必须等于 event ID。封闭 payload 包含 `share_grant/PASS/SHARE_ISSUED`、分享 ID、发行者 binding/epoch/来源 grant/规则、来源与目标 operation/view、资源类型及 HMAC、`GET/reusable_read` 和发行/到期秒数；强类型 ID、scoped name、lowercase hex、正 bigint epoch、1–86400 秒 TTL 均重新校验。凭证、凭证指纹、issuance key 和原始资源值不进入事件。

`evidence_retention` 精确领取 `evidence.purge_requested`、`evidence.deleted`、`evidence.purge_failed` 及对应三个 `evidence.orphan.*` 类型，只接受 `evidence-retention` / `evidence-retention-v1` 的完整 v3 envelope。每条事件有独立 UUIDv7 boot，两个序号均为 1，`request_id` 显式为 null；occurred_at/observed_at 为相同的规范 UTC 毫秒时间，trace 前 16 位等于 span。catalog payload 固定 `evidence_retention` 阶段，保留 source_request_id、原始 expires_at 和 `retained_metadata=true`；孤儿 payload 固定 `evidence_orphan_retention` 阶段及 authenticated_manifest 布尔值。两种封闭载荷分别校验，artifact 与唯一 evidence_ref 及 aggregate_ref 一致。意图无 cause，完成或失败恰有一个不同于自身的意图事件引用；十种稳定原因与事件/outcome 精确绑定。引用检查验证事件形状，不对跨存储历史完整性作证明。摘要为 `confidence=null/not_applicable`、`is_terminal=0`，分类为 `RESTRICTED`；维护事件按事件 ID、类型、原因或阶段查询，脱敏结果保留 artifact/cause 引用且不返回 payload。事件只描述删除事务与尝试，不恢复内容、延长原文权限或证明远端副本已删除。

九族的 producer、policy、请求/序号、确定性 proof、重复键、未知字段和列/envelope 一致性均重新校验，不会回退到通用解析。ClickHouse 插入前后均按 event_id 比对 SHA-256 content_digest；相同 ID 的不同正文保持完整性冲突，绝不确认 PostgreSQL 行。身份族现同时严格接收 `session.created`、`binding.created`、`identity.refreshed`、`epoch.changed` 与 `binding.revoked`；撤销事件只记录非秘密主体/上下文引用、epoch/generation 与 `explicit_logout` 原因，凭证仍保持在敏感载荷之外。

`evidence_retention` 同时领取 `evidence.hold.created` 与 `evidence.hold.released`。两种事件采用 `evidence-hold` / `evidence-hold-v1`，event_id 等于 producer_boot_id，UUID 去连字符得到 trace，span 为其前 16 位。封闭载荷固定 `evidence_hold/PASS`、对应 `EVIDENCE_HOLD_CREATED` 或 `EVIDENCE_HOLD_RELEASED`、hold/case/artifact、主体引用、请求摘要与原 hold_until。创建事件等于 hold ID、无 cause，期限在发生时间后 30 天内；释放事件引用一个不同于自身的 hold ID，可释放已到期锁。时间为规范 UTC 毫秒（秒为 00–59），request_id 显式 null，确定性 confidence 显式 null，分类 RESTRICTED；自由文本理由存受限数据库并经管理员 API 返回，不进入事件。摘要保持非业务终态，索引不作为保留或访问授权真值。

校准报告保留另使用 `calibration.report_retention.*` 六种受限事件，涵盖已提交报告的到期删除及 request-free 侧车孤儿的 intent、完成和失败。producer、scope、report/artifact 引用、UTC 毫秒、`retained_metadata=true`、原因/outcome 与 cause 绑定由 worker 和 schema 双重校验；孤儿路径不进入通用 evidence orphan 表。事件只记录维护阶段，不能恢复报告正文、延长期限或证明跨存储操作具备事务原子性。

`calibration` 族还接收 `calibration.partition_lineage.reviewed`。该事件只将一个独立 `calrev_` 审核、其 protected artifact、冻结 provenance 和四份 manifest 关联到受限历史索引；它不携带 source graph、source ID/revision、图摘要、样本、标签、指标或正文，也不把 ClickHouse/outbox 变成 catalog、vault、retention 或授权真值。

升级后可为既有完整清理事件启用 `evidence_retention` 调度；案件保留锁及升级后的清理任务须先应用迁移 `0020_m3_case_evidence_holds.sql`（见 12.9）。索引保留期仍从原始 occurred_at 起算，积压中已超期事件在 active 视图不可见。所有 v3 来源均要求 envelope 显式包含 request_id（可为 null，具体族另有限制），缺失字段的历史畸形记录按既有错误/水位规则保留待处理，不补造请求身份。

身份事务使用 request_id 作为独立 producer_boot_id，producer_seq/request_seq 均为 1，保留原网关请求 trace 与配置修订；两种序列不推进 journal 的序列，也不表示跨来源全序。当前时间线按 `(request_seq,event_id)` 排序，调查时应结合生产者与发生时间理解身份事件，不能以该位置推断源站先后。`identity_lifecycle` 的 PASS 是事务结果，`is_terminal=0`，不推断业务执行状态；确定性结果保持 `confidence=null/not_applicable`。主体/上下文引用与新旧凭证 HMAC 保留在 `SENSITIVE` payload_json，脱敏查询摘要不返回该载荷，普通检索不授予认证权力。

响应资格事务同样使用原 request_id 作为独立 producer_boot_id，并保留 trace 与策略修订；同一响应每个候选的 producer_seq/request_seq 相等，从 1 开始且不超过 candidate_count。occurred_at 与 observed_at 必须同时等于 issued_at_unix 的规范 UTC 整秒编码（`YYYY-MM-DDTHH:mm:ssZ`），重试沿用冻结值。批内序号与 journal 序列独立，不能用时间线位置推导跨生产者全序。`response_grant` 阶段索引保留 `PASS/GRANT_ISSUED`、GET 和目标 operation，确定性结果为 `confidence=null/not_applicable`、`is_terminal=0`；敏感引用、HMAC 和正文摘要保留在 `SENSITIVE` payload_json，evidence_refs/cause_event_ids 为空。发行历史不证明资格当前有效，也不证明客户端收到成功响应。

请求摘要的 method 仅来自 `request.accepted` 或 `control_access`，operation 仅来自 `request.accepted` 或请求阶段事实。资格事件中的目标方法与操作保留为事件字段；只有资格历史时，请求摘要中的来源方法与操作保持空值，等待请求上下文事件。

分享发行库 API 用完整 event ID 作为独立 producer_boot_id，producer_seq/request_seq 均为 1；同一请求可产生多个独立分享，request_id 保留原请求。occurred_at/observed_at 同时等于冻结 issued_at_unix 的规范 UTC 整秒编码，重试沿用原值。`share_grant` 摘要保留 `PASS/SHARE_ISSUED`、GET 和目标 operation，`confidence=null/not_applicable`、`is_terminal=0`，不推导跨生产者全序或客户端收到凭证；`SENSITIVE` payload 的 evidence_refs/cause_event_ids 为空。HTTP `response.share_issue` 适配器每请求只发行一条分享，event/share ID 复用服务器 request ID 的 UUID 部分，并使用固定前缀区分类型；请求、trace、策略和发行时间在单次事务前冻结，新 HTTP 请求独立发行。

完整缓冲响应已经验证后发生客户端写失败时，网关保留 `origin.response/response_received` 及实际源站状态，终态为 `request.aborted/REQUEST_INCOMPLETE`。尚未取得完整响应的代理故障保持 `origin.unknown`；发行 outbox 只证明事务提交，不证明客户端接收完成。

身份、通用资源资格、响应资格与分享发行生产者升级把业务字段放入完整 envelope 的 `payload`，运行中的生产者与发布器应配套升级。`GrantPersistence::new` 的 envelope 参数变更为冻结 trace_id，完整事件由持久化入口按 JSONB 约束表示生成；调用方须保留同一 event/grant ID、trace、时间与批准约束用于重试。历史稀疏行保留原文、保持未确认并记录 `OUTBOX_INVALID_EVENT`、延迟重试；不会以当前状态补造历史时间或来源。分享库 API 同时要求稳定 event/share ID 和完整精确重试正文，旧随机 share ID 或稀疏正文不匹配时拒绝重试，不重新发行凭证。上线前应盘点历史积压并保留原始证据，监控错误码及积压；当前首错停批会使已领取的后续行等待租约到期。发布器不重放身份转换、不重新发行资格，也不回滚已提交的状态。

## 11.9 已实现 calibration.reported 发布契约

`calibration` 族只接受 `calibration.reported` 的完整、受限元数据 envelope：producer 固定为 `calibration-evaluator`、policy revision 固定为 `calibration-v1`，聚合字段为 `calr_` UUIDv7 report ID；request_id 为 null，producer boot、两个序号、UTC 毫秒发生/观察时间、trace/span 与 report ID 的绑定均严格校验。封闭 payload 固定为 `calibration_report/PASS/CALIBRATION_REPORTED`，只含 report artifact、approval、dataset/label/task/threshold-policy/mapping revision、四份 manifest 和 ModelIdentity。report artifact 既是唯一 evidence_ref，也不得与四份 manifest 重复；resolved provider revision 只能是有效修订或显式 null，不能由当前路由推断。

schema 与消费端拒绝未知/重复字段、错误 producer/aggregate/evidence 绑定、非规范 ID 或时间、别名 artifact、额外 cause，以及任何标签、概率、样本、ground truth、指标、提示词、凭证或 evidence 内容。索引摘要固定为 deterministic、`confidence=null/not_applicable`、非业务终态且不带 HTTP 方法、操作或源站状态；它记录一个离线报告元数据事实，不授予授权、读取 evidence、改变/发布阈值或策略，也不代表报告或模型质量。

### 11.9.1 已实现 calibration.partition_lineage.reviewed 发布契约

`calibration.partition_lineage.reviewed` 的 producer 固定为 `calibration-lineage-reviewer`，policy revision 固定为 `calibration-lineage-v1`，aggregate 为 `calrev_` UUIDv7 review ID。request_id 和 cause_event_ids 必须为空，producer boot 等于 event ID，两个序号均为 1，trace/span 从 review UUID 导出，发生/观察时间为相同的数据库 UTC 毫秒。其封闭 payload 固定为 `calibration_partition_lineage/PASS/CALIBRATION_PARTITION_LINEAGE_REVIEWED`，只含 review/artifact ID、approval/dataset/label/task/threshold-policy/mapping revision、四份不同 manifest 及 ModelIdentity；review artifact 是唯一 evidence_ref，不能别名四份 manifest。

schema 与 calibration parser 同时拒绝未知或重复字段、错误 producer/policy/aggregate/time/trace/evidence binding、非规范 ID、artifact 别名和任何 source graph、source ID/revision、source-graph digest、样本、标签、指标、提示词、凭证或正文。索引摘要固定为 deterministic、`confidence=null/not_applicable` 和非业务终态。它记录提交声明已通过审核，不证明外部 corpus 独立、模型质量或阈值有效性，也不授予 evidence 读取、发布阈值/策略或业务资格。

### 11.9.2 已实现 calibration.lineage_review_retention 维护契约

`calibration.lineage_review_retention.*` 由 `calibration-lineage-review-retention` 生成，policy revision 固定为 `calibration-retention-v1`，aggregate、trace 和 span 均从 `calrev_` review ID 确定；request_id 为 null，唯一 evidence_ref 为 review artifact，发生/观察时间使用相同的数据库 UTC 毫秒。封闭 payload 固定为 `calibration_lineage_review_retention`、deterministic、`confidence=null/not_applicable` 与 `retained_metadata=true`，仅含 review/artifact ID 和到期时间。它不携带 source graph、source ID/revision、样本、标签、指标、提示词、凭证、sidecar、locator、摘要或正文。

六类事件分为 committed review 与 request-free orphan 两组：`purge_requested`/`deleted`/`purge_failed` 和 `orphan_purge_requested`/`orphan_deleted`/`orphan_purge_failed`。两种 intent 没有 cause；完成或失败事实必须引用已经提交的同一清理 intent。完成原因只允许 `...DELETED` 或 `...DELETE_ALREADY_ABSENT`，失败原因只允许 `...PURGE_REJECTED` 或 `...PURGE_UNAVAILABLE`，两者都不表示 review 重新可读、数据独立、阈值有效或任何业务终态。schema 与 calibration parser 拒绝未知/重复字段、错误 producer/policy/aggregate/trace/evidence binding、非规范 ID/时间、多个 evidence/cause 引用及内容字段。索引只记录受限维护历史，projection、sidecar、tombstone 和 capability eligibility 仍由 PostgreSQL/vault 决定。

## 11.10 已实现校准读取能力发行事实

`calibration.read_capability.issued` 是耐久 batch capability 发行的受限 outbox 事实，独立于 `calibration.reported`。producer 固定为 `calibration-capability-issuer`、policy revision 为 `calibration-v1`，aggregate 为 `calcap_` UUIDv7 capability ID；request_id、evidence_refs 和 cause_event_ids 均为空。其确定性 payload 固定为 `calibration_read_capability/PASS/CALIBRATION_READ_CAPABILITY_ISSUED`，只含 capability ID、规范 scope digest、成员数、冻结总字节数以及 Unix 秒的起止期限。trace/span 从 capability UUID 导出；event ID 与 producer boot 相同，两个序号均为 1，发生/观察时间由数据库以 UTC 毫秒冻结。

此事实与 capability header、完整成员 snapshot 同一 PostgreSQL 事务提交；成员行及其 catalog snapshot 留在受限关系表，不展开至 envelope。lease ID、私有 lease handle、artifact ID、批准/数据集/模型修订、标签、概率、内容、控制台主体和业务请求均不进入事实。它记录发行，不构成内容授权、消费完成、报告、模型质量、阈值/策略发布或业务终态。现有 calibration consumer 已严格解析该 event type，绑定 capability aggregate、producer、时钟、trace、空 evidence/cause 引用、64 位 scope digest 以及成员/字节/期限边界，并沿用族隔离的 at-least-once 发布；真实 ClickHouse 端到端投递仍需专有数据库验收。outbox 留存不能替代 durable header/members/lease 状态作为授权真值。

受限报告持久化适配器能够生成 `calibration-evaluator` 的 `calibration.reported`：worker evaluator 先认证专用 report vault sidecar、密文摘要、AEAD 和 canonical report DTO，再将该 attestation 与冻结投影、lease completion 和 outbox 行一并交给同一 PostgreSQL 事务。部署者不得人工伪造事件或用 outbox 代替 vault、lease、catalog 或 retention 状态；跨文件系统与数据库之间的崩溃恢复仍须由专用 reconciliation 路径闭合，不能据此推断 report 内容独立或真实校准结论。

## 11.11 已实现校准明文释放 journal 审计契约

`calibration.evidence_read` 是校准 reader 专用加密 journal 的单对象预释放屏障事实，不是 PostgreSQL outbox 事件。`LocalCalibrationEvidenceReader` 只在每次 PostgreSQL 授权、vault 认证 manifest、密文摘要和 AEAD 检查完成并取得 0025 的短时 release reservation 后构造它；成功 `PASS` 只证明有界明文已通过耐久预释放屏障，不证明 evaluator 已收到内容。必须先取得 `LocalJournal::append_batch` receipt，再由 `commit_calibration_evidence_release` 的事务提交交付边界；该事务失败时清零并扣留内容，不追加相互矛盾的终态。索引发布可按封存段至少一次延后进行，不能作为授权真值。journal 追加失败、receipt 错绑或序列耗尽时，调用方返回自己的 audit-unavailable 错误并阻断明文；不会伪造一条 `ERROR` 事件来表示一个没有耐久写入的结果。

producer 固定为 `calibration-evidence-reader`，policy revision 为 `calibration-v1`，request_id 为 null、request_seq 为 1、sensitivity 为 `RESTRICTED`、evidence_refs 与 cause_event_ids 为空。event ID 在单次预释放尝试前冻结；调用方持有的 helper 可仅以同一冻结字节和 ID 做精确 append 重试，新的尝试必须生成新的 event ID。当前 reader 在 append 边界不确定时不交付 plaintext，关闭已 poisoned journal 并要求其 owner 先走 journal recovery；它不将未确认 event 当作可重新释放的依据。producer boot 和 producer sequence 从持有 journal 的 writer 取得；trace 从 `calcap_` capability UUID 导出，span 从 `ev_` event UUID 导出。`JournalReceipt.receipt_id`、artifact、role、sample index、lease ID、lease handle、控制台主体和任何内容均不序列化到 envelope 或 payload。

封闭 payload 仅为 `stage=calibration_evidence_read`、outcome、reason_code、capability_id 以及成功时的 `bytes_released`。`PASS/CALIBRATION_EVIDENCE_READ_RELEASE_PREPARED` 要求 1–512 MiB 的准确字节数，并且仅表示预释放 barrier；`DENY/CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED` 不带字节数；`ERROR` 只允许 `CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE`、`...CAPACITY_UNAVAILABLE`、`...INTEGRITY_FAILED`、`...VAULT_UNAVAILABLE` 或 `...CANCELLED`，同样不带字节数。所有结果是 deterministic、`confidence=null/not_applicable`、非业务终态，不表示 evaluator 收到内容、batch consumed、完整评估、报告质量、阈值/策略发布或源站动作。`xshield_worker::calibration_audit::CalibrationEvidenceReadAuditEvent` 是 reader 调用的冻结/追加 helper；`LocalCalibrationEvidenceReader` 已将它接入 pre-plaintext barrier。

## 11.12 已实现校准 batch completion 终态

`calibration.read_batch.completed` 是迁移 0024 将完整 evaluator completion 持久化为 `lease active → completed`、capability `leased → consumed` 的同一 PostgreSQL 事务中的受限 outbox 终态。producer 固定为 `calibration-evidence-batch-completer`，aggregate/trace/span 都绑定 `calcap_` UUIDv7 capability；event ID 与 producer boot 相同，两个序号为 1，发生/观察时间为同一数据库 UTC 毫秒。capability header 以外键保存精确 completion event ID，未知提交重试先核对该引用和 event，不能因后续 retention 或 drift 复活读权。

封闭 payload 仅含 `calibration_read_batch/PASS/CALIBRATION_READ_BATCH_COMPLETED` 与 capability ID；request、evidence_refs、cause、lease ID/handle、runner、artifact、样本、label、概率、指标、evaluator 输出和 report 均禁止进入该事实。它是可检索的安全终态，不是 evidence 已完整读取的证明、模型质量、阈值/策略发布或业务授权真值；报告提交时该 completion 与 `calibration.reported` 在同一事务中产生，但两份受限 payload 仍不相互展开内容。

## 11.13 已实现校准报告调查访问审计

`console.calibration.report.read` 是控制面读取单个受限 `calr_` 报告 projection 的管理访问事件。它固定 `GET /control/v1/calibration-reports/{report_id}`、`AuditAdministrator` 与 `control_access` 发布路径；成功为 `PASS/CONTROL_CALIBRATION_REPORT_READ`。已认证的路径、请求或容量拒绝使用 `CONTROL_CALIBRATION_REPORT_ID_INVALID`、`CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID` 或 `CONTROL_CALIBRATION_REPORT_BUSY`，身份/范围/速率沿用通用管理原因；存储、限流和时钟依赖故障分别保留 `CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE`、`CONTROL_RATE_UNAVAILABLE` 与 `CONTROL_CLOCK_UNAVAILABLE`。

只有经路径校验的目标可写 `target_calibration_report_id=calr_…`；认证或范围未建立、限流/时钟失败和无效 ID 不写目标。成功以及已解析目标后的 request、busy 和 store 终态必须保留该目标。所有其他 target、query digest、bytes_read 和 evidence_refs 均为空；payload 不记录报告内容、body 状态、revision、manifest、provider、审批、游标、存储信息或读取资格。worker 对事件类型、方法、路径、目标前缀和上述 outcome/reason 集合严格解析；无法耐久追加该事件时控制面返回 `AUDIT_DURABILITY_FAILED` 并扣留原响应。

## 11.14 管理 journal 事件的发布覆盖规则

控制面每个端点在访问尝试结束时向管理 journal 追加一个 `control_access` 事件。worker 的管理发布器只接受 `crates/xshield-worker/src/control_audit.rs` 中显式列出的 (事件类型, 方法, 路径) 组合；任何不在表中的事件会使包含它的整个 segment 无法发布，其后的 segment 随之停在待发布状态，管理历史不可检索。因此新增端点的同一改动必须扩展该矩阵、目标与成功原因码校验及其测试。

下列事件在 2026-10-04 补入发布器：`console.workbench.overview.read`（`GET /control/v1/workbench/overview`，无目标）、`console.site.config.approve`（`POST /control/v1/sites/{site_id}/approve`）、`console.agent_api_key.admin`/`list`（`/control/v1/agent-api-keys`）、`console.agent_api_key.use`（API Key 认证成功，方法 `*`、路径 `/control/v1/*`）和导出族 `console.export.read`、`export.requested`、`export.approved`、`export.denied`、`export.downloaded`。导出事件新增强类型 `target_export_id=export_…`：成功必须携带，非导出事件必须为空；请求、批准、拒绝成功还须携带 `target_case_id`；下载成功须同时携带 `target_artifact_id`、与其相同的单个 `evidence_refs` 和 `bytes_read`。站点批准与 API Key 管理的成功原因码只受通用格式约束，未知成功原因码不得阻断发布。

API Key 管理事件新增强类型 `target_api_key_id=key_…`（`key_` + UUIDv7，严格前缀校验）：`console.agent_api_key.admin` 成功必须携带，拒绝/故障可携带路径中已校验的 Key 或为空；`console.agent_api_key.list`、`console.agent_api_key.use` 和所有其他事件类型必须为空，错位携带的事件会被发布器以 InvalidEvent 拒绝并停住所在 segment。控制面对创建、撤销、轮换（旧 Key 与新 Key 两条同请求事件，原因码 `CONTROL_API_KEY_ROTATED_OUT`/`CONTROL_API_KEY_ROTATED_IN`，同一 journal 批次）和列表追加成功事件，原因码见 [15 章](15-console-and-api.md)；事件只含管理者主体与 Key ID，不含明文、指纹或前缀。控制面先升级发布器再启用该字段：旧发布器遇到 `target_api_key_id` 会因未知字段停住 segment。`console.agent_api_key.use` 的成功事件主体为 `apikey:{key_id}:{subject}`，预算内的每次尝试恰好一条，预算耗尽的 429 不写事件。

`scripts/check_audit_event_coverage.py` 在 CI 中比较控制面全部 `AccessAction` 与该矩阵，缺任何一项即失败；它是文本级守卫，不替代发布器的真实 ClickHouse 回归（见 20.6、20.11）。
