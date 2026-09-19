# 29 控制 API 与审计责任清单

本章定义自定义接口；当前 `GET /control/v1/audit/health`、`GET /control/v1/requests/{request_id}`、`GET /control/v1/requests/{request_id}/events`、`POST /control/v1/search`、`GET /control/v1/requests/{request_id}/evidence`、`GET /control/v1/model-calls/{model_call_id}`、`GET /control/v1/artifacts/{artifact_id}`、`GET /control/v1/artifacts/{artifact_id}/content`、`POST /control/v1/cases`、`POST /control/v1/artifacts/{id}/access` 及证据访问批准/拒绝端点已由 `xshield-control` 实现，其余条目仍是设计契约。所有 `/control/v1` 接口经管理身份验证、tenant/site作用域检查与速率限制；用户数据API和控制API必须分网络/认证边界。状态变更使用CSRF或对应机器凭证防护，GET不得产生重放或生产业务副作用。

| 方法与路径 | 用途 | 必需审计 |
|---|---|---|
| GET /control/v1/requests/{request_id} | 请求概要和完整性状态 | console.request.read |
| GET /control/v1/requests/{request_id}/events | 事件游标分页和阶段树 | console.events.read |
| GET /control/v1/requests/{request_id}/evidence | 证据manifest清单 | console.manifest.read |
| GET /control/v1/model-calls/{model_call_id} | 模型调用、实际输入输出引用 | console.model.read |
| GET /control/v1/agent-runs/{agent_run_id} | Agent 运行及工具树 | console.agent.read |
| GET /control/v1/artifacts/{artifact_id} | 单个证据manifest | console.manifest.read |
| POST /control/v1/search | 受限查询AST，非任意SQL | console.query.executed |
| POST /control/v1/artifacts/{id}/access | 申请解密/原文查看能力 | evidence.access.requested |
| POST /control/v1/evidence-access-requests/{id}/approve | 独立批准并建立短时读取资格 | evidence.access.approved |
| POST /control/v1/evidence-access-requests/{id}/deny | 独立拒绝并终结申请 | evidence.access.denied |
| GET /control/v1/artifacts/{id}/content | 获批后读取，短时作用域能力 | evidence.read，含批准引用 |
| POST /control/v1/cases | 建立调查案例 | case.created |
| POST /control/v1/cases/{id}/items | 把获准证据加入案例 | case.evidence.added |
| POST /control/v1/cases/{id}/analyze | 启动只读调查Agent | agent.started，工具/模型独立事件 |
| POST /control/v1/replays | 离线规则评估，不送原站 | replay.requested/completed |
| POST /control/v1/exports | 带用途/范围/审批的导出任务 | export.requested/approved/downloaded |
| GET /control/v1/jobs/{id} | 查看任务进度与错误 | console.job.read |
| POST /control/v1/sites/{id}/candidates | 提交配置候选 | policy.proposed |
| POST /control/v1/candidates/{id}/validate | 受控验证 | policy.tested |
| POST /control/v1/candidates/{id}/approve | 审批不等于部署 | policy.approved |
| POST /control/v1/candidates/{id}/publish | 灰度签名发布 | policy.published |
| POST /control/v1/sites/{id}/rollback | 回退已验证版本 | policy.rolled_back |
| GET /control/v1/audit/health | 各层watermark、gap与存储状态 | console.health.read |

## 29.1 查询契约

请求包含 tenant/site（服务端仍校验）、时间窗、类型化过滤器、允许的sort、limit、cursor。禁止自由SQL或可注入表达式。request_id精确查找不要求用户猜日期；先经热定位目录到所属时间桶。返回 index_watermark、as_of、has_gaps、next_cursor。分页令牌绑定调用者作用域和查询摘要，不能跨租户复用。

对未获权ID返回不泄露存在性的统一结果。证据读取另走授权，不因能查摘要就能解密原包。大内容预览与下载分离，浏览器不执行证据中的脚本。

## 29.2 任务语义

长任务返回202和job_id，调用方查询进度。任务状态为queued/running/succeeded/failed/cancelled；失败附稳定原因码、可重试性和最后耐久点。幂等键绑定主体、动作和参数摘要；不同参数不复用。取消保留此前产生的审计证据，禁止删掉历史伪装任务没有发生。

## 29.3 权限角色

Observer 看脱敏概要；Investigator 执行受限查询和申请证据；SensitiveEvidenceApprover 为其他主体批准/拒绝原文访问；SensitiveEvidenceReader 在获批短时范围看受限内容；PolicyAuthor 提交候选；PolicyApprover 批准策略；ReleaseOperator 发布；AuditAdministrator 管理保留与完整性；KeyAdministrator 管理密钥但默认不能解密业务证据。支持职责分离和紧急break-glass，但紧急操作也须理由、短时权限和独立审计。

## 29.4 错误契约

统一结构包含error_code、message_safe、request_id、retryable、next_action；禁止堆栈、凭证、资源归属和内部SQL进入客户端错误。401用于管理认证要求，403用于已认证的禁止操作，409用于代际/修订冲突，429用于预算限制，503用于必需依赖不可用。具体重试不自动重新执行生产业务。

## 29.5 已实现的审计健康契约

`GET /control/v1/audit/health` 的 tenant/site 由服务启动配置固定注入，请求不能选择作用域。管理 Bearer 凭证只保存摘要并采用常量时间比对，签发和过期时间在启动时限制为最长 24 小时且每次请求重验；主体还须持有该精确作用域的 `AuditAdministrator`。服务仅监听 loopback，由独立管理 TLS 边界接入。

成功响应包含 request_id、tenant_id、site_id、观察时间、目标索引、元数据保留天数、关闭段数量与字节、published/pending/unsealed 数量、连续水位和 gap 状态，并设置 `Cache-Control: private, no-store`。401、403、429 和 503 使用 29.4 的统一错误结构。可审计尝试在响应前写入独立加密 journal 的 `console.health.read` 事件；该耐久写失败时返回 503。

## 29.6 已实现的请求事件契约

`GET /control/v1/requests/{request_id}/events` 要求 Observer 和服务端固定的 tenant/site 精确作用域；路径 ID 必须通过强类型校验。查询只访问去重且执行保留策略的 `audit_events_active`，以参数绑定注入作用域和请求 ID，并设置 2 秒执行、100 万扫描行及 1–1000 返回行上限。当前上限由 `XSHIELD_CONTROL_MAX_QUERY_EVENTS` 固定；响应以 `truncated=true` 和 `next_cursor` 明确还有后续数据。续页使用 `?cursor=` 原样传回服务端；游标为 URL-safe、不透明的 HMAC 令牌，由 `XSHIELD_CONTROL_CURSOR_KEY_HEX` 独立密钥签发，绑定管理主体、tenant/site、目标 request_id、查询版本、页大小及最后事件位置，不能跨主体、作用域、请求或配置复用。无效游标返回 `CONTROL_CURSOR_INVALID`，不会执行索引查询。

成功响应包含独立管理 request_id、目标 source_request_id、tenant/site、as_of、连续 index_watermark、has_gaps、truncated、next_cursor 和按 request_seq/event_id 排序的事件摘要。摘要不含 payload_json 或原文，只返回类型、阶段、结果、原因、证明类型、允许的 confidence、修订、证据引用和敏感级别；证据内容仍走独立审批。成功、拒绝和依赖故障写 `console.events.read` 管理审计并绑定已校验的目标请求 ID；审计失败返回 503。响应统一 `private, no-store`。

## 29.7 已实现的请求摘要契约

`GET /control/v1/requests/{request_id}` 复用 Observer、服务端 tenant/site 精确作用域、强类型路径 ID、固定 2 秒/100 万扫描行预算与 active 去重保留视图。发布器在事件契约校验通过后一次性提取 method、operation_id、origin_state、HTTP status 和终态标记；聚合查询不读取 `payload_json`。升级须先应用 `sql/clickhouse.sql` 的目标表/source 表扩展，再部署写入新列的发布器。

响应返回事件数、首末发生时间、可用的 method/operation、终态 decision/reason/status/origin/duration、是否产生转发意图及业务结果是否确认；`stages` 按首次 request_seq 排序，最多返回 128 个已观察阶段的最新结果、原因、证明、confidence 状态、序列范围、耗时和事件数，超界或索引行不满足事件契约时整次查询失败。缺失字段为 null。`completeness` 为 complete、pending、pending_index 或 not_found，并同时返回连续水位、gap 和 pending segment 数，避免在索引未追平时把缺失误报为不存在。成功、拒绝和依赖故障写 `console.request.read`；审计失败返回 503，响应统一 `private, no-store`。身份引用尚未进入 v3 脱敏事件契约，因此当前摘要不推断或伪造该字段。

## 29.8 已实现的请求证据 manifest 契约

`GET /control/v1/requests/{request_id}/evidence` 要求 Observer 与服务端固定 tenant/site 精确作用域；路径 ID 先转强类型，查询再绑定 tenant/site/request，只返回 PostgreSQL catalog 中 active、未删除且按数据库当前时钟未过期的行。响应包含独立管理 request_id、目标 source_request_id、作用域、`truncated`、`next_cursor` 及 typed manifest；不读取对象文件、不返回明文，也不把 catalog 元数据当作内容授权或完整性真值。

结果按规范 artifact UUIDv7 身份稳定排序，页大小由 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS` 固定在 1–128。游标由 `XSHIELD_CONTROL_CURSOR_KEY_HEX` 以 manifest 专用用途域签名，绑定管理 Bearer 摘要、主体、tenant/site、目标请求、页大小与最后 artifact，不能跨事件接口、主体、作用域、请求或配置复用。成功、拒绝、无效游标及数据库故障写 `console.manifest.read`；必需审计失败返回 503，所有响应设置 `private, no-store`。敏感内容仍须通过独立审批和短时 EvidenceReadPort 能力读取。

## 29.9 已实现的单证据 manifest 契约

`GET /control/v1/artifacts/{artifact_id}` 要求 Observer 与服务端固定 tenant/site 精确作用域；路径 ID 必须是规范 artifact UUIDv7。查询使用 catalog 主键前缀绑定 tenant/site/artifact，并按数据库时钟过滤 active、未删除和未过期状态。成功响应包含独立管理 request_id、目标 source_artifact_id、服务端作用域、`found` 和可选 typed manifest；不存在、删除、到期与其他作用域均返回 200、`found=false`、`artifact=null`。

有效目标 ID 会进入管理审计的 `target_artifact_id`，实际返回的对象才进入 `evidence_refs`。成功、拒绝和数据库故障均写 `console.manifest.read`；必需审计失败返回 503，响应统一 `private, no-store`。该接口不读取对象文件、manifest HMAC 或密文；后续内容接口仍须独立审批，并由 EvidenceReadPort 重验对象侧完整性与期限。

## 29.10 已实现的调查案件创建契约

`POST /control/v1/cases` 要求固定 tenant/site 作用域内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，只接受 `{"purpose":"..."}` 严格 JSON；purpose 去除首尾空白后必须保持原值，UTF-8 字节长度为 1–512。`Idempotency-Key` 必填，只允许 16–128 字节 ASCII 字母、数字、`-_.:`。tenant、site、owner 与 case UUIDv7 均由服务端确定。

服务使用独立的 `XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX` 以用途域 HMAC 保存绑定主体、tenant/site、键和请求参数的摘要，不保存原始幂等键，也不复用分页密钥。每个 owner/tenant/site 的 open 案件数由 `XSHIELD_CONTROL_MAX_OPEN_CASES` 限制在 1–10000；并发服务实例必须使用相同上限。PostgreSQL 事务在同一锁域完成精确幂等检查、容量检查、案件写入和 `case.created` outbox。首次创建返回 201，精确重试返回原案件和 200，不同参数复用同一键返回 409，容量耗尽返回 429，依赖故障返回 503。

所有尝试写管理审计；成功及精确重试携带 `target_case_id`，失败不猜测目标。事务 outbox 记录业务创建事实，管理审计记录接口尝试，两者均不包含原始幂等键。创建案件仅建立后续审批上下文，不授予 manifest、脱敏内容、敏感原文或导出权限；这些能力仍须独立授权。

## 29.11 已实现的证据访问申请契约

`POST /control/v1/artifacts/{artifact_id}/access` 要求固定 tenant/site 内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，严格接受 `case_id`、固定值 `access_kind=sensitive_raw` 和 1–512 UTF-8 字节且无首尾空白的 `justification`；路径 artifact、案件及申请 ID 均使用强类型 UUIDv7。`Idempotency-Key` 复用管理变更专用密钥但使用独立用途域，摘要绑定主体、作用域、路径 artifact、case、访问类型和理由，原始键不入库。

新申请必须引用请求主体自己拥有的 open 案件和同作用域 active、未删除、按数据库时钟未过期的 artifact。事务持有目标共享锁，按 tenant/site/subject 串行化精确重试与 pending 容量检查，并原子提交 `pending` 申请和 `evidence.access.requested` outbox。首次返回 201，精确重试返回原申请和 200，参数冲突 409，目标不可用统一 404，容量耗尽 429，依赖故障 503。

成功与失败尝试均写独立加密管理审计；成功及精确重试携带 artifact、case、access_request 目标和 artifact evidence ref。申请只建立待审批事实，不调用 EvidenceReadPort、不解密对象、不返回内容；后续独立审批必须绑定另一主体、明确期限与同一作用域。

## 29.12 已实现的证据访问决策契约

`POST /control/v1/evidence-access-requests/{access_request_id}/approve` 与 `/deny` 要求固定 tenant/site 内的 `SensitiveEvidenceApprover` 和管理机器凭证。两者请求体上限 4 KiB、要求规范 `Idempotency-Key`，并严格接受 1–512 UTF-8 字节且无首尾空白的 `reason`；批准额外要求 `ttl_seconds` 在 1 到服务端 `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS` 之间，该启动上限最大 86400 秒。决策幂等摘要以独立用途域绑定主体、作用域、键、申请、动作、理由和 TTL，原始键与理由均不进入 outbox。

PostgreSQL 按 tenant/site/decider 串行化幂等键并锁定申请行；申请人不能决定自己的申请，且 pending 申请只允许一个终态。拒绝直接终结申请且不产生读取资格；批准还会持有案件与 artifact 共享锁，重新要求申请人拥有 open 案件及 active、未删除、按数据库时钟未过期的 artifact。有效期限取数据库决策时间加请求 TTL 与 artifact 到期时间中的较早值，终态和 `evidence.access.approved` 或 `evidence.access.denied` outbox 同事务提交。首次和精确重试均返回 200；幂等或终态冲突 409，自批 403，申请或批准目标不可用统一 404，依赖故障 503。

成功响应携带申请、case、artifact、申请人、决策人、终态、决策时间和可选资格期限。每次尝试写独立加密管理审计，成功与精确重试包含全部目标和 artifact evidence ref。批准行是后续 EvidenceReadPort 的服务端资格真值；当前端点不读取对象、不返回明文或下载 URL。

## 29.13 已实现的证据内容读取契约

`GET /control/v1/artifacts/{artifact_id}/content` 要求固定 tenant/site 内的 `SensitiveEvidenceReader`、管理 Bearer，以及 `X-Xshield-Evidence-Access-Request` 头中的强类型 access request ID。服务端要求该申请的 `requested_by` 等于当前管理主体，状态为 `approved`，资格、案件和 catalog 均仍有效，且 artifact 仍 active、未删除并未过期；缺少、跨主体、跨作用域、拒绝、撤销、过期和删除统一返回 `CONTROL_EVIDENCE_READ_NOT_AVAILABLE`/404。数据库检查通过后，EvidenceReadPort 重新认证 vault manifest HMAC、scope、期限、key-id、ciphertext digest 与 AEAD；目录与 vault manifest 不一致或认证失败不会返回内容。

成功响应为 `application/octet-stream` 的 `attachment`，设置 `Cache-Control: private, no-store` 与 `X-Content-Type-Options: nosniff`，不返回下载 URL。内容释放前写入独立加密管理审计 `evidence.read`，绑定 access request、artifact 和 evidence ref，并记录实际字节数；审计、数据库、vault 或完整性依赖失败返回 503，响应正文不泄露资源归属或内部错误。

本地整对象 MVP 每个 EvidenceReadPort 同时保留一个读取/响应对象：许可在调度解密前获取，并随清零明文缓冲交给 HTTP 响应，直到最后一个响应字节引用释放；取消请求不会提前归还仍在执行的解密许可。容量占满返回带独立审计的 `CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED`/503。缓冲直接移交给响应，避免额外完整明文复制；需要并发大对象下载时再引入按字节计费的共享预算和分块读取。

## 29.14 已实现的受限调查查询契约

`POST /control/v1/search` 要求固定 tenant/site 作用域内的 `Investigator` 和管理 Bearer。请求体上限 8 KiB，严格接受 `schema_version=3`、UTC RFC3339 的 `start`/`end`、`sort`、`limit`、可选 `cursor` 及有界 `filters`。时间边界采用整秒，半开区间 `[start,end)` 最长 31 天且位于 1970-01-01 至 2300-01-01；单页受 `XSHIELD_CONTROL_MAX_QUERY_EVENTS` 限制，硬上限 1000 行，最多 8 个过滤器。过滤器只对同一事件做 AND 匹配：规范 request/event ID、`event_type`/`stage`/`reason_code`/`operation_id`/`model_revision` 精确文本、`PASS/ALLOW/DENY/UNKNOWN/ERROR/SKIPPED/CANCELLED` outcome 枚举和 0–10000 整数 basis-points 置信度上限。规则事件的空置信度不会匹配数值阈值；当前接口不做跨事件关联、聚合或自然语言编译。未知字段、版本、控制字符和自由表达式均拒绝。

```json
{
  "schema_version": 3,
  "start": "2026-09-19T00:00:00Z",
  "end": "2026-09-20T00:00:00Z",
  "sort": "occurred_at_desc",
  "limit": 25,
  "filters": [
    {"kind": "text", "field": "stage", "value": "admission"},
    {"kind": "outcome", "value": "DENY"}
  ]
}
```

服务端将认证作用域注入参数化 ClickHouse retention-aware 视图，配置 2 秒执行预算、100 万扫描行、64 MiB 扫描字节、16 MiB 结果和 256 MiB 内存上限，并以 5 秒客户端 deadline 限制连接/响应停滞。索引 deadline 不包含现有本地段完整性扫描和审计 fsync；二者耗时须按保留数据量与磁盘情况另行度量。单个控制实例的 search 与 model-call 查询共用一个执行许可；客户端断开后已开始的有界查询继续完成终态审计并释放许可。多实例部署仍须为 ClickHouse 账户配置共享配额；进程退出恢复不属于该同步接口的保证。

结果只包含脱敏摘要和证据引用，不读取 `payload_json` 或解密对象；可选字段缺省返回 null，事件时间为 UTC RFC3339。按 `occurred_at,event_id` 稳定升/降序分页，HMAC 游标绑定主体、管理凭证摘要、tenant/site、完整 QueryPlan 摘要和微秒位置，不能跨查询或作用域复用。响应携带 `schema_version=3`、`query_digest`、`as_of`、`index_watermark`、`has_gaps`、`pending_segments`、`scanned_rows`/`scanned_bytes`、`truncated` 和 `next_cursor`。扫描统计来自索引响应，未报告时为 null；分页期间的新发布/到期可能改变后续可见集合，游标不表示冻结快照。

无效计划返回 `CONTROL_QUERY_INVALID`/422，无效游标返回 `CONTROL_CURSOR_INVALID`/400，均在索引访问前拒绝。确定的查询预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=narrow_query`；单实例容量占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端超时返回 `CONTROL_QUERY_TIMEOUT`/503，依赖故障返回对应 503。可审计尝试均写 `console.query.executed`；通过计划校验后的成功或失败审计携带 `query_digest`，不保存原始查询文本或游标。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果；响应统一 `Cache-Control: private, no-store`。

## 29.15 已实现的模型调用查询契约

`GET /control/v1/model-calls/{model_call_id}` 要求固定 tenant/site 作用域内的 `Observer` 和管理 Bearer。路径 ID 先按 `mdl_` UUIDv7 强类型校验；服务端再以 tenant/site 与固定事件类型集合查询 retention-aware `audit_events_active`，不接受客户端传入作用域或任意表达式。索引中的模型生命周期 payload 必须再次通过同一 typed Jev 校验，调用 ID、request ID、版本、状态和证据引用不一致时整次查询失败。

模型事件的三个 artifact 引用字段均须显式存在，尚未产生时为 null；Schema、发布、恢复与查询边界统一拒绝省略字段。因果链中允许保留期限造成的缺失，但已可见 send 的前后事件必须直接关联，矛盾前驱与因果环按损坏记录拒绝。

成功响应返回独立管理 `request_id`、固定作用域、`source_model_call_id`、`found` 与脱敏 `model_call`。后者只包含生命周期状态、模型/提示版本、问题类型、置信度语义、耗时、按 request_seq 排序的生命周期摘要、因果前驱及输入/输出/调用记录的 artifact 引用；内部输入引用从事件 `evidence_refs` 和 manifest 父引用进一步定位。Noul 的 confidence 保持 null；响应不包含 `payload_json`、概率正文或供应商原文。证据内容仍须走 artifact manifest、独立审批和 EvidenceReadPort。

`completeness=complete` 仅表示可见 start、send、terminal 因果链完整（或 start 直接因果关联发出前的 failed）；进行中的可见前缀为 `pending`，已到终态但缺失前驱为 `partial`，未命中为 `not_indexed`。`found=false` 对尚未发布、不存在、过期和不同作用域保持统一结果，不证明源日志中不存在调用。`as_of`、`index_watermark`、`has_gaps`、`pending_segments` 是查询前检查的配置日志源健康快照，`watermark_scope=configured_journal` 明确其只覆盖该实例 source journal；模型与网关使用独立源时，网关水位不能用于判断模型是否已追平。发布和保留可能改变可见集合，响应不表示冻结快照。

当前按有界生命周期 payload 扫描精确 ID，读取最多 4 行以识别超出三事件生命周期的冲突。单 payload 上限 8 KiB，解码/服务端结果上限 128 KiB，跨事件证据引用去重后最多 256 个；配置 2 秒执行预算、100 万扫描行、64 MiB 扫描字节、256 MiB 内存和 5 秒客户端 deadline。deadline 只覆盖索引查询，本地健康检查及审计 fsync 另行度量。与 search 共用单实例执行许可，已准入请求在客户端断连后继续终态审计。

通过认证且路径校验成功的尝试以 `target_model_call_id` 绑定目标，实际返回的 artifact 引用进入 `evidence_refs`；可审计的成功、未命中、拒绝及依赖故障均写独立加密 `console.model.read`。无效 ID（含无法解码的 UTF-8 路径）返回 `CONTROL_MODEL_CALL_ID_INVALID`/400。预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=contact_operator`；许可占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端 deadline 返回 `CONTROL_QUERY_TIMEOUT`/503，索引/健康依赖故障返回对应 503。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，所有响应设置 `Cache-Control: private, no-store`。
