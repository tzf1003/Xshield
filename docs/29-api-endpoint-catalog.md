# 29 控制 API 与审计责任清单

本章定义自定义接口；当前 `GET /control/v1/audit/health`、`GET /control/v1/requests/{request_id}`、`GET /control/v1/requests/{request_id}/events`、`GET /control/v1/requests/{request_id}/evidence`、`GET /control/v1/artifacts/{artifact_id}`、`GET /control/v1/artifacts/{artifact_id}/content`、`POST /control/v1/cases`、`POST /control/v1/artifacts/{id}/access` 及证据访问批准/拒绝端点已由 `xshield-control` 实现，其余条目仍是设计契约。所有 `/control/v1` 接口经管理身份验证、tenant/site作用域检查与速率限制；用户数据API和控制API必须分网络/认证边界。状态变更使用CSRF或对应机器凭证防护，GET不得产生重放或生产业务副作用。

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
