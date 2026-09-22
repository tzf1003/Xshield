# 29 控制 API 与审计责任清单

本章定义自定义接口；当前 `GET /control/v1/audit/health`、`GET /control/v1/requests/{request_id}`、`GET /control/v1/requests/{request_id}/events`、`POST /control/v1/search`、`GET /control/v1/requests/{request_id}/evidence`、`GET /control/v1/model-calls/{model_call_id}`、`GET /control/v1/grants/{grant_id}`、`GET /control/v1/auth-bindings/{binding_id}`、`GET /control/v1/artifacts/{artifact_id}`、`GET /control/v1/artifacts/{artifact_id}/content`、`POST /control/v1/cases`、`GET /control/v1/cases`、`POST /control/v1/cases/{case_id}/items`、`GET /control/v1/cases/{case_id}/items`、`POST /control/v1/cases/{case_id}/close`、`POST /control/v1/artifacts/{id}/access`、证据访问批准/拒绝及 29.21 的保留锁创建/释放/列表端点已由 `xshield-control` 实现，其余条目仍是设计契约。所有 `/control/v1` 接口经管理身份验证、tenant/site作用域检查与速率限制；用户数据API和控制API必须分网络/认证边界。状态变更使用CSRF或对应机器凭证防护，GET不得产生重放或生产业务副作用。

| 方法与路径 | 用途 | 必需审计 |
|---|---|---|
| GET /control/v1/requests/{request_id} | 请求概要和完整性状态 | console.request.read |
| GET /control/v1/requests/{request_id}/events | 事件游标分页和阶段树 | console.events.read |
| GET /control/v1/requests/{request_id}/evidence | 证据manifest清单 | console.manifest.read |
| GET /control/v1/model-calls/{model_call_id} | 模型调用、实际输入输出引用 | console.model.read |
| GET /control/v1/grants/{grant_id} | 资格与当前绑定账本快照、来源请求引用 | console.grant.read |
| GET /control/v1/auth-bindings/{binding_id} | 当前身份与凭证代际、状态、期限 | console.binding.read |
| GET /control/v1/agent-runs/{agent_run_id} | Agent 运行及工具树 | console.agent.read |
| GET /control/v1/artifacts/{artifact_id} | 单个证据manifest | console.manifest.read |
| POST /control/v1/search | 受限查询AST，非任意SQL | console.query.executed |
| POST /control/v1/artifacts/{id}/access | 申请解密/原文查看能力 | evidence.access.requested |
| GET /control/v1/evidence-access-requests | 本人申请历史与独立审批待办（已实现，29.24） | console.evidence.access.list |
| GET /control/v1/evidence-access-requests/{access_request_id} | 申请理由、目标与历史决策详情（已实现，29.23） | console.evidence.access.read |
| POST /control/v1/evidence-access-requests/{id}/approve | 独立批准并建立短时读取资格 | evidence.access.approved |
| POST /control/v1/evidence-access-requests/{id}/deny | 独立拒绝并终结申请 | evidence.access.denied |
| GET /control/v1/artifacts/{id}/content | 获批后读取，短时作用域能力 | evidence.read，含批准引用 |
| POST /control/v1/cases | 建立调查案例 | case.created |
| GET /control/v1/cases | 分页发现本人开放和已关闭案件 | console.case.list |
| POST /control/v1/cases/{id}/items | 把获准证据加入案例 | case.evidence.added |
| GET /control/v1/cases/{id}/items | 查询本人案件证据引用集合 | console.case.read |
| POST /control/v1/cases/{id}/close | 关闭本人案件并保留调查历史 | case.closed |
| POST /control/v1/cases/{case_id}/holds | 管理员保留案件成员证据 | console.evidence.hold.created |
| POST /control/v1/evidence-holds/{hold_id}/release | 管理员释放保留锁 | console.evidence.hold.released |
| GET /control/v1/cases/{case_id}/holds | 管理员分页查询保留历史 | console.evidence.hold.read |
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

案件创建等端点使用的通用管理错误审计路径将 4xx 记为 `DENY`、5xx 记为 `ERROR`，区分输入/权限/预算拒绝与依赖故障；HTTP 状态和稳定原因码保持对应的端点契约。历史事件保留原记录。

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

`POST /control/v1/cases` 要求固定 tenant/site 作用域内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，只接受 `{"purpose":"..."}` 严格 JSON；purpose 去除首尾空白后必须保持原值，UTF-8 字节长度为 1–512，拒绝控制字符。`Idempotency-Key` 必填且须单值，只允许 16–128 字节 ASCII 字母、数字、`-_.:`。tenant、site、owner 与 case UUIDv7 均由服务端确定。

服务使用独立的 `XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX` 以用途域 HMAC 保存绑定主体、tenant/site、键和请求参数的摘要，不保存原始幂等键，也不复用分页密钥。每个 owner/tenant/site 的 open 案件数由 `XSHIELD_CONTROL_MAX_OPEN_CASES` 限制在 1–10000；并发服务实例必须使用相同上限。PostgreSQL 事务在同一锁域完成精确幂等检查、容量检查、案件写入和 `case.created` outbox。首次创建返回 201，精确重试返回原案件和 200，不同参数复用同一键返回 409，容量耗尽返回 429，依赖故障返回 503。

所有尝试写管理审计；成功及精确重试携带 `target_case_id`，失败不猜测目标。事务 outbox 记录业务创建事实，管理审计记录接口尝试，两者均不包含原始幂等键。创建案件仅建立后续审批上下文，不授予 manifest、脱敏内容、敏感原文或导出权限；这些能力仍须独立授权。

创建与案件关联/集合查询/关闭共享单实例一个执行许可，繁忙返回 `CONTROL_CASE_BUSY`/429。SQL 单语句及锁等待各限 5 秒，包含池等待的数据库整体操作限 15 秒；故障或超时为 `CONTROL_CASE_STORE_UNAVAILABLE`/503。准入后的任务在客户端断连后继续到数据库与耐久管理审计终态；许可持有至审计完成，本地 fsync 和进程退出仍为部署故障边界。超时或审计失败可能发生在事务提交之后，调用者须保留原键与 purpose 原样重试；不能由失败回复推断没有创建案件。创建响应保持既有无 schema_version 的契约；精确重试可返回已经 closed 的原案件。

## 29.11 已实现的证据访问申请契约

`POST /control/v1/artifacts/{artifact_id}/access` 要求固定 tenant/site 内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，严格接受 `case_id`、固定值 `access_kind=sensitive_raw` 和 1–512 UTF-8 字节且无首尾空白的 `justification`；路径 artifact、案件及申请 ID 均使用强类型 UUIDv7。`Idempotency-Key` 复用管理变更专用密钥但使用独立用途域，摘要绑定主体、作用域、路径 artifact、case、访问类型和理由，原始键不入库。

申请与批准/拒绝接口要求单值 Authorization 和 Idempotency-Key，拒绝任何查询串；重复认证头按未认证处理，重复幂等头按无效键处理。严格输入校验先于数据库准入。申请、批准、拒绝和内容读取与案件操作共享单实例在途许可，繁忙返回 `CONTROL_EVIDENCE_ACCESS_BUSY`/429；原有 pending 容量限制继续独立生效。

新申请必须引用请求主体自己拥有的 open 案件和同作用域 active、未删除、按数据库时钟未过期的 artifact。事务持有目标共享锁，按 tenant/site/subject 串行化精确重试与 pending 容量检查，并原子提交 `pending` 申请和 `evidence.access.requested` outbox。首次返回 201，精确重试返回原申请和 200，参数冲突 409，目标不可用统一 404，容量耗尽 429，依赖故障 503。

成功与失败尝试均写独立加密管理审计；成功及精确重试携带 artifact、case、access_request 目标和 artifact evidence ref。申请只建立待审批事实，不调用 EvidenceReadPort、不解密对象、不返回内容；后续独立审批必须绑定另一主体、明确期限与同一作用域。

申请与决策的数据库整体预算含连接池等待为 15 秒，事务内单语句和锁等待各限 5 秒。已准入任务在客户端断连后继续到数据库结果和管理审计终态，许可覆盖终态审计。超时、连接错误或审计失败不能证明事务未提交，应保留原键与完整参数确认结果；精确重试返回原记录。4xx 访问尝试记为 DENY，5xx 记为 ERROR；事务 outbox 与管理访问审计分别记录提交事实和接口尝试。进程退出仍是故障边界，预算不包含本地审计 fsync。

## 29.12 已实现的证据访问决策契约

`POST /control/v1/evidence-access-requests/{access_request_id}/approve` 与 `/deny` 要求固定 tenant/site 内的 `SensitiveEvidenceApprover` 和管理机器凭证。两者请求体上限 4 KiB、要求规范 `Idempotency-Key`，并严格接受 1–512 UTF-8 字节且无首尾空白的 `reason`；批准额外要求 `ttl_seconds` 在 1 到服务端 `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS` 之间，该启动上限最大 86400 秒。决策幂等摘要以独立用途域绑定主体、作用域、键、申请、动作、理由和 TTL，原始键与理由均不进入 outbox。

PostgreSQL 按 tenant/site/decider 串行化幂等键并锁定申请行；申请人不能决定自己的申请，且 pending 申请只允许一个终态。拒绝直接终结申请且不产生读取资格；批准还会持有案件与 artifact 共享锁，重新要求申请人拥有 open 案件及 active、未删除、按数据库时钟未过期的 artifact。有效期限取数据库决策时间加请求 TTL 与 artifact 到期时间中的较早值，终态和 `evidence.access.approved` 或 `evidence.access.denied` outbox 同事务提交。首次和精确重试均返回 200；幂等或终态冲突 409，自批 403，申请或批准目标不可用统一 404，依赖故障 503。

成功响应携带申请、case、artifact、申请人、决策人、终态、决策时间和可选资格期限。每次尝试写独立加密管理审计，成功与精确重试包含全部目标和 artifact evidence ref。批准行是后续 EvidenceReadPort 的服务端资格真值；当前端点不读取对象、不返回明文或下载 URL。

申请锁定目标后重新检查 artifact 期限，并在写入时再次检查；批准取得目标行锁后读取新的数据库时间，重新验证对象期限并从该时间计算 TTL。锁等待前的时间与期限条件不能作为锁后的有效性证明；精确决策重试保持原决策时间和原期限。准入、断连、超时与失败审计沿用 29.11。

## 29.13 已实现的证据内容读取契约

`GET /control/v1/artifacts/{artifact_id}/content` 要求固定 tenant/site 内的 `SensitiveEvidenceReader`、管理 Bearer，以及 `X-Xshield-Evidence-Access-Request` 头中的强类型 access request ID。服务端要求该申请的 `requested_by` 等于当前管理主体，状态为 `approved`，资格、案件和 catalog 均仍有效，且 artifact 仍 active、未删除并未过期；缺少、跨主体、跨作用域、拒绝、撤销、过期和删除统一返回 `CONTROL_EVIDENCE_READ_NOT_AVAILABLE`/404。数据库检查通过后，EvidenceReadPort 重新认证 vault manifest HMAC、scope、期限、key-id、ciphertext digest 与 AEAD；目录与 vault manifest 不一致或认证失败不会返回内容。

Authorization 与访问申请头必须各自单值，不接受查询串；重复访问申请头按缺少申请引用拒绝，查询串返回 `CONTROL_EVIDENCE_READ_REQUEST_INVALID`/400。数据库授权读取的整体预算为 15 秒，短事务中语句/锁等待最多 5 秒，持有申请、案件与 catalog 共享锁后用新的数据库时间检查资格和对象两项期限。事务在访问 vault 前结束；获准在途读取沿用其授权观察，后续状态改变不撤回已经释放的字节。

成功响应为 `application/octet-stream` 的 `attachment`，设置 `Cache-Control: private, no-store` 与 `X-Content-Type-Options: nosniff`，不返回下载 URL。内容释放前写入独立加密管理审计 `evidence.read`，绑定 access request、artifact 和 evidence ref，并记录实际字节数；审计、数据库、vault 或完整性依赖失败返回 503，响应正文不泄露资源归属或内部错误。

二进制成功响应通过 `X-Xshield-Request-Id`、`X-Xshield-Tenant-Id`、`X-Xshield-Site-Id`、`X-Xshield-Artifact-Id`、`X-Xshield-Evidence-Access-Request` 提供管理请求、已认证范围和精确目标，并用 `Content-Length` 声明完整字节数。控制台须核对这些头、媒体类型、附件属性、实际长度及当前会话范围后才生成临时下载对象；代理需透传这些头。旧客户端可忽略新增头，新下载界面须在控制服务升级后启用。服务端读取审计证明内容已准备释放，不证明浏览器收到或用户保存成功。

本地整对象 MVP 每个 EvidenceReadPort 同时保留一个读取/响应对象：许可在调度解密前获取，并随清零明文缓冲交给 HTTP 响应，直到最后一个响应字节引用释放；取消请求不会提前归还仍在执行的解密许可。容量占满返回带独立审计的 `CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED`/503。缓冲直接移交给响应，避免额外完整明文复制；需要并发大对象下载时再引入按字节计费的共享预算和分块读取。

内容请求另持有 29.11 的共享操作许可，覆盖数据库授权、vault 解密及耐久读取审计；它在响应构造完成后释放，整对象许可继续随响应缓冲保留。已准入任务断连后仍完成终态审计并丢弃无人接收的清零缓冲，不记录为客户端已收到内容。15 秒预算仅覆盖数据库操作，本地有界文件读取、解密与审计 fsync 完成后才释放各自资源；审计失败始终扣留明文。

## 29.14 已实现的受限调查查询契约

`POST /control/v1/search` 要求固定 tenant/site 作用域内的 `Investigator` 和管理 Bearer。请求体上限 8 KiB，严格接受 `schema_version=3`、UTC RFC3339 的 `start`/`end`、`sort`、`limit`、可选 `cursor` 及有界 `filters`。时间边界采用整秒，半开区间 `[start,end)` 最长 31 天且位于 1970-01-01 至 2300-01-01；单页受 `XSHIELD_CONTROL_MAX_QUERY_EVENTS` 限制，硬上限 1000 行，最多 8 个过滤器。过滤器只对同一事件做 AND 匹配：规范 request/event/grant/auth binding/case/artifact ID、`event_type`/`stage`/`reason_code`/`operation_id`/`model_revision` 精确文本、`PASS/ALLOW/DENY/UNKNOWN/ERROR/SKIPPED/CANCELLED` outcome 枚举和 0–10000 整数 basis-points 置信度上限。规则事件的空置信度不会匹配数值阈值；当前接口不做跨事件关联、聚合或自然语言编译。未知字段、版本、控制字符和自由表达式均拒绝。

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

结果只包含脱敏摘要、证据引用及 nullable `model_call_id`，不返回 `payload_json` 或解密对象；`model_call_id` 只会出现在 `proof_kind=model` 且必须为规范 `mdl_` UUIDv7，供调查界面跳转到 29.15 的独立详情查询。该投影不扩大 Investigator 的检索权限、Observer 的模型详情权限或证据读取权限。可选字段缺省返回 null，事件时间为 UTC RFC3339。按 `occurred_at,event_id` 稳定升/降序分页，HMAC 游标绑定主体、管理凭证摘要、tenant/site、完整 QueryPlan 摘要和微秒位置，不能跨查询或作用域复用。响应携带 `schema_version=3`、`query_digest`、`as_of`、`index_watermark`、`has_gaps`、`pending_segments`、`scanned_rows`/`scanned_bytes`、`truncated` 和 `next_cursor`。扫描统计来自索引响应，未报告时为 null；分页期间的新发布/到期可能改变后续可见集合，游标不表示冻结快照。

资格与身份定位分别使用 `{"kind":"grant_id","value":"grant_UUIDv7"}` 和 `{"kind":"auth_binding_id","value":"auth_UUIDv7"}`，value 必须为规范小写强类型 ID。资格过滤匹配 `grant.issued`、`response_grant.issued` 的 `grant_id` 及 `share.issued` 的 `issuer_grant_id`。身份过滤匹配 `session.created`、`binding.created`、`identity.refreshed`、`epoch.changed`、`binding.revoked`、`grant.issued`、`response_grant.issued` 的 `binding_id`，以及 `share.issued` 的 `issuer_binding_id`。事件族和 JSON 键由服务端固定，索引内有界读取这些 payload 字段参与过滤；其他事件中的同名键不构成关联。两类过滤可组合并继续占用原有 8 项预算，完整类型和值纳入 query_digest 和游标签名，访问审计仍仅记录计划摘要。

定位结果是保留窗口内已发布的直接引用事件，可通过返回的 request_id 继续查看请求时间线；不会自动遍历关联请求或报告当前 binding/grant 的有效状态。空结果可能来自未发布、到期或作用域不匹配，不能证明发行从未发生。响应中的水位只覆盖当前配置的 journal 源，不代表独立 outbox 生产者已追平。当前复用有界 payload 扫描，超出预算要求缩小时间窗；大规模索引列物化需另行容量测量。

案件使用 `{"kind":"case_id","value":"case_UUIDv7"}`，匹配固定阶段与事件组合中的直接引用：`case_management` 阶段的 `case.created/closed/evidence.added`、`evidence_access` 阶段的 `evidence.access.requested`、`evidence_hold` 阶段的 `evidence.hold.created/released` 读取 payload.case_id；`control_access` 阶段的 `case.created/closed/evidence.added`、`console.case.read`、`evidence.access.requested/approved/denied`、`console.evidence.access.read` 与 `console.evidence.hold.created/released/read` 读取 target_case_id。审批批准/拒绝事务 outbox 本身仅带申请引用，须通过其管理访问记录定位，不自动补关联。

证据使用 `{"kind":"artifact_id","value":"artifact_UUIDv7"}`，匹配所有事件的 evidence_refs 精确成员；另匹配 `control_access` 中 `console.manifest.read`、`case.evidence.added`、`evidence.access.requested/approved/denied`、`evidence.read` 和 `console.evidence.hold.created/released` 的 target_artifact_id，包含已校验目标但未返回证据的失败尝试。其他 payload 同名字段及嵌套引用不参与匹配；集合查询只匹配该页实际审计的 evidence_refs。

case/artifact 同样采用规范小写强类型校验、8 项总预算及完整计划摘要/游标绑定。组合要求同一事件直接引用两者，不展开案件成员的全部历史。检索沿用 Investigator 对固定 tenant/site 的脱敏审计权限，可观察该范围内其他主体的历史；当前案件集合仍单独检查所有者，保留管理与原文读取仍各自鉴权。关闭、到期、删除后保留的索引引用也可命中，不证明当前对象存在、可读或保留锁有效。新过滤器复用既有视图和事件，无需数据库迁移；新计划的管理日志仍只保存 query_digest。

无效计划返回 `CONTROL_QUERY_INVALID`/422，无效游标返回 `CONTROL_CURSOR_INVALID`/400，均在索引访问前拒绝。确定的查询预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=narrow_query`；单实例容量占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端超时返回 `CONTROL_QUERY_TIMEOUT`/503，依赖故障返回对应 503。可审计尝试均写 `console.query.executed`；通过计划校验后的成功或失败审计携带 `query_digest`，不保存原始查询文本或游标。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果；响应统一 `Cache-Control: private, no-store`。

## 29.15 已实现的模型调用查询契约

`GET /control/v1/model-calls/{model_call_id}` 要求固定 tenant/site 作用域内的 `Observer` 和管理 Bearer。路径 ID 先按 `mdl_` UUIDv7 强类型校验；服务端再以 tenant/site 与固定事件类型集合查询 retention-aware `audit_events_active`，不接受客户端传入作用域或任意表达式。索引中的模型生命周期 payload 必须再次通过同一 typed Jev 校验，调用 ID、request ID、版本、状态和证据引用不一致时整次查询失败。

模型事件的三个 artifact 引用字段均须显式存在，尚未产生时为 null；Schema、发布、恢复与查询边界统一拒绝省略字段。因果链中允许保留期限造成的缺失，但已可见 send 的前后事件必须直接关联，矛盾前驱与因果环按损坏记录拒绝。

成功响应返回独立管理 `request_id`、固定作用域、`source_model_call_id`、`found` 与脱敏 `model_call`。后者只包含 provider、独立的 provider_model_id、生命周期状态、内部模型/提示版本、问题类型、置信度语义、耗时、按 request_seq 排序的生命周期摘要、因果前驱及输入/输出/调用记录的 artifact 引用；provider_model_id 不能被当作精确 resolved_model_revision。兼容读取旧事件时两字段均为 null，不从当前路由配置推断历史值。内部输入引用从事件 `evidence_refs` 和 manifest 父引用进一步定位。Noul 的 confidence 保持 null；响应不包含 `payload_json`、概率正文或供应商原文。证据内容仍须走 artifact manifest、独立审批和 EvidenceReadPort。

`completeness=complete` 仅表示可见 start、send、terminal 因果链完整（或 start 直接因果关联发出前的 failed）；进行中的可见前缀为 `pending`，已到终态但缺失前驱为 `partial`，未命中为 `not_indexed`。`found=false` 对尚未发布、不存在、过期和不同作用域保持统一结果，不证明源日志中不存在调用。`as_of`、`index_watermark`、`has_gaps`、`pending_segments` 是查询前检查的配置日志源健康快照，`watermark_scope=configured_journal` 明确其只覆盖该实例 source journal；模型与网关使用独立源时，网关水位不能用于判断模型是否已追平。发布和保留可能改变可见集合，响应不表示冻结快照。

当前按有界生命周期 payload 扫描精确 ID，读取最多 4 行以识别超出三事件生命周期的冲突。单 payload 上限 8 KiB，解码/服务端结果上限 128 KiB，跨事件证据引用去重后最多 256 个；配置 2 秒执行预算、100 万扫描行、64 MiB 扫描字节、256 MiB 内存和 5 秒客户端 deadline。deadline 只覆盖索引查询，本地健康检查及审计 fsync 另行度量。与 search 共用单实例执行许可，已准入请求在客户端断连后继续终态审计。

通过认证且路径校验成功的尝试以 `target_model_call_id` 绑定目标，实际返回的 artifact 引用进入 `evidence_refs`；可审计的成功、未命中、拒绝及依赖故障均写独立加密 `console.model.read`。无效 ID（含无法解码的 UTF-8 路径）返回 `CONTROL_MODEL_CALL_ID_INVALID`/400。预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=contact_operator`；许可占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端 deadline 返回 `CONTROL_QUERY_TIMEOUT`/503，索引/健康依赖故障返回对应 503。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，所有响应设置 `Cache-Control: private, no-store`。

## 29.16 已实现的案件证据关联契约

`POST /control/v1/cases/{case_id}/items` 要求固定 tenant/site 内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，严格接受 `{"artifact_id":"artifact_UUIDv7"}`；case/artifact 均为规范强类型 ID，未知或重复字段拒绝。`Idempotency-Key` 必须单值且为 16–128 字节 ASCII 字母、数字、`-_.:`。复用管理变更专用密钥、独立用途域 HMAC，将键及请求摘要绑定主体、作用域、case 和 artifact；原始键不入库或审计。

事务先按 actor 串行化幂等，再锁定本人 open 案件；新关联要求同作用域 active、未删除的 artifact，取得行锁后及插入时重验数据库当前期限。每案最多 128 项，复合主键保证同案同证据唯一；关联与 `case.evidence.added` outbox 同事务提交。首次返回 201，响应只含 schema_version、request_id、固定作用域、case_id、artifact_id、added_by、added_at 和 replayed。精确重试返回 200、原 added_at 和 replayed=true，仍重验当前案件归属与 open 状态；即使 artifact 此后到期或删除，历史关联元数据也可返回，不表示证据仍可读取。

同键换参数，或同案同证据改用另一键，返回 `CONTROL_CASE_EVIDENCE_CONFLICT`/409，调用者应保留原键与请求。不存在、跨作用域、非本人/关闭案件及新关联的到期/删除证据统一为 `CONTROL_CASE_EVIDENCE_TARGET_UNAVAILABLE`/404。每案上限返回 `CONTROL_CASE_EVIDENCE_LIMIT_EXCEEDED`/429、retryable=false；单实例同时一个关联操作，忙时返回 `CONTROL_CASE_EVIDENCE_BUSY`/429、retryable=true。SQL 单语句和锁等待限 5 秒，包含连接池等待的数据库操作整体限 15 秒；故障或超时返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503，应使用相同键和参数确认结果。超时可能发生在 COMMIT 已耐久之后，不能据此认定操作未发生。

已准入操作在客户端断连后继续数据库终态与管理审计，许可覆盖至审计完成；本地 fsync 依赖健康存储，15 秒只限制数据库操作，进程退出仍是故障边界。每次可审计尝试写独立加密 `case.evidence.added` 管理事件，以 payload 的 outcome/reason 区分成功、拒绝和依赖故障；事务 outbox 只记录实际新增关联。经强类型校验的 case/artifact 进入目标字段，成功/精确重试的 artifact 进入 evidence_refs。管理审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留成功响应；已提交的事务及 outbox 保留，可用原请求重试确认。响应统一 `Cache-Control: private, no-store`。

部署前应用 `0017_m3_case_evidence.sql`，新增 `case_items` 及其约束。关联仅用于调查上下文，不授予 manifest/内容/导出权限，不改变对象期限、不建立 pin；原文读取继续走独立申请、批准和 EvidenceReadPort。保留锁存储与发布见 [12.9](12-evidence-capture-and-vault.md#129-案件证据保留锁存储与发布)，管理入口见 [29.21](#2921-已实现的案件保留锁管理契约)；集合浏览见 [29.17](#2917-已实现的案件证据集合查询契约)，关闭案件见 [29.18](#2918-已实现的案件关闭契约)。

## 29.17 已实现的案件证据集合查询契约

`GET /control/v1/cases/{case_id}/items` 要求固定 tenant/site 内的 `Investigator`、管理机器凭证和本人 owner。路径 case 使用规范强类型 ID；可选查询串只接受单个 `cursor`，其值为不透明 HMAC 游标，绑定管理凭证摘要、主体、服务端 tenant/site、case、查询版本/页大小和最后一个 artifact ID。缺失、越界、跨接口、跨主体、跨案件或签名不匹配的游标在访问 PostgreSQL 前统一返回 `CONTROL_CURSOR_INVALID`/400。

查询允许 open 与 closed 的本人案件；跨租户/站点、非本人和不存在案件统一返回 `CONTROL_CASE_NOT_AVAILABLE`/404，不泄露案件存在性。PostgreSQL 使用一条只读快照同时校验案件归属、成员行和 `case.evidence.added` outbox 关联，并按 artifact ID 升序取 `max_query_artifacts`（1–128）项及一个 lookahead；SQL 语句和锁等待各限 5 秒，连接池/事务整体限 15 秒。缺失或错绑 outbox、成员顺序/演员字段异常等可见持久化损坏返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503，不返回部分页面。

成功响应为 `schema_version=3`，包含管理 `request_id`、固定 tenant/site、案件 `case_id/status/purpose/created_at`、数据库 `as_of`、`items`、`truncated` 和 `next_cursor`。每项只包含 artifact ID、历史 `added_by/added_at` 和 catalog 状态：`active`（按同一 `as_of` 尚未到期）、`expired`、`deleted`（优先于到期）或 `unavailable`（防御性缺 catalog 状态；0017 外键和 retention tombstone 使正常路径使用 `deleted`）；不返回 manifest、storage locator、hash、key ref、请求元数据、密文或读取资格。读取不更新案件、membership、catalog、保留期限或审批状态。

成功、目标不可用、游标/鉴权拒绝及依赖故障均写独立 `console.case.read` 管理审计；成功事件的 `evidence_refs` 仅包含本页 artifact ID，拒绝/故障为空。审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。查询与 POST 关联共享单实例有界许可，繁忙返回 `CONTROL_CASE_EVIDENCE_BUSY`/429；数据库故障/超时返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503。已准入查询在客户端断连后继续到数据库和管理审计终态，响应统一 `Cache-Control: private, no-store`。

## 29.18 已实现的案件关闭契约

`POST /control/v1/cases/{case_id}/close` 要求服务端固定 tenant/site 内的 `Investigator`、管理机器凭证和当前本人 owner。路径须为规范 case UUIDv7；请求体上限 4 KiB，严格接受 `{"reason":"..."}`，理由为 1–512 UTF-8 字节、无控制字符及首尾空白。单个 `Idempotency-Key` 必填，沿用 16–128 字节 ASCII 字母、数字、`-_.:` 规则；作用域和主体均由服务端确定。

幂等摘要使用既有管理幂等密钥及独立关闭用途域，绑定 owner、tenant/site 和键；参数摘要再绑定 case 与 reason。事务先取得与创建相同的主体容量 advisory lock，再锁本人案件行。首次关闭将 `status=closed`、`case_closures` 和 `case.closed` outbox 同时提交，释放该主体的 open 案件容量。成功与精确重试均返回 200，响应含 `schema_version=3`、管理 request_id、tenant/site、case_id、status、数据库 closed_at 和 replayed；精确重试返回原 closed_at，并重验当前归属、closed 状态及原 outbox 绑定。

同键更换案件/理由返回 `CONTROL_CASE_CLOSE_CONFLICT`/409；不存在、跨作用域、非本人，以及用另一键关闭已终结案件，统一返回 `CONTROL_CASE_NOT_AVAILABLE`/404。严格路径、DTO 或幂等键错误为带稳定原因码的 400。关闭与证据关联/集合读取共享单实例一个在途许可，繁忙返回 `CONTROL_CASE_CLOSE_BUSY`/429；数据库整体操作含池等待限 15 秒，单 SQL/锁等待限 5 秒，故障或超时返回 `CONTROL_CASE_STORE_UNAVAILABLE`/503。提交结果不确定时使用相同键和参数确认结果。

每次可审计尝试写独立加密 `case.closed` 管理事件，通过 outcome/reason 区分成功、重试、拒绝和依赖故障；事务 outbox 只记录实际状态转换。合法 case ID 进入目标字段，evidence_refs 为空；自由文本理由仅保存于案件关闭表，outbox 保存参数摘要。管理审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，已提交事务和 outbox 保留。已准入操作在客户端断连后继续到数据库和审计终态，许可覆盖审计 fsync；进程退出仍是故障边界。所有响应为 `private, no-store`。

部署先应用 `0018_m3_case_lifecycle.sql`，该扩展保留既有 open/closed 记录。回滚应用版本时保留关闭表、closed 状态和 outbox，避免恢复已终结案件的访问条件。关闭保留历史证据关联、catalog、审批行和原始保留期限；后续新增关联、访问申请/批准及读取资格校验要求案件仍 open。已有审批的幂等查询只返回历史决策；内容读取仍重验当前案件状态。已完成资格校验的在途读取可能继续，已释放内容不能通过关闭收回。本人 closed 案件的引用集合继续通过 29.17 查询。

关闭时已有的 `pending` 原文访问申请保持待决，并继续占用申请主体的 pending 配额。独立 `SensitiveEvidenceApprover` 可通过 29.12 的拒绝接口终结 closed 案件的申请、释放该配额并保留决策历史；关闭操作本身仅释放 open 案件配额。

## 29.19 已实现的资格账本调查契约

`GET /control/v1/grants/{grant_id}` 要求 `Observer` 与服务端固定 tenant/site 的管理 Bearer。路径 ID 必须为规范小写 `grant_` UUIDv7；接口不接受查询参数。无效 ID 返回 `CONTROL_GRANT_ID_INVALID`/400，查询参数错误返回 `CONTROL_QUERY_INVALID`/400，均在数据库访问前拒绝。

读取按完整作用域和 grant 主键执行，单条只读 SQL 快照连接 `resource_grants`、`auth_bindings` 和 `ui_actions`。返回 `schema_version=3`、独立管理 request_id、tenant/site、source_grant_id、found、数据库语句时间 as_of 和可选 grant。缺失与其他作用域统一为 200、found=false、as_of=null、grant=null；同域已过期或撤销的账本行仍可调查。关联或类型损坏关闭查询，不伪装成未找到。

grant 含资格 ID、发行 auth_epoch、stored_status、issued_at/expires_at、resource_type、operation_id、view_id、policy_revision 及来源 event/request ID；内嵌 binding 仅含绑定 ID、当前 auth_epoch、stored_status、expires_at 和 epoch_matches_grant。两者独立以 `expires_at <= as_of` 计算 time_expired，保留数据库持久状态，因此尚未清理的 active 行也可能 time_expired=true。当前绑定后续缩短期限、撤销或推进代际仍可观察。响应不包含主体、认证上下文、凭证/资源指纹、动作引用、幂等键、constraints 或事件正文。

这是调查时的账本观察，不是可转交给网关的准入结果；实际请求继续检查完整认证组合、动作/证据、策略、目标字段和当前期限。来源 request_id 可继续查询时间线，发行及分享历史通过 29.14 检索；详情不使用 ClickHouse 授权状态，也不附带其发布水位。身份绑定详情见 29.20；控制台账本与引用导航见 15.7，完整来源图继续交付。

整体数据库操作含连接池等待最多 15 秒，单语句和锁等待最多 5 秒。与 search/model-call 调查查询共享单实例许可，繁忙返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429；数据库故障、超时或解码损坏返回 `CONTROL_GRANT_STORE_UNAVAILABLE`/503。已准入查询在客户端断连后继续到数据库与审计终态；许可覆盖审计 fsync，进程退出仍为故障边界。所有响应 `Cache-Control: private, no-store`。

每次可审计尝试写 `console.grant.read`，已校验目标记录在 target_grant_id；成功（包括未找到）使用 `CONTROL_GRANT_READ`，不记录查询出的账本快照或业务来源请求作为管理请求目标，evidence_refs 为空。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。部署须给控制数据库角色授予上述三表所需 SELECT；无需新增 migration，先升级支持该事件的管理 journal 发布器，再启用新端点。

## 29.20 已实现的身份绑定调查契约

`GET /control/v1/auth-bindings/{binding_id}` 要求 `Observer` 与服务端固定 tenant/site 的管理 Bearer。路径必须为规范小写 `auth_` UUIDv7，不接受查询参数；类型错误返回 `CONTROL_BINDING_ID_INVALID`/400，查询参数错误返回 `CONTROL_QUERY_INVALID`/400，均在数据库访问前拒绝。

读取以完整作用域和 binding 主键查询 `auth_bindings`，单条只读快照仅投影绑定 ID、身份/凭证代际、持久状态、绝对期限和更新时间。返回 `schema_version=3`、管理 request_id、tenant_id/site_id、source_binding_id、found、数据库语句时间 as_of 和可选 binding。缺失及跨作用域统一返回 200、found=false、as_of=null、binding=null。保留在账本中的 anonymous/active/revoked/expired 行均可查询；已物理清理的匿名记录通过现有生命周期事件继续调查。

binding 包含 binding_id、current_auth_epoch、credential_generation、stored_status、time_expired、expires_at、updated_at。time_expired 独立按 `expires_at <= as_of` 计算，时间字段为 UTC RFC3339；更新时间可能晚于期限。匿名代际须为 0，active 代际须为正数，撤销或过期允许保留匿名的 0 代际；未知状态、非法计数和非有限或 Unix 起点之前的时间均视为损坏，整次查询关闭。查询不读取主体、授权上下文、WAF SID 或凭证指纹，不读取或续期业务凭证。返回值是调查观察而非在线认证结果。

使用 binding_id 可继续执行 29.14 的 auth_binding_id 历史检索，再从事件 request_id 打开时间线或从 grant_id 打开资格详情。查询本身不递归展开资格或历史、不附带 ClickHouse 水位；当前账本与后续历史查询不构成跨存储冻结快照。历史检索仍要求 Investigator 角色。

数据库整体操作含池等待限 15 秒，单语句和锁等待限 5 秒，与资格/search/model-call 共用单实例查询许可。忙时返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，数据库故障、超时或损坏返回 `CONTROL_BINDING_STORE_UNAVAILABLE`/503。已准入请求在断连后继续完成数据库操作和审计，许可覆盖终态审计；进程退出仍是故障边界。响应统一为 `Cache-Control: private, no-store`。

每次可审计尝试写 `console.binding.read`，通过路径校验的目标写入 target_binding_id；成功（含未找到）原因为 `CONTROL_BINDING_READ`，evidence_refs 为空，审计中不保存查询快照。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。部署需给控制数据库角色配置 `auth_bindings` 所需 SELECT，先升级管理 journal 发布器，再启用端点；无新增 migration 或依赖。

## 29.21 已实现的案件保留锁管理契约

创建、释放和历史列表均要求独立管理 Bearer、`AuditAdministrator` 及服务端固定 tenant/site。该角色可管理同作用域内其他所有者案件；保留只推迟物理删除，原始 catalog/vault expires_at、敏感内容审批与到期拒读继续生效。

`POST /control/v1/cases/{case_id}/holds` 严格接受 `artifact_id`、`reason`、`hold_until`；`POST /control/v1/evidence-holds/{hold_id}/release` 严格接受 `reason`。路径使用规范 case/ev UUIDv7，artifact 使用规范 artifact UUIDv7；JSON 上限 4 KiB，拒绝未知或重复字段、查询参数和重复认证头。理由为 1–512 UTF-8 字节、无首尾空白或控制字符。期限只接受可表示为有符号纳秒、Unix 起点之后的 `YYYY-MM-DDTHH:MM:SS.sssZ`（秒为 00–59）；新建时另按数据库时钟要求未来 720 小时内。过期的原期限可用于精确重试。

两个 POST 要求单值 `Idempotency-Key`，允许 16–128 字节 ASCII 字母、数字、`-_.:`。使用管理幂等密钥和创建/释放各自用途域，摘要绑定主体、作用域、键及全部参数；原键不入库或审计。首次创建返回 201，精确创建重试及释放返回 200。响应含 schema_version=3、管理 request_id、tenant/site、hold_id、case_id、artifact_id、created_by、reason、created_at、hold_until、可空 released_event_id/released_by/released_reason/released_at 和 replayed。重试返回已提交记录及当前释放事实，保持原始期限，不建立新锁。

新建须为同域 open 案件、已有成员、active catalog 且没有删除意图；对象内容到期不阻止保留。每案累计 128 条历史、每作用域 1000 条活动锁，过期但未释放的同案同证据记录仍占自然唯一位置。释放允许案件关闭、内容到期或删除。缺失、跨域及不可用目标统一为 `CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE`/404；同键参数偏差、未释放的同案同证据或另一释放请求占用目标为 `CONTROL_EVIDENCE_HOLD_CONFLICT`/409。期限/DTO 错误为 `CONTROL_EVIDENCE_HOLD_REQUEST_INVALID`/400，容量耗尽为 `CONTROL_EVIDENCE_HOLD_LIMIT_EXCEEDED`/429、retryable=false。

`GET /control/v1/cases/{case_id}/holds` 只接受可选 `cursor`，HMAC 用途域绑定凭证摘要、主体、作用域、案件、页大小及最后 hold ID。页大小复用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128）；缺失/越界/错绑游标在查库前返回 `CONTROL_CURSOR_INVALID`/400。单条只读 SQL 快照按 hold ID 升序读取历史，包含 open/closed、过期/已释放记录；同时验证创建/释放的完整 outbox 绑定，包括多取的一条预读记录，损坏时整页失败。现有空案件返回空 items，缺失或跨域案件统一 404。响应为 schema_version=3、request_id、tenant/site、case_id、case_status、数据库微秒 as_of、items（上述保留记录字段）、truncated 和 next_cursor。每页是实时快照，原始期限和释放时间供调查使用，不返回内容元数据、读取资格、摘要或 outbox 正文。

三个入口与案件关联/关闭/集合查询共享单实例在途许可，繁忙为 `CONTROL_EVIDENCE_HOLD_BUSY`/429。数据库整体含池等待最多 15 秒，SQL 与锁等待最多 5 秒；数据库故障、损坏和超时为 `CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE`/503。许可覆盖最终审计；已准入操作在客户端断连后继续到数据库和审计终态，进程退出仍为故障边界。事务提交可能先于超时或审计故障，使用原键和完整参数确认结果。

每次可审计尝试分别写 `console.evidence.hold.created/released/read`。创建/释放成功原因依次为 `CONTROL_EVIDENCE_HOLD_CREATED`、`CONTROL_EVIDENCE_HOLD_RELEASED`，重试为 `CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED`、`CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED`，列表为 `CONTROL_EVIDENCE_HOLD_READ`；失败使用对应稳定原因。写成功绑定 case/artifact/hold 及唯一 artifact 引用，列表只绑定 case 和本页去重 artifact 引用，失败只保留已校验目标且引用为空。管理 journal 不记录自由理由、期限、原键或响应正文；事务 outbox 独立记录实际状态转换。审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，已提交事务保留。所有响应 `private, no-store`。

部署遵循 12.9 的迁移 0020 和清理升级顺序，并先升级管理 journal 发布器再开放三个端点，旧发布器遇到新事件会保留待发布段并停止推进。复用已有幂等与游标密钥，跨实例须保持一致；本增量无新依赖或 migration。管理主体启动校验现拒绝首尾空白；升级前核对 `XSHIELD_CONTROL_SUBJECT` 为原始规范身份，程序不会自动去空白以改变身份。

## 29.22 已实现的本人案件列表契约

`GET /control/v1/cases` 要求独立管理 Bearer、`Investigator` 及服务端固定 tenant/site，只返回当前管理主体拥有的 open/closed 案件。请求仅允许缺省查询或单个 `cursor`，拒绝 owner、status、scope 等额外字段、重复参数及重复认证头。发现案件不授予内容访问或保留权限，打开案件集合及后续变更仍重新鉴权。

返回 schema_version=3、管理 request_id、tenant_id、site_id、数据库微秒 UTC `as_of`、items、truncated 和可空 next_cursor。每项只有 case_id、status、purpose、毫秒 UTC created_at；空页仍返回数据库观察时间。按规范 case ID 的 `C` 排序降序，不声称按 created_at 排序。页大小复用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128），每页独立观察；分页期间新增的更大 ID 须刷新首页才能看到。

游标为 `v1.case_UUIDv7.64lowerhex`，用途域 `xshield-control-cases-cursor-v1` 的 HMAC 绑定管理凭证摘要、主体、tenant/site、页大小和最后输出案件 ID。下一页只读取小于该 ID 的记录；游标不能跨凭证、作用域、配置或其他端点复用。坏游标查库前返回 `CONTROL_CURSOR_INVALID`/400，签名服务不可用返回 `CONTROL_CURSOR_UNAVAILABLE`/503。单 SQL 只读快照连接案件与创建 outbox，校验 ID、owner、用途、状态及 outbox 的作用域、类型和 aggregate 绑定；包括用于判定下一页的多取一行，任何损坏使整页失败。

入口与案件创建、关联、关闭、集合及保留锁操作共用单实例在途许可，繁忙返回 `CONTROL_CASE_BUSY`/429。数据库整体含连接池等待最多 15 秒，SQL/锁等待最多 5 秒；依赖故障、超时或损坏为 `CONTROL_CASE_STORE_UNAVAILABLE`/503。已准入读取在客户端断连后继续到数据库和管理审计终态，许可覆盖审计；进程退出仍是故障边界。每次可审计尝试写 `console.case.list`，成功含空页为 `CONTROL_CASES_READ`；4xx 为 DENY、5xx 为 ERROR。所有 target 字段、query_digest、bytes_read 缺省或 null，evidence_refs 为空，不记录用途、游标或列表正文。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果；响应统一 `private, no-store`。

部署先应用 `0021_m3_case_listing.sql` 的 tenant/site/owner/case ID 降序索引，并升级管理 journal 发布器，再启用 API 与界面。索引采用事务内非并发构建，期间阻塞案件写入，大表须安排维护窗口；可回滚应用并保留这个加法索引。控制数据库角色需对 investigation_cases 和 audit_outbox 提供已有查询所需 SELECT；复用现有游标密钥，无新增依赖。

## 29.23 已实现的证据访问申请详情契约

`GET /control/v1/evidence-access-requests/{access_request_id}` 返回审批所需的申请理由、目标及历史决策。单值管理 Bearer、凭证时效、角色、固定 tenant/site 和速率均由服务端校验。`Investigator` 或 `SensitiveEvidenceReader` 仅能查询自己发起的申请；`SensitiveEvidenceApprover` 可查询同作用域内的申请。审批人查看自身申请不改变禁止自批规则，Observer 与 SystemAdmin 不隐含这些角色。

路径使用规范 access UUIDv7；任何查询串（包括空 `?`）及非空请求体均拒绝。无效 ID 为 `CONTROL_EVIDENCE_ACCESS_ID_INVALID`/400，查询或正文无效为 `CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID`/400；重复认证头按未认证处理。不存在、跨作用域及非本人且无审批角色的记录统一为 `CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE`/404。

200 响应包含 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、数据库微秒 UTC `as_of`、当前服务端 `max_approval_ttl_seconds` 和 `access_request` 对象。对象字段为 access_request_id、case_id、artifact_id、requested_by、access_kind、justification、stored_status、requested_at、requested_event_id、decided_by、decision_reason、decision_ttl_seconds、decision_event_id、decided_at、access_expires_at、case_status、artifact_status、artifact_expires_at、artifact_time_expired 和 capability_time_expired。可选决策字段显式为 null；pending/denied 的 capability_time_expired 为 null。对象及资格期限分别与 as_of 比较，持久状态不会由查询改写；到期 approved、expired、revoked、closed 案件和 deleted catalog 的历史记录仍可调查。所有时间保持 UTC 微秒。

单条 PostgreSQL 只读快照在 SQL 内限定主体可见性，并同时连接案件、catalog 和申请/决策 outbox，验证 ID、归属、状态、规范文本、有限时间与事件绑定。内容、manifest、locator、密钥与摘要不进入查询投影。损坏可见记录使请求失败，读取不锁定业务行、不写 outbox、不延长期限；详情和配置 TTL 上限仅供复核，批准及下载仍各自重新鉴权和检查当前状态。

详情与案件及原文访问共用单实例在途许可，繁忙为 `CONTROL_EVIDENCE_ACCESS_BUSY`/429；数据库操作含池等待限 15 秒，事务内语句/锁等待限 5 秒。数据库故障、超时或损坏为 `CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`/503。已准入任务在客户端断连后继续到数据库结果和终态审计；事务结束后才写审计，许可持有至审计完成。进程退出和本地 fsync 仍是故障边界。

每次可审计尝试写独立 `console.evidence.access.read` 管理事件，成功原因 `CONTROL_EVIDENCE_ACCESS_READ`，绑定申请、case、artifact 和唯一 artifact 引用；失败按 4xx/DENY、5xx/ERROR 记录，仅保留已验证的申请 ID。理由、历史决策人、期限和响应正文不进入管理 journal。审计失败为 `AUDIT_DURABILITY_FAILED`/503 并扣留详情；所有响应 `private, no-store`。部署先升级管理 journal 发布器再开放端点，旧发布器遇到新事件将停止推进并保留段；复用现有数据库查询权限、索引和依赖，无新迁移。

## 29.24 已实现的证据访问申请列表契约

`GET /control/v1/evidence-access-requests?view=mine` 用于发现当前主体的全部申请历史；同一固定 tenant/site 下具备 `Investigator`、`SensitiveEvidenceReader` 或 `SensitiveEvidenceApprover` 之一即可读取。`view=review` 仅允许 `SensitiveEvidenceApprover`，列出同作用域其他主体的 pending 申请。Observer 与 SystemAdmin 不隐含上述角色；每页重新校验单值管理 Bearer、凭证时效、作用域、角色和速率。历史 closed 案件、到期或 deleted artifact 的申请仍可发现；pending 只表示持久状态，批准与下载各自重验当前权限、目标及期限。

请求必须显式提供规范 `view=mine` 或 `view=review`，随后可附一个 `&cursor=...`；缺少/未知视图、逆序或重复参数、附加参数、百分号编码的视图别名、空游标及非空正文为 `CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID`/400。形状或签名无效的游标为 `CONTROL_CURSOR_INVALID`/400；二者均提示重新开始查询。游标采用独立用途域 `xshield-control-evidence-access-list-v1`，以 HMAC 绑定管理凭证摘要、主体、tenant/site、视图、服务端页大小和最后申请 ID，不能跨视图或接口复用；轮换凭证/游标密钥或改变页大小后需重开查询。游标签名依赖失败为 `CONTROL_CURSOR_UNAVAILABLE`/503。

200 响应字段为 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、`view`、数据库微秒 UTC `as_of`、`items`、`truncated` 和可空 `next_cursor`。每个 item 仅投影 access_request_id、case_id、artifact_id、requested_by、access_kind、stored_status、requested_at、requested_event_id。access_kind 固定 sensitive_raw；mine 保留 pending/approved/denied/expired/revoked，review 固定 pending。申请理由、完整决策与目标状态由 29.23 详情端点获取；列表不提供内容访问资格。空页仍包含数据库观察时间。

页大小沿用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128），按规范申请 ID 的 `C` 字节序严格降序，以最后 ID 排他续查，最多多取一条预读判断下一页。单 SQL 只读快照同时限制可见性并连接案件、catalog 和申请/决策 outbox，所有可见记录含预读均复用详情一致性校验；坏行使整页失败。每页独立观察，后续批准/拒绝可使 review 项消失，新增高位 ID 需刷新首页发现；游标不是跨页数据库快照，也不保证列表刷新可以确认未知写入。打开行重新读取详情，审批与内容读取继续独立授权。

列表与案件及证据访问共用单实例在途许可，繁忙为 `CONTROL_EVIDENCE_ACCESS_BUSY`/429。数据库操作含连接池等待限 15 秒，事务内 SQL/锁等待限 5 秒；故障、超时或损坏为 `CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`/503。只读事务结束后追加独立 `console.evidence.access.list` 管理审计，已准入任务断连后继续到结果和审计终态，许可覆盖审计；进程退出和本地 fsync 仍是故障边界。成功含空页为 `PASS/CONTROL_EVIDENCE_ACCESS_LIST_READ`；失败按 4xx/DENY、5xx/ERROR 使用 11.7 的精确原因集合。全部 target、query_digest 和 bytes_read 只允许缺省/null，evidence_refs 为空；事件只保存调用者与访问结果，列表视图、游标、记录及他人主体不进入载荷。必需审计失败为 `AUDIT_DURABILITY_FAILED`/503 并扣留响应数据，所有响应设置 `private, no-store`。

部署先应用 `0022_m4_evidence_access_listing.sql`，为 tenant/site/requested_by/access ID 建立降序索引，并为 tenant/site/access ID 建立 pending 部分索引；再升级管理 journal 发布器、控制 API 和控制台。索引在事务内非并发构建，期间阻塞该表写入，大表需维护窗口。数据库角色沿用详情所需的 evidence_access_requests、investigation_cases、artifact_catalog 和 audit_outbox 查询权限；无需新增密钥或依赖。回滚时先停用新界面/路由，继续使用可识别新事件的发布器直到相关积压已处理；应用可回退并保留两个加法索引，或仅移除本迁移的索引，保留所有申请和 outbox 历史。旧发布器遇到新事件会停止推进并保留待发布段。
