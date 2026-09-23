# 22 分阶段实施与交付物

## M0 基础契约与骨架

交付：Cargo workspace、领域类型、原因码、阶段事件与证据 Schema、Mock Ports、管理身份、站点禁用默认配置、CI/文档校验。审计从第一阶段开始，不等主功能结束后补 printf。

验收：同一合成 request_id 可看到阶段树，未实现功能显式 not_configured；示例不会被误认为运行网关。

## M1 身份与有迹可循闭环

交付：真实业务认证绑定、合法刷新/账号切换、根入口、列表/创建资源资格、UI 动作模板、目标/字段校验、有效期、默认拒绝、分享例外。

验收：A/B Cookie 拼接、评论作者 ID 改密、无来源直达、旧响应污染等被拒绝；同会话有效资格可复用；新浏览器必须重获。

## M2 双向协议接管

当前增量：已完成一种双向 enforce `DIRECT_DECRYPT` / `DIRECT_ENCRYPT` AES-256-GCM 协议、消息时效、请求共享原子防重放、双向冻结载荷重建、稳定失败终态、转换摘要审计及 Gateway↔Origin 反例测试；observe 已支持服务端固定的 opaque 透传。compatibility 已绑定严格 UI 动作资格、WAF 验证的页面构建指纹、服务端批准引用与绝对到期；两种 opaque 路径均禁止从未知内容签发身份/资格。网关已提供版本化同源探针与 loader、动态 no-store bootstrap、绑定当前 WAF 会话和身份代际的严格 HTTPS prepare 批量接收，以及独立耐久审计；客户端观测明确不产生授权效果。`SENSOR_HTML` 适配器可在同一 operation 有界并存至多 16 个批准构建，按完整源站摘要选择各自固定偏移；注入标签以 SHA-384 SRI 精确绑定实际静态资源，强制 CSP 使用逐响应随机 nonce 同步改写脚本指令和注入标签，构建或策略偏差在正文释放前关闭，并记录选中修订和转换摘要。ClickHouse 元数据索引已按配置固化绝对保留期限，active 视图按 `event_id` 合并至少一次重投并先于后台 TTL 隐藏过期行。动态 HTML、原文对象保留与案件 pin 继续迭代。

交付：一种真实加密请求/响应适配、冻结载荷重建、三种覆盖模式、探针及保留策略、构建版本共存。

验收：实际解密内容与源站接收语义一致，Hook 关闭不会给强制路径降级；请求/响应可见性分别展示。

## M3 完整日志后台

案件界面增量：已接入本人案件创建、本人 open/closed 列表及打开、证据集合分页、关联与关闭流程，展示数据库观察、catalog 状态、管理请求 ID 与精确幂等结果。列表固定 owner/tenant/site，以案件 ID 降序键集分页、独立签名游标和 `console.case.list` 审计完成发现闭环；创建或关闭后显式刷新。内存表单保留冻结键与参数，未知结果仅原样重试，会话终止清态；案件后端具备有界许可、数据库 deadline 和断连后终态审计。真实 PostgreSQL/HTTP/前端客户端闭环验证事务事实及独立管理审计，浏览器覆盖重试、权限、异步隔离与响应式布局；生产身份入口和批量导出界面继续交付。

界面增量：`web/console` 已交付 Observer 只读请求、单条模型调用和模型调用列表调查闭环。列表要求有界 UTC 窗口，以 `(occurred_at DESC, model_call_id DESC)` 发现每个 `mdl_` 的最新可见脱敏状态，签名游标、独立 `console.model.list` 审计、索引水位和详情重授权均已接通；它不把窗口内状态描述为完整生命周期或证据资格。AuditAdministrator 可显式读取一个配置 audit journal 到索引目标的发布快照，展示封存段、连续水位、待发布/未封存段与缺口；该观察不推导业务准入、全部 Outbox 或系统整体状态。Investigator 结构化事件检索已接入现有 search API，以有界 UTC 时间窗及最多 8 项同事件 AND 条件查询，展示提交计划/摘要、扫描量、可空事件事实和独立索引状态。分页复用冻结计划，编辑即失效；请求和证据元数据链接继续要求独立 Observer 权限。内存凭证、闲置/401 清态、跨范围/晚到响应隔离均有回归；真实 Rust HTTP 与前端客户端的 wire 测试校验摘要/事件、Gateway Choice、历史 Noul 部分生命周期、模型未命中及预算失败路径。生产身份入口、完整关联图和导出界面按 [15.7](15-console-and-api.md#157-已实现只读请求调查控制台) 继续交付。

当前增量：控制服务已提供单 request_id 的脱敏聚合摘要、受限阶段聚合、事件时间线、证据 manifest 列表及单 artifact 元数据查询，强制 Observer 角色与服务端 tenant/site 作用域。摘要和事件只查询 retention-aware 去重视图；manifest 只查询 PostgreSQL active、未删除、按数据库时钟未过期的 catalog 行，单项查询对缺失、到期、删除和作用域偏差返回统一不存在语义。事件、manifest 和案件证据集合列表均采用稳定游标分页，游标以独立 HMAC 密钥和不同用途域绑定主体、凭证摘要、作用域、目标、查询版本/页大小和最后位置。案件集合在单 PostgreSQL 只读快照内返回案件摘要、成员引用和 active/expired/deleted/unavailable 状态（正常 retention 使用 deleted tombstone，unavailable 保留为防御性一致性状态），不暴露内容元数据或授权能力。各类查询均写独立耐久管理审计，ClickHouse 查询还携带索引完整性状态。本地证据库已形成单对象 AES-256-GCM、artifact 作用域派生密钥、typed manifest HMAC、私有耐久写、到期/跨域统一拒读和篡改检测闭环；PostgreSQL catalog 支持认证 manifest 与 outbox 原子幂等发布，并提供有界到期密文与孤儿对象维护的删除意图、排他本地锁、tombstone、mtime/sidecar 复验与故障重试。调查案件创建、证据关联、集合查询、敏感原文申请和独立决策已形成固定作用域、主体级容量、精确幂等、禁止自批和 outbox 原子提交闭环；批准时重验目标并建立不超过 artifact 期限的短时服务端资格。EvidenceReadPort 内容读取已接入 `/control/v1/artifacts/{artifact_id}/content`：Reader 只能消费与自身主体绑定的批准行，读取前重验 PostgreSQL 案件/catalog 与 vault 侧 manifest、摘要、AEAD，释放前写入实际字节数审计。网关采集与远端对象 adapter 继续迭代。

交付：journal、ClickHouse、对象证据库、签名 manifest、全请求检索、阶段树、原文审批、转换对照、导出、故障恢复和索引水位。

管理审计增量：现有控制端点的独立 journal 已接通严格封存发布契约，可检索访问尝试、稳定原因和证据引用；管理结果与业务请求终态分离，使用独立源目录和水位。PostgreSQL outbox 已交付案件、证据目录、证据访问、证据清理、校准报告和分区血缘审查 metadata、身份生命周期、通用资源资格、响应资格和分享发行九族消费发布闭环，包含按族租约、精确确认、失败重试和 ClickHouse 内容冲突检查。校准族只消费已形成的受限 `calibration.reported` 与 `calibration.partition_lineage.reviewed` metadata，不生成报告或审核结果，也不授予读取权限。身份生产者已把会话创建、登录、刷新、上下文切换和显式撤销接入完整 v3 契约，并经真实网关/源站/PostgreSQL 回归；身份发布器已严格接收 `binding.revoked`。通用 `GrantPersistence` 库入口构造并原子提交完整 `grant.issued`，只消费网关已验证的类型化内部事实，不提供独立 HTTP 入口。站点 HTTP 资格发行由响应资格生产者在严格源站响应、响应证据、动作和资源资格的同一事务中提交完整 `response_grant.issued` envelope；分享库 API 原子提交完整 `share.issued`，绑定稳定 event/share ID、冻结时间和精确重试正文；HTTP `response.share_issue` 已接通独立获准分享操作、完整 JSON 校验、当前来源资格复验及提交后凭证注入。历史稀疏身份、通用资源资格、响应资格及分享记录保留未确认。清理族保留六类 catalog/孤儿删除意图、完成与失败事实，以独立维护阶段、artifact/cause 引用及空请求进入脱敏检索。各族合成契约与实际生产者的数据库覆盖及执行方式见 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)。案件与证据目标过滤已交付，更多管理目标过滤、调查包导出及控制台界面继续交付。

验收：按任一请求/模型/资格 ID 完整追链；每个缺失有状态；查看与导出也记录；高危审计失败不继续无证据执行。

资格调查增量：受限查询已增加 `grant_id` 与 `auth_binding_id`，按固定事件字段定位身份生命周期、通用/响应资格发行、分享来源及 `console.grant.read` / `console.binding.read` 管理历史。强类型校验、同事件 AND、作用域与游标绑定、查询预算和审计沿用既有闭环；返回直接引用事件及 request_id。`GET /control/v1/grants/{grant_id}` 已补齐资格、当前绑定状态及来源请求引用的 PostgreSQL 单快照调查，独立显示持久状态、数据库时间过期标志和代际是否一致；`GET /control/v1/auth-bindings/{binding_id}` 提供当前身份/凭证代际、持久状态、期限与更新时间，复用调查许可及断连终态审计。控制台已接通两类快照、资格到绑定/来源请求导航及需显式时间窗和独立权限的历史查询入口，保留微秒观察与缺失语义。历史命中不授予 Observer 详情权限；在线准入仍校验完整证明，完整关联图继续交付。

Trace ID 检索增量：结构化事件检索现在可按事件契约的 32 个小写十六进制字符 trace 精确查找 ClickHouse 中同 trace 的脱敏事件，复用现有 `FixedString(32)` 列、scope/time/budget、HMAC 游标及查询审计；未新增 Schema 或授权边界。

## M4 模型与调查

阈值评估基础增量：纯 core 已提供二元恶意概率的固定双阈值计算、九格计数、缺失原因、正确分母、可靠性桶和 Brier。该层无 I/O；获准证据组装、数据分区隔离、耐久报告、阈值选择及真实校准按 [10.12](10-jev-and-agents.md#1012-离线阈值评估内核) 继续交付。

校准数据集契约增量：`calibration::dataset` 已将每个离线样本分别绑定到模型调用记录和标签 artifact，冻结批准、数据集/标签/任务/映射/阈值、模型/提示/供应商修订及训练、校准、评估、标签四份不同 manifest。它拒绝 manifest 与样本来源、样本记录与标签角色之间的别名、重复调用/引用和模型或映射漂移，保留有序调用 ID—模型记录—标签证据三元关联、阈值和指标；实现保持无 I/O。引用集合不同不证明外部内容独立，受控 evidence 读取、内容去重/分区审查、独立报告 evidence、journal/outbox 终态和真实阈值选择仍需按 [10.14](10-jev-and-agents.md#1014-已实现校准数据集领域契约) 继续交付，不能借用 `model.*` 生命周期表示校准报告。

分区/血缘审查增量：`calibration::lineage_review` 已从纯领域 MVP 延伸至持久化闭环。canonical review artifact 保留四个 provenance-bound manifest 和分区绑定的 corpus/reviewed-label source graph；专用 vault 以独立 sidecar、tenant/site/review/artifact AAD 与 fresh attestation 保护正文。迁移 0029 与 PostgreSQL commit 在同一短事务固定 review artifact metadata、provenance、四份 manifest、source-graph digest 和 `calibration.partition_lineage.reviewed`，并以跨 request catalog、报告和 review 的 append-only artifact identity registry 关闭全局 artifact ID 碰撞。迁移 0033 为 review body 及 request-free orphan 追加 intent-first、sidecar 再认证、目录同步后 tombstone 的专用回收，通用 orphan 扫描跳过此对象族；有 intent 或 tombstone 的 review 不能再被新的 capability 使用。calibration outbox parser 仅接受受限 metadata，拒绝 source graph 和正文。PostgreSQL 回归已覆盖 registry 的三种锁图：capability header 阻塞期间 review 先取得 owner 时，释放 report 只会得到 `Conflict` 且 capability/lease 不消费；report 先 preclaim registry 后被 report-artifact relation gate 阻塞时，独立 scope 的 review 只能等待，释放 gate 后 report 成功完成、review `Conflict`，且 report 独占 registry/artifact/projection/outbox；同一 report preclaim 也使通用 catalog writer 等待，解除 gate 后其闭合为 `Conflict`，不暴露唯一键错误或留下 catalog/outbox。脚本拥有的真实 lifecycle 与 retention-orphan maintenance producer 已分别接入专有 PostgreSQL→生产 ClickHouse DDL 回归，配置测试服务后检查来源行、索引、ACK、重投和摘要冲突。该结果只说明提交的关系通过审核，不能证明外部 corpus 内容独立或替代受控 evidence 读取；更多锁位置和数据质量验收继续推进。

校准读取边界增量：`CalibrationEvidenceReadCapability` 和 `CalibrationEvidenceReadPort` 已规定离线批量读取的最小纯契约。每个 `calcap_` capability 强绑定 tenant/site、可信时间有效期、完整且不可扩展的四份 manifest 与 model-record/label artifact 集合、读取 role、样本数和 512 MiB 聚合字节上限；artifact 别名及 scope、期限、role/reference 偏差均须拒绝，局部读取拒绝统一为 `CALIBRATION_EVIDENCE_NOT_AUTHORIZED`。`CalibrationEvidenceBatchLease` 与不可复制的 `CalibrationEvidenceReadSession` 将权威发行器开始的一个 batch lease 绑定到精确内存 capability，局部请求必须同时匹配 session、capability、scope、期限和成员引用；私有 lease handle 不可格式化或复制。

耐久发行与 batch lease 增量：迁移 0023 与 PostgreSQL adapter 已在一个事务中锁定活跃 catalog、写入完整 capability/member snapshot 和受限 `calibration.read_capability.issued` outbox 事实；规范 scope digest 固定 provenance、manifest、成员角色/序号、catalog 摘要/字节及预算。精确幂等恢复只接受同一耐久输入；catalog 变化、范围/期限不匹配或超预算不发行。开始 batch 时再次锁定并比较 header/member/live catalog，数据库仅保存私有 lease handle 的 digest，并保证一个 active lease；到期会形成有界 recovery generation，旧 lease 不复活，超过恢复上限终结 capability。发行事实 `request_id=null` 且不含 artifact、内容或私有 handle；calibration worker family 已严格消费其封闭小型 payload 和 capability aggregate。该生产 issuance 与同 scope 的 review/completion/report 已接入专有 PostgreSQL→生产 ClickHouse DDL 回归；配置测试服务后检查精确确认、稳定 ID 重投、active-view 去重和冲突退避。

校准 vault reader 增量：worker 的 `LocalCalibrationEvidenceReader` 将用途限定的 PostgreSQL 再授权、`LocalEvidenceVault` 和专用 `LocalJournal` 组合为单对象读取适配器。每次打开对象前先重验 capability、lease、成员、当前 catalog 与预算；随后认证 vault manifest 并与 catalog manifest 精确比较，再由 vault 重验密文摘要和 AEAD。返回的严格内容 DTO 保留 artifact、role、sample slot、清零 plaintext 与唯一在途许可，调用方不能克隆或脱离该资源边界。每个已获得 journal receipt 的 `PASS`、`DENY`、`ERROR` 都使用封闭的 `calibration.evidence_read` event；成功内容只在同一 journal 锁内冻结 event、追加并收到 event/producer sequence 精确匹配的 receipt 后返回。manifest、摘要或 AEAD 完整性问题记录 `...INTEGRITY_FAILED`，vault 不可用记录 `...VAULT_UNAVAILABLE`；journal prepare、append 或 receipt 失败返回 audit-unavailable 并保留 plaintext，且不伪造未耐久的 `ERROR` event。该 journal 是释放屏障，后续索引发布不参与授权或释放判定。

它与控制台按申请下载单个对象的 `EvidenceReadPort` 完全分离，不能用 `ApprovalRef`、案件、access request 或管理角色复用/扩大为校准授权。PostgreSQL completion 只由完整 `EvaluationReport`、同一 configured runner、私有 lease token digest 及新近 vault attestation 触发：lease `active → completed` 与 capability `leased → consumed` 同时发生，并由迁移 0026 原子记录内容无关的 `calibration.read_batch.completed` 与受限 `calibration.reported` 终态；单对象 read 保持 `leased/active`，未知提交只识别完全一致的已完成报告。当前 reader、专用 report artifact、持久化适配器与 worker evaluator 编排已交付；后续重点是声明式分区/血缘审查及真实供应商质量验收。耐久状态、issued/completion outbox 或 journal 索引均不表示 evidence 已读取之外的评估、阈值选择或策略发布结论。

校准报告持久化增量：`calibration::publication` 已把已完成的 `EvaluationReport` 固定为独立 `calr_` report ID、canonical report artifact 与冻结 provenance/四份 manifest/ModelIdentity；专用 vault sidecar 与 AEAD 绑定 report/artifact/scope，report ciphertext 不进入 request catalog。迁移 0026、0030–0031 的短事务重验 capability、已提交 lineage review、live catalog、runner、active lease 和私有 token digest，再将 report metadata、immutable review projection、lease/capability completion、`calibration.read_batch.completed` 与 `calibration.reported` 同时提交；artifact-first 数据库失败不消费 lease，未知提交仅在 capability header 与 report projection 的 review ID 连同其余 durable inputs 全部匹配时恢复。事件只记录 `calibration_report/PASS/CALIBRATION_REPORTED` 的受限元数据，不授予权限或发布阈值/策略。worker evaluator 已接入受控读取、schema-v3 DTO 解码和报告提交；内容独立性仍按声明式分区/血缘证据单独验收，不得复用 `model.*` 生命周期表示这些结果。见 [10.15](10-jev-and-agents.md#1015-已实现校准报告持久化) 和 [11.9](11-audit-event-contract.md#119-已实现-calibrationreported-发布契约)。

Score 增量：一次性离线评估已接入 2–10 档有序量表、完整档位/概率校验和加权评分；成功调用证据保留 `legend`，供应商置信度独立记录。模型生命周期发布、查询及控制台同步接受 Score，真实 PostgreSQL 与合成 Gateway HTTP 回归验证原始字节取证、catalog/outbox、非法响应、429 和中断恢复。Gateway 费用元数据兼容官方响应形状；真实供应商质量及校准仍需独立验收。

保留管理界面增量：控制台已接通 AuditAdministrator 的案件成员保留创建、升序历史分页与显式释放。界面按数据库观察时间展示期限及持久释放事实，写入冻结原路径、键和完整参数供未知结果恢复；目标切换与会话生命周期隔离晚到结果。客户端和真实 PostgreSQL/HTTP 链路共同验证独立管理员权限、作用域、幂等、关闭案件后的释放及事务 outbox。该流程沿用 0020 保留与清理屏障，原文期限和访问审批保持独立。

审批发现增量：`GET /control/v1/evidence-access-requests` 已提供本人申请历史和独立审批待办，固定 tenant/site 与主体可见性，按申请 ID 降序有界分页，游标绑定凭证、主体、视图和页大小。控制台显式读取/刷新、逐页查看并打开当前详情，申请和决策仍各自重验权限与状态。单 SQL 快照、预读一致性校验、共享准入、15 秒整体期限、5 秒 SQL/锁期限、断连后管理审计与迁移 0022 的两个排序索引组成发现闭环，部署边界见 29.24。

原文访问可靠性增量：申请、批准/拒绝与内容读取已接入共享准入、数据库整体期限和断连后的终态审计；重复安全头与查询串在入库前拒绝。存储在锁等待后重验期限，批准 TTL 使用锁后数据库时钟，内容读取保持独立的明文响应许可。

审批详情增量：`GET /control/v1/evidence-access-requests/{access_request_id}` 已形成主体可见性、单数据库快照、历史申请/决策与目标状态、独立管理审计及发布契约闭环。申请人和同站点审批人可在决策前复核明确理由与范围。

控制台证据访问增量：申请、详情复核、独立批准/拒绝与申请人附件下载已接入固定 API。写入保持冻结原键恢复，二进制响应提供精确范围、目标和长度；客户端校验后才交付浏览器，目标与会话变更抑制晚到下载。生产企业身份、MFA、再认证和服务端浏览器会话仍是后续交付及生产启用门槛。

案件增量：`POST /control/v1/cases/{case_id}/items` 与 `GET /control/v1/cases/{case_id}/items` 已形成关联、单快照集合浏览、catalog 状态和审计闭环。`POST /control/v1/cases/{case_id}/close` 已提供所有者终结、容量释放、精确重试及事务 outbox，历史集合与审批保留，后续原文资格校验受 closed 状态约束；新增关联和关闭已覆盖断连终态审计回归。案件保留锁已完成有界存储、清理屏障、事件发布及 AuditAdministrator 创建/释放/历史查询 HTTP 闭环（见 12.9、29.21）；调查 Agent 与导出继续交付。保留锁延缓物理删除，案件生命周期与保留操作均不扩大原文权限或读取期限。

当前增量：已落地有界 QueryPlan AST、固定作用域的参数化 ClickHouse 事件查询、稳定 HMAC 游标和 `console.query.executed` 审计。查询返回脱敏事件摘要、实际扫描量及索引水位/gap，实施单实例并发上限和客户端 deadline；超预算计划须缩小范围。`case_id` 与 `artifact_id` 已覆盖直接引用的案件事实、审批管理尝试、保留锁及证据历史；`subject_ref` 精确检索固定的顶层主体/身份引用，使用用途隔离 HMAC 保护低熵摘要且不在结果中回显，均复用既有索引与预算，固定映射见 29.14。事件详情现在可逐跳查看记录的直接因果前驱，或按一个事件 ID 查找直接后继；入口仅预填、显式提交，不递归展开。检索权限沿用 Investigator 的 tenant/site 范围，当前案件、保留和内容权限仍各自校验。多跳关联图、调查 Agent、自然语言计划和只读回放继续按垂直闭环推进。

模型增量：一次性 Jev 离线评估已接通严格 Choice/Noul DTO、固定 Vercel AI Gateway HTTPS 传输（显式 direct 兼容路由）、实际请求/响应证据、catalog/outbox、`model.*` journal 与发布解析；429/529、超时、取消、容量和中断恢复具有明确终态。阶段索引统一 `mdl_`、模型版本与置信度状态，Gateway alias 未解析时保持 `resolved_model_revision=null`。迁移 0034 的 PostgreSQL admission scope/私有短租约已使 tenant/site 跨实例调用预算成为权威：数据库 advisory lock 与时钟回收过期 lease、限制在途调用，容量拒绝不写证据或发送 HTTP，发送前重新确认，终态 journal 耐久后精确释放；恢复不重放调用。缓存安全前置契约已强制独立于 provider/evidence/journal 密钥的 HMAC key、scope/domain、完整 canonical 输入与精确模型修订；Gateway alias 没有精确修订即拒绝配置。耐久 cache lookup/store 及其来源证据重验尚未交付，故没有缓存命中或复用行为。回归使用合成 loopback 供应商；OpenJev/SemIf、耐久缓存/自动重试、校准与真实供应商验收继续按 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估) 推进。

交付：Jev/OpenJev Provider adapter、有限候选匹配、校准、概率日志、调查 Agent、QueryPlan、只读回放；固定模型和模板版本。

验收：模型输出不覆盖硬拒绝，Noul 不伪造 confidence；实际模型输入输出可查看；模型停机行为按端点策略执行；没有实测不宣称检测率。

## M5 持续适配与产品化

交付：构建监测、隔离 Agent、候选协议/UI 映射、双身份测试、签名发布、灰度回滚；容量调优与部署指南。

验收：改变 JS 名称、封装和密钥分发后可验证适配或安全失败；扩大资格的变更不自动发布。

## 依赖关系与并行

日志 Schema、核心身份/资格和基础后台可并行，但运行时所有行为须使用同一事件契约。协议、UI 和模型团队不得各造一套 request_id。以里程碑验收而非预估天数承诺；每项任务提供输入、接口、失败矩阵、测试和 DoD。

首个演示站点应包含公开评论、私有订单、自己改密、管理员重置、共享和故意不安全的源站接口，以证明 Xshield 的控制，而非只展示正常业务。
