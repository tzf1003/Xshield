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

界面增量：`web/console` 已交付 Observer 只读请求和模型调用调查闭环，覆盖摘要、事件分页、水位/缺口、证据目录、模型生命周期/供应商标识/置信度和单项安全元数据；Investigator 结构化事件检索已接入现有 search API，以有界 UTC 时间窗及最多 8 项同事件 AND 条件查询，展示提交计划/摘要、扫描量、可空事件事实和独立索引状态。分页复用冻结计划，编辑即失效；请求和证据元数据链接继续要求独立 Observer 权限。内存凭证、闲置/401 清态、跨范围/晚到响应隔离均有回归；真实 Rust HTTP 与前端客户端的 wire 测试校验摘要/事件、Gateway Choice、历史 Noul 部分生命周期、模型未命中及预算失败路径。生产身份入口、完整关联图、模型列表和导出界面按 [15.7](15-console-and-api.md#157-已实现只读请求调查控制台) 继续交付。

当前增量：控制服务已提供单 request_id 的脱敏聚合摘要、受限阶段聚合、事件时间线、证据 manifest 列表及单 artifact 元数据查询，强制 Observer 角色与服务端 tenant/site 作用域。摘要和事件只查询 retention-aware 去重视图；manifest 只查询 PostgreSQL active、未删除、按数据库时钟未过期的 catalog 行，单项查询对缺失、到期、删除和作用域偏差返回统一不存在语义。事件、manifest 和案件证据集合列表均采用稳定游标分页，游标以独立 HMAC 密钥和不同用途域绑定主体、凭证摘要、作用域、目标、查询版本/页大小和最后位置。案件集合在单 PostgreSQL 只读快照内返回案件摘要、成员引用和 active/expired/deleted/unavailable 状态（正常 retention 使用 deleted tombstone，unavailable 保留为防御性一致性状态），不暴露内容元数据或授权能力。各类查询均写独立耐久管理审计，ClickHouse 查询还携带索引完整性状态。本地证据库已形成单对象 AES-256-GCM、artifact 作用域派生密钥、typed manifest HMAC、私有耐久写、到期/跨域统一拒读和篡改检测闭环；PostgreSQL catalog 支持认证 manifest 与 outbox 原子幂等发布，并提供有界到期密文与孤儿对象维护的删除意图、排他本地锁、tombstone、mtime/sidecar 复验与故障重试。调查案件创建、证据关联、集合查询、敏感原文申请和独立决策已形成固定作用域、主体级容量、精确幂等、禁止自批和 outbox 原子提交闭环；批准时重验目标并建立不超过 artifact 期限的短时服务端资格。EvidenceReadPort 内容读取已接入 `/control/v1/artifacts/{artifact_id}/content`：Reader 只能消费与自身主体绑定的批准行，读取前重验 PostgreSQL 案件/catalog 与 vault 侧 manifest、摘要、AEAD，释放前写入实际字节数审计。网关采集与远端对象 adapter 继续迭代。

交付：journal、ClickHouse、对象证据库、签名 manifest、全请求检索、阶段树、原文审批、转换对照、导出、故障恢复和索引水位。

管理审计增量：现有控制端点的独立 journal 已接通严格封存发布契约，可检索访问尝试、稳定原因和证据引用；管理结果与业务请求终态分离，使用独立源目录和水位。PostgreSQL outbox 已交付案件、证据目录、证据访问、证据清理、校准报告元数据、身份生命周期、通用资源资格、响应资格和分享发行九族消费发布闭环，包含按族租约、精确确认、失败重试和 ClickHouse 内容冲突检查。校准族仅消费已形成的受限 `calibration.reported` 元数据，不生成报告或授予读取权限。身份生产者已把会话创建、登录、刷新、上下文切换和显式撤销接入完整 v3 契约，并经真实网关/源站/PostgreSQL 回归；身份发布器已严格接收 `binding.revoked`。通用 `GrantPersistence` 库入口构造并原子提交完整 `grant.issued`，其 HTTP 发行适配器仍待交付。响应资格生产者随整批资格事务提交完整 `response_grant.issued` envelope；分享库 API 原子提交完整 `share.issued`，绑定稳定 event/share ID、冻结时间和精确重试正文；HTTP `response.share_issue` 已接通独立获准分享操作、完整 JSON 校验、当前来源资格复验及提交后凭证注入。历史稀疏身份、通用资源资格、响应资格及分享记录保留未确认。清理族保留六类 catalog/孤儿删除意图、完成与失败事实，以独立维护阶段、artifact/cause 引用及空请求进入脱敏检索。各族合成契约与实际生产者的数据库覆盖及执行方式见 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)。案件与证据目标过滤已交付，更多管理目标过滤、调查包导出及控制台界面继续交付。

验收：按任一请求/模型/资格 ID 完整追链；每个缺失有状态；查看与导出也记录；高危审计失败不继续无证据执行。

资格调查增量：受限查询已增加 `grant_id` 与 `auth_binding_id`，按固定事件字段定位身份生命周期、通用/响应资格发行及分享来源。强类型校验、同事件 AND、作用域与游标绑定、查询预算和审计沿用既有闭环；返回直接引用事件及 request_id。`GET /control/v1/grants/{grant_id}` 已补齐资格、当前绑定状态及来源请求引用的 PostgreSQL 单快照调查，独立显示持久状态、数据库时间过期标志和代际是否一致；`GET /control/v1/auth-bindings/{binding_id}` 提供当前身份/凭证代际、持久状态、期限与更新时间，复用调查许可及断连终态审计。控制台已接通两类快照、资格到绑定/来源请求导航及需显式时间窗和独立权限的历史查询入口，保留微秒观察与缺失语义。在线准入仍校验完整证明；完整关联图继续交付。

## M4 模型与调查

阈值评估基础增量：纯 core 已提供二元恶意概率的固定双阈值计算、九格计数、缺失原因、正确分母、可靠性桶和 Brier。该层无 I/O；获准证据组装、数据分区隔离、耐久报告、阈值选择及真实校准按 [10.12](10-jev-and-agents.md#1012-离线阈值评估内核) 继续交付。

校准数据集契约增量：`calibration::dataset` 已将每个离线样本分别绑定到模型调用记录和标签 artifact，冻结批准、数据集/标签/任务/映射/阈值、模型/提示/供应商修订及训练、校准、评估、标签四份不同 manifest。它拒绝 manifest 与样本来源、样本记录与标签角色之间的别名、重复调用/引用和模型或映射漂移，保留有序调用 ID—模型记录—标签证据三元关联、阈值和指标；实现保持无 I/O。引用集合不同不证明外部内容独立，受控 evidence 读取、内容去重/分区审查、独立报告 evidence、journal/outbox 终态和真实阈值选择仍需按 [10.14](10-jev-and-agents.md#1014-已实现校准数据集领域契约) 继续交付，不能借用 `model.*` 生命周期表示校准报告。

校准报告发布契约增量：`calibration::publication` 已把已完成的 `EvaluationReport` 缩减为独立 `calr_` report ID、report artifact 与冻结 provenance/四份 manifest/ModelIdentity；它拒绝 report artifact 与 manifest 或样本来源 artifact 的别名，显式保留未知 resolved revision，且不暴露 source tuple、标签、概率、指标或供应商正文。`calibration.reported` 现仅规定同一最小元数据的 schema 与 outbox 消费契约，记录 `calibration_report/PASS/CALIBRATION_REPORTED` 的非业务终态，不授予权限或发布阈值/策略。受控 evidence 读取、report artifact 写入、producer 与原子 outbox 持久化、内容独立性审查及真实校准仍待交付；不得复用 `model.*` 生命周期，也不得以该契约宣称这些能力已完成。见 [10.15](10-jev-and-agents.md#1015-已实现校准报告发布元数据契约) 和 [11.9](11-audit-event-contract.md#119-已实现-calibrationreported-发布契约)。

Score 增量：一次性离线评估已接入 2–10 档有序量表、完整档位/概率校验和加权评分；成功调用证据保留 `legend`，供应商置信度独立记录。模型生命周期发布、查询及控制台同步接受 Score，真实 PostgreSQL 与合成 Gateway HTTP 回归验证原始字节取证、catalog/outbox、非法响应、429 和中断恢复。Gateway 费用元数据兼容官方响应形状；真实供应商质量及校准仍需独立验收。

保留管理界面增量：控制台已接通 AuditAdministrator 的案件成员保留创建、升序历史分页与显式释放。界面按数据库观察时间展示期限及持久释放事实，写入冻结原路径、键和完整参数供未知结果恢复；目标切换与会话生命周期隔离晚到结果。客户端和真实 PostgreSQL/HTTP 链路共同验证独立管理员权限、作用域、幂等、关闭案件后的释放及事务 outbox。该流程沿用 0020 保留与清理屏障，原文期限和访问审批保持独立。

审批发现增量：`GET /control/v1/evidence-access-requests` 已提供本人申请历史和独立审批待办，固定 tenant/site 与主体可见性，按申请 ID 降序有界分页，游标绑定凭证、主体、视图和页大小。控制台显式读取/刷新、逐页查看并打开当前详情，申请和决策仍各自重验权限与状态。单 SQL 快照、预读一致性校验、共享准入、15 秒整体期限、5 秒 SQL/锁期限、断连后管理审计与迁移 0022 的两个排序索引组成发现闭环，部署边界见 29.24。

原文访问可靠性增量：申请、批准/拒绝与内容读取已接入共享准入、数据库整体期限和断连后的终态审计；重复安全头与查询串在入库前拒绝。存储在锁等待后重验期限，批准 TTL 使用锁后数据库时钟，内容读取保持独立的明文响应许可。

审批详情增量：`GET /control/v1/evidence-access-requests/{access_request_id}` 已形成主体可见性、单数据库快照、历史申请/决策与目标状态、独立管理审计及发布契约闭环。申请人和同站点审批人可在决策前复核明确理由与范围。

控制台证据访问增量：申请、详情复核、独立批准/拒绝与申请人附件下载已接入固定 API。写入保持冻结原键恢复，二进制响应提供精确范围、目标和长度；客户端校验后才交付浏览器，目标与会话变更抑制晚到下载。生产企业身份、MFA、再认证和服务端浏览器会话仍是后续交付及生产启用门槛。

案件增量：`POST /control/v1/cases/{case_id}/items` 与 `GET /control/v1/cases/{case_id}/items` 已形成关联、单快照集合浏览、catalog 状态和审计闭环。`POST /control/v1/cases/{case_id}/close` 已提供所有者终结、容量释放、精确重试及事务 outbox，历史集合与审批保留，后续原文资格校验受 closed 状态约束；新增关联和关闭已覆盖断连终态审计回归。案件保留锁已完成有界存储、清理屏障、事件发布及 AuditAdministrator 创建/释放/历史查询 HTTP 闭环（见 12.9、29.21）；调查 Agent 与导出继续交付。保留锁延缓物理删除，案件生命周期与保留操作均不扩大原文权限或读取期限。

当前增量：已落地有界 QueryPlan AST、固定作用域的参数化 ClickHouse 事件查询、稳定 HMAC 游标和 `console.query.executed` 审计。查询返回脱敏事件摘要、实际扫描量及索引水位/gap，实施单实例并发上限和客户端 deadline；超预算计划须缩小范围。`case_id` 与 `artifact_id` 已覆盖直接引用的案件事实、审批管理尝试、保留锁及证据历史，复用既有索引与预算，固定映射见 29.14。检索权限沿用 Investigator 的 tenant/site 范围，当前案件、保留和内容权限仍各自校验。当前为同一事件的 AND 过滤，模型接入、调查 Agent、跨事件关联和只读回放继续按垂直闭环推进。

模型增量：一次性 Jev 离线评估已接通严格 Choice/Noul DTO、固定 Vercel AI Gateway HTTPS 传输（显式 direct 兼容路由）、实际请求/响应证据、catalog/outbox、`model.*` journal 与发布解析；429/529、超时、取消、容量和中断恢复具有明确终态。阶段索引统一 `mdl_`、模型版本与置信度状态，Gateway alias 未解析时保持 `resolved_model_revision=null`。回归使用合成 loopback 供应商；OpenJev/SemIf、跨实例预算、校准与真实供应商验收继续按 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估) 推进。

交付：Jev/OpenJev Provider adapter、有限候选匹配、校准、概率日志、调查 Agent、QueryPlan、只读回放；固定模型和模板版本。

验收：模型输出不覆盖硬拒绝，Noul 不伪造 confidence；实际模型输入输出可查看；模型停机行为按端点策略执行；没有实测不宣称检测率。

## M5 持续适配与产品化

交付：构建监测、隔离 Agent、候选协议/UI 映射、双身份测试、签名发布、灰度回滚；容量调优与部署指南。

验收：改变 JS 名称、封装和密钥分发后可验证适配或安全失败；扩大资格的变更不自动发布。

## 依赖关系与并行

日志 Schema、核心身份/资格和基础后台可并行，但运行时所有行为须使用同一事件契约。协议、UI 和模型团队不得各造一套 request_id。以里程碑验收而非预估天数承诺；每项任务提供输入、接口、失败矩阵、测试和 DoD。

首个演示站点应包含公开评论、私有订单、自己改密、管理员重置、共享和故意不安全的源站接口，以证明 Xshield 的控制，而非只展示正常业务。
