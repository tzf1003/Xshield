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

当前增量：控制服务已提供单 request_id 的脱敏聚合摘要、受限阶段聚合、事件时间线、证据 manifest 列表及单 artifact 元数据查询，强制 Observer 角色与服务端 tenant/site 作用域。摘要和事件只查询 retention-aware 去重视图；manifest 只查询 PostgreSQL active、未删除、按数据库时钟未过期的 catalog 行，单项查询对缺失、到期、删除和作用域偏差返回统一不存在语义。事件、manifest 和案件证据集合列表均采用稳定游标分页，游标以独立 HMAC 密钥和不同用途域绑定主体、凭证摘要、作用域、目标、查询版本/页大小和最后位置。案件集合在单 PostgreSQL 只读快照内返回案件摘要、成员引用和 active/expired/deleted/unavailable 状态（正常 retention 使用 deleted tombstone，unavailable 保留为防御性一致性状态），不暴露内容元数据或授权能力。各类查询均写独立耐久管理审计，ClickHouse 查询还携带索引完整性状态。本地证据库已形成单对象 AES-256-GCM、artifact 作用域派生密钥、typed manifest HMAC、私有耐久写、到期/跨域统一拒读和篡改检测闭环；PostgreSQL catalog 支持认证 manifest 与 outbox 原子幂等发布，并提供有界到期密文与孤儿对象维护的删除意图、排他本地锁、tombstone、mtime/sidecar 复验与故障重试。调查案件创建、证据关联、集合查询、敏感原文申请和独立决策已形成固定作用域、主体级容量、精确幂等、禁止自批和 outbox 原子提交闭环；批准时重验目标并建立不超过 artifact 期限的短时服务端资格。EvidenceReadPort 内容读取已接入 `/control/v1/artifacts/{artifact_id}/content`：Reader 只能消费与自身主体绑定的批准行，读取前重验 PostgreSQL 案件/catalog 与 vault 侧 manifest、摘要、AEAD，释放前写入实际字节数审计。网关采集与远端对象 adapter 继续迭代。

交付：journal、ClickHouse、对象证据库、签名 manifest、全请求检索、阶段树、原文审批、转换对照、导出、故障恢复和索引水位。

管理审计增量：现有控制端点的独立 journal 已接通严格封存发布契约，可检索访问尝试、稳定原因和证据引用；管理结果与业务请求终态分离，使用独立源目录和水位。PostgreSQL outbox 已交付案件、证据目录、证据访问、身份生命周期、通用资源资格、响应资格和分享发行七族消费发布闭环，包含按族租约、精确确认、失败重试和 ClickHouse 内容冲突检查。身份生产者已把会话创建、登录、刷新、上下文切换和显式撤销接入完整 v3 契约，并经真实网关/源站/PostgreSQL 回归；身份发布器已严格接收 `binding.revoked`。通用 `GrantPersistence` 库入口构造并原子提交完整 `grant.issued`，其 HTTP 发行适配器仍待交付。响应资格生产者随整批资格事务提交完整 `response_grant.issued` envelope；分享库 API 原子提交完整 `share.issued`，绑定稳定 event/share ID、冻结时间和精确重试正文；HTTP `response.share_issue` 已接通独立获准分享操作、完整 JSON 校验、当前来源资格复验及提交后凭证注入。历史稀疏身份、通用资源资格、响应资格及分享记录保留未确认。七族十五组合成事件、通用资源资格、实际网关响应资格及分享库 API 已通过真实 PostgreSQL 与 ClickHouse 生产 DDL 回归；覆盖范围及执行方式见 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)。管理目标字段查询、调查包导出及控制台界面继续交付。

验收：按任一请求/模型/资格 ID 完整追链；每个缺失有状态；查看与导出也记录；高危审计失败不继续无证据执行。

## M4 模型与调查

案件增量：`POST /control/v1/cases/{case_id}/items` 与 `GET /control/v1/cases/{case_id}/items` 已形成关联、单快照集合浏览、catalog 状态和审计闭环。`POST /control/v1/cases/{case_id}/close` 已提供所有者终结、容量释放、精确重试及事务 outbox，历史集合与审批保留，后续原文资格校验受 closed 状态约束；新增关联和关闭已覆盖断连终态审计回归。案件 pin、调查 Agent 与导出继续独立交付，案件生命周期本身不扩大内容权限或保留期。

当前增量：已落地有界 QueryPlan AST、固定作用域的参数化 ClickHouse 事件查询、稳定 HMAC 游标和 `console.query.executed` 审计。查询返回脱敏事件摘要、实际扫描量及索引水位/gap，实施单实例并发上限和客户端 deadline；超预算计划须缩小范围。当前为同一事件的 AND 过滤，模型接入、调查 Agent、跨事件关联和只读回放继续按垂直闭环推进。

模型增量：一次性 Jev 离线评估已接通严格 Choice/Noul DTO、固定 HTTPS 传输、实际请求/响应证据、catalog/outbox、`model.*` journal 与发布解析；429/529、超时、取消、容量和中断恢复具有明确终态。阶段索引统一 `mdl_`、模型版本与置信度状态，汇总保留最新 null。回归使用合成 loopback 供应商；网关自动采用、OpenJev/SemIf、跨实例预算、校准与真实供应商验收继续按 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估) 推进。

交付：Jev/OpenJev Provider adapter、有限候选匹配、校准、概率日志、调查 Agent、QueryPlan、只读回放；固定模型和模板版本。

验收：模型输出不覆盖硬拒绝，Noul 不伪造 confidence；实际模型输入输出可查看；模型停机行为按端点策略执行；没有实测不宣称检测率。

## M5 持续适配与产品化

交付：构建监测、隔离 Agent、候选协议/UI 映射、双身份测试、签名发布、灰度回滚；容量调优与部署指南。

验收：改变 JS 名称、封装和密钥分发后可验证适配或安全失败；扩大资格的变更不自动发布。

## 依赖关系与并行

日志 Schema、核心身份/资格和基础后台可并行，但运行时所有行为须使用同一事件契约。协议、UI 和模型团队不得各造一套 request_id。以里程碑验收而非预估天数承诺；每项任务提供输入、接口、失败矩阵、测试和 DoD。

首个演示站点应包含公开评论、私有订单、自己改密、管理员重置、共享和故意不安全的源站接口，以证明 Xshield 的控制，而非只展示正常业务。
