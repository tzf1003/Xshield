# 31 已实现机制说明

本章保存此前写在 README“实现状态”中的逐机制说明，2026-10-06 原文迁出，内容未改动，只增加了小标题与目录。每一节记录“某个机制现在怎样工作、边界在哪里”，是交付当时的快照。

整体进度、里程碑与缺口以 [22 分阶段实施与交付物](22-delivery-roadmap.md) 的“实现状态核查”为准；接口契约以 [29](29-api-endpoint-catalog.md) 为准；控制台以 [15](15-console-and-api.md) 与 [30](30-console-redesign.md) 为准。新增机制请写进对应主题章节，不要再堆回 README。

## 目录

1. [控制台入口与开发环境](#1-控制台入口与开发环境)
2. [多站点运营后台与站点配置发布](#2-多站点运营后台与站点配置发布)
3. [案件分析 MVP（耐久任务）](#3-案件分析-mvp耐久任务)
4. [调查导出（独立审批的元数据包）](#4-调查导出独立审批的元数据包)
5. [事件调查：Trace ID 与因果检索](#5-事件调查trace-id-与因果检索)
6. [校准批量读取能力（read_capability）](#6-校准批量读取能力read_capability)
7. [校准报告持久化（publication 与 report vault）](#7-校准报告持久化publication-与-report-vault)
8. [校准报告元数据调查 API](#8-校准报告元数据调查-api)
9. [按 calibration_report_id 检索](#9-按-calibration_report_id-检索)
10. [离线校准数据集领域契约（dataset）](#10-离线校准数据集领域契约dataset)
11. [分区审查持久化闭环（lineage_review）](#11-分区审查持久化闭环lineage_review)
12. [Jev 离线评估：Score](#12-jev-离线评估score)
13. [证据保留工作台（保留锁）](#13-证据保留工作台保留锁)
14. [证据访问：我的申请与审批待办](#14-证据访问我的申请与审批待办)
15. [证据访问工作台：申请、审批与下载](#15-证据访问工作台申请审批与下载)
16. [证据访问申请详情 API](#16-证据访问申请详情-api)
17. [案件工作台（Investigator）](#17-案件工作台investigator)
18. [只读调查页：请求、模型、Agent、资格与检索](#18-只读调查页请求模型agent资格与检索)
19. [原文下载的 MFA 再认证（step-up）](#19-原文下载的-mfa-再认证step-up)
20. [一次性 Jev 离线评估（xshield-model-eval）](#20-一次性-jev-离线评估xshield-model-eval)
21. [模型阶段与调用审计索引](#21-模型阶段与调用审计索引)
22. [模型调用摘要 API](#22-模型调用摘要-api)
23. [按 model_call_id 检索](#23-按-model_call_id-检索)
24. [按 agent_run_id 检索](#24-按-agent_run_id-检索)
25. [Agent 运行脱敏详情 API](#25-agent-运行脱敏详情-api)
26. [按 evidence_access_request_id 检索](#26-按-evidence_access_request_id-检索)
27. [按 evidence_hold_id 检索](#27-按-evidence_hold_id-检索)
28. [按 grant_id 与 auth_binding_id 检索](#28-按-grant_id-与-auth_binding_id-检索)
29. [按 share_grant_id 检索](#29-按-share_grant_id-检索)
30. [按 subject_ref 检索](#30-按-subject_ref-检索)
31. [资格账本快照 API](#31-资格账本快照-api)
32. [身份绑定调查 API](#32-身份绑定调查-api)
33. [案件证据加入 API](#33-案件证据加入-api)
34. [案件证据集合查询 API](#34-案件证据集合查询-api)
35. [案件关闭 API](#35-案件关闭-api)
36. [按 case_id 与 artifact_id 检索](#36-按-case_id-与-artifact_id-检索)
37. [管理访问 journal 与发布器](#37-管理访问-journal-与发布器)
38. [原文访问的有界操作许可](#38-原文访问的有界操作许可)
39. [案件保留锁 API](#39-案件保留锁-api)
40. [PostgreSQL outbox 发布（按事件族）](#40-postgresql-outbox-发布按事件族)
41. [匿名 binding 与 WAF 会话](#41-匿名-binding-与-waf-会话)
42. [AUTH_ENTRY：首个 Bearer 认证建立](#42-auth_entry首个-bearer-认证建立)
43. [AUTHENTICATED_ROOT 刷新（auth_refresh）](#43-authenticated_root-刷新auth_refresh)
44. [身份上下文切换（auth_context_switch）](#44-身份上下文切换auth_context_switch)
45. [登出与撤销（auth_revoke）](#45-登出与撤销auth_revoke)
46. [xshield-control 管理接口](#46-xshield-control-管理接口)
47. [xshield-evidence 本地加密证据库](#47-xshield-evidence-本地加密证据库)
48. [证据 catalog（PostgreSQL）](#48-证据-catalogpostgresql)
49. [M2：双向 AES-256-GCM 加解密闭环](#49-m2双向-aes-256-gcm-加解密闭环)
50. [M0 工作区与开发启动示例](#50-m0-工作区与开发启动示例)
51. [身份存储（identity_store）配置](#51-身份存储identity_store配置)

## 说明

### 1. 控制台入口与开发环境

后台采用独立 URL 与角色导航，受保护站点以列表进入分类编辑。开发环境默认 http://127.0.0.1:55173；启动会验证基础 schema，并按 ledger 增量补齐 0041–0053。运行与验收方法见 [控制台 README](../web/console/README.md#回归验证)。

### 2. 多站点运营后台与站点配置发布

多站点运营后台已接入 `GET/POST /control/v1/sites`、站点配置、状态/健康、修订、校验、应用、审批、回滚接口。配置写入先落 PostgreSQL，再由控制面通过 loopback HMAC 通道发送完整租户快照；edge 原子确认后才返回 `active`，否则保留旧快照并返回 `pending`/`failed`。策略字段已覆盖路由、身份、加密、WAF、限流、健康检查和 secret reference；公开入口、敏感策略变化和暂停/恢复由 `PolicyApprover` 独立批准，审批人不能批准自己的修订，浏览器审批还要求近期 step-up 重新认证。edge 由监听器监督器在应用前绑定快照所需的全部内部端口，再原子切换路由；快照中声明 `page_actions` 的站点由 edge 在写入 pending 文件之前（以及重启恢复时、监听之前）把由配置推导的动作描述幂等写入 PostgreSQL，描述冲突或数据库不可用时整份快照以 `EDGE_APPLY_DESCRIPTOR_CONFLICT`/`EDGE_APPLY_DESCRIPTOR_UNAVAILABLE` 拒绝并点名站点（见 [19 §19.2](19-deployment-operations.md)）；`XSHIELD_EDGE_LISTEN_PORTS` 仅用于启动时的 bootstrap 监听集合，新站点端口可在不中断现有请求的情况下动态绑定。设置 `XSHIELD_EDGE_SNAPSHOT_PATH` 后，已确认快照以 HMAC 签名的 pending/active 文件原子持久化，edge 重启前会先验签和校验完整快照；损坏或作用域不符时拒绝启动，避免回退到未确认配置。

### 3. 案件分析 MVP（耐久任务）

案件分析 MVP 已形成可重试的耐久任务闭环：案件所有者显式提交清单计数分析，服务端在迁移 0038 的任务表中保存 `job_` 状态与幂等摘要，再通过本人范围的任务查询读取结果；固定审计事件覆盖创建、重放、拒绝与读取。当前实现只处理 catalog 元数据计数，模型、原文、导出和回放保持独立交付。

### 4. 调查导出（独立审批的元数据包）

调查导出 MVP 已形成独立审批的元数据包闭环：`POST /control/v1/exports` 在迁移 0039 中创建带用途的 `export_` 请求，独立的 `SensitiveEvidenceApprover` 在浏览器会话完成近期 step-up 后批准或拒绝，批准时只将案件/证据目录元数据与缺失清单写入现有加密证据库，`SensitiveEvidenceReader` 再以第二次 step-up 下载短时、最多两次的包。`web/console` 已接入显式申请、状态复核、审批/拒绝和下载工作台；包不复制证据正文、模型输入输出或连接凭据，每次请求、决定、生成和下载均写管理审计，目录指针与 vault manifest 在下载前再次逐项核对。包请求 ID 固定由 `export_id` 派生，迁移 0040 以 tenant/site/export 复合键、父引用摘要和短 lease 串行化外部包写入；过期 lease 可回收，旧 writer 不能提交 `ready`，claim 与 ready 在同一数据库事务内完成。完整事件/正文导出、自然语言查询和安全回放仍是后续 backlog。

### 5. 事件调查：Trace ID 与因果检索

结构化事件调查已支持精确 Trace ID 过滤，并增加直接因果边逐跳检索：每步沿用 Investigator 作用域、既有扫描预算与审计，需手动填写时间窗并提交。新增 `POST /control/v1/causality` 提供服务端有界多跳因果遍历：只沿已发布 `cause_event_ids` 在固定时间窗内查找，最多 4 跳、16 个非根节点，返回同一脱敏摘要并写 `console.causality.read`；它不读取正文、不授予详情或业务权限。事件抽屉现提供显式“查看因果”按钮（默认取事件前后各 15 分钟，方向与跳数上限在“高级”中调整，操作者主动提交）；结果按根事件、方向和跳数分组展示，本地已加载邻域仍作为即时视图，跨页完整图、自然语言计划和回放继续交付。

### 6. 校准批量读取能力（read_capability）

`xshield_core::calibration::read_capability` 与 `ports::CalibrationEvidenceReadPort` 已为离线校准批量读取定义纯领域/端口边界：独立的 `calcap_` capability 冻结 tenant/site、可信有效期、四份分区 manifest、每个样本的 model-record/label artifact 对、语义 role、样本上限及 512 MiB 聚合字节上限。请求只接受 capability 导出的精确引用及与该 capability 绑定的、不可复制的 batch lease/session handle，重验 scope、租约、capability ID 和成员关系；控制台单对象 `EvidenceReadPort`、案件、审批、`ApprovalRef` 或管理角色不能作为此批次授权。迁移 0023–0025 与 PostgreSQL 适配器已将完整 catalog 快照、规范 scope digest、受限 issuance/completion outbox 事实及明文释放 reservation 持久化；开始批次时再次锁定并核对完整集合，私有 lease handle 仅留在运行中会话。读取授权器在每次打开 vault 前再次锁定并核对完整 capability/member/live catalog、活动 lease 与私有 handle digest，只返回内部 catalog 预期；`LocalCalibrationEvidenceReader` 将该预期与本地 vault 的认证 manifest、密文摘要和 AEAD 校验结合，取得短时、精确绑定的 release reservation 后写入独立加密 `calibration.evidence_read` journal receipt，并在返回明文前原子提交 release boundary。完整 `EvaluationReport` 才能驱动原子 lease completion；受限报告 artifact、持久化适配器及内容无关事件提交 API 与 worker evaluator 编排已交付。evaluator 逐引用读取并校验 v3 model-call/label DTO、调用纯阈值内核、写入并 fresh-attest report，再以固定身份精确重试 PostgreSQL 提交；内容独立性仍需声明式分区/血缘审查，不能由 artifact 引用本身证明。适配器逐次重验及完整闭环见 [10.16](10-jev-and-agents.md#1016-已实现校准批量读取能力与端口契约)、[10.17](10-jev-and-agents.md#1017-已实现耐久发行与批次会话)、[16.4](16-rust-code-architecture.md#164-port-契约) 与 [20.3](20-testing-and-acceptance.md#203-误拒与安全收益)。

### 7. 校准报告持久化（publication 与 report vault）

`xshield_core::calibration::publication` 与专用 report vault 已交付受限报告持久化适配器：独立 `calr_` UUIDv7 报告 ID、canonical JSON report artifact、专用认证 manifest 和 AEAD AAD 均绑定 tenant/site/report/artifact。迁移 0026、0030–0031 与 `PostgresIdentityStore::complete_and_publish_calibration_report` 在同一短 PostgreSQL 事务中重验完整 capability/member/live catalog、已提交 lineage review、活动 lease/token digest、runner、报告 manifest 和数据库时钟；随后写入专用报告元数据、immutable lineage review projection、lease `active → completed`、capability `leased → consumed`，以及内容无关的 `calibration.read_batch.completed` 和受限 `calibration.reported` outbox 事实。精确未知提交重试只识别完全一致的 review、report、lease、artifact 和两个事件绑定；数据库拒绝不会消费 lease。报告 artifact 不进入通用 request catalog，事件不携带样本、标签、概率、指标、提示词或正文，也不授予读取、发布阈值/策略或业务资格。worker evaluator 已调用这组 API 完成受控单批编排；外部内容独立性与真实供应商质量仍需单独验收。边界见 [10.15](10-jev-and-agents.md#1015-已实现校准报告持久化)、[11.9](11-audit-event-contract.md#119-已实现-calibrationreported-发布契约) 和 [20.3](20-testing-and-acceptance.md#203-误拒与安全收益)。

### 8. 校准报告元数据调查 API

`GET /control/v1/calibration-reports/{report_id}` 已为 `AuditAdministrator` 提供固定 tenant/site 的受限报告元数据调查。接口只读取专用 PostgreSQL projection；缺失或跨 scope 以同构 `found=false` 返回，已删除 report body 保留为 `body_status=deleted` tombstone。每次已认证尝试在释放结果前耐久写入 `console.calibration.report.read`，projection、outbox 或 retention 链接损坏及审计故障均扣留响应。它不读取专用密文正文、不访问通用 evidence catalog，也不返回能力、lease、storage locator、密钥、完整性摘要、样本、标签、概率、指标、提示词或读取 URL。完整契约见 [29.26](29-api-endpoint-catalog.md#2926-已实现的校准报告调查契约)。

### 9. 按 calibration_report_id 检索

`POST /control/v1/search` 现可用强类型 `calibration_report_id=calr_…` 检索同一 scope 内已发布的报告、报告正文保留维护和单报告管理读取历史。常规检索仍要求 Investigator；该过滤条件额外要求同一主体持有 AuditAdministrator，缺少角色在索引读取前拒绝并仅耐久记录计划摘要。服务端固定事件族、JSON 键和参数绑定；查询不返回报告正文、样本、标签、概率、指标、提示词、能力、lease、存储信息、阈值/策略或任何授权。契约见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 10. 离线校准数据集领域契约（dataset）

`xshield_core::calibration::dataset` 已为离线阈值评估提供无 I/O 的数据集领域契约：每个样本分别引用模型调用记录和标签证据，冻结批准、数据集/标签/任务/映射/阈值、provider、wire model、模型/提示修订及可未知的 resolved revision；训练、校准、评估和标签 manifest 必须是四个不同 artifact，且不能复用为样本来源。它拒绝样本证据别名、跨角色复用、重复引用以及模型或映射修订漂移，并在结果保留按输入顺序的调用 ID、模型记录、标签证据三元关联和统计指标。worker content decoder 进一步严格消费现有 schema-v3 model_call 与 reviewed-label DTO，只接受经 role/slot 授权的 `risk_projection` 并对映射缺失、状态失败和 provenance 漂移 fail-closed；该契约只能比较提交的引用集合，不能证明外部内容互不重叠。详情与测试边界见 [10.14](10-jev-and-agents.md#1014-已实现校准数据集领域契约) 和 [20.3](20-testing-and-acceptance.md#203-误拒与安全收益)。

### 11. 分区审查持久化闭环（lineage_review）

`xshield_core::calibration::lineage_review` 已形成声明式分区审查的持久化闭环代码：纯领域审查将四份冻结 manifest、分区绑定的 corpus/reviewed-label 来源图与独立 `calrev_` review/artifact ID 精确绑定；专用 vault 将 canonical review artifact 和认证 sidecar 以 tenant/site/review/artifact AAD 加密；迁移 0029 与 `PostgresIdentityStore::commit_calibration_lineage_review` 将经 fresh attestation 的受限 artifact metadata、冻结 provenance、四份 manifest、source-graph digest 和 `calibration.partition_lineage.reviewed` 事实原子提交。全局 artifact identity registry 阻止 request catalog、报告和 review 三个对象族复用 artifact ID。迁移 0033 将 review body 的到期与孤儿回收接入同一受限维护命令：数据库先写 intent，vault 以认证 sidecar 重新校验后才移除精确密文，成功才写 tombstone；projection、sidecar 和冻结 provenance 留作恢复/审计元数据，通用 orphan 扫描器跳过此对象族。尚有 purge intent 或已 tombstone 的 review 不能再绑定新的读取 capability。受限 outbox 只索引 review identity、artifact、provenance 和 manifest metadata，不展开 source graph、source ID/revision 或正文。该事实只说明已审核声明关系，不替代受控读取、内容去重或外部语料独立性验证；并发 registry 冲突、真实 ClickHouse 投递和数据质量验收仍需独立完成。契约与验证边界见 [10.19](10-jev-and-agents.md#1019-已实现声明式分区与血缘审查持久化契约)、[11.9.1](11-audit-event-contract.md#1191-已实现-calibrationpartition_lineagereviewed-发布契约) 和 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)。

### 12. Jev 离线评估：Score

Jev 离线评估已支持 Score：操作员提交 2–10 档有序描述，适配器验证完整档位、概率分布和加权评分，并将评分、档位及独立供应商置信度写入加密调用证据。模型审计、查询及控制台接受 Score 生命周期；Gateway 官方费用元数据经过有界校验。部署顺序、数值容差与运行方式见 [10.11](10-jev-and-agents.md#1011-已实现-score-离线评估)。

### 13. 证据保留工作台（保留锁）

控制台已接入 AuditAdministrator 的证据保留工作台：为案件成员创建有期限和理由的保留锁、分页复核保留历史并显式释放。创建与释放使用冻结幂等请求恢复未知结果，列表按数据库观察时间区分期限与释放事实；保留延缓物理删除，原文读取继续使用独立审批和原期限。使用及部署边界见 [15.10](15-console-and-api.md#1510-已实现证据保留工作台)。

### 14. 证据访问：我的申请与审批待办

证据访问工作台已提供“我的申请”和“审批待办”：通过 `GET /control/v1/evidence-access-requests` 分页发现本人历史或同作用域其他主体的 pending 申请，打开记录后重新读取详情。每页具有独立数据库观察时间、凭证/主体/视图绑定游标和 `console.evidence.access.list` 审计；申请及决策后显式刷新。启用前先应用迁移 0022 并升级管理 journal 发布器，契约与回滚边界见 [29.24](29-api-endpoint-catalog.md#2924-已实现的证据访问申请列表契约)。

### 15. 证据访问工作台：申请、审批与下载

`web/console` 已提供“证据访问”工作台：以案件和明确理由提交原文申请，读取详情后由独立审批人批准或拒绝，获批申请人显式下载 `.bin` 附件。写入保留冻结原键和参数以确认未知结果；下载核对服务端范围、目标及有界完整字节，沿会话生命周期隔离晚到响应。角色、当前状态与内容完整性由服务端重新验证；升级顺序及生产身份边界见 [15.9](15-console-and-api.md#159-已实现证据访问工作台)。

### 16. 证据访问申请详情 API

`GET /control/v1/evidence-access-requests/{access_request_id}` 已提供审批前的申请详情：申请人按独立 Investigator/Reader 角色查看本人记录，同站点 Approver 可复核申请与历史决策。返回理由、目标、持久状态与单次数据库时间观察，经独立 `console.evidence.access.read` 审计后释放；审批与下载仍重新校验，契约和发布器升级顺序见 [29.23](29-api-endpoint-catalog.md#2923-已实现的证据访问申请详情契约)。

### 17. 案件工作台（Investigator）

`web/console` 已接入 Investigator 案件工作台：显式创建本人案件、分页发现并打开本人开放/已关闭案件、浏览证据引用、关联有效证据及关闭案件。列表按案件 ID 降序，每页展示独立数据库观察时间，创建或关闭后显式刷新。变更展示管理请求 ID 和幂等结果；提交后冻结原键与参数，断网、超时或晚到响应保持结果未知，供操作者原样重试。案件接口共用有界许可，已准入操作在断连后继续到数据库及管理审计终态。案件状态、catalog 状态、内容权限与保留期限分别校验，运行及恢复边界见 [15.8](15-console-and-api.md#158-已实现案件工作台)，列表升级与契约见 [29.22](29-api-endpoint-catalog.md#2922-已实现的本人案件列表契约)。

### 18. 只读调查页：请求、模型、Agent、资格与检索

`web/console` 已提供只读请求、模型调用、Agent 运行详情、资格/身份绑定调查与结构化事件检索（请求调查页按已索引的请求终态浏览，基于结构化检索，不是实时流量并显示索引间隔；资格与身份绑定合为“身份与资格”一页，模型调用列表与按 ID 打开合为“模型调用”一页）：Observer 可查看请求摘要、事件分页、模型生命周期/供应商标识、Agent 脱敏生命周期、证据元数据及资格/绑定账本快照，并打开来源请求和绑定详情；检索和请求时间线中的模型阶段会投影强类型调用 ID，可跳转至独立重新鉴权的模型详情，Agent 运行 ID 可打开独立重新鉴权的脱敏详情。Investigator 可提交有界 UTC 时间窗、同事件 AND 条件和稳定排序，按冻结计划继续分页。账本持久状态、时间到期和代际分别展示，数据库观察与日志水位独立，历史入口须显式选择时间窗并重新鉴权。客户端校验查询摘要和精确微秒位置，显示实际扫描量、空值与配置日志水位/缺口；历史查询权限不替代 Observer 或原文权限。凭证只存页面内存，401、闲置及刷新清态，跨范围和晚到响应受到隔离。模型与 Agent 生命周期完整性和日志水位独立显示，历史未知供应商和 Noul 空置信度按实际记录呈现。运行方式、验证范围及企业身份入口待补边界见 [控制台说明](../web/console/README.md) 和 [15.7](15-console-and-api.md#157-已实现只读请求调查控制台)。

### 19. 原文下载的 MFA 再认证（step-up）

证据原文下载还要求当前 OIDC 浏览器会话完成两分钟有效的 MFA 再认证，并继续通过逐次独立审批；该 step-up 使用迁移 0036 和部署方精确 ACR/auth_time 校验。当前机器 Bearer 自动化没有 step-up 凭据，原文端点会 fail-closed 拒绝，详见 [29.28](29-api-endpoint-catalog.md#2928-已实现的-mfa-再认证契约)。

### 20. 一次性 Jev 离线评估（xshield-model-eval）

`xshield-model-eval` 已实现操作员批准的一次性 Jev 离线评估：严格 Choice/Noul 契约、固定 Vercel AI Gateway HTTPS 端点（显式 `direct` 可兼容 TypeSafe 直连）、实际请求/响应加密证据、PostgreSQL catalog/outbox 和 `model.*` 耐久终态。迁移 0034 进一步将 tenant/site 跨实例调用容量绑定到 PostgreSQL scope 和私有短租约；迁移 0037 为 direct 精确模型修订增加了耐久结果缓存，命中前重新验证来源 catalog/vault 和完整模型证据，写入新的 `model_call_id`/`request_id` 与 `model.cache_hit`，不申请 admission 或发送 HTTP；缓存不提供证据读取或业务资格，缓存写入失败也不改写已完成的模型结果。容量拒绝只形成模型终态，不创建证据或 HTTP 调用；发送前以数据库时钟重验，终态 journal 耐久后释放，进程中断只可由 TTL 回收而不重放。429/529、超时、取消、超限和中断恢复均有明确结果；使用方法与运行边界见 [10.9](10-jev-and-agents.md#109-已实现一次性离线评估) 和 [RB-11](26-runbooks.md#rb-11-一次性模型离线评估)。当前验证使用合成 loopback 供应商，不代表真实模型质量、计费或外部服务可用性；校准及调查 Agent 继续迭代。

### 21. 模型阶段与调用审计索引

模型阶段及调用审计支持 `mdl_` 强类型引用、provider/provider_model_id 与内部模型版本索引；阶段汇总保留最新 null 置信度，Gateway alias 不伪造精确 resolved revision。发布与查询边界见 [11.4](11-audit-event-contract.md#114-阶段结果契约) 和 [20.6](20-testing-and-acceptance.md#206-clickhouse-真实集成回归)。

### 22. 模型调用摘要 API

`GET /control/v1/model-calls/{model_call_id}` 已提供固定作用域的模型调用摘要、因果链完整性与输入/输出证据引用，要求 `Observer` 并写独立耐久访问审计。查询预算、索引可见性及配置日志水位语义见 [29.15](29-api-endpoint-catalog.md#2915-已实现的模型调用查询契约)。

### 23. 按 model_call_id 检索

`POST /control/v1/search` 已支持强类型 `model_call_id=mdl_…` 检索固定模型生命周期及对应 `console.model.read` 历史。该计划保持 Investigator 的受限历史权限，模型详情仍需独立 Observer 重新鉴权；服务端固定事件族、JSON 键和参数绑定，审计仅保留查询摘要。控制台模型详情仅预填该条件，操作者必须填写独立时间窗后主动提交。完整边界见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 24. 按 agent_run_id 检索

`POST /control/v1/search` 现支持强类型 `agent_run_id=agt_…` 检索固定 Agent 生命周期（启动、工具调用/结果、产物和终态）及对应 `console.agent.read` 历史。该过滤器沿用 Investigator 的脱敏历史范围；它不实现或触发 Agent 执行，不返回输入/输出正文、工具参数、证据内容或权限快照，也不授予回放、详情或业务权限。服务端固定事件族、JSON 键和参数绑定，审计仅保留查询摘要；控制台提供该字段供操作者主动提交有界检索。完整边界见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 25. Agent 运行脱敏详情 API

`GET /control/v1/agent-runs/{agent_run_id}` 已提供 Observer 重新鉴权的脱敏 Agent 生命周期详情：仅返回固定事件族的类型、时间、结果/原因、因果和证据引用，严格限制 64 个事件与 16 KiB payload，并独立写 `console.agent.read`。输入/输出、工具参数、权限快照、产物正文、执行与回放仍不进入详情投影；见 [29.30](29-api-endpoint-catalog.md#2930-已实现的-agent-运行脱敏详情契约)。

### 26. 按 evidence_access_request_id 检索

`POST /control/v1/search` 已支持强类型 `evidence_access_request_id=access_…` 检索固定访问申请/决策事件及对应 `console.evidence.access.read` 历史。该计划保持 Investigator 的受限历史权限，申请详情、审批与原文读取仍各自重新鉴权；服务端固定事件族、JSON 键和参数绑定，审计仅保留查询摘要。控制台访问申请详情仅预填该条件，操作者必须填写独立时间窗后主动提交。完整边界见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 27. 按 evidence_hold_id 检索

`POST /control/v1/search` 已支持 `evidence_hold_id=ev_…` 检索固定保留锁创建、释放及相应管理尝试历史。该条件要求同一主体同时持有 Investigator 与 AuditAdministrator；控制台保留历史只预填 ID，不自动提交，时间窗仍由操作者填写。查询只返回脱敏历史摘要，访问审计仅保存计划摘要，不改变保留、详情或原文权限。完整边界见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 28. 按 grant_id 与 auth_binding_id 检索

`POST /control/v1/search` 已支持按 `grant_id`、`auth_binding_id` 强类型过滤身份与资格发行事件、分享来源及对应的管理详情读取历史。复用 Investigator 权限、固定作用域、有界时间窗、签名游标与独立访问审计；结果为已发布历史事实，具体字段映射和可见性边界见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。管理详情本身仍须单独具备 Observer 权限。

### 29. 按 share_grant_id 检索

`POST /control/v1/search` 另支持强类型 `share_grant_id=share_…` 精确定位固定 `share.issued` 事件中的分享签发记录。该过滤器沿用 Investigator 的固定作用域、有界时间窗、签名游标和访问审计，只返回脱敏事件摘要；不会返回分享 bearer 凭证或扩大权限。

### 30. 按 subject_ref 检索

受限检索现支持 `subject_ref` 精确筛选身份与管理历史中的直接主体引用；输入有 256 UTF-8 字节上限且拒绝控制字符，服务端只匹配固定顶层引用字段。结果不回显查询值，计划摘要使用用途隔离的 HMAC 处理该低熵值；审计不保存过滤条件，仍保留标准调用者主体引用与计划摘要。检索沿用 Investigator 的固定 tenant/site 范围，不授予详情或证据读取权限。完整字段映射见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 31. 资格账本快照 API

`GET /control/v1/grants/{grant_id}` 提供 Observer 可读的资格及当前绑定账本快照、数据库时间过期标志和来源请求/事件引用。过期、撤销和代际变化仍可调查；所有返回经过 `console.grant.read` 耐久审计，字段与部署权限见 [29.19](29-api-endpoint-catalog.md#2919-已实现的资格账本调查契约)。

### 32. 身份绑定调查 API

`GET /control/v1/auth-bindings/{binding_id}` 已提供 Observer 可读的身份绑定详情：当前身份与凭证代际、持久状态、期限和更新时间，支持匿名、过期及撤销记录。响应经 `console.binding.read` 耐久审计，生命周期历史可通过绑定 ID 检索；字段和部署边界见 [29.20](29-api-endpoint-catalog.md#2920-已实现的身份绑定调查契约)。

### 33. 案件证据加入 API

`POST /control/v1/cases/{case_id}/items` 已支持 Investigator 将同作用域有效证据引用加入本人开放案件：每案最多 128 项，关联与 outbox 原子提交，精确幂等重试，并在客户端断连后完成已准入操作的终态审计。先应用迁移 `0017_m3_case_evidence.sql`；关联只建立调查上下文，内容读取与保留期限仍独立校验，详见 [29.16](29-api-endpoint-catalog.md#2916-已实现的案件证据关联契约)。

### 34. 案件证据集合查询 API

`GET /control/v1/cases/{case_id}/items` 已提供本人案件的有界证据集合查询：HMAC 游标绑定凭证、主体、作用域、案件和页大小，单 PostgreSQL 快照返回案件摘要、成员引用及 `active`/`expired`/`deleted`/`unavailable` catalog 状态（正常 retention 使用 deleted tombstone）；响应不包含 manifest、locator、hash、key ref 或内容，且所有结果均写 `console.case.read` 审计，详见 [29.17](29-api-endpoint-catalog.md#2917-已实现的案件证据集合查询契约)。

### 35. 案件关闭 API

`POST /control/v1/cases/{case_id}/close` 已支持所有者关闭案件：关闭记录、状态与 `case.closed` outbox 原子提交，释放 open 案件容量，后续新增关联、原文申请/批准与读取资格校验要求案件仍为 open。历史证据集合和审批记录保留，证据期限保持原值。部署先应用 `0018_m3_case_lifecycle.sql`；幂等、并发及审计边界见 [29.18](29-api-endpoint-catalog.md#2918-已实现的案件关闭契约)。

### 36. 按 case_id 与 artifact_id 检索

`POST /control/v1/search` 支持 `case_id`、`artifact_id` 历史检索，定位已发布的案件操作、审批管理尝试、保留锁及证据引用。固定事件字段、同事件 AND、查询预算和游标绑定沿用现有 QueryPlan；历史可检索与当前案件、保留及内容权限分开校验，详见 [29.14](29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

### 37. 管理访问 journal 与发布器

管理访问 journal 已接通封存段发布器：当前控制端点的访问尝试按严格契约进入 `control_access` 索引阶段，可通过管理 request_id 时间线及有界事件检索复核；独立日志源的部署、水位及 outbox 边界见 [11.7](11-audit-event-contract.md#117-已实现的管理访问审计发布)。

### 38. 原文访问的有界操作许可

原文访问申请、独立审批与内容读取共用有界操作许可，已准入任务断连后继续完成数据库结果及访问审计；数据库操作含池等待限 15 秒、SQL/锁等待限 5 秒。锁等待后重新验证期限，批准 TTL 从锁后数据库时钟计算；内容明文另由响应生命周期许可约束。严格请求、安全错误、重试与本地 I/O 边界见 [29.11–29.13](29-api-endpoint-catalog.md#2911-已实现的证据访问申请契约)。

### 39. 案件保留锁 API

案件保留锁已提供 AuditAdministrator 专属的创建、释放与分页历史 API，复用固定作用域、严格输入、幂等、容量和终态审计；活动锁暂停物理删除，内容读取仍遵守原期限与审批。接口与升级顺序见 [29.21](29-api-endpoint-catalog.md#2921-已实现的案件保留锁管理契约)。

### 40. PostgreSQL outbox 发布（按事件族）

PostgreSQL outbox 已接通按事件族隔离的发布闭环：`xshield-outbox-worker TENANT_ID SITE_ID` 默认处理 `case.*`，设置 `XSHIELD_OUTBOX_FAMILY=evidence_catalog`、`evidence_access`、`evidence_retention`、`calibration`、`identity`、`grant`、`response_grant` 或 `share_grant` 可分别处理证据目录、证据访问请求/审批、证据清理、受限校准报告与分区血缘审查 metadata、身份生命周期、通用资源资格、响应资格和分享发行；各族均使用 tenant/site 绑定的 `FOR UPDATE SKIP LOCKED` 租约、服务端时钟、行/字节上限和精确 token 确认，严格解析后按 event_id/content_digest 至少一次写入 ClickHouse。`calibration` 消费 `calibration.reported`、`calibration.partition_lineage.reviewed`、batch completion/capability 事实，以及报告和 lineage-review 的到期/孤儿维护事实；它不读取 evidence、不发布阈值/策略，outbox 也不是这些授权或保留状态的真值。`GrantPersistence` 库入口从冻结的类型化内部命令构建并原子提交 `grant.issued`，不提供独立 HTTP 发行面。站点 HTTP 资格由网关在已验证的源站响应、响应证据、动作和资源资格的同一事务中提交 `response_grant.issued` 完整 v3 envelope，保留原请求、批内序号和冻结发行时间；`ShareIssueApi` 原子提交 `share.issued`，绑定稳定 event/share ID 和精确重试正文；网关 `response.share_issue` 已将获准分享操作的完整响应接入发行与凭证交付。`AUTHENTICATED_ROOT` 的 `auth_revoke` 登出响应现已原子撤销绑定及全部活动/过渡凭证并写入 `binding.revoked`，身份发布器同步严格解析该事件；失败只记录稳定错误码并延迟重试，历史稀疏身份、通用资源资格、响应资格及分享记录保持未确认。证据清理族接收 catalog 与孤儿对象的六类删除意图/成功/失败事实，以及案件保留锁的创建/释放事实，保留 artifact 与因果引用、确定性空置信度和独立维护阶段；其脱敏检索不授予原文访问权。各族合成契约、通用资源资格、实际网关响应资格、分享库 API 及实际清理生产者的数据库覆盖见 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)，配置与升级边界见 [11.8](11-audit-event-contract.md#118-已实现的按事件族-outbox-发布)。

### 41. 匿名 binding 与 WAF 会话

缺少 WAF Cookie 的受保护根/API 请求会先原子创建一条有服务端绝对期限的匿名空 binding 与 `session.created` outbox，再以 401 拒绝并签发 `Secure`、`HttpOnly`、`SameSite=Lax` 的 `__Host-xshield_sid`。匿名 binding 的 epoch/generation 均为 0，不含主体、授权上下文、业务凭证或资格；重复携带该 Cookie 不会扩增记录，附加任意 Bearer 也不能升级身份。匿名 TTL、来源/站点创建速率与每租户/站点活动容量由 `identity_store` 有界配置；进程内预算先限制数据库调用，PostgreSQL 短事务再以传输层对端地址的租户/站点隔离 HMAC 实施分布式来源/站点限流。速率超限返回 429，容量超限返回 503，均不签发 Cookie。

### 42. AUTH_ENTRY：首个 Bearer 认证建立

`AUTH_ENTRY` 已支持首个 Bearer 认证建立闭环：有界严格 JSON 成功响应提供配置指针指定的主体、授权上下文引用与 Bearer，网关在释放正文前原子写入新 binding、初始 credential generation 和 `binding.created` outbox，并签发 `Secure`、`HttpOnly`、`SameSite=Lax` 的 `__Host-xshield_sid`。源站同名 Cookie、响应形状偏差或事务失败均不建立身份；端到端测试已使用新签发的 WAF Cookie 与业务 Bearer 访问受保护根入口。

### 43. AUTHENTICATED_ROOT 刷新（auth_refresh）

`AUTHENTICATED_ROOT` 刷新端点可配置 `auth_refresh`：请求先用旧 WAF Cookie 与旧 Bearer 精确加载身份，成功响应只接受同一主体、同一授权上下文引用的新 Bearer；提交事务再次比较 binding、主体、授权上下文、epoch、generation、完整旧凭证集合及旧凭证期限，随后撤销旧 generation、写入新 generation 与 `identity.refreshed` outbox。CAS 冲突、身份上下文变化、原凭证过期或响应偏差均不释放成功正文；刷新保持 auth epoch，因此刷新前已提交且仍有效的资源资格可继续使用。

### 44. 身份上下文切换（auth_context_switch）

身份上下文切换端点可配置 `auth_context_switch`：请求仍以旧上下文的完整认证组合准入，成功响应必须提供主体或授权上下文引用的变化及新 Bearer；网关在释放正文前原子更新上下文、auth epoch 与 credential generation，撤销旧凭证并提交 `epoch.changed` outbox。同主体的租户/角色变化也会隔离旧 epoch，切换期间晚到的旧响应不能发行资格；WAF 会话 Cookie 与绝对期限保持不变。升级迁移会撤销缺少已验证授权上下文的活动绑定，客户端需重新认证。

### 45. 登出与撤销（auth_revoke）

`AUTHENTICATED_ROOT` 登出端点可配置 `auth_revoke`：仅接受当前 WAF Cookie、Bearer、主体、授权上下文和 auth epoch 的完整快照；源站返回配置成功状态且完整响应通过缓冲校验后，网关在响应释放前锁定快照，原子撤销绑定及全部 `active`/`transition` 凭证并提交 `binding.revoked` outbox。过期、已撤销或并发代际变化统一冲突关闭，正文不会在事务失败时释放；后续请求以 `AUTH_BINDING_MISMATCH` 拒绝，原始凭证不进入日志或事件载荷。

### 46. xshield-control 管理接口

`xshield-control` 已提供独立管理接口：固定从服务端配置注入 tenant/site 作用域，以常量时间摘要比对管理 Bearer 凭证，执行每分钟有界限流，并在返回前写独立加密管理审计。`GET /control/v1/audit/health` 仅允许 `AuditAdministrator`；请求摘要、事件时间线和证据 manifest 查询允许 `Observer`；结构化搜索与有界因果查询允许 `Investigator`，后者沿已发布引用返回脱敏多跳摘要并写独立审计。`POST /control/v1/search` 仅允许 `Investigator`，使用有界 QueryPlan 和参数化 ClickHouse 查询，HMAC 游标绑定完整计划、主体及作用域，不接受任意 SQL。manifest 列表和单 artifact 查询只访问 PostgreSQL 中 active、未删除且按数据库时钟未过期的元数据；列表使用 HMAC 游标绑定主体、作用域、目标请求和页大小，单项查询把缺失、过期、删除和作用域偏差统一为 `found=false`，两者均不读取或解密证据内容。`POST /control/v1/cases` 仅允许 `Investigator` 在固定作用域创建有界调查案；`POST /control/v1/artifacts/{artifact_id}/access` 只为同一主体拥有的 open 案件和 active 未过期证据建立有界 pending 原文访问申请。独立 `SensitiveEvidenceApprover` 可批准或拒绝申请，数据库拒绝申请人自批；批准会产生绑定申请人、案件、artifact 且不超过对象期限的短时服务端读取资格。`GET /control/v1/artifacts/{artifact_id}/content` 要求同一申请主体的 `SensitiveEvidenceReader`，以 `X-Xshield-Evidence-Access-Request` 指定已批准申请，重新校验案件、目录、数据库时钟、vault manifest、密文摘要和 AEAD 后才返回附件，并把实际字节数写入 `evidence.read` 管理审计。所有管理变更均使用主体与参数绑定的用途隔离 HMAC 摘要实现精确幂等，并把状态转换与对应 outbox 原子提交。

### 47. xshield-evidence 本地加密证据库

`xshield-evidence` 已提供本地加密证据库 MVP：只打开预建的私有目录，对每个 artifact 以 tenant/site/request/artifact/kind/chunk AAD 和独立 HMAC 派生数据密钥执行 AES-256-GCM，密文对象、typed manifest 与 manifest HMAC 均不覆盖耐久写入。manifest 读取使用库内当前时钟重验作用域、期限与 key-id，内容读取额外重验密文摘要与 AEAD；未知、过期和跨作用域对象返回相同不可用状态。`xshield-control` 的 EvidenceReadPort 已把 PostgreSQL 批准资格与 vault 侧复验接成内容读取闭环。整对象模式硬限制 64 MiB，业务配置只能继续收紧；网关已接入显式批准的 BUFFERED_JSON 响应采集：秘密排除清单与正文副本加密落盘、catalog/outbox 与 journal 耐久提交后才释放业务正文，并受单采集许可、磁盘/文件配额和数据库期限约束。`xshield-evidence-retain` 提供按 tenant/site/key 有界、排他锁保护的到期密文与宽限孤儿维护，先写删除意图，再完成 tombstone，故障可重试；配置与覆盖范围见 [12.7](12-evidence-capture-and-vault.md#127-已实现有界-json-响应采集屏障) 和 [12.8](12-evidence-capture-and-vault.md#128-已实现到期密文孤儿维护与故障重试)。请求、HTML、最终客户端实体采集、远端对象 adapter 与分块仍继续迭代。

### 48. 证据 catalog（PostgreSQL）

PostgreSQL catalog 只接受证据库产生或认证的 manifest 类型，按 artifact 身份执行精确幂等发布，并与 `evidence.cataloged` outbox 事件同事务提交；同 ID 元数据冲突返回稳定冲突终态，审计写入失败不留下 catalog 行。request 查询固定绑定 tenant/site/request，使用数据库当前时钟排除过期或删除对象，最多返回 128 条 typed manifest；catalog 元数据不能替代对象侧 HMAC、摘要和 AEAD 复验。

### 49. M2：双向 AES-256-GCM 加解密闭环

M2 已落地 `DIRECT_DECRYPT` / `DIRECT_ENCRYPT` 双向 AES-256-GCM 垂直闭环。请求侧 AAD 绑定租户、站点、operation、HTTP 语义、适配版本、独立 key-id、规范 message-id 与时效；认证成功后由 PostgreSQL 原子消费 key 作用域的 message-id 和 nonce，重复、过期或超前消息不会到达源站。响应侧先完成严格 JSON 校验、身份/资格提交与确定性正文重建，再用独立用途密钥、随机 nonce 和短时 message-id 封装冻结客户端实体；AAD 额外绑定请求 ID 和源站状态，旧 Content-Length、编码、摘要及缓存验证头不会沿用。双向共享内存配额覆盖接收、解析、明文、密文和预分配封包峰值，容量不足时在分配前关闭。服务端可为非 UI 动作操作选择 `OBSERVE`，也可为 `UI_ACTION_REQUIRED` 操作配置 `COMPATIBILITY`；后者必须同时通过既有动作资格、页面证据中的精确构建指纹、服务端批准引用和绝对到期检查。两种 opaque 路径均禁止响应加密及身份/资格签发，Xshield 封包不会进入 compatibility。网关已在保留命名空间提供版本化同源探针与 loader、动态 no-store bootstrap，以及绑定当前 WAF 会话和身份代际的严格 HTTPS prepare 批量接收；观测以 `client_claimed` 写入耐久审计且不产生授权效果。`SENSOR_HTML` 响应适配器可在同一 operation 有界并存至多 16 个批准构建，按完整源站 SHA-256 选择各自固定 `</head>` 偏移；注入标签以 SHA-384 SRI 绑定网关实际提供的版本化资源，强制 CSP 使用逐响应 128 位随机 nonce 同步改写所有脚本指令和注入标签，构建、类型或策略偏差在正文释放前关闭，并记录选中修订、nonce 应用状态和注入前后摘要。ClickHouse 元数据索引按配置固化绝对保留期限，active 视图按 `event_id` 合并重投并先于后台 TTL 隐藏过期行。动态 HTML、原文对象保留与案件 pin 继续迭代。

### 50. M0 工作区与开发启动示例

M0 已提供 Cargo workspace、强类型 ID、稳定原因码、独立管理身份、审计端口及禁用站点的 `NOT_CONFIGURED` 阶段树。M1 已实现 WAF 会话与业务凭证的精确组合绑定、六类 operation 入口准入、页面证据与精确动作来源、有界资源资格账本，以及对应 PostgreSQL 约束和原子事务。Pingora MVP 网关可按可信 JSON 配置转发精确 `PUBLIC` / `AUTH_ENTRY` 操作；配置身份存储后，`AUTHENTICATED_ROOT` 会用租户隔离 HMAC 核对 `__Host-xshield_sid`、Bearer 凭证、当前 generation、epoch 和服务端期限。`UI_ACTION_REQUIRED` 会按不透明动作引用重验当前策略、页面证据和动作描述；GET 查询资源操作还会从实际 URI 严格提取资源与字段，以租户、站点和资源类型带域 HMAC 精确匹配资格账本。`SERVICE_IDENTITY` 使用独立边缘凭证头，按租户和站点带域 HMAC 精确加载 PostgreSQL 中的活动服务身份，并再次校验有限 operation 集和期限。`SHARE_ENTRY` 使用独立分享头，按租户、站点、资源、operation 和 view 精确加载 PostgreSQL 中活动且未过期的只读分享资格。分享发行 API 使用已验证的响应事实派生凭证与指纹，随后重新锁定当前身份与精确 ResourceGrant，要求活动策略中的独立发行规则批准目标 operation/view，并将 ShareGrant 与 outbox 原子提交后才把明文凭证交给响应适配器；来源失效、规则偏差、TTL 越界、幂等冲突或容量耗尽均不发行。分享令牌使用独立密钥按租户、站点和幂等键派生可重试的不透明长凭证，持久化与入口验证只接触另一用途密钥生成的 HMAC 指纹。按 operation 配置的 `BUFFERED_JSON` 响应适配器会在释放正文前完成 Content-Type、Content-Encoding、Content-Length、单请求与共享内存上限和完整 JSON 校验；非法、超限或共享配额耗尽均不释放正文，并以稳定原因写入 `origin.response` 与 `request.aborted`。响应资源规则会把已认证来源、业务成功状态、严格 JSON Pointer、动作引用字段、唯一目标资源 operation、单响应数量、TTL 和会话容量在启动时一起编译；完整正文解析会拒绝重复 JSON 键、形状偏差、无效或重复资源值。已验证响应会保留原请求的 AuthSnapshot，在一个短事务内重验当前 binding、auth epoch、活动策略、精确动作描述和整批容量，再原子写入 ResponseEvidence、逐资源 ActionGrant、ResourceGrant 与 outbox；事务提交后把不透明 `action_ref` 注入对应列表项并以 `private, no-store` 释放改写正文，源站预占字段或失败不留下部分资格。端到端测试已使用响应中的引用访问新资源，验证同会话资格可复用。显式 `resource_path_parameter` 可启用单个最终路径段适配器；它严格解码一次并拒绝额外查询、嵌套路径、编码斜杠、歧义路由和未精确命中的资格。缺失、替换、退休、过期、资源偏差、字段扩张或歧义查询均在源站前拒绝。WAF Cookie、动作引用、服务凭证头与分享头在访问源站前剥离。网关已接入加密分段 journal：准入、阶段、判定和转发意图必须批量持久化成功后才能访问源站，配额、写入或恢复失败均关闭转发。journal 按 `segment_max_bytes` 自动关闭并轮转；网关重启时在开放流量前认证扫描历史关闭段，为缺少终态或只留下合法批次前缀的请求耐久追加 `origin.unknown` / `request.aborted`，保留已收到的源站响应且不发起业务重试。独立封存命令可在 edge 持续写入时重验关闭段的 AEAD、CRC 与哈希链，生成包含整段摘要和链头的 Ed25519 签名清单，并以不覆盖方式持久化到独立私有位置。`xshield-worker` 按段顺序重新认证并解析事件，投递前后检查稳定 `event_id` 的正文摘要，ClickHouse 确认同步插入后才原子推进目标绑定的本地水位；同 ID 不同正文、缺失清单或水位冲突均停止后续段。worker 还可从重新认证的段与精确 checkpoint 生成连续索引水位、pending、unsealed、gap 和本地占用健康快照。

```bash
cargo test --workspace --all-targets
cargo run -p xshield-core --example m0_stage_tree
cargo test -p xshield-audit
cargo test -p xshield-evidence
scripts/test_postgres.sh
scripts/test_gateway_identity.sh
scripts/test_gateway_request_crypto.sh
scripts/test_gateway_dynamic_listeners.sh
XSHIELD_CONFIG=examples/gateway-config.json \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_DATABASE_URL="$YOUR_POSTGRES_URL" \
XSHIELD_FINGERPRINT_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SHARE_TOKEN_KEY_HEX="$YOUR_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_REQUEST_DECRYPTION_KEY_HEX="$YOUR_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX="$YOUR_OTHER_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
cargo run -p xshield-gateway

install -d -m 0700 target/xshield-audit-manifests
XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_KEY_HEX="$YOUR_ED25519_SEED_AS_64_LOWERCASE_HEX" \
cargo run -p xshield-audit --bin xshield-audit-seal -- \
  target/xshield-audit-demo target/xshield-audit-manifests

XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_PUBLIC_KEY_HEX="$YOUR_ED25519_PUBLIC_KEY_AS_64_LOWERCASE_HEX" \
XSHIELD_CLICKHOUSE_URL="https://clickhouse.example.invalid:8443" \
XSHIELD_CLICKHOUSE_DATABASE="xshield" \
XSHIELD_CLICKHOUSE_USER="xshield_publisher" \
XSHIELD_CLICKHOUSE_PASSWORD="$YOUR_CLICKHOUSE_PASSWORD" \
XSHIELD_INDEX_TARGET_ID="clickhouse-primary" \
XSHIELD_AUDIT_METADATA_RETENTION_DAYS="30" \
XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES="67108864" \
cargo run -p xshield-worker -- \
  target/xshield-audit-demo target/xshield-audit-manifests target/xshield-index-checkpoints

install -d -m 0700 target/xshield-control-audit target/xshield-evidence
XSHIELD_TENANT_ID="tenant_demo" \
XSHIELD_SITE_ID="site_demo" \
XSHIELD_CONTROL_SUBJECT="audit-operator" \
XSHIELD_CONTROL_ROLES="observer,audit_administrator" \
XSHIELD_CONTROL_TOKEN="$YOUR_RANDOM_MANAGEMENT_TOKEN" \
XSHIELD_CONTROL_CURSOR_KEY_HEX="$YOUR_CURSOR_HMAC_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX="$YOUR_DISTINCT_IDEMPOTENCY_HMAC_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_CONTROL_TOKEN_ISSUED_AT="$TOKEN_ISSUED_UNIX_SECONDS" \
XSHIELD_CONTROL_TOKEN_EXPIRES_AT="$TOKEN_EXPIRY_UNIX_SECONDS" \
XSHIELD_CONTROL_REQUESTS_PER_MINUTE="30" \
XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS="64" \
XSHIELD_CONTROL_MAX_OPEN_CASES="1000" \
XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS="1000" \
XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS="3600" \
XSHIELD_EVIDENCE_ROOT="target/xshield-evidence" \
XSHIELD_EVIDENCE_KEY_ID="evidence-key-r1" \
XSHIELD_EVIDENCE_KEY_HEX="$YOUR_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES="67108864" \
XSHIELD_EVIDENCE_MAX_RETENTION_DAYS="30" \
XSHIELD_CONTROL_LISTEN="127.0.0.1:9443" \
XSHIELD_DATABASE_URL="$YOUR_POSTGRES_URL" \
XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS="4" \
XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS="5000" \
XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_PUBLIC_KEY_HEX="$YOUR_ED25519_PUBLIC_KEY_AS_64_LOWERCASE_HEX" \
XSHIELD_CONTROL_AUDIT_KEY_ID="control-audit-key-r1" \
XSHIELD_CONTROL_AUDIT_KEY_HEX="$YOUR_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_CONTROL_AUDIT_MAX_BYTES="1073741824" \
XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES="858993459" \
XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES="67108864" \
XSHIELD_CLICKHOUSE_URL="https://clickhouse.example.invalid:8443" \
XSHIELD_CLICKHOUSE_DATABASE="xshield" \
XSHIELD_CLICKHOUSE_USER="xshield_reader" \
XSHIELD_CLICKHOUSE_PASSWORD="$YOUR_CLICKHOUSE_PASSWORD" \
XSHIELD_INDEX_TARGET_ID="clickhouse-primary" \
XSHIELD_AUDIT_METADATA_RETENTION_DAYS="30" \
XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES="67108864" \
XSHIELD_CONTROL_MAX_QUERY_EVENTS="100" \
cargo run -p xshield-control -- \
  target/xshield-audit-demo target/xshield-audit-manifests \
  target/xshield-index-checkpoints target/xshield-control-audit
```

### 51. 身份存储（identity_store）配置

身份存储由可选的 `identity_store` 配置启用；受保护入口或请求防重放存在时必须配置。运行时从 `XSHIELD_DATABASE_URL` 和 `XSHIELD_FINGERPRINT_KEY_HEX` 读取数据库连接与 32 字节 HMAC 密钥。配置 `response.share_issue` 时还须注入不同的 `XSHIELD_SHARE_TOKEN_KEY_HEX`；示例中的分享发行 GET 具有创建资格的副作用，须预先批准对应来源动作、资源资格及数据库发行规则，配置边界见 [6.5](06-capability-ledger.md#65-分享)。请求与响应加密分别从 `XSHIELD_REQUEST_DECRYPTION_KEY_HEX`、`XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX` 注入不同的 32 字节用途密钥；两侧 key-id 和实际密钥不得复用，当前进程每个方向只接受一个精确 key-id，轮换通过并行版本实例完成。UI 动作、服务调用和限权分享使用独立边缘证明，转发前全部剥离；网关只信任 PostgreSQL 中与当前作用域、期限和活动状态精确匹配的记录。封存目标目录须预先以私有权限创建；独立任务周期运行 `xshield-audit-seal`，其 Ed25519 私钥仅注入封存进程。控制服务的 ClickHouse 账号只授予 active 视图读取权限；PostgreSQL 账号只授予 catalog 查询、案件、证据访问申请/决策、outbox 及 advisory-lock 所需权限。请求摘要、脱敏事件和证据 manifest 查询均使用服务端作用域并写独立管理审计。事件与 manifest 游标由同一独立分页密钥按不同用途域签名，不能跨接口、主体、作用域、目标请求或配置复用；管理变更幂等摘要使用另一独立密钥并继续按动作分域。生产秘密均应由秘密管理器按用途注入和轮换，不写入配置文件或日志。
