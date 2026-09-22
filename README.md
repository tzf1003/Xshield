# Xshield 设计与开发文档库 v3.0

**纯前置 WAF · 界面操作来源准入 · Rust 主干 · 全链路可审计**

基线日期：2026-09-17。此库包含完整设计基线、开发规范、配置/数据契约和验收计划，以及正在实现的 Rust 产品代码。Word 总册为正文便于评审的排版版；本目录 Markdown 与机器可读文件作为工程协作源文件。

## 实现状态

`xshield_core::calibration::read_capability` 与 `ports::CalibrationEvidenceReadPort` 已为离线校准批量读取定义纯领域/端口边界：独立的 `calcap_` capability 冻结 tenant/site、可信有效期、四份分区 manifest、每个样本的 model-record/label artifact 对、语义 role、样本上限及 512 MiB 聚合字节上限。请求只接受 capability 导出的精确引用及与该 capability 绑定的、不可复制的 batch lease/session handle，重验 scope、租约、capability ID 和成员关系；控制台单对象 `EvidenceReadPort`、案件、审批、`ApprovalRef` 或管理角色不能作为此批次授权。迁移 0023–0025 与 PostgreSQL 适配器已将完整 catalog 快照、规范 scope digest、受限 issuance/completion outbox 事实及明文释放 reservation 持久化；开始批次时再次锁定并核对完整集合，私有 lease handle 仅留在运行中会话。读取授权器在每次打开 vault 前再次锁定并核对完整 capability/member/live catalog、活动 lease 与私有 handle digest，只返回内部 catalog 预期；`LocalCalibrationEvidenceReader` 将该预期与本地 vault 的认证 manifest、密文摘要和 AEAD 校验结合，取得短时、精确绑定的 release reservation 后写入独立加密 `calibration.evidence_read` journal receipt，并在返回明文前原子提交 release boundary。完整 `EvaluationReport` 才能驱动原子 lease completion；受限报告 artifact、持久化适配器及内容无关事件提交 API 与 worker evaluator 编排已交付。evaluator 逐引用读取并校验 v3 model-call/label DTO、调用纯阈值内核、写入并 fresh-attest report，再以固定身份精确重试 PostgreSQL 提交；内容独立性仍需声明式分区/血缘审查，不能由 artifact 引用本身证明。适配器逐次重验及完整闭环见 [10.16](docs/10-jev-and-agents.md#1016-已实现校准批量读取能力与端口契约)、[10.17](docs/10-jev-and-agents.md#1017-已实现耐久发行与批次会话)、[16.4](docs/16-rust-code-architecture.md#164-port-契约) 与 [20.3](docs/20-testing-and-acceptance.md#203-误拒与安全收益)。

`xshield_core::calibration::publication` 与专用 report vault 已交付受限报告持久化适配器：独立 `calr_` UUIDv7 报告 ID、canonical JSON report artifact、专用认证 manifest 和 AEAD AAD 均绑定 tenant/site/report/artifact。迁移 0026、0030–0031 与 `PostgresIdentityStore::complete_and_publish_calibration_report` 在同一短 PostgreSQL 事务中重验完整 capability/member/live catalog、已提交 lineage review、活动 lease/token digest、runner、报告 manifest 和数据库时钟；随后写入专用报告元数据、immutable lineage review projection、lease `active → completed`、capability `leased → consumed`，以及内容无关的 `calibration.read_batch.completed` 和受限 `calibration.reported` outbox 事实。精确未知提交重试只识别完全一致的 review、report、lease、artifact 和两个事件绑定；数据库拒绝不会消费 lease。报告 artifact 不进入通用 request catalog，事件不携带样本、标签、概率、指标、提示词或正文，也不授予读取、发布阈值/策略或业务资格。worker evaluator 已调用这组 API 完成受控单批编排；外部内容独立性与真实供应商质量仍需单独验收。边界见 [10.15](docs/10-jev-and-agents.md#1015-已实现校准报告持久化)、[11.9](docs/11-audit-event-contract.md#119-已实现-calibrationreported-发布契约) 和 [20.3](docs/20-testing-and-acceptance.md#203-误拒与安全收益)。

`GET /control/v1/calibration-reports/{report_id}` 已为 `AuditAdministrator` 提供固定 tenant/site 的受限报告元数据调查。接口只读取专用 PostgreSQL projection；缺失或跨 scope 以同构 `found=false` 返回，已删除 report body 保留为 `body_status=deleted` tombstone。每次已认证尝试在释放结果前耐久写入 `console.calibration.report.read`，projection、outbox 或 retention 链接损坏及审计故障均扣留响应。它不读取专用密文正文、不访问通用 evidence catalog，也不返回能力、lease、storage locator、密钥、完整性摘要、样本、标签、概率、指标、提示词或读取 URL。完整契约见 [29.26](docs/29-api-endpoint-catalog.md#2926-已实现的校准报告调查契约)。

`xshield_core::calibration::dataset` 已为离线阈值评估提供无 I/O 的数据集领域契约：每个样本分别引用模型调用记录和标签证据，冻结批准、数据集/标签/任务/映射/阈值、provider、wire model、模型/提示修订及可未知的 resolved revision；训练、校准、评估和标签 manifest 必须是四个不同 artifact，且不能复用为样本来源。它拒绝样本证据别名、跨角色复用、重复引用以及模型或映射修订漂移，并在结果保留按输入顺序的调用 ID、模型记录、标签证据三元关联和统计指标。worker content decoder 进一步严格消费现有 schema-v3 model_call 与 reviewed-label DTO，只接受经 role/slot 授权的 `risk_projection` 并对映射缺失、状态失败和 provenance 漂移 fail-closed；该契约只能比较提交的引用集合，不能证明外部内容互不重叠。详情与测试边界见 [10.14](docs/10-jev-and-agents.md#1014-已实现校准数据集领域契约) 和 [20.3](docs/20-testing-and-acceptance.md#203-误拒与安全收益)。

`xshield_core::calibration::lineage_review` 已形成声明式分区审查的持久化闭环代码：纯领域审查将四份冻结 manifest、分区绑定的 corpus/reviewed-label 来源图与独立 `calrev_` review/artifact ID 精确绑定；专用 vault 将 canonical review artifact 和认证 sidecar 以 tenant/site/review/artifact AAD 加密；迁移 0029 与 `PostgresIdentityStore::commit_calibration_lineage_review` 将经 fresh attestation 的受限 artifact metadata、冻结 provenance、四份 manifest、source-graph digest 和 `calibration.partition_lineage.reviewed` 事实原子提交。全局 artifact identity registry 阻止 request catalog、报告和 review 三个对象族复用 artifact ID。迁移 0033 将 review body 的到期与孤儿回收接入同一受限维护命令：数据库先写 intent，vault 以认证 sidecar 重新校验后才移除精确密文，成功才写 tombstone；projection、sidecar 和冻结 provenance 留作恢复/审计元数据，通用 orphan 扫描器跳过此对象族。尚有 purge intent 或已 tombstone 的 review 不能再绑定新的读取 capability。受限 outbox 只索引 review identity、artifact、provenance 和 manifest metadata，不展开 source graph、source ID/revision 或正文。该事实只说明已审核声明关系，不替代受控读取、内容去重或外部语料独立性验证；并发 registry 冲突、真实 ClickHouse 投递和数据质量验收仍需独立完成。契约与验证边界见 [10.19](docs/10-jev-and-agents.md#1019-已实现声明式分区与血缘审查持久化契约)、[11.9.1](docs/11-audit-event-contract.md#1191-已实现-calibrationpartition_lineagereviewed-发布契约) 和 [20.12](docs/20-testing-and-acceptance.md#2012-outbox-发布回归)。

Jev 离线评估已支持 Score：操作员提交 2–10 档有序描述，适配器验证完整档位、概率分布和加权评分，并将评分、档位及独立供应商置信度写入加密调用证据。模型审计、查询及控制台接受 Score 生命周期；Gateway 官方费用元数据经过有界校验。部署顺序、数值容差与运行方式见 [10.11](docs/10-jev-and-agents.md#1011-已实现-score-离线评估)。

控制台已接入 AuditAdministrator 的证据保留工作台：为案件成员创建有期限和理由的保留锁、分页复核保留历史并显式释放。创建与释放使用冻结幂等请求恢复未知结果，列表按数据库观察时间区分期限与释放事实；保留延缓物理删除，原文读取继续使用独立审批和原期限。使用及部署边界见 [15.10](docs/15-console-and-api.md#1510-已实现证据保留工作台)。

证据访问工作台已提供“我的申请”和“审批待办”：通过 `GET /control/v1/evidence-access-requests` 分页发现本人历史或同作用域其他主体的 pending 申请，打开记录后重新读取详情。每页具有独立数据库观察时间、凭证/主体/视图绑定游标和 `console.evidence.access.list` 审计；申请及决策后显式刷新。启用前先应用迁移 0022 并升级管理 journal 发布器，契约与回滚边界见 [29.24](docs/29-api-endpoint-catalog.md#2924-已实现的证据访问申请列表契约)。

`web/console` 已提供“证据访问”工作台：以案件和明确理由提交原文申请，读取详情后由独立审批人批准或拒绝，获批申请人显式下载 `.bin` 附件。写入保留冻结原键和参数以确认未知结果；下载核对服务端范围、目标及有界完整字节，沿会话生命周期隔离晚到响应。角色、当前状态与内容完整性由服务端重新验证；升级顺序及生产身份边界见 [15.9](docs/15-console-and-api.md#159-已实现证据访问工作台)。

`GET /control/v1/evidence-access-requests/{access_request_id}` 已提供审批前的申请详情：申请人按独立 Investigator/Reader 角色查看本人记录，同站点 Approver 可复核申请与历史决策。返回理由、目标、持久状态与单次数据库时间观察，经独立 `console.evidence.access.read` 审计后释放；审批与下载仍重新校验，契约和发布器升级顺序见 [29.23](docs/29-api-endpoint-catalog.md#2923-已实现的证据访问申请详情契约)。

`web/console` 已接入 Investigator 案件工作台：显式创建本人案件、分页发现并打开本人开放/已关闭案件、浏览证据引用、关联有效证据及关闭案件。列表按案件 ID 降序，每页展示独立数据库观察时间，创建或关闭后显式刷新。变更展示管理请求 ID 和幂等结果；提交后冻结原键与参数，断网、超时或晚到响应保持结果未知，供操作者原样重试。案件接口共用有界许可，已准入操作在断连后继续到数据库及管理审计终态。案件状态、catalog 状态、内容权限与保留期限分别校验，运行及恢复边界见 [15.8](docs/15-console-and-api.md#158-已实现案件工作台)，列表升级与契约见 [29.22](docs/29-api-endpoint-catalog.md#2922-已实现的本人案件列表契约)。

`web/console` 已提供只读请求、模型调用、资格/身份绑定调查与结构化事件检索：Observer 可查看请求摘要、事件分页、模型生命周期/供应商标识、证据元数据及资格/绑定账本快照，并打开来源请求和绑定详情；检索和请求时间线中的模型阶段会投影强类型调用 ID，可跳转至独立重新鉴权的模型详情。Investigator 可提交有界 UTC 时间窗、同事件 AND 条件和稳定排序，按冻结计划继续分页。账本持久状态、时间到期和代际分别展示，数据库观察与日志水位独立，历史入口须显式选择时间窗并重新鉴权。客户端校验查询摘要和精确微秒位置，显示实际扫描量、空值与配置日志水位/缺口；历史查询权限不替代 Observer 或原文权限。凭证只存页面内存，401、闲置及刷新清态，跨范围和晚到响应受到隔离。模型生命周期完整性与日志水位独立显示，历史未知供应商和 Noul 空置信度按实际记录呈现。运行方式、验证范围及企业身份入口待补边界见 [控制台说明](web/console/README.md) 和 [15.7](docs/15-console-and-api.md#157-已实现只读请求调查控制台)。

`xshield-model-eval` 已实现操作员批准的一次性 Jev 离线评估：严格 Choice/Noul 契约、固定 Vercel AI Gateway HTTPS 端点（显式 `direct` 可兼容 TypeSafe 直连）、实际请求/响应加密证据、PostgreSQL catalog/outbox 和 `model.*` 耐久终态。迁移 0034 进一步将 tenant/site 跨实例调用容量绑定到 PostgreSQL scope 和私有短租约：容量拒绝只形成模型终态，不创建证据或 HTTP 调用；发送前以数据库时钟重验，终态 journal 耐久后释放，进程中断只可由 TTL 回收而不重放。429/529、超时、取消、超限和中断恢复均有明确结果；使用方法与运行边界见 [10.9](docs/10-jev-and-agents.md#109-已实现一次性离线评估) 和 [RB-11](docs/26-runbooks.md#rb-11-一次性模型离线评估)。当前验证使用合成 loopback 供应商，不代表真实模型质量、计费或外部服务可用性；校准及调查 Agent 继续迭代。

模型阶段及调用审计支持 `mdl_` 强类型引用、provider/provider_model_id 与内部模型版本索引；阶段汇总保留最新 null 置信度，Gateway alias 不伪造精确 resolved revision。发布与查询边界见 [11.4](docs/11-audit-event-contract.md#114-阶段结果契约) 和 [20.6](docs/20-testing-and-acceptance.md#206-clickhouse-真实集成回归)。

`GET /control/v1/model-calls/{model_call_id}` 已提供固定作用域的模型调用摘要、因果链完整性与输入/输出证据引用，要求 `Observer` 并写独立耐久访问审计。查询预算、索引可见性及配置日志水位语义见 [29.15](docs/29-api-endpoint-catalog.md#2915-已实现的模型调用查询契约)。

`POST /control/v1/search` 已支持按 `grant_id`、`auth_binding_id` 强类型过滤身份与资格发行事件，并定位分享的来源资格和绑定。复用 Investigator 权限、固定作用域、有界时间窗、签名游标与独立访问审计；结果为已发布历史事实，具体字段映射和可见性边界见 [29.14](docs/29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

`GET /control/v1/grants/{grant_id}` 提供 Observer 可读的资格及当前绑定账本快照、数据库时间过期标志和来源请求/事件引用。过期、撤销和代际变化仍可调查；所有返回经过 `console.grant.read` 耐久审计，字段与部署权限见 [29.19](docs/29-api-endpoint-catalog.md#2919-已实现的资格账本调查契约)。

`GET /control/v1/auth-bindings/{binding_id}` 已提供 Observer 可读的身份绑定详情：当前身份与凭证代际、持久状态、期限和更新时间，支持匿名、过期及撤销记录。响应经 `console.binding.read` 耐久审计，生命周期历史可通过绑定 ID 检索；字段和部署边界见 [29.20](docs/29-api-endpoint-catalog.md#2920-已实现的身份绑定调查契约)。

`POST /control/v1/cases/{case_id}/items` 已支持 Investigator 将同作用域有效证据引用加入本人开放案件：每案最多 128 项，关联与 outbox 原子提交，精确幂等重试，并在客户端断连后完成已准入操作的终态审计。先应用迁移 `0017_m3_case_evidence.sql`；关联只建立调查上下文，内容读取与保留期限仍独立校验，详见 [29.16](docs/29-api-endpoint-catalog.md#2916-已实现的案件证据关联契约)。

`GET /control/v1/cases/{case_id}/items` 已提供本人案件的有界证据集合查询：HMAC 游标绑定凭证、主体、作用域、案件和页大小，单 PostgreSQL 快照返回案件摘要、成员引用及 `active`/`expired`/`deleted`/`unavailable` catalog 状态（正常 retention 使用 deleted tombstone）；响应不包含 manifest、locator、hash、key ref 或内容，且所有结果均写 `console.case.read` 审计，详见 [29.17](docs/29-api-endpoint-catalog.md#2917-已实现的案件证据集合查询契约)。

`POST /control/v1/cases/{case_id}/close` 已支持所有者关闭案件：关闭记录、状态与 `case.closed` outbox 原子提交，释放 open 案件容量，后续新增关联、原文申请/批准与读取资格校验要求案件仍为 open。历史证据集合和审批记录保留，证据期限保持原值。部署先应用 `0018_m3_case_lifecycle.sql`；幂等、并发及审计边界见 [29.18](docs/29-api-endpoint-catalog.md#2918-已实现的案件关闭契约)。

`POST /control/v1/search` 支持 `case_id`、`artifact_id` 历史检索，定位已发布的案件操作、审批管理尝试、保留锁及证据引用。固定事件字段、同事件 AND、查询预算和游标绑定沿用现有 QueryPlan；历史可检索与当前案件、保留及内容权限分开校验，详见 [29.14](docs/29-api-endpoint-catalog.md#2914-已实现的受限调查查询契约)。

管理访问 journal 已接通封存段发布器：当前控制端点的访问尝试按严格契约进入 `control_access` 索引阶段，可通过管理 request_id 时间线及有界事件检索复核；独立日志源的部署、水位及 outbox 边界见 [11.7](docs/11-audit-event-contract.md#117-已实现的管理访问审计发布)。

原文访问申请、独立审批与内容读取共用有界操作许可，已准入任务断连后继续完成数据库结果及访问审计；数据库操作含池等待限 15 秒、SQL/锁等待限 5 秒。锁等待后重新验证期限，批准 TTL 从锁后数据库时钟计算；内容明文另由响应生命周期许可约束。严格请求、安全错误、重试与本地 I/O 边界见 [29.11–29.13](docs/29-api-endpoint-catalog.md#2911-已实现的证据访问申请契约)。

案件保留锁已提供 AuditAdministrator 专属的创建、释放与分页历史 API，复用固定作用域、严格输入、幂等、容量和终态审计；活动锁暂停物理删除，内容读取仍遵守原期限与审批。接口与升级顺序见 [29.21](docs/29-api-endpoint-catalog.md#2921-已实现的案件保留锁管理契约)。

PostgreSQL outbox 已接通按事件族隔离的发布闭环：`xshield-outbox-worker TENANT_ID SITE_ID` 默认处理 `case.*`，设置 `XSHIELD_OUTBOX_FAMILY=evidence_catalog`、`evidence_access`、`evidence_retention`、`calibration`、`identity`、`grant`、`response_grant` 或 `share_grant` 可分别处理证据目录、证据访问请求/审批、证据清理、受限校准报告与分区血缘审查 metadata、身份生命周期、通用资源资格、响应资格和分享发行；各族均使用 tenant/site 绑定的 `FOR UPDATE SKIP LOCKED` 租约、服务端时钟、行/字节上限和精确 token 确认，严格解析后按 event_id/content_digest 至少一次写入 ClickHouse。`calibration` 消费 `calibration.reported`、`calibration.partition_lineage.reviewed`、batch completion/capability 事实，以及报告和 lineage-review 的到期/孤儿维护事实；它不读取 evidence、不发布阈值/策略，outbox 也不是这些授权或保留状态的真值。`GrantPersistence` 库入口从冻结的类型化内部命令构建并原子提交 `grant.issued`，不提供独立 HTTP 发行面。站点 HTTP 资格由网关在已验证的源站响应、响应证据、动作和资源资格的同一事务中提交 `response_grant.issued` 完整 v3 envelope，保留原请求、批内序号和冻结发行时间；`ShareIssueApi` 原子提交 `share.issued`，绑定稳定 event/share ID 和精确重试正文；网关 `response.share_issue` 已将获准分享操作的完整响应接入发行与凭证交付。`AUTHENTICATED_ROOT` 的 `auth_revoke` 登出响应现已原子撤销绑定及全部活动/过渡凭证并写入 `binding.revoked`，身份发布器同步严格解析该事件；失败只记录稳定错误码并延迟重试，历史稀疏身份、通用资源资格、响应资格及分享记录保持未确认。证据清理族接收 catalog 与孤儿对象的六类删除意图/成功/失败事实，以及案件保留锁的创建/释放事实，保留 artifact 与因果引用、确定性空置信度和独立维护阶段；其脱敏检索不授予原文访问权。各族合成契约、通用资源资格、实际网关响应资格、分享库 API 及实际清理生产者的数据库覆盖见 [20.12](docs/20-testing-and-acceptance.md#2012-outbox-发布回归)，配置与升级边界见 [11.8](docs/11-audit-event-contract.md#118-已实现的按事件族-outbox-发布)。

缺少 WAF Cookie 的受保护根/API 请求会先原子创建一条有服务端绝对期限的匿名空 binding 与 `session.created` outbox，再以 401 拒绝并签发 `Secure`、`HttpOnly`、`SameSite=Lax` 的 `__Host-xshield_sid`。匿名 binding 的 epoch/generation 均为 0，不含主体、授权上下文、业务凭证或资格；重复携带该 Cookie 不会扩增记录，附加任意 Bearer 也不能升级身份。匿名 TTL、来源/站点创建速率与每租户/站点活动容量由 `identity_store` 有界配置；进程内预算先限制数据库调用，PostgreSQL 短事务再以传输层对端地址的租户/站点隔离 HMAC 实施分布式来源/站点限流。速率超限返回 429，容量超限返回 503，均不签发 Cookie。

`AUTH_ENTRY` 已支持首个 Bearer 认证建立闭环：有界严格 JSON 成功响应提供配置指针指定的主体、授权上下文引用与 Bearer，网关在释放正文前原子写入新 binding、初始 credential generation 和 `binding.created` outbox，并签发 `Secure`、`HttpOnly`、`SameSite=Lax` 的 `__Host-xshield_sid`。源站同名 Cookie、响应形状偏差或事务失败均不建立身份；端到端测试已使用新签发的 WAF Cookie 与业务 Bearer 访问受保护根入口。

`AUTHENTICATED_ROOT` 刷新端点可配置 `auth_refresh`：请求先用旧 WAF Cookie 与旧 Bearer 精确加载身份，成功响应只接受同一主体、同一授权上下文引用的新 Bearer；提交事务再次比较 binding、主体、授权上下文、epoch、generation、完整旧凭证集合及旧凭证期限，随后撤销旧 generation、写入新 generation 与 `identity.refreshed` outbox。CAS 冲突、身份上下文变化、原凭证过期或响应偏差均不释放成功正文；刷新保持 auth epoch，因此刷新前已提交且仍有效的资源资格可继续使用。

身份上下文切换端点可配置 `auth_context_switch`：请求仍以旧上下文的完整认证组合准入，成功响应必须提供主体或授权上下文引用的变化及新 Bearer；网关在释放正文前原子更新上下文、auth epoch 与 credential generation，撤销旧凭证并提交 `epoch.changed` outbox。同主体的租户/角色变化也会隔离旧 epoch，切换期间晚到的旧响应不能发行资格；WAF 会话 Cookie 与绝对期限保持不变。升级迁移会撤销缺少已验证授权上下文的活动绑定，客户端需重新认证。

`AUTHENTICATED_ROOT` 登出端点可配置 `auth_revoke`：仅接受当前 WAF Cookie、Bearer、主体、授权上下文和 auth epoch 的完整快照；源站返回配置成功状态且完整响应通过缓冲校验后，网关在响应释放前锁定快照，原子撤销绑定及全部 `active`/`transition` 凭证并提交 `binding.revoked` outbox。过期、已撤销或并发代际变化统一冲突关闭，正文不会在事务失败时释放；后续请求以 `AUTH_BINDING_MISMATCH` 拒绝，原始凭证不进入日志或事件载荷。

`xshield-control` 已提供独立管理接口：固定从服务端配置注入 tenant/site 作用域，以常量时间摘要比对管理 Bearer 凭证，执行每分钟有界限流，并在返回前写独立加密管理审计。`GET /control/v1/audit/health` 仅允许 `AuditAdministrator`；请求摘要、事件时间线和证据 manifest 查询允许 `Observer`。`POST /control/v1/search` 仅允许 `Investigator`，使用有界 QueryPlan 和参数化 ClickHouse 查询，HMAC 游标绑定完整计划、主体及作用域，不接受任意 SQL。manifest 列表和单 artifact 查询只访问 PostgreSQL 中 active、未删除且按数据库时钟未过期的元数据；列表使用 HMAC 游标绑定主体、作用域、目标请求和页大小，单项查询把缺失、过期、删除和作用域偏差统一为 `found=false`，两者均不读取或解密证据内容。`POST /control/v1/cases` 仅允许 `Investigator` 在固定作用域创建有界调查案；`POST /control/v1/artifacts/{artifact_id}/access` 只为同一主体拥有的 open 案件和 active 未过期证据建立有界 pending 原文访问申请。独立 `SensitiveEvidenceApprover` 可批准或拒绝申请，数据库拒绝申请人自批；批准会产生绑定申请人、案件、artifact 且不超过对象期限的短时服务端读取资格。`GET /control/v1/artifacts/{artifact_id}/content` 要求同一申请主体的 `SensitiveEvidenceReader`，以 `X-Xshield-Evidence-Access-Request` 指定已批准申请，重新校验案件、目录、数据库时钟、vault manifest、密文摘要和 AEAD 后才返回附件，并把实际字节数写入 `evidence.read` 管理审计。所有管理变更均使用主体与参数绑定的用途隔离 HMAC 摘要实现精确幂等，并把状态转换与对应 outbox 原子提交。

`xshield-evidence` 已提供本地加密证据库 MVP：只打开预建的私有目录，对每个 artifact 以 tenant/site/request/artifact/kind/chunk AAD 和独立 HMAC 派生数据密钥执行 AES-256-GCM，密文对象、typed manifest 与 manifest HMAC 均不覆盖耐久写入。manifest 读取使用库内当前时钟重验作用域、期限与 key-id，内容读取额外重验密文摘要与 AEAD；未知、过期和跨作用域对象返回相同不可用状态。`xshield-control` 的 EvidenceReadPort 已把 PostgreSQL 批准资格与 vault 侧复验接成内容读取闭环。整对象模式硬限制 64 MiB，业务配置只能继续收紧；网关已接入显式批准的 BUFFERED_JSON 响应采集：秘密排除清单与正文副本加密落盘、catalog/outbox 与 journal 耐久提交后才释放业务正文，并受单采集许可、磁盘/文件配额和数据库期限约束。`xshield-evidence-retain` 提供按 tenant/site/key 有界、排他锁保护的到期密文与宽限孤儿维护，先写删除意图，再完成 tombstone，故障可重试；配置与覆盖范围见 [12.7](docs/12-evidence-capture-and-vault.md#127-已实现有界-json-响应采集屏障) 和 [12.8](docs/12-evidence-capture-and-vault.md#128-已实现到期密文孤儿维护与故障重试)。请求、HTML、最终客户端实体采集、远端对象 adapter 与分块仍继续迭代。

PostgreSQL catalog 只接受证据库产生或认证的 manifest 类型，按 artifact 身份执行精确幂等发布，并与 `evidence.cataloged` outbox 事件同事务提交；同 ID 元数据冲突返回稳定冲突终态，审计写入失败不留下 catalog 行。request 查询固定绑定 tenant/site/request，使用数据库当前时钟排除过期或删除对象，最多返回 128 条 typed manifest；catalog 元数据不能替代对象侧 HMAC、摘要和 AEAD 复验。

M2 已落地 `DIRECT_DECRYPT` / `DIRECT_ENCRYPT` 双向 AES-256-GCM 垂直闭环。请求侧 AAD 绑定租户、站点、operation、HTTP 语义、适配版本、独立 key-id、规范 message-id 与时效；认证成功后由 PostgreSQL 原子消费 key 作用域的 message-id 和 nonce，重复、过期或超前消息不会到达源站。响应侧先完成严格 JSON 校验、身份/资格提交与确定性正文重建，再用独立用途密钥、随机 nonce 和短时 message-id 封装冻结客户端实体；AAD 额外绑定请求 ID 和源站状态，旧 Content-Length、编码、摘要及缓存验证头不会沿用。双向共享内存配额覆盖接收、解析、明文、密文和预分配封包峰值，容量不足时在分配前关闭。服务端可为非 UI 动作操作选择 `OBSERVE`，也可为 `UI_ACTION_REQUIRED` 操作配置 `COMPATIBILITY`；后者必须同时通过既有动作资格、页面证据中的精确构建指纹、服务端批准引用和绝对到期检查。两种 opaque 路径均禁止响应加密及身份/资格签发，Xshield 封包不会进入 compatibility。网关已在保留命名空间提供版本化同源探针与 loader、动态 no-store bootstrap，以及绑定当前 WAF 会话和身份代际的严格 HTTPS prepare 批量接收；观测以 `client_claimed` 写入耐久审计且不产生授权效果。`SENSOR_HTML` 响应适配器可在同一 operation 有界并存至多 16 个批准构建，按完整源站 SHA-256 选择各自固定 `</head>` 偏移；注入标签以 SHA-384 SRI 绑定网关实际提供的版本化资源，强制 CSP 使用逐响应 128 位随机 nonce 同步改写所有脚本指令和注入标签，构建、类型或策略偏差在正文释放前关闭，并记录选中修订、nonce 应用状态和注入前后摘要。ClickHouse 元数据索引按配置固化绝对保留期限，active 视图按 `event_id` 合并重投并先于后台 TTL 隐藏过期行。动态 HTML、原文对象保留与案件 pin 继续迭代。

M0 已提供 Cargo workspace、强类型 ID、稳定原因码、独立管理身份、审计端口及禁用站点的 `NOT_CONFIGURED` 阶段树。M1 已实现 WAF 会话与业务凭证的精确组合绑定、六类 operation 入口准入、页面证据与精确动作来源、有界资源资格账本，以及对应 PostgreSQL 约束和原子事务。Pingora MVP 网关可按可信 JSON 配置转发精确 `PUBLIC` / `AUTH_ENTRY` 操作；配置身份存储后，`AUTHENTICATED_ROOT` 会用租户隔离 HMAC 核对 `__Host-xshield_sid`、Bearer 凭证、当前 generation、epoch 和服务端期限。`UI_ACTION_REQUIRED` 会按不透明动作引用重验当前策略、页面证据和动作描述；GET 查询资源操作还会从实际 URI 严格提取资源与字段，以租户、站点和资源类型带域 HMAC 精确匹配资格账本。`SERVICE_IDENTITY` 使用独立边缘凭证头，按租户和站点带域 HMAC 精确加载 PostgreSQL 中的活动服务身份，并再次校验有限 operation 集和期限。`SHARE_ENTRY` 使用独立分享头，按租户、站点、资源、operation 和 view 精确加载 PostgreSQL 中活动且未过期的只读分享资格。分享发行 API 使用已验证的响应事实派生凭证与指纹，随后重新锁定当前身份与精确 ResourceGrant，要求活动策略中的独立发行规则批准目标 operation/view，并将 ShareGrant 与 outbox 原子提交后才把明文凭证交给响应适配器；来源失效、规则偏差、TTL 越界、幂等冲突或容量耗尽均不发行。分享令牌使用独立密钥按租户、站点和幂等键派生可重试的不透明长凭证，持久化与入口验证只接触另一用途密钥生成的 HMAC 指纹。按 operation 配置的 `BUFFERED_JSON` 响应适配器会在释放正文前完成 Content-Type、Content-Encoding、Content-Length、单请求与共享内存上限和完整 JSON 校验；非法、超限或共享配额耗尽均不释放正文，并以稳定原因写入 `origin.response` 与 `request.aborted`。响应资源规则会把已认证来源、业务成功状态、严格 JSON Pointer、动作引用字段、唯一目标资源 operation、单响应数量、TTL 和会话容量在启动时一起编译；完整正文解析会拒绝重复 JSON 键、形状偏差、无效或重复资源值。已验证响应会保留原请求的 AuthSnapshot，在一个短事务内重验当前 binding、auth epoch、活动策略、精确动作描述和整批容量，再原子写入 ResponseEvidence、逐资源 ActionGrant、ResourceGrant 与 outbox；事务提交后把不透明 `action_ref` 注入对应列表项并以 `private, no-store` 释放改写正文，源站预占字段或失败不留下部分资格。端到端测试已使用响应中的引用访问新资源，验证同会话资格可复用。显式 `resource_path_parameter` 可启用单个最终路径段适配器；它严格解码一次并拒绝额外查询、嵌套路径、编码斜杠、歧义路由和未精确命中的资格。缺失、替换、退休、过期、资源偏差、字段扩张或歧义查询均在源站前拒绝。WAF Cookie、动作引用、服务凭证头与分享头在访问源站前剥离。网关已接入加密分段 journal：准入、阶段、判定和转发意图必须批量持久化成功后才能访问源站，配额、写入或恢复失败均关闭转发。journal 按 `segment_max_bytes` 自动关闭并轮转；网关重启时在开放流量前认证扫描历史关闭段，为缺少终态或只留下合法批次前缀的请求耐久追加 `origin.unknown` / `request.aborted`，保留已收到的源站响应且不发起业务重试。独立封存命令可在 edge 持续写入时重验关闭段的 AEAD、CRC 与哈希链，生成包含整段摘要和链头的 Ed25519 签名清单，并以不覆盖方式持久化到独立私有位置。`xshield-worker` 按段顺序重新认证并解析事件，投递前后检查稳定 `event_id` 的正文摘要，ClickHouse 确认同步插入后才原子推进目标绑定的本地水位；同 ID 不同正文、缺失清单或水位冲突均停止后续段。worker 还可从重新认证的段与精确 checkpoint 生成连续索引水位、pending、unsealed、gap 和本地占用健康快照。

```bash
cargo test --workspace --all-targets
cargo run -p xshield-core --example m0_stage_tree
cargo test -p xshield-audit
cargo test -p xshield-evidence
scripts/test_postgres.sh
scripts/test_gateway_identity.sh
scripts/test_gateway_request_crypto.sh
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

身份存储由可选的 `identity_store` 配置启用；受保护入口或请求防重放存在时必须配置。运行时从 `XSHIELD_DATABASE_URL` 和 `XSHIELD_FINGERPRINT_KEY_HEX` 读取数据库连接与 32 字节 HMAC 密钥。配置 `response.share_issue` 时还须注入不同的 `XSHIELD_SHARE_TOKEN_KEY_HEX`；示例中的分享发行 GET 具有创建资格的副作用，须预先批准对应来源动作、资源资格及数据库发行规则，配置边界见 [6.5](docs/06-capability-ledger.md#65-分享)。请求与响应加密分别从 `XSHIELD_REQUEST_DECRYPTION_KEY_HEX`、`XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX` 注入不同的 32 字节用途密钥；两侧 key-id 和实际密钥不得复用，当前进程每个方向只接受一个精确 key-id，轮换通过并行版本实例完成。UI 动作、服务调用和限权分享使用独立边缘证明，转发前全部剥离；网关只信任 PostgreSQL 中与当前作用域、期限和活动状态精确匹配的记录。封存目标目录须预先以私有权限创建；独立任务周期运行 `xshield-audit-seal`，其 Ed25519 私钥仅注入封存进程。控制服务的 ClickHouse 账号只授予 active 视图读取权限；PostgreSQL 账号只授予 catalog 查询、案件、证据访问申请/决策、outbox 及 advisory-lock 所需权限。请求摘要、脱敏事件和证据 manifest 查询均使用服务端作用域并写独立管理审计。事件与 manifest 游标由同一独立分页密钥按不同用途域签名，不能跨接口、主体、作用域、目标请求或配置复用；管理变更幂等摘要使用另一独立密钥并继续按动作分域。生产秘密均应由秘密管理器按用途注入和轮换，不写入配置文件或日志。

## Rust 运行时依赖

| 依赖 | 用途 | 许可证与更新策略 |
|---|---|---|
| Pingora 0.9.0 + OpenSSL backend | HTTP 代理生命周期、固定源站连接、请求过滤、journal AES-256-GCM、段清单 Ed25519 签名及模型缓存安全域的 HMAC-SHA-256 派生 | Apache-2.0；精确版本并锁文件，部署同步审查 OpenSSL 版本与许可证，升级先复跑协议歧义、加密恢复、签名验证、缓存键隔离、转发和故障测试 |
| SQLx 0.9.0 | PostgreSQL 异步事务和连接池 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 migration、回滚和并发测试 |
| clickhouse 0.15.2 | 已封存审计段的类型化查询、同步批量投递与传输加密 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 RowBinary schema、重复投递、并发冲突和故障水位测试 |
| hyper 1.x / hyper-util 0.1.x / http-body-util 0.1.x / hyper-rustls 0.27.x | 复用已锁定依赖提供单次 Jev HTTPS、原生信任根和有界响应读取 | hyper 系列为 MIT，hyper-rustls 为 Apache-2.0 OR ISC OR MIT；锁文件固定，升级复跑 TLS 配置、精确报文、取消、超时、限流与秘密排除回归 |
| Tokio 1.51 LTS | SQLx 异步运行时 | MIT；跟随 1.51 LTS 补丁，变更 minor 前执行故障与负载回归 |
| serde / serde_json 1.x | 类型化配置 DTO 与 outbox JSON | MIT OR Apache-2.0；锁文件固定，补丁升级执行配置和契约测试 |
| UUID 1.x | 生成服务器侧 UUIDv7 请求 ID | MIT OR Apache-2.0；锁文件固定，补丁升级执行 ID 契约测试 |
| async-trait / bytes / http 1.x | 实现 Pingora 异步过滤器、有界拒绝响应体及 trailer 边界类型 | MIT OR Apache-2.0；锁文件固定，随 Pingora 兼容线评估更新 |
| Axum 0.8.x / Tower 0.5.x | 独立管理 HTTP 路由与可测试 Service 边界 | MIT；锁文件固定，升级先执行管理认证、作用域、限流、错误契约及审计回归 |
| crc32fast / zeroize 1.x | journal 快速损坏检测与秘密缓冲清零 | MIT OR Apache-2.0；锁文件固定，升级执行篡改、恢复和秘密生命周期测试 |
| chrono 0.4.x | 生成审计契约要求的 UTC RFC 3339 时间戳 | MIT OR Apache-2.0；锁文件固定，补丁升级执行审计契约与时钟异常测试 |
| Python cryptography 49.0.0（仅测试） | 生成 Gateway→Origin 加密请求测试向量，不进入产品运行时 | Apache-2.0 OR BSD-3-Clause；精确版本，升级先执行认证失败、不回退与源站不可见反例 |
| ClickHouse Server 25.8.29.51 LTS（集成测试服务） | 执行实际部署 DDL、RowBinary 与查询回归 | Apache-2.0；CI 固定版本，升级先复跑建库/重入、发布、权限、分页和保留回归，运行方式见 [20.6](docs/20-testing-and-acceptance.md#206-clickhouse-真实集成回归) |

当前 workspace MSRV 为 Rust 1.94，与 SQLx 0.9.0 一致。生产依赖升级需审查许可证、安全公告和 Cargo.lock 差异。

## 开始阅读

打开 [Word 总册（48 页）](Xshield_Design_Book_v3.0.docx) 进行评审，或双击 [START_HERE.html](START_HERE.html) 离线阅读全部正文；或从 [产品需求](docs/00-product-requirements.md) 和 [最终对话决策](docs/28-conversation-decisions-and-traceability.md) 开始。

- 架构/产品评审：00 → 01 → 02 → 04 → 05 → 06 → 09 → 28。
- 日志后台实施：11 → 12 → 13 → 14 → 15 → 18 → 26 → 29。
- 开发 Agent：先读 [AGENTS.md](AGENTS.md)，再读 16、17、22 与相关模块。
- 站点适配：07 → 08 → 10 → 27；发布前执行 20 中安全/兼容验收。

## 已确定的最终规则

没有当前有效认证绑定下的认可界面操作来源就拒绝，即使源站实际有权限。已取得的具体资格在有效期内可复用；新浏览器、未查询的新资源须重新经过认可入口。看到 ID 不代表可执行任何操作。WAF Cookie 与真实业务凭证、身份代际、资格账本强绑定。日志/模型/普通成功响应不自行创造资格。

双向加密接管检查并重建同一实际业务参数；兼容回退由服务器批准且标注覆盖缺口。心跳/堆栈提供线索，不是权限证明。Jev/Agent只在受控任务边界工作，代码执行确定性约束。

审计包含每请求、每阶段、实际模型及Agent输入输出、解密与转换证据；普通检索索引和加密证据库分离。秘密脱敏、捕获上限、不可用和裁剪必须显示，不能把脱敏包声称为字节级原件。确定性规则与Noul不伪造置信度。

## 正文目录

| 编号 | 文档 |
|---|---|
| 00 | [产品定位与需求基线](docs/00-product-requirements.md) |
| 01 | [威胁模型与安全不变量](docs/01-threat-model-and-invariants.md) |
| 02 | [总体架构与技术选型](docs/02-system-architecture.md) |
| 03 | [请求、响应及提交时序](docs/03-request-response-pipeline.md) |
| 04 | [身份与会话绑定](docs/04-auth-session-binding.md) |
| 05 | [界面操作来源验证：Xshield 核心准入机制](docs/05-ui-action-provenance.md) |
| 06 | [资格账本、根入口及分享](docs/06-capability-ledger.md) |
| 07 | [自动注入探针、心跳与请求关联](docs/07-browser-sensor.md) |
| 08 | [双向应用层加密接管](docs/08-crypto-takeover.md) |
| 09 | [策略引擎与判定合成](docs/09-policy-engine.md) |
| 10 | [Jev、OpenJev 与分析 Agent](docs/10-jev-and-agents.md) |
| 11 | [全链路审计事件与 ID 契约](docs/11-audit-event-contract.md) |
| 12 | [内容证据采集、秘密隔离与加密证据库](docs/12-evidence-capture-and-vault.md) |
| 13 | [审计存储、耐久性、完整性与容灾](docs/13-audit-storage-reliability.md) |
| 14 | [按 ID 检索、证据分析与安全回放](docs/14-investigation-query-replay.md) |
| 15 | [管理后台与调查 API](docs/15-console-and-api.md) |
| 16 | [Rust 代码架构与模块边界](docs/16-rust-code-architecture.md) |
| 17 | [开发规范：必须进入代码评审与 CI](docs/17-development-standards.md) |
| 18 | [数据模型、契约版本及存储责任](docs/18-api-and-data-models.md) |
| 19 | [部署、隔离、升级与运行策略](docs/19-deployment-operations.md) |
| 20 | [测试策略与验收矩阵](docs/20-testing-and-acceptance.md) |
| 21 | [性能、容量与成本模型](docs/21-performance-capacity.md) |
| 22 | [分阶段实施与交付物](docs/22-delivery-roadmap.md) |
| 23 | [剩余风险与待验证决策](docs/23-risks-and-open-decisions.md) |
| 24 | [架构决策记录（ADR）](docs/24-adrs.md) |
| 25 | [来源与核验登记](docs/25-source-register.md) |
| 26 | [运维与调查 Runbook](docs/26-runbooks.md) |
| 27 | [站点规则编写指南与评审清单](docs/27-rule-authoring-cookbook.md) |
| 28 | [对话决策汇总与需求追踪](docs/28-conversation-decisions-and-traceability.md) |
| 29 | [控制 API 与审计责任清单](docs/29-api-endpoint-catalog.md) |

## 配套材料

| 路径 | 内容 |
|---|---|
| schemas/ | 4份自定义 JSON Schema：审计事件、证据manifest、模型调用、站点策略 |
| examples/ | 禁用状态的站点配置，合成审计事件与证据，78项待实施验收用例 |
| sql/ | PostgreSQL migration 与 ClickHouse 部署 schema；真实数据库回归见 [20.6](docs/20-testing-and-acceptance.md#206-clickhouse-真实集成回归) |
| templates/ | PR、ADR、crate说明和只读调查Agent约束 |
| scripts/ | 可重复运行的文档/Schema/合成证据验证脚本 |
| reference/ | 原始资料来源、旧输入文件哈希和决策基线 |
| validation/ | 本次实际执行的验证结果；不等于产品测试报告 |

## 验证方法

```bash
python -m pip install -r scripts/requirements.txt
python scripts/validate_library.py
```

验证结果见 [report.md](validation/report.md)。验收用例的 `planned` 是未执行状态，不得在项目报告里作为已通过的安全测试。

## 版本与维护

新增需求先更新 RQ/INV/ADR，再同步 Schema、配置与用例。参考资料中的供应商能力是核验时状态；模型与依赖版本必须在实现时锁定并重新验证，不能将文档中的性能目标当成已实测指标。变更说明见 [CHANGELOG.md](CHANGELOG.md)。
