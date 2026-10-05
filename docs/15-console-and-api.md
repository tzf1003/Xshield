# 15 管理后台与调查 API

## 15.1 信息架构

站点运营后台支持同一租户下的多个受保护站点。站点列表使用租户范围的 `SystemAdmin` 管理身份，单站点配置使用站点路径再次校验作用域；每个站点拥有独立的内部 edge 监听端口，并通过签名游标分页。现有 `/control/v1/site-config` 保留为单站点兼容入口，新增多站点路径见 29 章。保存会产生 desired revision 和 apply intent；控制面在配置校验后通过 loopback HMAC apply 通道发送完整租户快照，只有 edge 原子确认后才显示 `active`（确认带 edge 的 HMAC 签名并绑定到该次请求，控制面验签失败按 `failed`、原因 `EDGE_APPLY_ACK_SIGNATURE_INVALID` 处理），否则显示 `pending` 或 `failed` 并保留上一份有效快照。edge 健康探测带时间戳和 nonce，edge 在控制面升级完成前可能短暂显示 `unavailable`，详见 19 章。健康页面会探测批准的上游 health path，同时显示 edge 与 upstream 状态。

部署时可用 `XSHIELD_EDGE_LISTEN_PORTS` 提供逗号分隔的 bootstrap 监听集合；edge 监听器监督器会在 apply 前绑定快照所需的全部端口，成功后再原子替换路由。新站点端口默认绑定同一私网/loopback 地址，可在不中断已有请求的情况下动态加入；配置中的监听地址必须与 bootstrap 地址一致。设置持久卷上的 `XSHIELD_EDGE_SNAPSHOT_PATH` 后，已确认的完整快照会以 HMAC 签名文件恢复，启动时验签失败会保持拒绝启动。

Overview：防护状态、未覆盖端点、拒绝趋势、配置应用失败、审计水位、模型成本。站点详情按 Overview、Network、Security Entry、Routes & Operations、Identity、Crypto、WAF & Limits、Policies、Release（发布）、Audit 分区，页首固定显示站点状态、desired/active 修订和“草稿 → 已校验 → 待审批 → 应用中 → 已生效”生命周期；新建站点是五步向导（基本信息、上游与监听、入口与模式、首批路由、校验与保存）；secret 只展示 reference、key ID 和状态。

Sites：域名与上游、认证 profile、根入口、UI 映射、资格来源、加密版本、模式与覆盖。

Requests：全请求检索、保存过滤器、详情时间线与关联证据。

Identity & Grants：认证绑定、代际、资格来源图、过期/撤销与异常串用。

Models & Agents：调用列表、概率分布、输入/输出、工具链、成本、失败重试与评估。

Evidence & Cases：敏感证据审批、调查案、保留、验证与导出。

Rules & Releases：差异、测试、审批、签名、灰度、回滚。

Operations：节点、队列、存储、密钥引用、告警与审计访问。

控制台是 React 19 + antd 6 的单页应用，路由使用 TanStack Router 的代码式路由树，管理路径与此前保持一致。左侧导航按服务端会话角色隐藏无权模块，分为工作台、站点、流量与调查、案件与审批、运维与治理五组；非 SystemAdmin 的 Observer 与 PolicyAuthor、PolicyApprover、ReleaseOperator 额外得到当前会话站点的“站点状态”“站点发布”入口；视口宽度不超过 760 px 时导航收为抽屉。站点详情、调查、案件、证据、审计和权限中心使用独立 URL，查询表单只存在于对应业务页面。顶栏显示面包屑、服务端确认的 tenant/site 范围、MFA 再认证剩余时间（仅为提示，高危请求仍由服务端校验）、存在未决写入时的“待确认操作”提示，以及主题（跟随系统/浅色/深色）、密度和用户菜单。Ctrl/⌘+K 命令面板搜索当前角色可见的页面，也可粘贴规范（小写 UUIDv7）的对象 ID：`req_`、`mdl_`、`agt_`、`grant_`、`auth_`、`calr_` 直接打开既有详情路由，`case_` 打开案件详情，`access_`、`export_` 打开审批中心并选中该项，`job_` 打开案件分析任务的状态对话框，`artifact_` 进入案件工作台；`access_`、`job_`、`ev_` 与 32 位十六进制 trace ID 还可把单个条件预填到结构化检索（只预填，不自动提交；`ev_` 同时有事件和保留锁两种解释，保留锁解释只对 AuditAdministrator 显示）。隐藏导航与命令面板都不替代服务端授权；每个响应仍须重新验证 tenant/site scope、身份代际、操作资格和审计终态。

会话与数据层位于 `src/security`：ControlClient、服务端确认的 tenant/site、角色和会话代际（epoch）只存在于内存。401、15 分钟闲置、离开或卸载页面（`pagehide`）、退出或响应 scope 不一致时，会话、TanStack Query 缓存和待确认操作登记一并清空，晚到的旧响应不能回填状态。新数据层的读取把 epoch 放入 query key，透传 AbortSignal，逐响应核对 tenant/site scope，且不自动轮询、不重试，也不在窗口聚焦或网络恢复时刷新；写入在发送前冻结方法、路径、幂等键和正文，结果未知时只允许以原键原正文精确重试，并触发离页提醒和“待确认操作”提示。浏览器存储只保存主题与密度偏好。控制台重做已完成第 0 阶段（基础设施）和第 1 阶段（站点接入与发布）：工作台概览、会话信息刷新和全部站点页面（列表、详情、新建向导、发布、路由抽屉）走这套读取层和写入登记，站点的未决写入会出现在“待确认操作”提示中；案件工作台与审批中心（第 3 阶段，见 15.8–15.11）也走这套读取层和写入登记；调查和 API Key 页面仍由旧页面宿主渲染，沿用各自的请求取消、写入冻结和离页提醒，尚未接入新的待确认登记，因此不会出现在该提示中。站点草稿只存在于页面内存：同一站点内切换分类和前进/后退保留，离开站点前须确认，刷新清空，不使用任何浏览器存储。

`./dev.sh` 启动时以 `xshield.dev_schema_migrations` ledger 和 PostgreSQL advisory lock 增量补齐 M5 站点迁移 0041–0049、导出列表索引 0050 与站点审批绑定 0051，现有开发数据卷无需重置。

站点策略的 `static_asset_max_path_depth` 默认关闭（`0` 或缺省），站点显式设为 1–16 才启用静态资源兜底。兜底会在没有身份和精确 operation 的情况下放行请求，因此匹配很窄：只放行 `GET`；路径深度不超过该值；路径先做一次严格百分号解码，以解码后的文本判定（源站实际路由的就是这个文本）；最后一段必须有真实的点、非空主名，且扩展名属于 `js`、`css`、`ico`、`png`、`jpg`、`jpeg`、`gif`、`svg`、`webp`、`woff`、`woff2`、`ttf`（大小写不敏感），所以 `/api/json`、`/css` 这类无点名称不会被当成文件。`.json` 与 `.map` 不在列表中：API 响应和 source map 常以这些后缀命名，放行等于让任何人把 API 伪装成资源，需要时请配置显式路由。`;`（路径参数，如 `/admin/users;.js`）、反斜杠、`%2F`、`.`/`..`/空路径段、控制字符、`?`、`#`、解码后仍含 `%`（双重编码）、空格和非 ASCII 字节一律拒绝，其余字符限于字母、数字和 `. _ ~ @ + -`；畸形转义不会被猜测。超过深度、不符合上述规则和 API 路径仍按精确 operation 拒绝。兜底只在没有精确 operation 命中时生效，不改变 WAF、限流或审计链路。已存在站点策略中保存的 `5` 是此前默认值的序列化结果，升级后继续生效，直到重新保存策略；开发靶场脚本 `scripts/register_juice_shop.py` 显式设置 `5`，安全靶场和示例配置不依赖该兜底。

对象级实验站点还可显式设置 `origin_object_access_enforced=true`。Gateway 会删除客户端同名请求头，并仅在签名快照要求时向源站加入受信标记；源站据此执行对象所有者校验。该字段默认关闭，不能由请求方自行开启或关闭。

## 15.2 请求详情布局

顶部摘要：request_id、站点、方法/路由、decision、主要原因、发生时间、身份引用、是否转发、业务结果是否已确认。

左侧阶段树：每层 outcome、耗时、证明类型、概率/置信度（适用时）、未执行原因。点击节点定位右侧证据。

内容页签：输入与输出；界面来源；资源操作资格；加密转换；Jev 判别；Agent 关联；审计完整性。

原文默认脱敏折叠；解密查看单独授权。字节版本与 JSON 视图可对照，展示截断长度、字符编码、格式化是否改变字节。风险颜色不代替文字标签，界面“ALLOW”旁明确实际检查范围。

## 15.3 后台身份与权限

Observer：只读脱敏摘要；Investigator：创建案件、查询授权证据；SensitiveEvidenceApprover：为其他主体批准或拒绝原文访问；SensitiveEvidenceReader：在获批短时范围内读原文；PolicyAuthor：提交候选；PolicyApprover：审批策略；ReleaseOperator：发布已签名工件；AuditAdministrator：保留与完整性运维；SystemAdmin：基础配置但不自动获得全部原文读取权。

高危原文导出、全站降级、权限扩大、关键签名操作要求再认证及独立审批；站点删除要求再认证（见 15 章末“站点发布审批与应用语义”，不经过独立审批流程）。拒绝作者自批高危变更。控制台 MFA、CSRF、会话超时、每站访问范围、管理员操作审计为首版要求。

## 15.4 API 最小集（自定义契约）

| 方法与路径 | 用途 |
|---|---|
| POST /control/v1/search | 结构化 QueryPlan，返回游标和水位 |
| POST /control/v1/causality | 固定窗口内有界多跳因果摘要 |
| GET /control/v1/requests/{request_id} | 聚合摘要、阶段、覆盖和关联 |
| GET /control/v1/requests/{request_id}/events | 不可变事件分页 |
| GET /control/v1/requests/{request_id}/evidence | 作用域内证据 manifest 分页，不读取内容 |
| GET /control/v1/model-calls | 在固定窗口内分页发现模型调用的最新脱敏状态 |
| GET /control/v1/model-calls/{model_call_id} | 逻辑调用与实际尝试、输入输出引用 |
| GET /control/v1/grants/{grant_id} | 资格与当前绑定的脱敏账本快照、来源请求引用 |
| GET /control/v1/auth-bindings/{binding_id} | 身份绑定的代际、状态与期限快照 |
| GET /control/v1/agent-runs/{agent_run_id} | Agent 脱敏生命周期与工具事件摘要（正文/权限快照隔离） |
| GET /control/v1/artifacts/{artifact_id} | 作用域内单个证据状态、长度、保密和完整性，不读取内容 |
| POST /control/v1/artifacts/{id}/access | 申请受限原文访问 |
| GET /control/v1/evidence-access-requests | 分页发现本人申请历史或独立审批待办 |
| GET /control/v1/evidence-access-requests/{access_request_id} | 按主体范围复核申请、目标及历史决策 |
| POST /control/v1/evidence-access-requests/{id}/approve | 独立批准并建立短时读取资格 |
| POST /control/v1/evidence-access-requests/{id}/deny | 独立拒绝并终结申请 |
| POST /control/v1/cases | 建立调查案与证据集合 |
| GET /control/v1/cases | 分页发现本人开放和已关闭案件 |
| POST /control/v1/cases/{case_id}/items | 将同作用域有效证据引用加入本人开放案件 |
| GET /control/v1/cases/{case_id}/items | 查询本人案件的有界证据引用集合及 catalog 状态 |
| POST /control/v1/cases/{case_id}/close | 关闭本人案件并保留调查历史 |
| POST /control/v1/cases/{case_id}/analyze | 生成只读案件清单分析任务（MVP） |
| GET /control/v1/jobs/{job_id} | 查看本人任务状态与确定性分析结果 |
| POST /control/v1/cases/{case_id}/holds | 管理员为案件成员证据创建保留锁 |
| GET /control/v1/cases/{case_id}/holds | 管理员分页查看案件保留历史 |
| POST /control/v1/evidence-holds/{hold_id}/release | 管理员显式释放保留锁 |
| POST /control/v1/replays | 异步安全回放任务（设计，尚未实现） |
| POST /control/v1/exports | 加密调查包导出任务 |
| POST /control/v1/candidates/{id}/validate | 类型、依赖、扩权和覆盖检查（设计，尚未实现） |
| POST /control/v1/candidates/{id}/publish | 发布已审批工件，不直接接受自由脚本（设计，尚未实现） |
| GET /control/v1/audit/health | 已认证的连续索引水位、缺口与本地存储状态 |

浏览器探针仅能访问 `/__xshield/v1/bootstrap` 和 `/__xshield/v1/events/prepare`，不能访问管理 API。API path 中的 ID 均需按 tenant/site 和资源权限再验，不使用“知道 ID 就可读取”。

当前案件创建接口要求 `Investigator`、管理机器凭证和 16–128 字节规范 `Idempotency-Key`；tenant/site 与 owner 均由服务端身份确定，请求只接受严格 JSON `purpose`。每个 owner/tenant/site 的 open 案件数受启动配置限制，案件与 `case.created` outbox 同事务提交；精确重试返回原案件，不同参数复用键返回 409。

案件关闭要求相同角色与本人归属，严格接受 `reason` 与独立用途的幂等键。关闭状态、理由及 `case.closed` outbox 同事务提交，并释放 open 案件容量；精确重试返回原关闭时间。关闭后的历史集合仍可查询，后续新增关联、访问申请/批准及读取资格校验继续要求 open 状态；既已通过校验的在途读取可能完成。具体失败、审计和迁移边界见 [29.18](29-api-endpoint-catalog.md#2918-已实现的案件关闭契约)。

案件清单分析 MVP 要求 Investigator、固定 tenant/site、空请求体和规范幂等键；事务内只统计本人案件的成员引用及当前 active catalog 数，不读取 vault、不调用模型、不授予证据资格。首次和精确重试返回 202 与耐久 `job_id`，任务记录为 `case_analysis/succeeded` 并保留检查点；不同案件复用同一键返回 409，跨主体目标统一 404。`GET /control/v1/jobs/{job_id}` 只读取本人任务，规范但不可见的任务返回 `found=false`，成功和失败均写独立 `console.job.read` 审计。完整边界见 [29.31](29-api-endpoint-catalog.md#2931-已实现的案件清单分析与任务状态契约-mvp)。

案件证据关联要求同一角色、固定作用域与幂等键，只接受本人 open 案件及同作用域 active 未过期 artifact。每案最多 128 项，关联与 `case.evidence.added` outbox 原子提交；关联不授予内容读取权限，也不延长 artifact 保留期限。精确重试返回原关联时间，详情见 [29.16](29-api-endpoint-catalog.md#2916-已实现的案件证据关联契约)。

案件集合查询同样要求 `Investigator`、服务端固定作用域和本人 owner；open/closed 案件均可读取。仅接受可选的 HMAC `cursor`，服务端在同一 PostgreSQL 只读快照中校验案件归属、成员关系、outbox 关联和 catalog 状态，最多返回 128 个引用。响应只含案件摘要、数据库 `as_of`、artifact ID、加入者/时间及 `active`、`expired`、`deleted`、`unavailable` 状态；其中 `unavailable` 是外键保护下的防御性一致性状态，正常 retention 以 `deleted` tombstone 表示。不返回 manifest、locator、hash、key ref 或内容能力；每次成功、拒绝或依赖故障均写 `console.case.read`，审计失败扣留结果，详见 [29.17](29-api-endpoint-catalog.md#2917-已实现的案件证据集合查询契约)。

保留锁管理已提供创建、释放和分页历史 API，要求独立的 `AuditAdministrator` 与精确作用域，可管理同域内其他所有者案件。操作具有用途隔离幂等键，历史响应含原期限、理由和释放事实；每次可审计尝试写 `console.evidence.hold.created/released/read`。它只控制物理保留，原文权限和到期拒读保持独立，详见 [29.21](29-api-endpoint-catalog.md#2921-已实现的案件保留锁管理契约)。

原文访问申请接口同样要求 Investigator 与规范幂等键，只接受自己拥有的 open 案件、同作用域 active 未过期 artifact、固定 `sensitive_raw` 类型和有界理由。服务在事务内锁定目标、限制主体 pending 数，并原子提交申请与 `evidence.access.requested` outbox。批准/拒绝要求用途独立的 `SensitiveEvidenceApprover` 和规范幂等键；决策主体不能等于申请主体，申请只允许一次终态。批准时重新验证并锁定案件与 artifact，短时资格不超过请求 TTL、服务端 `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS` 和 artifact 期限；拒绝不产生资格。内容端口通过 EvidenceReadPort 消费该资格，并在释放前重验数据库、vault 完整性及必需读取审计，详见 [29.13](29-api-endpoint-catalog.md#2913-已实现的证据内容读取契约)。

## 15.5 交互和错误语义

申请详情 API 已提供原始申请理由、目标、决策理由/期限及同一数据库观察的案件和 catalog 状态。Investigator 或 Reader 仅查看本人申请，Approver 可复核同站点申请；历史关闭、到期及删除状态保留可见。详情读取写独立管理审计，后续批准及内容访问继续独立检查当前权限；字段和部署顺序见 [29.23](29-api-endpoint-catalog.md#2923-已实现的证据访问申请详情契约)，控制台操作见 15.9。

申请列表支持 `view=mine` 和 `view=review`。前者允许 Investigator、Reader 或 Approver 分页查看本人全部历史状态，后者仅允许 Approver 查看同站点其他主体的 pending 申请。每页按申请 ID 降序，只投影目标、申请主体、类型、持久状态、申请时间和事件引用；完整理由及目标状态在打开详情后读取。每次查询产生独立 `console.evidence.access.list` 审计，游标绑定凭证、主体、作用域、视图及页大小，迁移和实时分页语义见 [29.24](29-api-endpoint-catalog.md#2924-已实现的证据访问申请列表契约)。

查询成功但索引未完成：200 + completeness/pending，并提供可重试水位；长任务 202 + job_id。后台未认证/无权限分别 401/403；扫描超限 429/422；依赖不可用 503。响应不泄露敏感对象是否存在。

所有列表使用游标和受限排序字段。多租户筛选在服务端注入，不信任页面传来的 tenant_id。查询、解密查看、导出和回放均有自己的 request_id 并写管理审计，避免审计工具成为无记录旁路。

## 15.6 第一版不做

不内嵌可执行源站页面，不提供任意 SQL 控制台，不一键重放生产写请求，不默认开放跨站原文全文搜索，不让 Agent 自动对流量下发永久封禁或发布新权限规则。可增加经过批准的自动告警，不等于赋予自动修改准入权。

## 15.7 已实现只读请求调查控制台

结构化检索另支持精确 `trace_id` 条件：仅接受 32 个小写十六进制字符，仍要求有界 UTC 时间窗，不据 trace 推断主体、资格或跨作用域关联。检索事件详情展示已校验的 trace 引用，并可显式预填同 Trace 检索。

结构化检索支持 `share_grant_id` 精确定位已发布的 `share.issued` 脱敏事件；ID 按 `ShareGrantId` 校验，使用 Investigator 既有固定范围与查询审计，不读取或返回分享 bearer 凭证。

服务端因果查询 `POST /control/v1/causality` 要求 Investigator 和管理 Bearer，固定接受 UTC 整秒窗口、根 `ev_`、方向及 1–4 跳/1–16 节点的上限。结果只投影已发布的脱敏事件摘要，按记录的 `cause_event_ids` 有界遍历前驱/后继，附带水位、缺口与扫描统计；根未命中与索引缺口保持同构的 `found=false`/健康字段语义。请求不读取 payload 或证据正文，审计事件为 `console.causality.read`，成功或计划后的失败只保存 HMAC 查询摘要。控制台事件详情提供显式查询表单，操作者填写 UTC 窗口、方向和上限后主动提交，结果以根事件为中心按方向和跳数分组显示脱敏节点；已加载事件的即时因果卡片继续独立展示。接入该端点不改变详情、原文、回放或业务资格权限。

`web/console` 以 React + TypeScript 实现请求 ID → 摘要 → 事件时间线 → 证据目录/单项元数据、模型调用 ID → 脱敏生命周期 → 证据元数据 → 仅预填模型调用 ID 的历史检索、Agent 运行 ID → 脱敏生命周期与固定事件引用 → 仅预填 Agent 运行 ID 的历史检索、访问申请 ID → 历史申请/决策元数据 → 仅预填申请 ID 的历史检索、固定 UTC 窗口 → 模型调用分页发现、校准报告 ID → 受限冻结元数据、资格 ID → 账本快照 → 身份绑定/来源请求，以及结构化事件检索的可交互闭环。模型列表、模型详情和 Agent 详情均调用独立的 Observer API；校准报告详情独立要求 `AuditAdministrator`；列表行仅为窗口内最新可见状态，点击 `mdl_` 或 `agt_` 后仍重新鉴权并写独立详情审计。结构化检索调用 29.14 的 `POST /control/v1/search`，通常要求 Investigator；当计划含 `calibration_report_id` 或 `evidence_hold_id` 时，同一主体还必须在固定 tenant/site 持有 `AuditAdministrator`。主体引用可精确筛选已发布历史，但结果不回显该值；其密钥化 query_digest 由服务端生成，浏览器只校验不透明摘要格式。模型、Agent、访问申请或保留锁历史预填不会提交检索，操作者仍须填写时间窗并以 Investigator 身份独立提交；三个角色分别校验，Investigator 不隐含 Observer 或 AuditAdministrator。范围由首次成功响应确认并在同一会话后续响应中逐一校验。事件、证据和模型列表分页显式触发，每页替换当前页。

控制台还提供 AuditAdministrator 专用的“审计发布状态”：操作者手动调用 29.5 的 `GET /control/v1/audit/health`，读取当前配置 audit journal 到索引目标的单次发布快照。界面展示 `as_of`、目标/表、元数据保留期、关闭段和字节、已发布/待发布/未封存段、缺口及连续水位；不自动轮询。每次读取由服务端重新鉴权并记录 `console.health.read`，客户端重新校验 tenant/site，401、范围偏差和晚到响应都清空页面状态。此处仅用于发布观察，不表达业务准入、全部 Outbox 状态或系统整体健康。

AuditAdministrator 还可手动读取 29.26 的 `GET /control/v1/calibration-reports/{report_id}`。页面只接受规范 `calr_` UUIDv7，并以严格白名单 DTO 展示冻结报告元数据及专用正文 `active`/`deleted` tombstone；缺失或跨范围保留为明确的当前范围未找到观察。每次刷新都独立重新鉴权并写 `console.calibration.report.read`，没有自动轮询。正文 tombstone 只表示专用密文保留观察，不表达正文读取权、报告质量、阈值/策略发布或业务资格；页面不请求或展示正文、样本、标签、概率、指标、提示词、存储信息或内容读取能力。401、范围偏差和晚到响应清空会话或查询状态。

检索使用原生表单输入 UTC 整秒半开时间窗（1970 至 2300，最长 31 天）、1–1000 条页大小及事件时间升/降序。最多 8 个 allowlist 条件按同事件 AND 组合，包含 request/event/trace/直接因果/grant/auth binding/case/artifact/calibration-report/model-call/agent-run/job/evidence-access-request/evidence-hold/share-grant ID、`subject_ref`、五类精确文本、outcome 和整数基点置信度上限；数值阈值不匹配空置信度。`job_id` 只定位固定 `console.job.read` 管理访问历史，不返回任务投影或案件内容；案件面板只预填该条件，仍要求操作者填写时间窗并显式提交。校准报告 ID 只定位固定的报告发布、报告正文保留维护及 `console.calibration.report.read` 历史，不提供报告正文、样本、阈值或读取授权；它要求同一主体同时具备 Investigator 和 AuditAdministrator。模型调用 ID 只定位固定的模型生命周期与 `console.model.read` 历史；它不返回模型详情或证据，也不把 Investigator 提升为 Observer。Agent 运行 ID 只定位固定的 Agent 启动、工具调用/结果、产物和终态事件及 `console.agent.read` 历史；它不触发 Agent 执行，不返回输入/输出、工具正文或权限快照，也不授予回放或详情权限。访问申请 ID 只定位固定的申请、决策与 `console.evidence.access.read` 历史；它不返回原文或授予审批/读取资格。界面展示已提交计划、服务端查询摘要、管理请求 ID、实际扫描行/字节和索引水位/pending/gap，区分统计未知与 0。分页冻结已提交计划；编辑任何查询条件使旧结果、详情、摘要和游标失效，后续新发布或到期记录仍可能改变分页可见集合。

搜索事件和请求时间线保留 nullable 请求、阶段、结果、证明、置信度、模型版本与强类型模型调用引用，并原样显示 RFC3339 微秒时间。结构化搜索事件额外投影并校验 32 位 `trace_id`；详情可准备同 Trace 检索，旧服务端尚未回传该字段时不显示入口。模型引用可打开既有模型详情；该跳转继续由 `Observer` 端点重新鉴权并写独立 `console.model.read` 审计，检索权限不扩大详情或证据访问。空结果与索引完整性独立呈现；水位只覆盖配置日志源，不能推断独立 Outbox 已追平。已知请求和 artifact 引用也可显式打开对应详情，仍由各端点重新鉴权。事件与模型生命周期中已记录的直接前驱 ID 可点选以准备精确事件检索；已选事件也可准备按其前驱 ID 查找直接后继的检索；trace 入口只预填同 Trace 条件。控制台还可在当前已加载事件集合内，沿已记录的 `cause_event_ids` 展示最多 4 跳、每方向最多 16 个节点；未载入引用只准备精确 `event_id` 检索。服务端 `POST /control/v1/causality` 另提供固定窗口内最多 4 跳/16 个非根节点的有界摘要遍历，沿已发布引用返回脱敏事件并独立审计；当前 UI 局部视图仍不自动提交或递归展开。所有入口均不扩大 Investigator 搜索、Observer 详情或证据读取权限，也不推断缺失边或跨作用域关系。客户端只展示脱敏事件投影，payload、存储地址、密钥和原文保持在展示边界之外。跨页完整关联图、资格/身份全链路、自然语言查询和回放继续迭代。

摘要保留缺失、未知和未确认语义；`complete` 与索引 gap/pending 独立呈现，分别披露摘要/事件观察时间与配置日志源水位。事件展示证明类型、置信度可用性、修订和证据引用；确定性规则不填造置信度。目录只展示采集状态、保真度、字节数、分级及期限，`found=false` 统一为“当前不可用”；存储地址、密钥引用和密文摘要不进入展示 DTO。

模型列表使用 1970–2300、最长 31 天的 UTC 整秒半开时间窗和 1–100 条页大小，固定以 `(occurred_at DESC, model_call_id DESC)` 键集分页。每行只显示模型/提示版本、provider/provider_model_id、问题类型、窗口内最新状态/原因及置信度可用性，不显示数值置信度、概率、证据引用、生命周期或供应商正文。列表游标绑定凭证、主体、服务端 tenant/site、窗口、页大小、排序和最后位置；编辑条件清空旧页，后续发布或保留可能改变后页可见集合。它不主张当前状态、完整生命周期、模型索引已追平或证据读取资格。点击行会调用单项模型查询，继续由 Observer 重鉴权并记录 `console.model.read`。

单项模型查询展示 provider/provider_model_id、内部模型与提示版本、问题类型、置信度可用性和按 request_seq 排序的有界生命周期；Noul 保持空置信度，历史供应商双空字段保持未知。界面区分 complete、pending、partial 和 not_indexed，强调配置日志源水位不证明模型追平，模型评估完成不表示业务操作获准。输入、输出与调用记录仅以 artifact 引用打开元数据；概率正文和供应商原文须经独立证据内容授权。

资格及身份绑定查询展示单次 PostgreSQL 观察的 `as_of`、持久状态、时间到期与代际事实，保留 UTC 微秒并校验精确到期关系。资格内嵌当前绑定与资格共享快照；打开独立绑定详情或来源请求会产生新的观察。匿名、撤销和过期不被折叠成未找到，active 行仍可能到期；未找到时明确当前范围未返回记录。主体、凭证、资源指纹、动作引用及 constraints 不进入展示对象。历史检索入口仅预填目标条件，要求填写 UTC 时间窗并主动提交，独立校验 Investigator；账本与历史查询不构成跨存储冻结快照。界面不从这些事实派生在线准入结论，完整来源图继续迭代。

生产控制台使用 OIDC 建立的 HttpOnly 同源会话 Cookie；页面不读取或保存会话秘密。受控自动化仍可在客户端内存使用短期管理 Bearer，退出、闲置 15 分钟、401 或主动断连后清态；异步响应绑定查询代际和操作序号，旧响应不能恢复已清除数据，跨范围响应断连。原生 Fetch 固定同源路径、拒绝重定向，浏览器会话请求只发送同源 Cookie，Bearer 自动化请求省略 Cookie；实施 15 秒读体总期限及 16 MiB 上限，错误只呈现固定安全文案、稳定代码和管理请求 ID。管理审计继续由服务端控制端点完成。

生产控制台已实现 OIDC authorization-code + S256 PKCE 登录、单次 state/nonce、签名验证、精确 issuer/audience 与部署要求的 MFA `acr`，以及 PostgreSQL 撤销型 HttpOnly 浏览器会话、15 分钟闲置/8 小时绝对超时和 Origin + CSRF 防护。subject 必须由部署配置显式映射到管理角色；每次请求按当前映射重建固定 tenant/site principal，IdP 自声明角色不授信。原文读取与调查导出另要求同一浏览器 session 在两分钟内完成 MFA step-up，并仍须通过独立审批；step-up 使用迁移 0036 和最近 60 秒 `auth_time`。机器 Bearer 暂无 step-up 路径，不能读取原文、批准导出或下载导出包。启用须先应用迁移 0035/0036，配置 TLS、专用同源管理 origin、CSP/缓存策略及本文 19.3 的 OIDC 环境变量。开发和部署步骤、测试数据语义见 [控制台说明](../web/console/README.md)。

## 15.8 已实现案件工作台

案件工作台（第 3 阶段重做，取代旧的案件、证据访问、证据保留和调查导出四页）使用 `/cases`、`/cases/{case_id}` 和 `/cases/{case_id}/{evidence|access|holds|exports|analysis}`，对应 29.10、29.16–29.18、29.22。Investigator 打开 `/cases` 时即读取“我的案件”（open/closed，按案件 ID 降序，签名游标逐页替换，每页独立显示数据库 `as_of` 和管理请求 ID；“全部/开放/已关闭”筛选只作用于已读取的这一页），并可经“新建案件”（调查目的 1–512 UTF-8 字节）创建案件。AuditAdministrator 不能列案件（列表要求 Investigator），只能按规范案件 ID 打开仅含“保留锁”页签的案件；其他角色看到说明且不发请求。

案件详情由用途、状态、“关闭案件”（危险操作，须填写理由）和五个页签组成，页签在首次打开时各读取一次：证据集合（成员的历史加入者/时间和 catalog 状态，关联同域有效 artifact，元数据抽屉独立要求 Observer，成员行可申请原文访问）、访问申请（本人申请，来自 `view=mine` 列表并按本案件过滤）、保留锁（仅 AuditAdministrator，见 15.10）、导出（`GET /control/v1/exports?view=mine`，浏览器只保留属于本案件的行，并可申请导出，见 15.11）和分析任务（`POST /control/v1/cases/{case_id}/analyze` 与 `GET /control/v1/jobs/{job_id}`，只覆盖 catalog 计数快照，不触发模型、正文读取、导出或回放）。打开页签重新鉴权并读取当前状态，不从列表状态推断后续操作获准。

旧的 `/evidence/holds`、`/evidence/exports` 重定向到 `/cases?moved=holds|exports`，`/evidence/access` 重定向到 `/approvals?moved=access`，页面顶部显示一次可关闭的说明。命令面板的 `case_` 打开案件详情，`job_` 打开 `/cases/jobs/{job_id}` 的任务状态对话框（并链接到该案件的“分析任务”页签），`artifact_` 进入案件工作台。

所有写操作（创建案件、关联证据、关闭案件，以及 15.9–15.11 的申请、决定、保留锁和导出）由用户按钮提交，经 `useGuardedMutation` 和待确认操作登记：表单校验 1–512 UTF-8 字节文本与强类型 ID，提交同步冻结目标、路径和正文，幂等键由框架生成（不是表单字段，操作者不能填写）；成功显示管理 request_id、原操作时间和 replayed。明确拒绝（400/403/404/409/422/429 的 `CONTROL_*` 响应）后可以准备新的操作；断网、超时、响应契约失败或查询切换使回复失效时，操作保持“结果未知”，仅允许以原键、原路径、原正文精确重试，之后的拒绝也不能证明早先的未知尝试没有提交。冻结的请求显示在对话框或页面面板中并列入“待确认操作”，SPA 内导航不会丢失它，未确认操作离开页面时触发浏览器原生提醒。

冻结请求和未知结果只存在于页面内存：刷新、401、15 分钟闲置、pagehide 或断连之后全部清空，控制台既不保存也无法恢复原幂等键。此后只能读取列表和详情核对服务端记录——列表里出现新记录不能证明某次未知写入已提交，换新键重提也不受原键的幂等保护，操作者须先核对再决定。跨 tenant/site 的响应断开连接并清空状态，晚到或被替换的旧响应不能回填页面。后端已准入的操作仍可能完成，客户端清态不撤销数据库提交。

客户端只调用固定同源路径并发送 JSON；生产浏览器请求使用同源 OIDC 会话 Cookie、由 API client 提交 CSRF header，受控自动化仍显式发送 Bearer 且省略 Cookie。两者都拒绝重定向并沿用有界读体及安全错误投影。状态变更与事务 outbox、管理访问审计均由服务端完成；案件工作台的提供不替代 15.3 的生产身份入口要求。真实 PostgreSQL/Axum/Node 契约和合成浏览器回归范围见控制台说明。

## 15.9 已实现证据访问工作台

证据访问分布在两处，使用 29.11–29.13、29.23–29.24 的固定端点：Investigator 在案件详情的“证据集合”或“访问申请”页签对本案件 open 的成员 artifact 提交明确理由的原文申请（幂等键由框架生成）；其余步骤在审批中心（`/approvals`，侧栏“审批中心”，带待办数量）完成——独立审批人决定，申请人在“我的申请”读取状态并下载。

“待我审批”页签在打开时各读取一次三个来源的第一页，合并为一张按提交时间由新到旧排序的表（行类型为“原文/导出/策略”，显示申请人、等待时间和对象）：原文访问待办（`GET /control/v1/evidence-access-requests?view=review`）和导出待办（`GET /control/v1/exports?view=review`），二者要求 SensitiveEvidenceApprover；以及等待独立审批的站点策略修订——由 `GET /control/v1/sites` 中 `requires_approval` 为真的站点推出。服务端要求 SystemAdmin 才能读取这份站点清单，只持有 PolicyApprover 的主体在该来源得到 403，页面说明并指向站点发布页。各来源各自失败、各自重试，其余照常显示；服务端不列已决定的待办，所以没有“已处理”视图。类型筛选选“原文”或“导出”时逐页读取该来源，游标绑定来源与筛选，筛选改变即丢弃游标；“全部”只显示各来源第一页并提示还有更多。列表 DTO 不含用途和理由，选中行后才读取详情；每次读取都被审计，页面不自动轮询，“刷新待办”才重读。

选中一行（`?item=` 可深链接，命令面板的 `access_`、`export_` 直接打开）后读取详情并显示决定表单：审批理由必填（1–512 UTF-8 字节）；批准原文访问时选择 15 分钟、1 小时或 4 小时的预设或自定义秒数，预设与输入都受详情返回的 `max_approval_ttl_seconds` 限制，拒绝可终结目标已失效的 pending 申请，导出审批只需理由。申请人是当前主体本人时不提供批准/拒绝按钮并说明职责分离，服务端的 `…SELF_APPROVAL…` 拒绝同样按职责分离解释。服务端持续校验角色、作用域、禁止自批和当前期限；界面观察只用于复核。策略修订行只负责定位：决定在站点发布页 `/sites/{site_id}/releases` 提交，审批中心不调用站点批准接口。

“我的申请”页签（`/approvals/mine`）列出本人的原文访问申请与导出申请（状态、到期），列表逐页替换并显示数据库微秒观察时间和管理请求 ID。获批原文由 Reader 角色在详情里点击“下载原文（.bin）”：客户端校验规范响应头、已确认的 tenant/site、申请和 artifact、附件媒体类型及实际字节数，二进制读取上限 64 MiB，发送到读体总期限 15 秒；内容保持 Blob 并以 `.bin` 附件交给浏览器，页面不解释原文，临时对象 URL 及时释放，下载切换目标、查询或会话后旧响应不能触发保存；界面显示管理请求 ID、字节数和交付浏览器状态，不能由此推断磁盘落盘成功。审批过期、案件关闭和证据删除由后端在每次读取时重验。

原文下载、导出的批准/拒绝和导出包下载要求同一 OIDC 会话两分钟内的 MFA step-up，且不替代独立审批。被服务端以 `CONTROL_STEP_UP_REQUIRED` 或 `CONTROL_EXPORT_STEP_UP_REQUIRED` 拒绝时，页面弹出“需要 MFA 再认证”，操作者在新窗口完成验证、控制台重新读取会话的 `step_up_valid` 后，用相同路径、幂等键和正文的冻结请求重发；取消、窗口被拦截或会话结束时保持服务端的原拒绝。机器 Bearer 当前不能读取原文或导出包，也没有 step-up 路径。

侧栏“审批中心”旁的数字是最近一次读取到的待办数量；有来源读取失败或还有后续页时为下限（`N+`）。点击数字只重新读取各来源第一页，没有自动轮询，会话结束即清空。二进制响应身份头须先升级控制服务并配置代理透传后启用界面；启用列表须先应用迁移 0022（访问申请）和 0050（导出）、升级管理 journal 发布器，再部署控制 API 和控制台。

## 15.10 已实现证据保留工作台

“保留锁”页签位于案件详情（`/cases/{case_id}/holds`），仅对独立的 `AuditAdministrator` 角色开放，调用 29.21 的三个固定 API，要求服务端 tenant/site 作用域。管理员填写已有成员 artifact、明确理由和 UTC 毫秒截止时间以创建保留锁，或读取保留历史并释放；可以按案件 ID 打开同作用域其他调查员的案件，案件所有权、Investigator 或 SystemAdmin 本身不授予保留管理权。保留锁只延缓物理删除，不授予读取权限，页签顶部说明一次；原文访问仍遵守原始期限及独立审批。

新建期限由数据库时钟限制为未来 720 小时内：选择器给出 1 天、7 天和最长三个预设，也可输入 UTC 毫秒时间；客户端用最近一次 `as_of` 加已流逝时间估计服务端时钟并留两分钟余量，允许原期限用于精确重试。创建要求 open 案件、现有成员和没有删除意图的 active catalog；内容已到期仍可保留，释放可在案件关闭后执行。界面显示原始期限、创建主体/理由和完整释放事实，历史页提供数据库微秒 `as_of` 与管理请求 ID；活动状态仅表示该页观察时的保留状态。

列表按 hold ID 升序，每页独立观察，最多 128 项；客户端检查规范 ID、时间精度、字段完整性、作用域、案件、严格跨页顺序及末项游标绑定，并丢弃未知元数据。创建或释放后显式刷新，切换案件使旧页和游标失效；每条记录可“准备历史检索”，只预填 `evidence_hold_id`，时间窗留空且不自动提交。列表结果不能确认未知写入。

创建/释放遵循 15.8 的写入语义：提交即冻结原路径、键和正文，未知结果仅原样重试，冻结请求只在页面内存、刷新后消失；首次明确拒绝或有效成功结果允许准备新的操作。

启用前应用迁移 0020 并完成 12.9 的保留感知清理升级，部署可识别 `console.evidence.hold.*` 的管理 journal 发布器和 29.21 控制 API，再上线界面及代理路由。回退界面保留数据库锁和历史记录；保留锁仍存在时继续使用支持它们的清理服务。工作台沿用 15.7 的 OIDC 管理会话；强操作再认证仍独立交付。客户端、合成浏览器及真实 PostgreSQL/HTTP 回归各自的验证边界见控制台说明。

## 15.11 已实现调查导出 API（MVP）

调查导出先交付服务端闭环，控制台随后接入：案件详情的“导出”页签申请导出，审批中心批准或拒绝并在“我的申请”下载。Investigator 以 `POST /control/v1/exports` 提交本人 open/closed 案件的用途和幂等键；`GET /control/v1/exports/{export_id}` 允许请求人读取状态，或由同作用域的 Approver、Reader、AuditAdministrator 复核。请求人不能批准自己的导出；批准和拒绝均要求独立 `SensitiveEvidenceApprover`、近期浏览器 step-up、明确理由及原键，批准成功后由数据库快照生成短时加密 `metadata_only` 包。

包只包含案件与最多 128 个成员的证据 catalog 元数据、active/expired/deleted/unavailable 缺失清单和 omitted 字段说明，不包含证据正文、事件载荷、模型输入输出、存储定位或连接凭据。包请求 ID 固定由 `export_id` 派生；批准提交与包生成分离时，重试先按固定请求 ID、包类型、父引用和期限复用已发布 catalog 对象，不重复生成活动包。包的 `artifact_id`、包请求 ID、catalog digest、字节数和 tenant/site 在下载前同时与 PostgreSQL 记录、catalog manifest 和 vault manifest 比较；任一不一致都扣留响应。Reader 需再次完成 step-up，`GET /download` 的 claim 在数据库中原子限制为两次并受 15 分钟过期时间约束；下载响应为带 `nosniff` 的有界 JSON 附件，控制台还会将实际附件 artifact/长度与最近一次 `ready` 状态逐项绑定，审计失败或存储不确定时不返回包。

部署先应用迁移 0039、0040，再升级可识别 `export.requested`、`export.approved`、`export.denied`、`export.downloaded` 和 `console.export.read` 的管理 journal 发布器，开放固定代理路由后再启用工作台。迁移 0040 按 tenant/site/export 保存包 claim；短 lease 保护 vault 写入，过期 claim 可回收，ready 提交必须携带当前 lease，claim 与 ready 在同一 PostgreSQL 事务内提交。当前不提供完整事件/正文导出、自然语言查询、安全回放、自动轮询或 Bearer 强操作；导出只在页面打开和显式刷新时读取，未知写入结果保留原键与参数（仅在页面内存，见 15.8），下载仅接收有界 JSON Blob。

导出发现使用 `GET /control/v1/exports?view=mine|review`（29.33），为审批待办提供服务端能力，控制台已接入：审批中心的“待我审批”读取 `review`，案件的“导出”页签和“我的申请”读取 `mine`；列表只用于发现，详情仍按规范 `export_` ID 读取（命令面板粘贴 `export_` ID 会打开审批中心并选中该导出），开发代理只转发 `?view=mine|review` 加可选签名游标。客户端按严格契约解码：`schema_version` 3、微秒 `as_of`、待审批没有决定人、已决定带决定人和时间且与申请人不同、已批准/就绪必须带到期、ID 严格降序、游标等于末项、`review` 只含待审批。`mine` 允许 Investigator、Reader 或 Approver 分页查看本人全部持久状态，`review` 仅允许 Approver 查看同站点其他主体仍为 `pending_approval` 的导出。每页按导出 ID 降序，仅投影导出/案件 ID、申请人、持久状态、申请时间、决定人/时间和包期限；用途、决定理由与包标识仍在详情读取，列表不授予批准或下载资格。每次查询写独立 `console.export.list` 审计，游标绑定凭证、主体、作用域、视图及页大小。启用前先应用迁移 0050、升级管理 journal 发布器，再部署控制 API 与固定代理路由。

## 后台路由与角色独立性验收（2026-09-27）

站点列表和编辑器分别位于 /sites 与 /sites/{siteId}/{section}；创建入口是五步向导 /sites/new/{basics,upstream,entry,routes,review}（旧的 /sites/new/network 等地址重定向到对应步骤）。概览、网络、安全入口、路由、身份、加密、WAF/限流、策略/健康、发布与审计按分类独立渲染。TanStack Router 管理路径和前进后退，同站点分类共享草稿，向导的草稿也在步骤之间保留；跨站点、跨模块时清空响应并取消旧请求，所有站点响应既核对服务端确认的 tenant/site，也核对所请求的站点 ID。草稿离页有显式确认，未知写入保留原幂等键与正文供人工重试，且在站点内导航时保持可见。

只读运行视图和配置编辑独立：Observer 使用当前会话范围的状态/健康/修订 API，SystemAdmin 管理站点配置。PolicyAuthor、PolicyApprover、ReleaseOperator 的发布入口各自只显示获准操作；没有 Observer 不发起状态或修订读取。权限中心显示服务端 subject、scope、角色、绝对/闲置期限和再认证状态。侧边栏可见性不替代 endpoint 授权。

本地启动顺序为：端口占用检查 → Docker 依赖就绪 → advisory lock → 0040 基础对象检查 → 0041–0051 迁移与 ledger → schema 检查 → control → 55173 控制台。已登记迁移仍重新核对对象定义；部分对象、缺约束、checksum 变化会阻止启动。开发角色字段按固定本地角色集合同步，其他生成值和生产配置保持原有管理方式。

## 站点发布审批与应用语义（2026-10-04）

**审批要求只由“edge 正在服务什么”决定。** 站点写入事务内，以站点 active revision 的已存储完整配置为基线（从未应用过的站点没有基线），与新的 desired 配置一起交给 `xshield-core` 的纯函数 `assess_change_risk` 计算原因集合；调用方不能提供、也不能通过再次提交等价内容清除该结果，因为它从不参考“上一份 desired”。结果与原因词元（`ACTIVATION`、`TAKEDOWN`、`UPSTREAM_CHANGED` 等，存于 `site_apply_intents.risk_reasons`）随 apply intent 一起持久化。

**触发规则按“可自由变化项”的白名单定义，而不是按危险项列举。** 站点开始被服务（新建即 `active`、`draft`→`active`、`paused`→`active`）总需要审批，无论其余字段如何；正在服务的站点被暂停或改回 draft 也需要审批（Takedown）；基线与 desired 之间任何安全相关字段的变化都需要审批，包括上游地址/服务名/TLS、公开 origin、监听端口、入口路径与入口准入、路由的增删改（准入从 `ui_action_required` 降为 `authenticated_root`、source action、资源绑定、请求/响应 crypto、响应模式与大小）、identity、站点 crypto、WAF 开关/拦截头/拦截片段/Cookie 上限、限额（任何方向的变化，包括调高）、健康检查、secret 引用、sensor、静态资源深度和 `origin_object_access_enforced`；新增字段默认也算变化（`OTHER_CHANGE`）。只有 `display_name`、`policy_revision` 标签和路由/secret 的顺序变化不需要审批。draft 与未服务的 paused 站点不暴露任何东西，编辑它们不需要审批。与此前版本相比：限额调优、`policy_revision` 标签变化的判定改变，降级路由、清空 WAF 片段/拦截头、关闭对象级校验、调高限额不再绕过审批。

**审批绑定到所审阅的修订。** `POST /approve` 在持有租户锁和 apply intent 行锁的单个事务内读取 desired revision、配置摘要、apply_id 与该修订的作者，然后：幂等键只在其批准过的 `(revision, digest, apply_id)` 上重放，对其他修订返回 409 `CONTROL_SITE_APPROVAL_REVISION_MISMATCH`；请求带 `X-Xshield-Expected-Config-Digest`（64 位小写十六进制）时，摘要必须等于当前 desired 摘要，否则同样 409；审批人等于该修订作者时返回 403 `CONTROL_SITE_APPROVAL_SELF_REJECTED`（数据库 CHECK 约束再兜底一次）；清除要求的 UPDATE 同时限定 revision 与 apply_id。审批、拒绝、重放和不需要审批（409 `CONTROL_SITE_APPROVAL_NOT_REQUIRED`）都有独立审计终态；批准记录写入追加式 `site_apply_approvals`。未带摘要头的旧客户端仍可调用，但只能批准事务内读到的 desired，建议控制台随审阅页面的 `config_digest` 一并发送该头。

**直接应用保留，但留痕。** 持有明确作用域 `site.config.apply_direct` 的 Agent API Key 仍可对需要审批的 desired revision 调用 `POST /apply`；控制面在同一事务内写入 `approval_kind=direct_apply` 的审批记录（调用主体、修订、配置摘要、apply_id）并清除要求，因此不会留下阻塞其他站点的过期 `requires_approval`。成功与失败的终态审计分别为 `EDGE_DIRECT_APPLY_CONFIRMED` 与 `EDGE_DIRECT_APPLY_NOT_CONFIRMED`。没有该能力的调用者仍得到 `requires_approval=true` 且不发布。

**draft 不可路由。** 保存 draft 不会发布；对 draft 站点调用 `POST /apply` 返回 409 `CONTROL_SITE_DRAFT_NOT_APPLICABLE` 并写 DENY 审计；快照不包含 draft，也不会把 draft 标成已应用；draft→active 属于需要审批的上线。

**一个站点不会冻结或污染整个租户。** 控制面读取租户状态与分配快照 revision 在同一事务内完成。每个站点在快照中的内容：已批准（或无需批准）、有效且 `active` 的 desired 配置按 desired 发布并确认；待审批的站点保持在其最后一次获批（active）配置，不会把未批准内容带到 edge，状态保持待审批；从未应用且待审批的站点不出现在快照中；paused 站点不出现但按 paused 确认；draft 不出现也不确认。desired 配置无法通过校验的同级站点同样保持在最后一次获批配置，并在自己的状态上标为 `failed`/`CONTROL_SITE_POLICY_INVALID`，不使其他站点的 apply 失败；被应用的目标站点本身不满足这些条件时，apply 以其稳定原因失败并写入该站点状态：`CONTROL_SITE_POLICY_INVALID`、`CONTROL_SITE_PORT_UNAVAILABLE`（保持旧配置的站点占用的端口与新站点冲突）。保持不变的配置不再重新校验，避免校验收紧把正在服务的站点变成故障。

**幂等键覆盖每一次写入。** 每个修订都保存写入的幂等标识。重放最新写入返回原结果；重放更早写入的键返回 409 `CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED` 且不创建修订（同键不同内容仍是 `CONTROL_IDEMPOTENCY_CONFLICT`）。API 没有加入 expected-revision 前置条件：两个操作者并发保存仍以后写入者为准，写入后的审批要求照旧由基线决定。

**回滚。** `POST /control/v1/sites/{site_id}/rollback` 需要 `ReleaseOperator` 和规范 `Idempotency-Key`，没有请求体。它读取一个修订的完整已存储配置，并把它作为**新修订**写入（修订号永不复用），然后走与其他保存完全相同的路径：风险按当前 active 基线评估（从 D 回滚到 B 同样是上游变化，需要独立审批，批准前 edge 不变）、校验、幂等、审计和应用。回滚目标取决于状态：存在未完成的变更（desired 不等于 active，或上一次应用未完成）时取 active 修订，等于取消该变更，由于与基线一致所以无需审批；否则取**先前 active 的修订**，即按 edge 确认顺序（迁移 0051 的 `activated_at`）排在当前 active 之前的那一个，而不是 `active - 1`（后者可能是从未批准或从未服务的修订）；没有可回滚的目标时返回 409 `CONTROL_SITE_ROLLBACK_UNAVAILABLE`。同一个键重放回滚请求先于目标解析被识别，返回原结果（`CONTROL_SITE_CONFIG_REPLAYED`）且不创建修订；站点已有后续写入后重放，返回 409 `CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED`。修订历史（`GET /revisions`）里的每一行现在都是包含 `policy_revision` 的完整配置，读取更早版本写入的行时由 `policy_revision` 列补全。此前存储的修订缺少 `policy_revision` 而回滚反序列化要求它，所以每次回滚都返回 400 `CONTROL_SITE_CONFIG_REQUEST_INVALID`。

**删除站点要求 step-up。** `DELETE /control/v1/sites/{site_id}` 会把受保护站点从 edge 移除，因此与原文读取、导出审批使用同一套浏览器 MFA step-up：同一会话须在两分钟内完成 OIDC 再认证（迁移 0036 的 step-up 状态），否则返回 403 `CONTROL_SITE_DELETE_STEP_UP_REQUIRED`（`next_action=reauthenticate`）并写 DENY 审计，站点和 edge 均不变。机器 Bearer 和 Agent API Key 没有 step-up 路径，所以无论持有 `site.config.write`（映射为 SystemAdmin）等何种能力都不能删除站点；也不存在可授予的删除能力。通过 step-up 后流程不变：先以调用者的名义写入暂停修订（该预授权由存储记录为绑定该修订的 `delete_step_up` 审批，因此可以取代尚未批准的待审批修订，未批准的内容不会被服务），edge 确认不含该站点路由的快照后才删除数据库记录；edge 无法确认时站点保持暂停并返回 `CONTROL_SITE_DELETE_EDGE_NOT_CONFIRMED`。删除不要求第二个人审批：授权依据是再认证加上 `console.site.delete` 终态审计，作者自己也可以删除自己创建的站点，这是有意保留的取舍。

**控制台如何呈现这些语义（第 1 阶段）。** 发布页并排显示 edge 正在服务的修订与已暂存的修订。服务端只返回 `requires_approval`，不返回原因，所以“为什么需要审批”由控制台用 `assess_change_risk` 的同一套规则（TypeScript 移植，有单测）从两个修订的已存储配置复算，逐项列出涉及的字段和无需审批的修改；复算与服务端结论不一致时（例如服务端对控制台尚未识别的字段一律按 `OTHER_CHANGE` 要求审批）以服务端为准并如实说明，没有 Observer 角色、读不到修订时只显示服务端的结论。批准、应用、回滚先弹出确认框，展示将发布的字段差异和随后会发生什么，再走与以前相同的冻结写入（方法、路径、幂等键和正文在发送前冻结，结果未知只能原样重试）；验证配置不改变任何东西，直接执行。批准带 `X-Xshield-Expected-Config-Digest`，值取自已审阅修订的 `config_digest`（修订历史中暂存修订的摘要；与状态里的摘要不一致时拒绝提交；读不到修订的角色不带该头，批准的是服务端事务内的 desired）。回滚 API 没有请求体：有待生效变更时服务端恢复 active 修订，确认框点名它并列出被放弃的变更；否则服务端恢复先前 active 的修订，该顺序（`activated_at`）不在任何读取 API 中，控制台不能点名，只说明规则并提供较早修订的对比预览（预览不决定目标）；两种情况都说明会创建新修订。修订历史把内容与更早修订完全相同的修订标为“内容与 rN 相同”，用于回滚之后核对。批准与删除的 MFA step-up 对控制台只是提示：确认框显示再认证是否有效，服务端始终是授权方；批准返回 401 `CONTROL_STEP_UP_REQUIRED`（不会触发会话断开）或删除返回 403 `CONTROL_SITE_DELETE_STEP_UP_REQUIRED` 都表示请求没有执行，控制台保留冻结的原请求，完成再认证后原样重试。删除站点需要逐字输入站点 ID，成功后回到列表并说明结果。批准、应用、回滚针对已保存的修订，不包含未保存草稿；动作之后的重新读取不会替换草稿。

# 管理 API Key

`POST/GET /control/v1/agent-api-keys`、`POST /{id}/revoke`、`POST /{id}/rotate` 仅允许 KeyAdministrator 或 SystemAdmin 的浏览器管理会话并要求 CSRF。创建响应只返回一次完整 `xsk_` 明文，数据库和审计只保存 HMAC 指纹、前缀、scope 与生命周期。

## 管理 API Key 的授权模型

**管理入口只认浏览器会话。** 上述四个端点要求 OIDC 浏览器会话（持有 KeyAdministrator 或 SystemAdmin 并通过 CSRF）。静态机器 Bearer 虽可配置 SystemAdmin，但不是浏览器会话，同样返回 403 `CONTROL_SCOPE_DENIED`；API Key 本身没有任何角色，永远不能创建、列出、撤销或轮换 Key。早期实现曾接受机器 Bearer，本节以文档为准并已修正代码。

**Key 没有角色，只有精确授权。** 每个 scope 行是 `(tenant_id, site_id, capability)`，鉴权对每个 `(站点, 能力)` 单独判定：只看点名该站点的那一行，不合并多行的角色，也不把某个能力当作另一个能力的超集。Key 不具备 Observer、Investigator 等调查角色，所以 `/requests`、`/search`、`/evidence`、`/cases`、`/grants`、`/auth-bindings`、`/exports`、`/audit/health`、`/session`、Key 管理等一律返回 403 `CONTROL_SCOPE_DENIED`（`/control/v1/*` 中凡未在下表列出的路由对 Key 关闭）。

| 能力 | 放行的路由 | 授权范围 |
|---|---|---|
| `site.read` | `GET /sites`（仅返回有该能力的站点）、`GET /sites/{id}`、`GET /sites/{id}/config`、`/status`、`/revisions`、`GET /control/v1/workbench/overview`、旧 `GET /site-config` | 该行点名的站点 |
| `site.health.read` | `GET /sites/{id}/health` | 该行点名的站点 |
| `site.config.write` | `PUT /sites/{id}/config`、`PATCH /sites/{id}`、旧 `PUT /site-config`（只更新已存在站点） | 该行点名的站点 |
| `site.config.validate` | `POST /sites/{id}/validate` | 该行点名的站点 |
| `site.config.apply_direct` | `POST /sites/{id}/apply`（唯一的 apply 能力，无需独立审批，见下） | 该行点名的站点 |
| `site.rollback` | `POST /sites/{id}/rollback` | 该行点名的站点 |
| `site.create` | `POST /sites`（只创建不存在的站点） | 租户级，必须使用标记 `site_id = "__tenant__"` |

任何能力都不放行 `DELETE /sites/{id}` 和 `POST /sites/{id}/approve`：删除站点与独立审批只能由人员完成。`site.config.write` 不能创建站点，`site.create` 不能读取、改写或覆盖已存在的站点：`POST /sites` 命中已存在站点时，除非该 Key 同时持有该站点的 `site.config.write`，否则返回 409 `CONTROL_API_KEY_SITE_EXISTS`；`PUT` 命中不存在的站点时，除非持有租户级 `site.create`，否则返回 403 `CONTROL_SCOPE_DENIED`。创建响应后重试同一请求时，仅持有 `site.create` 的 Key 会得到 409（它无权读取站点，需由人员或带 `site.read` 的 Key 确认）。

**租户级标记。** `site.create` 不依附于任何已存在站点，因此只能以保留的 `site_id = "__tenant__"` 授予；该标记不能与其他能力搭配，`site.create` 也不能出现在具体站点上，二者均返回 400 `CONTROL_API_KEY_SCOPE_INVALID`。以前把 `site.create` 绑定到具体站点会隐式变成租户级的 SystemAdmin，现已取消；库中残留的此类行不再授予任何权限。名为 `__tenant__` 的站点不能被授予任何能力。

**签发者不能授予自己行使不了的权限。** 创建与轮换时，签发会话必须在对应站点（租户级能力则在整个租户）持有该能力所依赖的全部角色，否则整个请求返回 403 `CONTROL_API_KEY_SCOPE_FORBIDDEN`，不会裁剪后继续：

| 能力 | 签发者必须持有的角色 |
|---|---|
| `site.read` | SystemAdmin 与 Observer（该能力同时放行 SystemAdmin 与 Observer 保护的读路由） |
| `site.health.read` | Observer |
| `site.config.write`、`site.create` | SystemAdmin（`site.create` 需租户范围） |
| `site.config.validate` | PolicyAuthor |
| `site.rollback` | ReleaseOperator |
| `site.config.apply_direct` | ReleaseOperator 与 PolicyApprover（直接应用等价于“批准并发布”） |

因此仅持有 KeyAdministrator 的会话可以撤销或轮换，但不能签发任何带权限的 Key。

**站点投影。** 站点列表与工作台只返回主体实际被授权的站点：Key 为持有 `site.read` 的站点，租户范围的浏览器 SystemAdmin 保持整个租户，仅有精确站点作用域的管理员为其作用域站点。仅持有 `site.config.write` 等其他能力而无 `site.read` 的 Key 访问站点列表和工作台返回 403。游标只会指向调用者可见的站点。

**无效 Key 的预算与审计。** 每个携带 `X-Xshield-API-Key` 的请求，在查询 Key 表和追加任何审计事件之前，先从进程级未认证预算取一个配额（与登录端点共用，容量等于 `XSHIELD_CONTROL_REQUESTS_PER_MINUTE`，窗口 60 秒）。预算耗尽时直接返回 429 `CONTROL_RATE_LIMITED`（`retryable=true`），既不查询数据库，也不写 journal。允许的尝试恰好留下一条 `console.agent_api_key.use` 终态事件：有效 Key 为 PASS；未知、过期、已撤销的 Key 为 DENY `CONTROL_API_KEY_INVALID`（响应 401 同码）；缺少或超长的 `X-Xshield-Agent-Run-Id` 为 DENY `CONTROL_AUTH_REQUIRED`（401）；Key 存储不可用为 ERROR `CONTROL_API_KEY_UNAVAILABLE`（503）。被拒绝的 Key 请求在此终结，路由不再运行，也不会追加第二条事件。有效 Key 在验证通过后归还所取配额，所以正常的 Agent 流量不消耗该预算；但垃圾 Key 耗尽预算期间，合法 Key 也会收到可重试的 429，直到窗口滚动。Bearer 与浏览器会话不受 Key 洪泛影响。此前垃圾 Key 每次都无预算地写一条持久事件，3000 个垃圾 Key 即可写满 1 MiB 的 journal，之后包括合法 Bearer 在内的所有请求都返回 503 `AUDIT_DURABILITY_FAILED`。

**主体与审计。** Key 的主体在控制面内以 `apikey:{api_key_id}:{subject}` 表示，所有审计事件的 `subject_ref`、站点配置的 `updated_by` 与幂等摘要都因此带有 Key ID，且不可能与人员主体相同；明文 Key 永不进入审计或日志。`site.config.apply_direct` 的直接应用标志只在该 Key 对路径中那个站点持有该能力时才成立，其审批绕过的耐久记录由站点审批闸门负责。

## 管理 API Key 的生命周期与审计

**先审计后生效。** 创建、撤销和轮换都按同一顺序执行：校验请求，在数据库事务中暂存变更，追加持久审计事件，最后提交。审计追加失败时事务回滚并返回 503 `AUDIT_DURABILITY_FAILED`：不会出现没有创建记录的 Key，不会返回明文，撤销保持原状，轮换不会杀死旧 Key。列表也只在其访问事件已持久记录后才返回。提交本身在审计之后失败时返回 503 `CONTROL_API_KEY_UNAVAILABLE` 并追加一条 ERROR 事件，操作者以审计轨迹和列表核对结果。

**事件。** 全部使用既有事件类型，管理者的 `subject_ref` 为浏览器会话主体，所作用的 Key 记录在强类型字段 `target_api_key_id`（`key_` + UUIDv7，见 [11.14](11-audit-event-contract.md)），指纹、前缀和明文不进入事件：

| 操作 | 事件类型 | outcome / reason_code | target_api_key_id |
|---|---|---|---|
| 创建 | `console.agent_api_key.admin` | PASS `CONTROL_API_KEY_CREATED` | 新 Key |
| 撤销 | `console.agent_api_key.admin` | PASS `CONTROL_API_KEY_REVOKED` | 被撤销的 Key |
| 轮换 | `console.agent_api_key.admin`（同一请求、同一 journal 批次两条） | PASS `CONTROL_API_KEY_ROTATED_OUT`、PASS `CONTROL_API_KEY_ROTATED_IN` | 旧 Key、新 Key |
| 列表 | `console.agent_api_key.list` | PASS `CONTROL_API_KEYS_LISTED` | 无 |
| 拒绝或故障 | 同上 | DENY/ERROR，`CONTROL_API_KEY_REQUEST_INVALID`、`..._EXPIRY_INVALID`、`..._SCOPE_INVALID`、`..._SCOPE_FORBIDDEN`、`..._NOT_FOUND`、`..._UNAVAILABLE` 等 | 路径中已校验的 Key，未知时为空 |

Key 的使用另有 `console.agent_api_key.use`（PASS 的主体为 `apikey:{api_key_id}:{subject}`，见上）。

**轮换是一个事务。** `rotate` 先校验整个请求（JSON、过期、主体、scope、签发者权限），任何一项失败都返回 400/403 且旧 Key 不受影响；校验通过后在同一事务中撤销旧 Key 并写入新 Key，旧 Key 不存在或已撤销时返回 404 且不创建新 Key，并发的相同轮换恰有一个成功。此前代码先撤销旧 Key 再解析请求体，坏请求会留下已失效的旧 Key 而没有替换。

**主体与显示名。** `subject` 是用于审计和列表的标签：1–128 个 ASCII 字符，取自字母、数字和 `. _ : @ / -`，且以字母或数字开头；`display_name` 为 1–128 个字符，可使用任何语言，但不得含控制、双向覆盖和零宽字符，也不得有首尾空白。不合规的输入直接返回 400 `CONTROL_API_KEY_SCOPE_INVALID`，不做静默规范化（空白、非 ASCII 字符会被用来冒充他人的名字）。`subject` 在租户内不要求唯一：凭证以 Key ID 区分，同一 `subject` 可以同时有多把有效 Key（轮换重叠、按能力拆分），审计主体因带有 Key ID 而始终可追溯到具体凭证。

**最近使用。** 认证成功后写入 `last_used_at`，但同一 Key 每分钟最多写一次：节流在 UPDATE 语句内完成，被节流时语句不命中任何行也不产生新版本；失败认证和已撤销的 Key 不会更新。该写入只是记账，失败不会拒绝刚通过认证的 Key。
