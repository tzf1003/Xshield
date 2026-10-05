# Xshield 管理后台

React + TypeScript 界面，按请求 ID 读取摘要、事件分页和证据元数据，按模型调用 ID 读取脱敏生命周期与证据引用并预填历史检索，按 Agent 运行 ID 读取脱敏生命周期与固定事件引用并预填历史检索，按访问申请 ID 读取历史申请/决策元数据并预填历史检索，按校准报告 ID 读取受限冻结元数据，或在固定 UTC 时间窗内分页发现模型调用；也可按资格或身份绑定 ID 读取账本快照，或用结构化条件检索事件，并从事件详情显式提交有界服务端因果查询。UI 调用固定 GET 端点及只读 `POST /control/v1/search`、`POST /control/v1/causality`；权限、访问审计和 tenant/site 范围由 `xshield-control` 决定。模型详情、Agent 详情与模型调用列表均需要显式 `Observer`，校准报告详情需要 `AuditAdministrator`，事件检索与因果查询需要 `Investigator`；带 `calibration_report_id` 或 `evidence_hold_id` 的检索还要求同一主体同时具备 `AuditAdministrator`，三种角色分别校验。

控制台使用 TanStack Router 的后台路由和 antd 左侧导航（窄屏为抽屉），不再用“查询类型”选择菜单；Ctrl/⌘+K 命令面板按页面名搜索，或按 ID 前缀打开既有详情路由、预填结构化检索（不自动提交）。站点、调查、案件、审批、审计和权限中心各自拥有独立 URL；页面刷新会恢复深链接，导航隐藏只改善操作体验，服务端仍对每个请求独立授权。

“站点接入后台”由 `SystemAdmin` 读取租户范围的 `GET /control/v1/sites`，再通过 `GET/PUT /control/v1/sites/{site_id}/config` 管理每个受保护站点；旧 `GET/PUT /control/v1/site-config` 保留兼容。表单保存经过服务端校验的公网入口、源站地址、入口安全模式、探针标志、策略版本和状态，并按租户端口租约分配唯一 edge 内部监听端口。写入使用 `Idempotency-Key`，失败或断连时按原键重试；列表和单站点响应的 tenant/site 范围由客户端再次校验。浏览器会话返回服务端会话角色，界面只展示当前角色可用的站点页面和验证、批准、应用、回滚操作；服务端仍是最终授权边界。敏感配置只显示 secret reference、key ID 和状态。

站点页面按“接入、编辑、发布”三件事组织（第 1 阶段重做，取代旧的整页表单）：

- **站点列表**（`/sites`）：可搜索的表格，行里是名称与 ID、公网入口、监听端口、配置状态、应用状态和最近更新（列表 API 不返回上游地址，所以不显示）；摘要和状态筛选只统计已读取的行，“加载更多”读取下一页签名游标，“刷新”从第一页重来。
- **新建站点**（`/sites/new/{step}`）：五步向导——基本信息、上游与监听、入口与模式、首批路由、校验与保存。每一步是独立 URL，前进/后退可用，草稿在步骤之间保留；后面的步骤要等前面的校验通过才可进入。第 4 步可套用一个明确标注为“示例”的路由模板（入口页面加列表/详情/写入接口），也可留空，由 edge 使用入口路径生成的默认路由。最后一步汇总、预检并按“保存为草稿”创建一次；草稿不会发布，上线需要审批。旧的 `/sites/new/network` 等地址会重定向到对应步骤。
- **站点详情**（`/sites/{siteId}/{section}`）：页首是站点 ID、一个词的状态、desired/active 修订、edge 正在服务与已暂存的修订，以及“草稿 → 已校验 → 待审批 → 应用中 → 已生效”的生命周期，失败停在失败的那一步并给出原因与建议；十个分类共享同一份草稿。任何分类里有未保存修改时，底部变更栏显示数量与所在分类，提供“放弃”“查看差异”（字段名加修改前/后）和“保存草稿”。路由用表格加抽屉编辑，可搜索、复制，最多 256 条。保存只创建新修订；是否需要审批、何时生效由“发布”页说明。
- **发布**：左右并排显示 edge 正在服务的修订与已暂存的修订（提交人、时间、配置摘要）、“为什么需要审批”、发布操作、修订历史、手动健康读取，以及 SystemAdmin 的“危险操作”。服务端只告诉控制台“需要/不需要审批”，原因由控制台用服务端同一套规则（`assess_change_risk` 的 TypeScript 移植）从 edge 在用的修订与暂存修订的已存储配置复算，逐项列出涉及的字段；复算与服务端不一致时以服务端结论为准并如实说明。验证配置直接执行；批准并应用、应用期望版本、回滚上一版本都先弹出确认框，展示将发布的变更和随后会发生什么，再走与以前相同的冻结写入。批准请求带 `X-Xshield-Expected-Config-Digest`，值是已审阅修订的摘要（与状态里的摘要不一致时拒绝提交）。回滚 API 没有目标参数：有待生效变更时服务端恢复 edge 在用的修订，对话框点名并展示被放弃的变更；否则服务端恢复“先前生效过的修订”，控制台读不到生效顺序，只能说明规则，并提供较早修订的对比预览（预览不决定目标）。回滚总是创建**新修订**。批准和删除需要两分钟内的 MFA 再认证：对话框提示是否有效，被拒绝后请求保持冻结，再认证后可原样重试。删除站点还要求逐字输入站点 ID。

“审计发布状态”由 `AuditAdministrator` 手动读取 `GET /control/v1/audit/health`。它展示一个配置 audit journal 到索引目标的封存段发布快照：观察时间、目标、保留期、关闭/已发布/待发布/未封存段、缺口和连续水位；界面不自动轮询。该观察不判断业务准入、全部 Outbox 状态或系统整体健康。

“校准报告”由 `AuditAdministrator` 手动读取 `GET /control/v1/calibration-reports/{report_id}`。页面严格校验 `calr_` UUIDv7，并只展示受限 projection 的冻结元数据与正文 `active`/`deleted` tombstone；缺失或跨范围保留为当前范围未找到。正文 tombstone 不是读取授权、质量结论、阈值/策略发布或业务资格。该页面不请求或显示正文、样本、标签、概率、指标、提示词、存储信息或内容读取能力，也不自动轮询。

案件与审批页面按“案件”和“审批”两件事组织（第 3 阶段重做，取代旧的案件、证据访问、证据保留和调查导出四页）：

- **案件工作台**（`/cases`、`/cases/{case_id}`）：打开 `/cases` 就读取“我的案件”（`GET /control/v1/cases`，`Investigator`），按案件 ID 降序用签名游标逐页替换，显示数据库微秒 `as_of`；“全部/开放/已关闭”筛选只作用于已读取的这一页。“新建案件”弹窗要求 1–512 UTF-8 字节的调查目的。案件详情的页签是“证据集合”“访问申请”“保留锁”（仅 `AuditAdministrator`）“导出”“分析任务”，每个页签在打开时读取一次：关联证据、申请原文访问、创建/释放保留锁、申请导出（`GET /control/v1/exports?view=mine` 按本案件过滤）和案件清单分析（`POST /control/v1/cases/{case_id}/analyze` 与 `GET /control/v1/jobs/{job_id}`）都在案件里完成；“关闭案件”是页首的危险操作。`AuditAdministrator` 不能列案件，只能按案件 ID 打开仅含“保留锁”页签的案件。
- **审批中心**（`/approvals`，侧栏新增，带待办数量）：“待我审批”页签在打开时各读取一次三个来源的第一页——原文访问待办（`GET /control/v1/evidence-access-requests?view=review`）、导出待办（`GET /control/v1/exports?view=review`；这两项要求 `SensitiveEvidenceApprover`）和等待独立审批的站点策略修订（从 `GET /control/v1/sites` 中 `requires_approval` 为真的站点推出，服务端要求 `SystemAdmin` 才能读取这份清单）——合并为一张按提交时间由新到旧排序的表，行类型为“原文/导出/策略”，显示申请人、等待时间与对象。任何一个来源失败只在它自己的横幅里报错并可单独重试，其余来源照常显示；表格不提供“已处理”视图，因为服务端不列已决定的待办。选中一行后右侧读取详情并出现决定表单（审批理由必填；批准原文访问可选 15 分钟/1 小时/4 小时或自定义秒数，不超过服务端上限；拒绝只需理由）。申请人是当前主体本人时不提供批准/拒绝按钮；服务端的自批拒绝（`…SELF_APPROVAL…`）按职责分离解释。策略修订行只负责定位，决定在站点发布页（`/sites/{site_id}/releases`）提交，审批中心从不调用站点批准接口。“我的申请”页签（`/approvals/mine`）列出本人的原文访问申请与导出申请及其状态，获批的原文可“下载原文（.bin）”，就绪的导出包可“下载导出包”（显示剩余领取次数与到期）。
- **旧地址**：`/evidence/access` 重定向到 `/approvals?moved=access`，`/evidence/holds`、`/evidence/exports` 重定向到 `/cases?moved=holds|exports`，页面顶部显示一次可关闭的说明。
- **命令面板**：`case_` 打开案件详情；`access_`、`export_` 打开审批中心并选中该项（`access_` 另可预填结构化检索）；`job_` 打开 `/cases/jobs/{job_id}` 的任务状态对话框（也可预填检索）；`artifact_` 进入案件工作台；`ev_` 的保留锁解释只对 `AuditAdministrator` 显示。
- **审批数量徽标**：侧栏“审批中心”旁的数字是最近一次读取到的待办数量；有来源读取失败或还有后续页时显示 `N+`（下限）。点击数字只重新读取各来源第一页，不跳转；没有自动轮询，会话结束即清空。

## 本地运行

使用 Node.js 22.12+（22 系列）或 24+，推荐从仓库根目录执行：

```sh
./dev.sh
```

它会编排本地 PostgreSQL、ClickHouse、Keycloak OIDC、`xshield-control` 和 Vite 控制台；启动前会在现有 PostgreSQL 数据卷上以 advisory lock 增量补齐站点迁移 `0041–0049`，不会删除数据。打开 `http://127.0.0.1:55173` 后，点击“使用企业身份登录”，使用本地开发身份 `developer` / `xshield-dev-password` 完成登录。该身份只存在于本地 Keycloak 开发 realm；本地 realm 的认证等级声明是开发测试值，不代表企业 MFA 验收。

只启动前端（连接已存在的控制服务）时执行：

```sh
(cd web/console && npm ci && npm run dev)
```

等价的仓库根目录参数是 `./dev.sh --console-only`。`./dev.sh --reset` 只清理本地开发 Docker 数据卷并重新应用迁移。

页面为 `http://127.0.0.1:55173`。开发代理默认连接 `http://127.0.0.1:9443`；该端口需运行已按 [管理 API](../../docs/29-api-endpoint-catalog.md) 配置的控制服务。可由操作者设置 `XSHIELD_CONTROL_PROXY=https://control.internal.example` 后启动 Vite；只接受 HTTPS origin 或 loopback HTTP origin，拒绝 URL 用户信息、路径、查询和片段。该变量是开发服务器配置，不进入浏览器 bundle。

代理只转发固定调查 GET、案件列表/集合/保留历史 GET、证据申请列表/详情/内容 GET、导出列表 `GET /control/v1/exports?view=mine|review`（只接受这两个视图和可选签名游标）、站点配置 `GET/PUT /control/v1/site-config`、精确 `POST /control/v1/search`、`POST /control/v1/causality` 及案件、保留创建/释放和证据申请/审批路径；写路径与证据详情/内容路径拒绝附加查询串。OIDC callback 保留经服务端校验的授权响应 query；其他身份路径拒绝 query。代理只转发 Xshield session/state Cookie，剥离所有其他 Cookie；`Set-Cookie` 仅允许来自登录开始、callback、reauth-start 与 logout。代理不注入管理身份且不跟随重定向。正常开发启动使用 OIDC 会话；只有 Playwright 配置会设置 `VITE_XSHIELD_E2E_MACHINE_LOGIN=1` 启用合成 Bearer 表单，生产构建不会提供该入口。应用中没有演示数据入口；合成响应仅在 `tests/` 用于回归。

## 查询与安全语义

- 摘要后再读事件；证据目录和单项元数据按点击惰性读取。分页显式触发，每页替换前页，换请求重置游标。
- 审计发布状态由操作者显式读取和刷新；每次读取均由服务端重新鉴权并写 `console.health.read`。连续水位只覆盖该配置 journal 的已确认封存段；缺口、待发布段和未封存段是发布观察，不能替代对其他路径或服务的独立检查。
- 校准报告详情由操作者显式读取和刷新；每次读取均由服务端重新鉴权并写 `console.calibration.report.read`。控制台只接受严格白名单响应；401、范围偏差和晚到响应清空状态。报告正文 tombstone 仅是专用加密正文的保留观察，不会启用内容读取或改变现有校准、策略和业务边界。
- 结构化事件检索输入 UTC 整秒半开时间窗（1970 至 2300，最长 31 天）、1–1000 条页大小及事件时间升/降序。服务端配置可进一步收紧单页上限。最多 8 个条件要求同一事件全部匹配，字段选择限定为 request/event/前驱事件/32 个小写十六进制字符 trace ID/grant/auth binding/case/artifact/calibration-report/model-call/agent-run/evidence-access-request/evidence-hold/share-grant ID、event_type/stage/reason_code/operation_id/model_revision 精确文本、outcome 和 0–10000 整数基点置信度上限。Trace ID 精确匹配现有 `FixedString(32)` 索引列，搜索摘要回传经过校验的 trace 引用；详情页可预填同 Trace 检索，仍须提供有界 UTC 时间窗并主动提交。前驱事件 ID 只检索固定 `cause_event_ids` 中的直接关联，不递归遍历。校准报告和保留锁 ID 只定位固定生命周期、保留维护和管理操作历史，不读取正文或授予任何能力；两类过滤均要求同作用域 `AuditAdministrator`，服务端在索引访问前拒绝权限不足的 Investigator。模型调用 ID 只定位固定模型生命周期和 `console.model.read` 历史，详情和证据继续各自重新鉴权。Agent 运行 ID 只定位固定 Agent 生命周期和 `console.agent.read` 历史，不读取 Agent 输入/输出或工具正文，也不触发 Agent 执行、回放或权限提升。访问申请 ID 只定位固定申请/决策和 `console.evidence.access.read` 历史，详情、审批和原文读取继续各自重新鉴权。原生日期框中的值按 UTC 解释。

- `share_grant_id` 按强类型 ID 过滤固定 `share.issued` 顶层 `share_id`；仅返回脱敏事件摘要，沿用 Investigator 查询范围、时间/扫描预算和审计，不返回分享 bearer 凭证。
- 已提交计划、服务端查询摘要和管理 request_id 可见；下一页沿用冻结计划，编辑即清除旧结果、详情和游标。结果保留 nullable 字段与 RFC3339 微秒时间，扫描统计未知与 0 分开显示，空结果与索引 gap/pending 分别判断。水位只覆盖配置日志源，独立 Outbox 可能仍待发布；分页期间发布或到期可能改变后续可见集合。
- 查询摘要使用浏览器原生 WebCrypto 验证，需要 HTTPS 或 localhost 安全上下文；能力不可用时本地拒绝查询。
- 搜索只读已发布历史事实；请求与证据引用可打开现有详情，但仍需 Observer，Investigator 不隐含该权限。当前资格/绑定有效性、案件归属与原文读取由对应服务分别校验。事件详情可逐跳查看直接前驱或查找一个事件的直接后继；服务端另提供固定 UTC 窗口的 `POST /control/v1/causality`，最多 4 跳/16 个非根节点，沿已发布引用返回脱敏摘要并独立审计。详情中的服务端因果表单要求操作者填写 UTC 窗口、方向和上限后主动提交，结果按根事件、方向和跳数分组，编辑或切换事件会清除旧结果；当前页卡片仍按已加载事件集合即时计算。无上限完整图、自然语言计划与回放继续迭代。
- `subject_ref` 可精确定位固定顶层主体/身份引用；值限制为 256 UTF-8 字节且不允许控制字符。结果不会回显该值，服务端使用用途隔离 HMAC 生成计划摘要，浏览器不对主体值自行计算摘要。
- 案件分析结果可“准备任务历史检索”，预填规范 `job_` ID；服务端只匹配固定 `console.job.read` 管理历史，切换后仍需填写 UTC 时间窗并显式提交，不返回任务投影或案件内容。
- 查询类型可切换为模型调用，接受 `mdl_` UUIDv7。结果显示 provider、请求所用 provider_model_id、内部模型/提示版本、置信度语义、因果生命周期及输入/输出/调用记录引用；点击引用沿用单项证据元数据查询。旧记录两项供应商字段均为空时显示“历史记录未提供”，Noul 置信度显示“不适用”。
- “模型调用列表”要求 UTC 整秒半开时间窗（最长 31 天）及 1–100 条页大小，固定按 `(occurred_at DESC, model_call_id DESC)` 返回窗口内可见的最新脱敏记录。页面只显示 `latest_confidence_status`，不显示数值置信度、证据引用、生命周期、概率或供应商正文；游标由服务端绑定身份、范围和窗口，客户端只原样继续分页。点击模型调用 ID 会重新调用单项详情并重新鉴权，列表行不代替详情、当前状态、生命周期完整性或证据访问权。
- 模型的 `complete/pending/partial/not_indexed` 分别表示可见生命周期完整、等待终态、终态前驱不全和当前索引未命中。索引水位只覆盖配置日志源，不表示模型已全部追平；供应商模型标识不代替精确解析版本，评估完成不授予业务操作资格。
- 资格与身份绑定查询接受规范 `grant_` / `auth_` UUIDv7，展示数据库 `as_of`、持久状态和独立时间到期标志。资格记录包含发行代际、操作/视图、策略与来源引用，以及同一快照的当前绑定状态和代际是否一致；绑定详情还包含凭证代际与更新时间。UTC 微秒原样保留，客户端精确核对到期关系，超出 JavaScript 安全整数范围的代际值拒绝展示。匿名、撤销和过期记录可调查，`active` 标签不等于在线准入通过。
- 资格可打开绑定详情和来源请求时间线；“准备历史检索”只预填对应 ID，须填写 UTC 时间窗并主动提交 Investigator 查询。账本观察不附带 ClickHouse 水位，后续查询不构成跨存储冻结快照。`found=false` 显示“当前账本未找到”，不推断历史不存在；主体、凭证、资源指纹、动作引用和约束正文均不进入展示对象。
- `complete` 表示观察到保留的请求终态，不表示索引无缺口。页面分别显示摘要/事件水位和观察时间；水位只覆盖配置 journal，不覆盖所有 Outbox。
- Agent 详情只展示固定生命周期事件的类型、时间、结果/原因、因果和证据引用；工具参数、结果、提示、权限快照及正文不进入客户端。生命周期完整性与索引 gap/pending 分开显示，证据引用仍由独立 Observer/Reader 端点重新鉴权。
- 转发意图不是源站已执行证明，确认源站响应不等于业务成功。缺失判定与 `UNKNOWN`、等待终态分开显示；确定性证明保持空置信度。
- 证据 `found=false` 显示“当前不可用”，不推断对象存在性；manifest 不证明内容读取权或对象侧完整性。locator、密钥引用和密文摘要在客户端投影时丢弃。
- Bearer 不写 URL、日志或浏览器持久存储；所有请求 `credentials: omit`、`cache: no-store`、禁止重定向，读取上限 16 MiB、全程期限 15 秒。凭证须可被浏览器原样编码为 Authorization 头。
- 401、断连、页面离开、刷新或闲置 15 分钟清空会话。更换查询类型、目标与详情选择会使旧响应失效；跨响应 tenant/site 偏差断连。客户端清态不等于服务端凭证撤销，JavaScript 也不提供秘密内存可靠清零保证。
- 403、429 和依赖失败显示固定安全文案、稳定代码及管理 request_id；用户显式重试，不自动重试或释放原文。

## 案件与审批的读取

- 每一次读取都会被服务端审计，所以页面只在打开时和操作者点击“刷新”时读取，没有轮询，也不在窗口聚焦或网络恢复时重读；案件和审批的读取规格都是手动刷新，自己确认成功的写入之后相关列表会被标记为过期并重读。
- 分页游标绑定提交时的查询（视图、案件、类型筛选）：筛选或视图改变会丢弃游标，回到第一页；列表逐页替换，每一页独立观察，客户端只保留白名单元数据，并校验响应视图、作用域、严格降序（保留锁为升序）、微秒时间和游标末项绑定。
- 列表与详情的 DTO 不同：访问申请和导出列表只投影 ID、申请人、状态和时间，用途、理由和决定理由只在详情里，所以审批中心的行不显示“用途”，选中后才显示；导出详情没有数据库观察时间，导出是否已过期只按列表页的 `as_of` 判断，从不使用浏览器时钟。
- 响应的 tenant/site 与所请求目标不符会断开连接并清空所有状态；晚到或被替换的响应不会重新填充页面；401、闲置 15 分钟、页面离开和断连清空会话、缓存和待确认操作。角色隐藏只是便利，服务端对每个请求独立授权，拒绝时页面显示稳定代码、HTTP 状态和管理请求 ID。

## 案件与审批的写入与恢复

所有写入——创建案件、关联证据、关闭案件、申请原文访问、批准/拒绝原文访问、申请导出、批准/拒绝导出、创建/释放保留锁、案件清单分析——都经 `useGuardedMutation` 与待确认操作登记：

- 提交时同步冻结方法、路径、幂等键和正文；键由框架生成，不是表单字段，也不能由操作者填写；重复点击不会改变已冻结的请求。
- 明确的拒绝（400/403/404/409/422/429 的 `CONTROL_*` 响应）后可以准备新的操作；超时、断网、响应不符合契约或晚到响应使结果未知，此后只允许用**原键、原路径、原正文**精确重试，之后的拒绝不能证明早先的未知尝试没有提交。冻结的请求（方法与路径、键、正文）显示在对话框或页面面板里，也列在顶栏“待确认操作”中；有未决写入时关闭页面会触发浏览器原生提醒。
- 冻结的请求和未知结果**只存在于页面内存**：刷新、401、闲置、页面离开或断连之后全部消失，控制台既不保存也无法恢复原幂等键。此后只能读取列表和详情核对服务端记录；列表里出现新记录不能证明那一次未知写入已提交，用新键重新提交也不受原键的幂等保护，操作者要先核对再决定。SPA 内部导航不会丢失冻结的请求，回到原页面仍然只能原样重试。

## 高危操作与下载

- 原文下载（`GET /control/v1/artifacts/{artifact_id}/content`）需要 `SensitiveEvidenceReader`、两分钟内的 MFA step-up 和独立批准，缺一不可，只有申请人本人可以下载；导出包下载（`GET /control/v1/exports/{export_id}/download`）需要 step-up，每个导出最多领取两次。导出的批准与拒绝同样要求 step-up。机器 Bearer 没有 step-up 路径，不能读取原文或导出包。
- 被服务端以 `CONTROL_STEP_UP_REQUIRED` 或 `CONTROL_EXPORT_STEP_UP_REQUIRED` 拒绝时，页面弹出“需要 MFA 再认证”对话框；操作者在新窗口（`xshield-step-up`，同源 BroadcastChannel 只作提示）完成 OIDC 再认证后，控制台重新读取会话的 `step_up_valid`，再用**相同的冻结请求**（相同路径、幂等键和正文）重发一次。取消、窗口被浏览器拦截或会话结束时，保持服务端原来的拒绝，不再重发。服务端先检查 step-up，拒绝发生在任何数据库访问之前，所以重发是安全的。首次提交遇到的拒绝没有执行任何操作，取消后不留下冻结的请求，表单保持可编辑，再次提交会冻结一个新请求；被拒绝的若是结果未知之后的重试，先前的尝试仍可能已提交，该写入继续保持“结果未知”，也继续只能原样重试，并保持离页提醒。
- 原文和导出包都是附件：客户端校验响应的服务端范围、申请/证据或导出目标、媒体类型、附件属性和完整字节长度，在 15 秒总期限内有界读取（原文至多 64 MiB），保留为 Blob，以 `.bin`（导出为 `.json`）附件交给浏览器保存，页面不显示、不解释内容；临时对象 URL 在使用后释放，目标、查询或会话变化会抑制晚到的保存。界面不能证明文件已写入磁盘，附件由操作者保管；浏览器内存与系统下载管理器不提供可靠清零保证。
- 控制服务须先升级以提供 29.13 的六个二进制身份/长度响应头，代理必须透传并禁止缓存与正文日志。详情和当前 approved 状态仅供复核，不代替内容端点的重新授权。

## 保留锁

案件详情的“保留锁”页签只对独立的 `AuditAdministrator` 角色开放。创建要求案件成员的 artifact、理由和 UTC 毫秒期限（选择器给出 1 天、7 天、最长三个预设，最长为数据库当前时间之后 720 小时；客户端据最近一次 `as_of` 加上已流逝时间估计服务端时钟，并留两分钟余量，过期的原参数仍可用于精确重试）。保留锁只延缓物理删除，不授予读取权限，原文访问仍遵守原始期限及独立审批，页签顶部说明一次。历史按 hold ID 升序分页，显示原始期限、创建主体/理由和完整释放事实；每条记录可“准备历史检索”，只预填 `evidence_hold_id`，时间窗留空，不自动提交。管理员可处理同作用域其他调查员的案件。

首次启用先暂停全部旧版清理任务，再应用迁移 0020、升级保留感知清理服务及 outbox/管理 journal 发布器、控制 API、控制台和同源代理路由，完成验收后恢复清理。界面回退保留已经提交的锁和历史，仍须使用支持保留锁的清理服务。保留管理复用现有管理身份边界，生产入口要求见下一节。

## 构建与部署边界

```sh
npm run build
```

`dist/` 是静态产物。部署到专用管理 origin，由同源受控反向代理将 `/control/v1` 指向控制服务；生产环境必须使用 TLS、网络隔离和企业 OIDC 身份入口。控制服务需配置 `XSHIELD_CONTROL_OIDC_ISSUER`、`XSHIELD_CONTROL_OIDC_CLIENT_ID`、`XSHIELD_CONTROL_OIDC_CLIENT_SECRET`、`XSHIELD_CONTROL_OIDC_REQUIRED_ACR`、`XSHIELD_CONTROL_CONSOLE_ORIGIN` 和 `XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON`，并在启用前应用迁移 0035/0036、升级可发布 `console.auth.*` 的管理 journal。代理需允许 `POST /control/v1/auth/oidc/reauth/start` 并透传 `Set-Cookie`，禁止缓存或记录请求/响应正文。角色仅来自部署侧精确 subject allowlist，当前每个实例固定到启动时配置的 tenant/site。会话 Cookie 为 Secure/HttpOnly/SameSite=Lax，服务端执行 15 分钟闲置和 8 小时绝对超时，写请求强制精确 Origin + CSRF token。机器 Bearer API 仅保留给受控自动化，生产 UI 不采集 token，且当前不能读取原文。真实企业 IdP 联调仍须独立验收。Vite dev/preview 只供本地开发，不是生产管理边界。

静态服务器应返回 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`，并以响应头设置：

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

API 同样保持 `private, no-store`。生产代理仅向指定控制服务传递 Authorization，剥离业务 Cookie，禁止缓存、重定向和请求/响应正文日志；日志须脱敏认证头。不要把秘密放进 `VITE_*` 或静态配置。案件列表启用前先应用迁移 0021 并升级管理 journal 发布器，见 [29.22](../../docs/29-api-endpoint-catalog.md#2922-已实现的本人案件列表契约)。证据申请列表启用前先应用迁移 0022、升级管理 journal 发布器，再部署控制 API 与界面；索引构建需要安排写入维护窗口，回滚应用可保留索引，见 [29.24](../../docs/29-api-endpoint-catalog.md#2924-已实现的证据访问申请列表契约)。模型调用列表依赖支持其固定窗口、签名游标和 `console.model.list` 审计的控制 API。校准报告详情须先升级至能识别 `console.calibration.report.read` 的管理 journal 发布器，再启用控制 API 与界面；调查导出 API 启用前应用迁移 0039、升级导出管理事件发布器并开放 Vite 的固定 `/exports` 代理路由；导出列表（审批中心的待办与“我的申请”）另需迁移 0050、`console.export.list` 审计和同一代理路由；无新增 secret。完整事件/正文导出继续独立交付。

## 脚本、代码风格与目录

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | Vite 开发服务器，`http://127.0.0.1:55173` |
| `npm run lint` | `biome check`：格式与 lint，只有错误才失败；CI 的 `console` 作业在 `npm ci` 之后运行 |
| `npm run lint:debt` | 汇总旧模块仍有的 lint 警告（不阻塞） |
| `npm run format` | `biome format --write` |
| `npm run theme:css` | 由 `src/theme/tokens.ts` 重新生成 `src/theme/tokens.generated.css`；单测校验两者一致 |
| `npm test` | Node 单元测试（`node --experimental-strip-types --test tests/*.test.ts`） |
| `npm run build` | `tsc --noEmit` 后 `vite build` |
| `npm run test:e2e` | Playwright，见“验证” |

`biome.json` 不支持注释，规则取舍写在这里：recommended 规则开启，`noExplicitAny` 为错误，import 排序（assist）未启用，`src/theme/tokens.generated.css` 不参与格式化。旧模块仍有违规的 `noArrayIndexKey`、`useIterableCallbackReturn`、`useExhaustiveDependencies`、`useJsxKeyInIterable`、`noUnsafeOptionalChaining`、`useButtonType`、`useAriaPropsSupportedByRole` 暂为警告；在 `src/security`、`src/theme`、`src/shell`、`src/router`、`src/pages`、`src/sites`、`src/ui` 中它们与 `noNonNullAssertion` 都是错误，所以欠账只会减少。`src/api.ts`、`src/api-contract.ts`、`src/search.ts` 里拒绝控制字符的正则是有意为之，只对这三个文件关闭 `noControlCharactersInRegex`。

- `src/security`：会话（`SessionStore`、epoch、15 分钟闲置计时）、`guardedQuery` / `runFrozenWrite`、内存中的待确认操作登记和 `SessionProvider`。这里的数据只在内存，不写 Web Storage。
- `src/theme`：设计 Token（`tokens.ts` 是品牌色与浅色/深色/紧凑密度的唯一来源）、antd 主题、生成的 `--xs-*` CSS 变量层、自托管字体（`@fontsource`，输出为同源静态文件），以及主题/密度偏好——这是控制台唯一写入 `localStorage` 的内容，读写都在 try/catch 内。`style.css` 里不允许出现十六进制或 rgb 颜色（单测校验）。
- `src/router`：路由树；`src/admin-routes.ts` 保持原有的严格路径解析，路由测试以它为基准。
- `src/shell`：侧栏、顶栏、移动抽屉、命令面板及其 ID 分类器、MFA 再认证提示、“待确认操作”提示和审批待办数量徽标（`ApprovalNavBadge`）。
- `src/pages`：登录、概览、权限中心、“页面不存在”和站点页面（`pages/sites`：列表、详情与分类、新建向导、发布页、路由抽屉、变更栏）。站点页面按路由懒加载，不进入首屏脚本。案件（`pages/cases`：列表、详情和五个页签、对话框）与审批中心（`pages/approvals`：待我审批、我的申请、详情区）同样按路由懒加载。
- `src/sites`：站点的不含 React 的领域层——配置模型与草稿、字段差异引擎（`model/diff.ts`）、审批风险推算（`model/risk.ts`，`assess_change_risk` 的移植）、生命周期（`model/lifecycle.ts`）、发布规则（`model/release.ts`：回滚计划、审批摘要、操作可用性）、校验、角色可见性（`access.ts`）、写入的种类与结果文案，以及读取/写入 hook（`state/`，建立在 `src/security` 的 guarded 读取和冻结写入上）。
- `src/ui`：跨页面共享的领域组件和词典——状态胶囊、可复制的 ID、时间戳、问题提示，以及原因码词典 `reason-codes.ts`（每个站点/应用/edge/健康原因码的人话说明与下一步；单测扫描 Rust 源码，缺任何一个码都会失败）。
- `src/work`：案件与审批共用的不含路由的部分——读取规格与键（`queries.ts`）、写入 hook（`use-write.ts`，建立在 `useGuardedMutation` 与待确认操作登记之上）、冻结请求面板和对话框、原文/导出详情与决定表单（`AccessDetail`、`ExportDetail`）、下载（`downloads.ts`）、原地 MFA 再认证（`step-up.ts`、`step-up-window.ts`）、待办合并与排序（`inbox.ts`）、状态词典（`status.ts`）、保留期限（`holds.ts`）、审批数量徽标的存储（`approval-badge.ts`），以及 `work.css`。
- `src/legacy/LegacyHost.tsx`：尚未迁移的调查页面和 API Key 页面；由外壳懒加载并保持挂载，导航不会丢失已冻结的写入。

antd 的运行时样式使用 `index.html` 中 `xshield-csp-nonce` meta 的 nonce（仓库内为空，由部署模板写入同一个值，并须在响应 CSP 的 `style-src` 中允许它；上文的示例响应头没有展开该 nonce）。

控制台重做的边界：第 0 阶段（基础设施）提供会话、guarded 数据层和待确认操作登记；第 1 阶段把全部站点页面（列表、详情、新建向导、发布、路由抽屉）迁到这套数据层——读取带 epoch、透传取消并逐响应核对 tenant/site 与所请求的站点 ID，不自动轮询（健康读取只在点击时发生，每次都会被服务端审计）；写入在发送前冻结方法、路径、幂等键和正文，结果未知只能原样重试，并出现在“待确认操作”里。站点草稿只在页面内存中：同一站点内切换分类、前进/后退都保留，离开站点或刷新会清空（离开前有确认），不写任何 Web Storage。第 3 阶段把案件工作台和审批中心迁到同一数据层，写入同样登记到“待确认操作”。调查和 API Key 页面仍沿用各自的请求取消、写入冻结和离页提醒，尚未登记到“待确认操作”。命令面板只导航或预填，不提交查询。`window.__xshieldE2E` 是 Playwright 夹具，只在显式启用机器凭证登录的本地开发构建中存在，生产构建不包含。

## 验证

```sh
npm run lint
npm test
npm run build
npx playwright install chromium --only-shell
npm run test:e2e
# Playwright 同时启动两个 Vite 服务：XSHIELD_E2E_PORT（默认 5175，机器凭证构建）和它加 1（默认 5176，Cookie 会话构建）。
# 并行 worktree 为各自的运行指定不冲突的端口对：
XSHIELD_E2E_PORT=5311 npm run test:e2e
# 从仓库根目录执行，Node.js 22 必须在 PATH：
cargo test -p xshield-control --lib console_client_ -- --ignored
# 需要已应用迁移的隔离测试 PostgreSQL；设置 XSHIELD_TEST_DATABASE_URL：
cargo test -p xshield-control --lib console_ledger_client_reads_postgres_http_contract -- --ignored
cargo test -p xshield-control --lib console_case_client_mutates_postgres_http_contract -- --ignored
cargo test -p xshield-control --lib console_access_client_mutates_postgres_and_reads_vault_http_contract -- --ignored
cargo test -p xshield-control --lib console_hold_client_mutates_postgres_http_contract -- --ignored
# 或使用仓库的自动隔离建库、迁移和清理流程（包含上述账本 wire）：
scripts/test_postgres.sh
```

Node 单测覆盖请求/响应边界、OIDC step-up 的空正文/CSRF/安全授权 URL、模型生命周期一致性、校准报告严格白名单 projection、发布快照的白名单字段与计数关系、精度、空值、取消、超时和流式上限。Playwright 使用真实客户端加显式合成 HTTP 响应，覆盖校准报告和审计发布状态的显式读取/刷新及会话隔离、分页、模型查询与引用详情、Noul/历史空字段，以及搜索 POST 正文、冻结计划分页、编辑失效、事件详情预填同 Trace 条件且不自动提交、输入边界、空结果与 gap、可空事实和独立角色权限。共享回归覆盖 403/429/503、401/闲置/页面离开/刷新清态、异步响应隔离、跨范围拒绝、文本注入及 1536/390 像素布局；默认不记录截图或 trace。需要本地截图时显式将 `XSHIELD_CONSOLE_SCREENSHOT_DIR` 设为仓库外临时目录，验收后清理。

Rust 跨语言测试启动真实 Axum 路由、复用合成 ClickHouse 行和管理 journal，验证摘要、事件分页与微秒时间、目录依赖故障和 401，以及完整 Gateway Choice、旧记录 Noul 部分生命周期、模型未命中、预算 429 和模型访问审计。浏览器回归的 manifest 成功数据是合成契约，不代表已在生产数据源或企业 SSO 上验收。

搜索 wire 回归覆盖 nullable 字段、RFC3339 微秒、升降序游标、扫描统计与未知值、预算 429、篡改 HMAC 游标 400、Observer 查询 403，以及七次 `console.query.executed` 耐久审计。以上两项 wire 测试使用真实 HTTP 路由与合成索引，不执行外部模型调用。

账本 Node 回归覆盖目标/版本/空值、状态与代际一致性、微秒到期边界、未知字段投影和固定错误诊断。浏览器验证资格→绑定/来源请求、显式历史检索、生命周期状态、权限失败与会话隔离。独立账本 wire 使用真实 PostgreSQL 测试数据、Axum 路由、Node 客户端和加密管理 journal；范围为隔离合成记录，不代表生产数据或企业身份入口验收。

案件 Node 回归验证固定路径与键、UTF-8/控制字符边界、目标/状态/分页一致性及显式重试；本人列表额外验证严格降序、游标位置和白名单投影。浏览器回归（`case-center`、`case-tabs`、`case-isolation`）覆盖打开即读取、开放/已关闭筛选与降序分页、新建案件、五个页签、关联证据校验、从案件申请原文访问，以及每种写入（创建案件、关联、关闭、申请原文访问、申请导出、创建/释放保留锁）和分析任务的“冻结→结果未知→后续拒绝→原样重试”矩阵（含 SPA 导航之后）、切换案件后的晚到响应、401/闲置/pagehide 清态、跨 tenant/site 断开、Cookie 会话下的角色可见性、文本注入及 1440/390 像素布局。案件 wire 使用真实 PostgreSQL、Axum 和 Node 客户端，覆盖本人 open/closed 列表、范围隔离、连接池整体超时、SQL 锁超时、断连创建恢复、幂等重试/冲突、关联及分页、关闭后约束、外部所有者不可用、401/403，并复核案件、outbox 和管理 journal。独立列表故障测试验证断连后完成审计、预读坏行整页拒绝和审计失败扣留结果。测试仅使用隔离合成记录。

证据访问 Node 测试覆盖请求与决策的规范参数、精确重放、微秒期限和历史状态、未知字段投影、二进制目标/范围/安全响应头、实际长度、64 MiB 上限、单字节分块、取消与读体超时。浏览器回归（`approvals`、`work-session`、`downloads`）使用合成响应验证：三个来源的合并、排序与类型标签，空状态与单来源失败/全部失败的横幅，`?item=` 选中与深链接，决定表单（理由必填、期限预设受服务端上限约束、拒绝不带期限），自己的申请没有批准/拒绝按钮与服务端 `…SELF_APPROVAL…` 的解释，结果未知后的原样重试，导出批准遇 step-up 后用相同的冻结请求（同键同正文）重发，“我的申请”的状态与下载入口，原文与导出包的精确字节下载、错绑/跨范围响应、晚到下载抑制与对象 URL 释放，旧地址重定向、命令面板跳转、数量徽标、会话清理、文本注入及桌面/移动布局。独立 wire 使用真实 PostgreSQL、Axum、Node 客户端和加密 vault，验证独立审批、幂等冲突、17 字节原文、过期/关闭约束及 outbox/管理审计；不访问生产证据或企业身份服务。

导出列表 `exportList` 由 `tests/export-list.test.ts` 严格校验：视图与 `schema_version` 3、微秒 `as_of`、毫秒时间、待审批没有决定人、已决定带决定人与时间且与申请人不同、已批准/就绪必须带到期、ID 严格降序、游标等于末项、`review` 只含待审批。待办合并与排序、站点修订推导、数量徽标、期限与保留窗口由 `tests/work-model.test.ts` 覆盖；axe 扫描（`work-a11y`）在浅色和深色下覆盖案件列表、案件五个页签、审批中心各状态及 390 像素抽屉，关键与严重级别违规为零。

保留管理 Node 回归检查固定路径、原始参数、毫秒期限和微秒观察、释放字段完整性、升序分页/游标绑定与安全错误。浏览器回归（`case-tabs`）以合成响应验证创建（期限预设、720 小时上限与两分钟余量）、历史分页、释放、结果未知后的原样重试、异步与会话隔离及桌面/移动布局。独立 `console_hold_client_mutates_postgres_http_contract` 使用真实 PostgreSQL、Axum、Node 客户端和管理 journal，验证独立管理员处理其他调查员案件、跨租户/站点与角色拒绝、幂等冲突、成员约束、关闭后释放、事务 outbox 及原始内容期限保持。所有数据为隔离测试记录，生产企业身份验收继续独立执行。

## 依赖与维护

运行依赖：`react` / `react-dom`（界面与 DOM 更新）、`antd` 与 `@ant-design/icons`（组件与图标）、`@tanstack/react-router` 与 `@tanstack/react-query`（路由与服务端状态），均为 MIT；`@fontsource/ibm-plex-sans`、`@fontsource/jetbrains-mono` 提供自托管字体，字体文件为 OFL-1.1，由 Vite 输出为同源静态文件。构建与检查依赖 `vite`（MIT）、`typescript`（Apache-2.0）、`@biomejs/biome`（MIT OR Apache-2.0），类型依赖 `@types/react`、`@types/react-dom`、`@types/node`（MIT）；`@playwright/test`（Apache-2.0）和 `@axe-core/playwright`（MPL-2.0）仅用于真实浏览器回归与可访问性扫描。直接依赖除沿用 `^` 范围的 `antd` 与 `@ant-design/icons` 外固定版本，实际安装版本由提交的 npm lockfile 固定；依赖升级通过审查，重新执行类型、构建、API、浏览器及 Rust wire 测试。安全修复优先处理，主版本升级需核对 Node 兼容性。复用全局 npm 和 Playwright 浏览器缓存，不为临时分支重复安装。

工具依据：[Vite 指南](https://vite.dev/guide/)、[React 构建指南](https://react.dev/learn/build-a-react-app-from-scratch)、[Playwright 测试服务器](https://playwright.dev/docs/test-webserver)。

## 后台页面与恢复行为

/sites 展示站点列表，选择记录后进入 /sites/{siteId}/overview；新建站点是 /sites/new/{basics,upstream,entry,routes,review} 五步向导（旧的 /sites/new/network、/sites/new/security-entry 等地址重定向到对应步骤，书签不会失效）。详情按 overview、network、security-entry、routes、identity、crypto、waf-limits、policies、releases、audit 分类；只渲染当前分类。分类切换和浏览器前进/后退保留当前草稿，刷新从服务端恢复深链接并清空草稿。离开有未保存草稿或待确认写入的站点前会提示确认；向导里有已填写内容时离开同样会提示。

- system_admin：站点列表、新建向导、网络和策略配置编辑，以及发布页上的“危险操作”（删除站点：输入站点 ID，并需要两分钟内的 MFA 再认证；机器凭证不能删除）；发布权限单独校验。
- observer：当前会话站点的只读状态、健康观察和修订；独立的“站点状态”入口；发布页显示状态、审批原因和修订历史，不提供任何写操作。
- policy_author、policy_approver、release_operator：独立“站点发布”入口，分别验证配置（直接执行）、批准并应用、应用期望版本/回滚上一版本（后三者先弹出确认框）。没有 observer 时显示操作入口和服务端结果，状态及修订读取仍需该角色；此时确认框说明读不到修订内容，批准不带摘要。
- 调查、案件、审批和审计模块按各自服务端角色显示：案件工作台给 Investigator（保留锁页签给 AuditAdministrator，按案件 ID 打开），审批中心给 SensitiveEvidenceApprover/Reader、Investigator 和 PolicyApprover。/access/session 对所有已认证主体只读开放。

资格账本使用 /investigation/grants，身份绑定使用 /investigation/bindings，后台任务使用 /operations/jobs。详情 URL 使用对应稳定对象 ID。路由变化取消旧请求并使旧响应失效；每个站点读取和写入响应都单独匹配 tenant 和目标 site。

站点不存在时，服务端的 requires_approval: null 按缺失状态处理。已保存端口必须在 6100–65535；创建请求的 0 仅表示自动分配。HTTP 错误显示本地安全提示、稳定错误码、状态码和 request ID。结果未知的写入冻结原正文和幂等键，只有操作者点击“确认后原样重试”才重发。

## 回归验证

在 web/console 运行：

    npm run lint
    npm test
    npm run build
    npm run test:e2e

从仓库根目录执行，需要 ./dev.sh 的本地服务：

    node scripts/test_console_oidc.mjs
    python3 scripts/test_dev_postgres_migrations.py
    bash scripts/test_gateway_dynamic_listeners.sh

Playwright 默认使用 5175 的明确机器 fixture 和 5176 的浏览器会话 fixture 两套入口（可用 XSHIELD_E2E_PORT 改为 N 与 N+1）；业务 API 响应为合成契约。站点页面的用例集中在 `tests/sites-list`、`site-workspace`（生命周期、变更栏、差异、200 条路由、移动端与可访问性）、`site-wizard`、`site-release`、`site-release-session`（Cookie 会话下的 MFA 与角色矩阵）和 `site-roles`；单测 `reason-codes.test.ts` 会扫描 Rust 源码里的站点/应用/edge 稳定码，词典缺任何一个就失败。test_console_oidc.mjs 另行访问 55173，执行真实本地 OIDC 登录、站点列表、详情刷新、资格账本、只读权限中心及 1440×1000 / 390×844 布局检查，截图写入 /tmp/xshield-console-smoke。它只执行管理读取，不创建业务站点、不保存 Cookie。
# 管理 API Key 页面

控制台通过后端管理 API 管理 Agent Key。页面只向具备 KeyAdministrator/SystemAdmin 的浏览器会话展示创建、scope、过期、撤销和轮换操作；明文只在创建响应中展示一次。
