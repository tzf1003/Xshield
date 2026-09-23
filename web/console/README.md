# Xshield 调查控制台

React + TypeScript 界面，按请求 ID 读取摘要、事件分页和证据元数据，按模型调用 ID 读取脱敏生命周期与证据引用并预填历史检索，按访问申请 ID 读取历史申请/决策元数据并预填历史检索，按校准报告 ID 读取受限冻结元数据，或在固定 UTC 时间窗内分页发现模型调用；也可按资格或身份绑定 ID 读取账本快照，或用结构化条件检索事件。UI 调用固定 GET 端点及只读 `POST /control/v1/search`；权限、访问审计和 tenant/site 范围由 `xshield-control` 决定。模型详情与模型调用列表均需要显式 `Observer`，校准报告详情需要 `AuditAdministrator`，事件检索需要 `Investigator`；带 `calibration_report_id` 或 `evidence_hold_id` 的检索还要求同一主体同时具备 `AuditAdministrator`，三种角色分别校验。

“审计发布状态”由 `AuditAdministrator` 手动读取 `GET /control/v1/audit/health`。它展示一个配置 audit journal 到索引目标的封存段发布快照：观察时间、目标、保留期、关闭/已发布/待发布/未封存段、缺口和连续水位；界面不自动轮询。该观察不判断业务准入、全部 Outbox 状态或系统整体健康。

“校准报告”由 `AuditAdministrator` 手动读取 `GET /control/v1/calibration-reports/{report_id}`。页面严格校验 `calr_` UUIDv7，并只展示受限 projection 的冻结元数据与正文 `active`/`deleted` tombstone；缺失或跨范围保留为当前范围未找到。正文 tombstone 不是读取授权、质量结论、阈值/策略发布或业务资格。该页面不请求或显示正文、样本、标签、概率、指标、提示词、存储信息或内容读取能力，也不自动轮询。

案件工作台另外调用本人案件列表和集合 GET 及创建、证据关联、关闭三个 POST，均要求 `Investigator`。它显示调查元数据和操作结果；证据内容、审批、保留管理和导出仍由独立权限与流程控制。

证据访问工作台调用申请、详情、批准/拒绝及内容端点，分别校验 Investigator、申请主体或 Approver、独立 Approver、获批主体 Reader。详情显示原始理由、审批历史与目标状态，原文通过显式附件下载交付。

“我的申请”按本人主体发现历史记录，允许 Investigator、SensitiveEvidenceReader 或 SensitiveEvidenceApprover；“审批待办”要求 SensitiveEvidenceApprover，列出同作用域其他主体的 pending 申请。列表逐页替换，打开记录时重新读取详情；每页展示独立数据库观察时间和管理请求 ID。

证据保留工作台使用独立 AuditAdministrator 角色，为案件成员创建保留锁、逐页核对历史及显式释放。保留管理控制物理删除资格，原文访问仍遵守原始期限及独立审批。

## 本地运行

使用 Node.js 22.12+（22 系列）或 24+，在此目录执行：

```sh
npm ci
npm run dev
```

页面为 `http://127.0.0.1:5173`。开发代理默认连接 `http://127.0.0.1:9443`；该端口需运行已按 [管理 API](../../docs/29-api-endpoint-catalog.md) 配置的控制服务。可由操作者设置 `XSHIELD_CONTROL_PROXY=https://control.internal.example` 后启动 Vite；只接受 HTTPS origin 或 loopback HTTP origin，拒绝 URL 用户信息、路径、查询和片段。该变量是开发服务器配置，不进入浏览器 bundle。

代理只转发固定调查 GET、案件列表/集合/保留历史 GET、证据申请列表/详情/内容 GET、精确 `POST /control/v1/search` 及案件、保留创建/释放和证据申请/审批路径；写路径与证据详情/内容路径拒绝附加查询串。服务端要求证据申请列表使用规范 `view=mine` 或 `view=review` 及其后可选的单个 `cursor`，保留历史只接受可选游标。代理剥离 Cookie/Set-Cookie，不注入管理身份、不跟随重定向。连接表单只在页面内存中保存 Bearer；首次成功响应后显示经服务端确认的范围。应用中没有演示数据入口；合成响应仅在 `tests/` 用于回归。

## 查询与安全语义

- 摘要后再读事件；证据目录和单项元数据按点击惰性读取。分页显式触发，每页替换前页，换请求重置游标。
- 审计发布状态由操作者显式读取和刷新；每次读取均由服务端重新鉴权并写 `console.health.read`。连续水位只覆盖该配置 journal 的已确认封存段；缺口、待发布段和未封存段是发布观察，不能替代对其他路径或服务的独立检查。
- 校准报告详情由操作者显式读取和刷新；每次读取均由服务端重新鉴权并写 `console.calibration.report.read`。控制台只接受严格白名单响应；401、范围偏差和晚到响应清空状态。报告正文 tombstone 仅是专用加密正文的保留观察，不会启用内容读取或改变现有校准、策略和业务边界。
- 结构化事件检索输入 UTC 整秒半开时间窗（1970 至 2300，最长 31 天）、1–1000 条页大小及事件时间升/降序。服务端配置可进一步收紧单页上限。最多 8 个条件要求同一事件全部匹配，字段选择限定为 request/event/grant/auth binding/case/artifact/calibration-report/model-call/evidence-access-request/evidence-hold ID、event_type/stage/reason_code/operation_id/model_revision 精确文本、outcome 和 0–10000 整数基点置信度上限。校准报告和保留锁 ID 只定位固定生命周期、保留维护和管理操作历史，不读取正文或授予任何能力；两类过滤均要求同作用域 `AuditAdministrator`，服务端在索引访问前拒绝权限不足的 Investigator。模型调用 ID 只定位固定模型生命周期和 `console.model.read` 历史，详情和证据继续各自重新鉴权。访问申请 ID 只定位固定申请/决策和 `console.evidence.access.read` 历史，详情、审批和原文读取继续各自重新鉴权。详情页的“准备历史检索”只预填 ID，操作者仍须填写 UTC 时间窗并主动提交。原生日期框中的值按 UTC 解释。
- 已提交计划、服务端查询摘要和管理 request_id 可见；下一页沿用冻结计划，编辑即清除旧结果、详情和游标。结果保留 nullable 字段与 RFC3339 微秒时间，扫描统计未知与 0 分开显示，空结果与索引 gap/pending 分别判断。水位只覆盖配置日志源，独立 Outbox 可能仍待发布；分页期间发布或到期可能改变后续可见集合。
- 查询摘要使用浏览器原生 WebCrypto 验证，需要 HTTPS 或 localhost 安全上下文；能力不可用时本地拒绝查询。
- 搜索只读已发布历史事实；请求与证据引用可打开现有详情，但仍需 Observer，Investigator 不隐含该权限。当前资格/绑定有效性、案件归属与原文读取由对应服务分别校验。完整关联图、跨事件遍历与自然语言计划继续迭代。
- `subject_ref` 可精确定位固定顶层主体/身份引用；值限制为 256 UTF-8 字节且不允许控制字符。结果不会回显该值，服务端使用用途隔离 HMAC 生成计划摘要，浏览器不对主体值自行计算摘要。
- 查询类型可切换为模型调用，接受 `mdl_` UUIDv7。结果显示 provider、请求所用 provider_model_id、内部模型/提示版本、置信度语义、因果生命周期及输入/输出/调用记录引用；点击引用沿用单项证据元数据查询。旧记录两项供应商字段均为空时显示“历史记录未提供”，Noul 置信度显示“不适用”。
- “模型调用列表”要求 UTC 整秒半开时间窗（最长 31 天）及 1–100 条页大小，固定按 `(occurred_at DESC, model_call_id DESC)` 返回窗口内可见的最新脱敏记录。页面只显示 `latest_confidence_status`，不显示数值置信度、证据引用、生命周期、概率或供应商正文；游标由服务端绑定身份、范围和窗口，客户端只原样继续分页。点击模型调用 ID 会重新调用单项详情并重新鉴权，列表行不代替详情、当前状态、生命周期完整性或证据访问权。
- 模型的 `complete/pending/partial/not_indexed` 分别表示可见生命周期完整、等待终态、终态前驱不全和当前索引未命中。索引水位只覆盖配置日志源，不表示模型已全部追平；供应商模型标识不代替精确解析版本，评估完成不授予业务操作资格。
- 资格与身份绑定查询接受规范 `grant_` / `auth_` UUIDv7，展示数据库 `as_of`、持久状态和独立时间到期标志。资格记录包含发行代际、操作/视图、策略与来源引用，以及同一快照的当前绑定状态和代际是否一致；绑定详情还包含凭证代际与更新时间。UTC 微秒原样保留，客户端精确核对到期关系，超出 JavaScript 安全整数范围的代际值拒绝展示。匿名、撤销和过期记录可调查，`active` 标签不等于在线准入通过。
- 资格可打开绑定详情和来源请求时间线；“准备历史检索”只预填对应 ID，须填写 UTC 时间窗并主动提交 Investigator 查询。账本观察不附带 ClickHouse 水位，后续查询不构成跨存储冻结快照。`found=false` 显示“当前账本未找到”，不推断历史不存在；主体、凭证、资源指纹、动作引用和约束正文均不进入展示对象。
- `complete` 表示观察到保留的请求终态，不表示索引无缺口。页面分别显示摘要/事件水位和观察时间；水位只覆盖配置 journal，不覆盖所有 Outbox。
- 转发意图不是源站已执行证明，确认源站响应不等于业务成功。缺失判定与 `UNKNOWN`、等待终态分开显示；确定性证明保持空置信度。
- 证据 `found=false` 显示“当前不可用”，不推断对象存在性；manifest 不证明内容读取权或对象侧完整性。locator、密钥引用和密文摘要在客户端投影时丢弃。
- Bearer 不写 URL、日志或浏览器持久存储；所有请求 `credentials: omit`、`cache: no-store`、禁止重定向，读取上限 16 MiB、全程期限 15 秒。凭证须可被浏览器原样编码为 Authorization 头。
- 401、断连、页面离开、刷新或闲置 15 分钟清空会话。更换查询类型、目标与详情选择会使旧响应失效；跨响应 tenant/site 偏差断连。客户端清态不等于服务端凭证撤销，JavaScript 也不提供秘密内存可靠清零保证。
- 403、429 和依赖失败显示固定安全文案、稳定代码及管理 request_id；用户显式重试，不自动重试或释放原文。

## 案件工作台

案件使用流程：选择“案件工作台”→读取“我的案件”→打开集合，或填写用途与幂等键创建新案件→加入 artifact 引用→显式刷新集合→填写理由关闭。本人列表包含 open/closed，按案件 ID 降序逐页替换，保留数据库微秒观察时间和管理请求 ID；各页独立观察，创建或关闭后请显式刷新。按 ID 打开仍可使用，列表打开会重新读取当前集合。集合分页显示 `active/expired/deleted/unavailable`；状态不证明内容读取权或对象完整性。列表不代替未知写入的原键确认，切换调查类型清除列表与游标。

写入后表单冻结原键、目标及参数。首次明确拒绝可重新准备操作，未知结果只能原样重试；后续拒绝不能消除早先未知结果。冻结请求在调查类型切换时保留，401、闲置、页面离开、刷新或断连后清空。未确认操作触发原生离页提醒；操作者须先安全保管界面显示的原路径、键和正文，重新鉴权后填写这些值恢复，禁止用新键推断重试不会产生重复创建。默认键来自浏览器随机 UUID，键不作为授权凭证。

## 证据访问工作台

选择“证据访问”，填写本人案件 ID、证据 ID、申请理由和幂等键。提交后显式刷新“我的申请”，或使用返回的申请 ID 读取详情。独立审批人选择“审批待办”并读取列表，打开目标复核申请人、理由、目标、历史决策和数据库观察时间。批准须填写理由和明确秒数，受服务端上限及证据期限限制；拒绝可终结目标已失效的 pending 申请。每次操作仍由服务端重新检查角色、主体和当前状态。

列表按申请 ID 降序，每页是独立实时观察；已批准/拒绝的记录可能在后续待办页消失，新申请需刷新首页发现。列表不代替冻结原请求的未知写入确认。视图切换、调查类型切换与会话清态使旧列表/游标失效，打开申请重新读取当前详情。客户端校验响应视图、作用域、记录状态、严格降序、微秒时间和游标末项绑定，只保留白名单元数据。

变更冻结原路径、原键和正文，未知结果只允许原样重试；切换调查类型保留恢复参数，401、闲置、页面离开、刷新和断连清空会话。刷新后可显式勾选恢复原访问申请，或读取详情并恢复原审批请求，由服务端确认精确幂等结果；恢复后遭拒绝仍保持未知，直至有效成功响应确认原操作。申请/批准/拒绝的结果与附件读取分别记录管理请求 ID。

获批申请人以 SensitiveEvidenceReader 凭证读取详情后点击“下载原文（.bin）”。客户端校验二进制响应的服务端范围、申请/证据目标、媒体类型、附件属性和完整字节长度，15 秒总期限内有界读取至多 64 MiB，保留字节形成 Blob，并交给浏览器保存 `.bin` 文件。原文不进入页面内容或持久浏览器存储，临时对象 URL 在使用后释放；清态或切换目标抑制晚到下载。浏览器内存与系统下载管理器不提供可靠清零保证；已交给浏览器的附件由操作者管理，界面提示不证明磁盘保存完成。

控制服务须先升级以提供 29.13 的六个二进制身份/长度响应头，代理必须透传并禁止缓存与正文日志。详情和当前 approved 状态仅供复核，不代替内容端点的重新授权。企业身份、MFA、再认证及服务端浏览器会话仍为生产启用前置要求。

## 证据保留工作台

选择“证据保留”后，AuditAdministrator 按案件 ID 读取历史；新建须填写案件成员 artifact、理由和规范 UTC 毫秒期限，从列表选择记录或填写 hold ID 可执行释放。创建和释放由服务端重验作用域、目标、容量及期限；管理员可处理同作用域其他主体的案件。每页显示数据库微秒观察时间、原始保留期限及释放主体/理由/时间，按 hold ID 升序分页。新建期限最多为数据库当前时间之后 720 小时；过期原参数仍可用于精确重试。保留延缓物理删除，内容读取继续受原期限与独立审批限制。

每条历史记录可“准备历史检索”，只清空当前结果、预填对应 `evidence_hold_id` 并切换到结构化检索，不会自动提交。Investigator 与 AuditAdministrator 仍由服务端分别校验，时间窗保持为空，须由操作者填写后主动查询。

变更提交后冻结路径、原键和全部参数。超时、断网、响应契约失败及晚到结果保持未知，须按原请求显式重试；后续拒绝不能清除先前未知状态。首次拒绝或确认成功后可准备新操作，创建/释放后显式刷新历史。切换案件或调查类型使旧查询失效，冻结写入保留；会话结束清空内存并对未确认操作提示离页。重新鉴权后可勾选恢复请求并填写保存的原参数，页面不会把历史记录当作幂等确认。

首次启用先暂停全部旧版清理任务，再应用迁移 0020、升级保留感知清理服务及 outbox/管理 journal 发布器、控制 API、控制台和同源代理路由，完成验收后恢复清理。界面回退保留已经提交的锁和历史，仍须使用支持保留锁的清理服务。保留管理复用现有管理身份边界，生产入口要求见下一节。

## 构建与部署边界

```sh
npm run build
```

`dist/` 是静态产物。部署到专用管理 origin，由同源受控反向代理将 `/control/v1` 指向控制服务；生产环境必须使用 TLS、网络隔离和企业身份入口，配置 MFA、凭证发放/撤销及会话策略。当前版本的浏览器连接使用机器 Bearer，尚未实现 OIDC/MFA 登录或服务端浏览器会话，因此不能宣称达到 15.3 的完整生产身份要求。Vite dev/preview 只供本地开发，不是生产管理边界。

静态服务器应返回 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`，并以响应头设置：

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

API 同样保持 `private, no-store`。生产代理仅向指定控制服务传递 Authorization，剥离业务 Cookie，禁止缓存、重定向和请求/响应正文日志；日志须脱敏认证头。不要把秘密放进 `VITE_*` 或静态配置。案件列表启用前先应用迁移 0021 并升级管理 journal 发布器，见 [29.22](../../docs/29-api-endpoint-catalog.md#2922-已实现的本人案件列表契约)。证据申请列表启用前先应用迁移 0022、升级管理 journal 发布器，再部署控制 API 与界面；索引构建需要安排写入维护窗口，回滚应用可保留索引，见 [29.24](../../docs/29-api-endpoint-catalog.md#2924-已实现的证据访问申请列表契约)。模型调用列表依赖支持其固定窗口、签名游标和 `console.model.list` 审计的控制 API。校准报告详情须先升级至能识别 `console.calibration.report.read` 的管理 journal 发布器，再启用控制 API 与界面；无新增 migration 或 secret。批量导出继续独立交付。

## 验证

```sh
npm test
npm run build
npx playwright install chromium --only-shell
npm run test:e2e
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

Node 单测覆盖请求/响应边界、模型生命周期一致性、校准报告严格白名单 projection、发布快照的白名单字段与计数关系、精度、空值、取消、超时和流式上限。Playwright 使用真实客户端加显式合成 HTTP 响应，覆盖校准报告和审计发布状态的显式读取/刷新及会话隔离、分页、模型查询与引用详情、Noul/历史空字段，以及搜索 POST 正文、冻结计划分页、编辑失效、输入边界、空结果与 gap、可空事实和独立角色权限。共享回归覆盖 403/429/503、401/闲置/页面离开/刷新清态、异步响应隔离、跨范围拒绝、文本注入及 1536/390 像素布局；默认不记录截图或 trace。需要本地截图时显式将 `XSHIELD_CONSOLE_SCREENSHOT_DIR` 设为仓库外临时目录，验收后清理。

Rust 跨语言测试启动真实 Axum 路由、复用合成 ClickHouse 行和管理 journal，验证摘要、事件分页与微秒时间、目录依赖故障和 401，以及完整 Gateway Choice、旧记录 Noul 部分生命周期、模型未命中、预算 429 和模型访问审计。浏览器回归的 manifest 成功数据是合成契约，不代表已在生产数据源或企业 SSO 上验收。

搜索 wire 回归覆盖 nullable 字段、RFC3339 微秒、升降序游标、扫描统计与未知值、预算 429、篡改 HMAC 游标 400、Observer 查询 403，以及七次 `console.query.executed` 耐久审计。以上两项 wire 测试使用真实 HTTP 路由与合成索引，不执行外部模型调用。

账本 Node 回归覆盖目标/版本/空值、状态与代际一致性、微秒到期边界、未知字段投影和固定错误诊断。浏览器验证资格→绑定/来源请求、显式历史检索、生命周期状态、权限失败与会话隔离。独立账本 wire 使用真实 PostgreSQL 测试数据、Axum 路由、Node 客户端和加密管理 journal；范围为隔离合成记录，不代表生产数据或企业身份入口验收。

案件 Node 回归验证固定路径与键、UTF-8/控制字符边界、目标/状态/分页一致性及显式重试；本人列表额外验证严格降序、游标位置和白名单投影。浏览器覆盖列表分页/打开、创建→浏览→关联→关闭、断网/超时与原键恢复、未知后再次拒绝、切换调查类型和目标后的冻结参数、401/闲置/刷新清态、独立 Observer 权限、文本注入及桌面/移动布局。案件 wire 使用真实 PostgreSQL、Axum 和 Node 客户端，覆盖本人 open/closed 列表、范围隔离、连接池整体超时、SQL 锁超时、断连创建恢复、幂等重试/冲突、关联及分页、关闭后约束、外部所有者不可用、401/403，并复核案件、outbox 和管理 journal。独立列表故障测试验证断连后完成审计、预读坏行整页拒绝和审计失败扣留结果。测试仅使用隔离合成记录。

证据访问 Node 测试覆盖请求与决策的规范参数、精确重放、微秒期限和历史状态、未知字段投影、二进制目标/范围/安全响应头、实际长度、64 MiB 上限、单字节分块、取消与读体超时。浏览器使用合成响应验证申请→复核→批准/拒绝→精确字节下载、恢复未知操作、历史状态限制、会话清理、错绑/跨范围响应、晚到下载抑制、文本注入和桌面/移动布局。独立 wire 使用真实 PostgreSQL、Axum、Node 客户端和加密 vault，验证独立审批、幂等冲突、17 字节原文、过期/关闭约束及 outbox/管理审计；不访问生产证据或企业身份服务。

保留管理 Node 回归检查固定路径、原始参数、毫秒期限和微秒观察、释放字段完整性、升序分页/游标绑定与安全错误。浏览器以合成响应验证创建、历史分页、释放、原键恢复、异步与会话隔离及桌面/移动布局。独立 `console_hold_client_mutates_postgres_http_contract` 使用真实 PostgreSQL、Axum、Node 客户端和管理 journal，验证独立管理员处理其他调查员案件、跨租户/站点与角色拒绝、幂等冲突、成员约束、关闭后释放、事务 outbox 及原始内容期限保持。所有数据为隔离测试记录，生产企业身份验收继续独立执行。

## 依赖与维护

运行依赖仅 `react` / `react-dom`（MIT），负责界面与 DOM 更新。构建依赖 `vite`（MIT）和 `typescript`（Apache-2.0），类型依赖 `@types/react`、`@types/react-dom`、`@types/node`（MIT）；`@playwright/test`（Apache-2.0）仅用于真实浏览器回归。全部直接依赖固定版本并提交 npm lockfile；依赖升级通过审查，重新执行类型、构建、API、浏览器及 Rust wire 测试。安全修复优先处理，主版本升级需核对 Node 兼容性。复用全局 npm 和 Playwright 浏览器缓存，不为临时分支重复安装。

工具依据：[Vite 指南](https://vite.dev/guide/)、[React 构建指南](https://react.dev/learn/build-a-react-app-from-scratch)、[Playwright 测试服务器](https://playwright.dev/docs/test-webserver)。
