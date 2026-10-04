# 变更记录

## Unreleased

- 修复 Gateway 静态资源兜底绕过默认拒绝：该兜底默认以深度 5 对所有站点开启，且扩展名取最后一段 `rsplit('.')` 的结果，导致任意位置的 `.json`/`.map`、与扩展名同名的无点路径（`/api/json`、`/css`、`/search/png`）以及 `/admin/users;.js` 这类分号后缀都在无身份、无精确 operation 的情况下被放行，与“API 路径保持拒绝”的文档不符。现在该兜底按站点显式开启（`static_asset_max_path_depth` 为 `0` 或缺省即关闭，字段名不变）；开启后只放行 GET，路径经一次严格百分号解码后以解码文本判定，最后一段必须有真实的点、非空主名且扩展名属于 `js css ico png jpg jpeg gif svg webp woff woff2 ttf`；`.json` 与 `.map` 移出列表，`;`、反斜杠、`%2F`、点段与空段、控制字符、`?`/`#`、双重编码、空格和非 ASCII 字节一律拒绝。已存在站点策略里保存的 `5` 仍然有效，直到重新保存；`scripts/register_juice_shop.py` 已显式设置 5。原测试把“默认深度 5、默认策略放行 `/chunk.js`”当作期望，现改为断言默认关闭并在测试中显式开启。

- 修复管理 API Key 管理操作无审计、轮换会破坏旧 Key、`last_used_at` 永不更新：此前签发三个 Key 产生 0 条审计事件，撤销和列表成功路径也没有事件，Key 主体是不受约束的自由文本且 Key ID 从未入审计；`rotate` 先撤销旧 Key 再解析请求体，坏请求留下已失效的旧 Key 而没有替换；`last_used_at` 从未被写入。现在创建、撤销、轮换（旧/新两条同批事件）和列表都追加成功事件，Key ID 记录在新增的强类型 `target_api_key_id`（worker 发布器严格校验前缀、仅限管理事件且成功必带，需先升级发布器再启用）；变更按“校验、事务暂存、持久审计、提交”执行，审计失败回滚并返回 503 `AUDIT_DURABILITY_FAILED`，不返回明文也不留下半成品；`rotate` 先校验后在单个事务中交换，并发轮换恰有一个成功；认证成功后每个 Key 每分钟最多写一次 `last_used_at`（节流在 UPDATE 内）。`subject` 限定为 1–128 个 ASCII 标签字符、`display_name` 拒绝控制/零宽/双向覆盖字符且不做静默规范化，违规返回 400 `CONTROL_API_KEY_SCOPE_INVALID`；`subject` 不要求租户内唯一（凭证以 Key ID 区分，审计主体带 Key ID）。存储层以暂存事务取代原有的创建/撤销函数，并删除了每次调用都写 `last_used_at` 且无人使用的 `lookup_management_api_key`；scope 查询新增 scope 行必须属于 Key 所属租户的约束。

- 修复无效 API Key 洪泛耗尽审计 journal：认证 Key 的路径此前没有未认证限流预算，每个垃圾 Key 都无条件追加一条持久审计事件（路由随后还会再追加一条），3000 个垃圾 Key 即可写满 1 MiB 的 journal，之后所有请求（包括合法 Bearer）都返回 503 `AUDIT_DURABILITY_FAILED`。现在每个携带 `X-Xshield-API-Key` 的请求先取一个进程级未认证预算配额，再查询 Key 和写审计；预算耗尽返回 429 `CONTROL_RATE_LIMITED` 且不写 journal，预算内的尝试恰好留下一条 `console.agent_api_key.use` 终态事件，被拒绝的 Key 请求不再运行路由，有效 Key 归还配额。无效 Key 的响应码改为 401 `CONTROL_API_KEY_INVALID`（缺少 Agent Run ID 仍为 401 `CONTROL_AUTH_REQUIRED`）；垃圾 Key 耗尽预算期间合法 Key 会收到可重试的 429。

- 修复管理 API Key 的授权越界：此前 Key 的角色在多个 scope 行之间累加并与站点并集相乘（站点 A 写、站点 B 读的 Key 可以 `PUT` 站点 B），`site.config.write` 与 `site.create` 同映射 `SystemAdmin`（仅写 Key 可 `DELETE`，默认站点的写 Key 可签发带 `site.create`/`apply_direct` 的新 Key），`site.read` Key 还能读取 `/auth-bindings`、`/grants` 和 Key 列表。现在 Key 不再有任何角色，鉴权对每个 `(站点, 能力)` 只看点名该站点的 scope 行：`site.read`、`site.health.read`、`site.config.write`（只更新）、`site.config.validate`、`site.config.apply_direct`（仅 apply）、`site.rollback` 各自只放行 15 章列出的路由；`site.create` 必须使用租户级标记 `site_id=__tenant__`，只创建、不覆盖已存在站点，`PUT` 也不再能创建站点；`DELETE`、独立审批和全部调查/证据/案件/导出/会话路由对 Key 关闭。Key 管理仅限带 CSRF 的 OIDC 浏览器会话（此前代码还接受静态机器 Bearer，已按 docs/15 修正），签发者只能授予自己能行使的能力（否则 403 `CONTROL_API_KEY_SCOPE_FORBIDDEN`）；站点列表与工作台只投影 Key 的 `site.read` 站点，租户范围的浏览器 SystemAdmin 保持整个租户；直接应用标志只在 apply 路径中那个站点上成立；Key 主体以 `apikey:{key_id}:{subject}` 进入全部审计与 `updated_by`。控制台需把 `site.create` 作为 `site_id=__tenant__` 的独立 scope 行提交，并识别新增的 400 `CONTROL_API_KEY_SCOPE_INVALID`、403 `CONTROL_API_KEY_SCOPE_FORBIDDEN` 与 409 `CONTROL_API_KEY_SITE_EXISTS`；库中已有的“具体站点 + `site.create`”行不再授予任何权限，需重新签发。

- 修复管理审计发布器拒收控制面已产生的事件：`console.workbench.overview.read`、`console.site.config.approve`、API Key 管理/使用和导出全族（`console.export.read`、`export.requested/approved/denied/downloaded`）此前不在发布矩阵中，任何一次调用都会使所在 journal segment 无法发布并阻断其后的管理历史。发布器现按固定路径、强类型 `target_export_id`、成功原因码和下载证据绑定校验这些事件；新增 `scripts/check_audit_event_coverage.py` 并接入 CI，让控制面新增端点缺少发布矩阵项时直接失败。工作台改为展示真实的 edge 探测、edge 审计屏障状态和最近一次持久化的上游健康观察（各带观察时间），不再把每个来源写死为不可用；edge 健康接口不再硬编码 `audit_state=healthy`。

- 落地多站点运营增量并修复收口问题：迁移 0041–0049、站点配置与应用 API、工作台快照、Agent API Key、edge 动态监听与签名快照、控制台管理后台和安全靶场进入版本库。请求摘要与事件时间线在索引失败时不再返回空的 200：只有本地 journal 的认证命中可以代替索引结果，否则保持 `CONTROL_INDEX_UNAVAILABLE`/503；本地 journal 扫描在阻塞线程上执行。`inspect_publication_health` 只把未封存的活动 segment 计为待发布，不再把已关闭 segment 的字节误计为活动尾部（此前会让空闲系统永久显示一个待发布段，并掩盖在测试期望里），补充回归。工作台站点列表在满页时标记 partial。修复 clippy 和控制台 Playwright 的移动端抽屉与角色导航断言，库验证报告随新增 JSON 文件重生成。

- 收口调查导出包的并发生成：迁移 0040 以 tenant/site/export claim、长度前缀父引用摘要和短 lease 串行化 vault 写入；过期 lease 可回收，旧 writer 不能提交 ready，claim 与 ready 在同一 PostgreSQL 事务内完成，并补充 Busy、参数冲突、损坏、过期回收、精确重试和级联清理回归。

- 收紧调查导出包完成的幂等边界：`ready` 记录只有在 artifact、包请求、摘要和字节数全部精确匹配时才接受重试；错绑元数据返回存储损坏并扣留结果，补充 PostgreSQL 回归。

- 修复调查导出包在批准提交结果未知后的重试边界：包请求 ID 固定由 `export_id` 派生，重试会按固定 scope、类型、父引用与期限复用已发布 catalog 对象，避免重复活动包；增加稳定 ID 回归和 PostgreSQL 包完成精确重放覆盖。

- 增加离线校准批量读取 capability/port 契约：`calcap_` 精确冻结 tenant/site、有效期、四份分区 manifest、model-record/label artifact 对及 role、样本和聚合字节上限；请求只接受 capability 导出的成员引用，拒绝跨 scope、过期、集合外、角色偏差及不同 capability 的引用。该边界与控制台单对象证据读取隔离，当前仍未实现 capability 发行/持久化、消费状态、catalog/vault 内容读取、读取审计或真实校准。

- 增加离线校准报告发布元数据契约：`calr_` 报告 ID 和独立 report artifact 只投影冻结的批准、数据集/标签/任务/映射/阈值策略修订、四份 manifest 与模型身份；拒绝 report artifact 与 manifest 或样本来源 artifact 别名，保留显式未知的 resolved revision。`calibration.reported` 仅定义受限元数据 schema/消费契约，不包含样本、标签、概率、指标或供应商正文，也不实现 evidence 读取、报告持久化 producer、阈值/策略发布或真实校准。

- 增加离线校准数据集领域契约：样本分别绑定模型调用和标签 artifact，冻结批准、数据集/标签/任务/映射/阈值、模型与提示修订及四份分区 manifest；拒绝分区与样本来源、样本角色之间的引用别名、重复、模型或映射漂移，并保留调用 ID、模型记录、标签证据三元关联。该纯 Rust 层不执行证据读取、持久报告或真实校准，引用不同也不证明外部内容独立。

- 将批准的风险概率映射接入离线模型评估：完整候选/档位分布按版本化类别聚合，未知质量触发弃权，调用证据保留三类原始质量与映射修订。

- 增加纯 Rust 离线阈值评估内核：有界唯一调用样本、三态真值和缺失原因，输出九格计数、明确分母的错误率/覆盖率、可靠性桶及 Brier，提供合成示例和公开 API 回归。

- 增加 Jev Score 离线评估：严格有序档位、概率与加权评分校验，保存完整档位和原始供应商证据，接通模型审计查询及控制台；补齐 Gateway 官方费用元数据解析和真实 PostgreSQL、HTTP 客户端回归。

- 增加控制台证据保留工作台：管理员创建、分页查询和释放案件成员保留锁，展示数据库观察时间及释放历史；冻结写入支持原键恢复，客户端校验目标、时间、游标和响应范围，补齐真实 PostgreSQL/HTTP 客户端回归。

- 增加证据申请发现与审批待办：本人历史和独立审批队列按申请 ID 有界分页，签名游标绑定凭证、主体、作用域与视图；控制台可打开记录复核详情，迁移 0022 提供排序索引，列表访问具有独立终态审计。

- 增加控制台证据访问工作台：提交申请、复核理由和历史决策、独立审批/拒绝及获批附件下载；写入冻结原键与参数，下载校验服务端范围、目标与完整字节数。

- 增加证据访问申请详情 API：按申请主体和同站点审批角色限定可见性，复核申请理由、历史决策及目标状态，提供有界只读快照、断连终态审计和严格发布契约。

- 完善原文申请、审批及读取的有界执行与断连终态审计；锁等待后重新验证对象和资格期限，批准期限从锁后数据库时间计算，安全请求头按单值解析。

- 增加 Investigator 本人案件发现闭环：PostgreSQL 有界降序键集分页、签名游标、独立访问审计和控制台列表/打开；迁移 0021 添加 owner/scope 排序索引，包含关闭案件及断连终态验证。

- 接通 `AUTHENTICATED_ROOT` 的 `auth_revoke` 响应：冻结快照后原子撤销绑定及全部活动/过渡凭证，提交完整 `binding.revoked` outbox，并让身份发布器严格校验该事件；加入 HTTP/PostgreSQL 回归和秘密排除检查。

- 接通限资源分享的 HTTP 响应发行：冻结本次准入的精确来源资格，完整 JSON 与注入大小校验后原子发行并返回凭证；加入用途独立密钥、固定目标规则、私有缓存策略与响应清零。

- 实现通用资源资格 `grant.issued` 的完整 v3 生产契约、原子 outbox 和按族发布，加入真实 PostgreSQL/ClickHouse 回归；强化锁等待过期、撤销重放及冻结时间精度检查。`GrantPersistence::new` 接受冻结 trace_id，签发事务按 JSONB 约束表示生成事件；HTTP 发行适配器继续交付。
- 实现单次 Jev 离线评估 CLI、严格 Choice/Noul 转换、固定 HTTPS、限流/超时/取消终态、加密输入输出证据与目录审计，以及中断恢复和 `model.*` 索引解析。

- 实现受保护入口缺失 WAF Cookie 时的有界匿名空会话、原子 `session.created` 审计、401 安全 Cookie 响应，以及进程内、分布式来源/站点速率和并发容量控制。
- 建立 Rust Cargo workspace 与 M0 核心领域边界。
- 实现禁用站点的可审计 `NOT_CONFIGURED` 阶段树和失败关闭测试。
- 增加独立管理身份、Mock ports 及 Rust/文档联合 CI。
- 实现 M1 认证组合强绑定、匿名空账本与不可变身份快照领域规则。
- 实现同上下文凭证刷新、身份 epoch 轮换、撤销和旧响应失效规则。
- 实现资源、操作、视图和身份 epoch 精确匹配的有界幂等资格账本。
- 增加 M1 PostgreSQL 版本化 migration、CAS/epoch/outbox 集成验证及 CI 服务。
- 增加 SQLx PostgreSQL 身份刷新适配器，原子提交 generation、凭证状态和 outbox。
- 将业务授权上下文引用纳入认证建立、刷新、切换、资格提交和 PostgreSQL CAS；同主体范围变化推进 epoch，升级时撤销无法证明上下文的旧绑定。
- 增加 PostgreSQL 资格发行事务，校验身份、动作、策略、期限与容量，并原子写入 outbox。
- 实现受验证页面证据、批准动作描述和动作资格领域校验，拒绝目标、字段、方法与路由扩张。
- 增加 M1 UI 来源 migration，以同租户外键绑定页面证据、批准动作描述和动作资格。
- 增加 UI 来源 SQLx 事务，重验身份和批准描述，原子写入页面证据、动作资格及 outbox。
- 实现 operation 入口分类与准入矩阵，精确组合方法、路由、身份、UI 动作及资源资格。
- 实现限资源只读分享与服务身份 operation 集合证明，并接入专用入口准入。
- 增加 Pingora MVP 网络入口：可信 JSON 配置编译精确操作，固定源站转发，未配置及缺少证明的受保护请求在源站前拒绝。
- 增加本地耐久审计 journal：AES-256-GCM 记录、持久 receipt、CRC32、段内哈希链、单写者锁、目录配额、私有权限及不完整尾部恢复。
- 将 Pingora 准入接入 journal 持久屏障：转发前原子记录请求、阶段、判定与转发意图；记录失败或配额不足时关闭源站转发，并在响应后写入终态事件。
- 增加受保护根入口的 PostgreSQL 身份读取端口：精确核对 WAF 会话 HMAC、Bearer HMAC、当前 credential generation、身份 epoch 与服务端期限，读取失败时审计并关闭转发；转发前剥离仅供边缘使用的 WAF Cookie。
- 接通无资源、无请求字段 UI 动作的网关闭环：按 `X-Xshield-Action-Ref` 从 PostgreSQL 重建并重验页面证据、活动描述符、策略、认证 epoch、方法、路由和期限；缺失、替换、退休均在源站前拒绝，并剥离边缘动作头。
- 接通 GET 查询资源资格闭环：策略声明资源参数后，从实际 URI 严格提取字段和值，以租户隔离带域 HMAC 匹配 PostgreSQL ResourceGrant，并对未知资源、operation/view 偏差、字段扩张和歧义编码关闭转发。
- 增加关闭 journal 段的完整验证与 Ed25519 签名清单：提交整段摘要、链头、序号和密钥标识，读取时精确匹配段内容，并以原子、不覆盖方式写入独立私有位置。
- 增加 journal 字节阈值自动轮转和独立 `xshield-audit-seal` 封存命令；封存进程可与 edge 并行验证关闭段，重复运行会重验已有清单并保持幂等。
- 增加签名关闭段的认证流式读取边界；完整段与清单先精确匹配，每条事件再重验 CRC、AEAD、序号及哈希链，并提供正文摘要支持下游检测同 ID 异内容冲突。
- MSRV 更新为 Rust 1.94；锁定 SQLx 0.9.0 与 Tokio 1.51 LTS 依赖线。

## 3.0 — 2026-09-17
项目正式命名Xshield，Rust主语言。整合前置JS/加密接管、受控回退、严格界面来源准入、资源操作账本、WAF与业务认证强绑定、分享例外与AI适配。

新增每层决策事件、置信度语义、证据库、耐久journal、ClickHouse索引、查询/案例/导出/离线回放、调查Agent与后台自身审计；增加开发规范、契约、数据库草案、运维和验收库。

不再默认要求业务SDK/Guard；不再为无资格直接URL、新浏览器、未刷新资源做隐式兼容。一天是可配置会话最大租期。历史ID不授予任意操作，UI动作来源必须经批准。普通凭证替换拒绝，合法续期和换身份区分。

当前交付为设计与合成验证资料，未交付可运行WAF、真实模型基准或生产部署。
