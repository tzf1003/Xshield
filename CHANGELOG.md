# 变更记录

## Unreleased

- 限制站点健康观察的无界增长：任何 Observer 都可以反复执行站点健康读取，而每次读取都会向 `site_health_snapshots` 追加一行；该表现在于同一事务内只保留每个站点最新的 64 条观察（`HEALTH_SNAPSHOT_HISTORY`），工作台和健康接口只读取最新一行，不受影响。真实 PostgreSQL 回归覆盖保留数量、其他站点历史不受影响和最新观察保留。

- 控制台重做第 1 阶段（站点接入与发布，只改 `web/console/`，不改后端）：站点列表改为可搜索表格；新建站点改为五步向导（`/sites/new/{basics,upstream,entry,routes,review}`，旧的 `/sites/new/network` 等地址重定向到对应步骤）；站点详情加入生命周期步骤条、跨分类的未保存变更栏与字段差异、路由表格加抽屉（最多 256 条）；发布页并排显示 edge 在用与已暂存的修订，按两个修订的已存储配置复算“为什么需要审批”，批准/应用/回滚先经确认框，批准带 `X-Xshield-Expected-Config-Digest`，回滚按服务端规则说明目标并提示会创建新修订，删除站点需逐字输入站点 ID 并完成 MFA step-up（被拒绝的请求原样保留、可原样重试）。新增站点原因码词典（单测扫描 Rust 源码，缺码即失败）；全部站点页面迁到 guarded 读取层和“待确认操作”登记，旧 `SiteConfigPanel`/`SiteOperationsPanel` 删除。批准、应用或回滚针对已保存的修订，动作之后的重新读取不会替换未保存的草稿。已知限制：回滚目标的生效顺序没有读取 API，控制台只能说明规则、不能点名；列表 API 不返回上游地址；`scripts/test_console_oidc.mjs` 的站点步骤仍是旧页面的选择器，本阶段没有更新（需要 `./dev.sh` 的真实 OIDC 环境）。

- 增加发布打包脚本 `scripts/package_release.sh`：构建 7 个 release 二进制与控制台静态包，附迁移、ClickHouse 结构、示例配置和部署/运行手册，生成带文件清单与 SHA-256 的 tar.gz。输出目录必须显式给出且不得在仓库内，使大体积构建产物可放在外接大容量磁盘上（含 exFAT 外接盘上使用 APFS 稀疏包的做法，见 19.7）；不构建镜像、不签名、不部署。

- 增加调查导出发现与审批待办 API：`GET /control/v1/exports?view=mine|review` 按导出 ID 降序有界分页，`mine` 含本人全部持久状态，`review` 仅 Approver 可见他人 `pending_approval` 导出；游标绑定凭证、主体、作用域、视图与页大小，条目只投影元数据，不含用途、决定理由与包标识。列表访问写独立 `console.export.list` 审计（成功 `CONTROL_EXPORTS_READ`），worker 发布矩阵、封闭原因集和覆盖检查同步扩展；迁移 0050 增加加法排序索引并纳入开发库 reconciliation。控制台接入和 Vite 代理放行属于后续前端增量，本次未改动 `web/`。

- 修复站点删除既无独立审批也无 step-up：`DELETE /control/v1/sites/{site_id}` 会把受保护站点从 edge 移除，却只要求 SystemAdmin 角色（持有 `site.config.write` 的 Agent API Key 同样映射为 SystemAdmin，可以删除）。现在与原文读取、导出审批一样要求同一浏览器会话两分钟内的 MFA step-up，否则返回 403 `CONTROL_SITE_DELETE_STEP_UP_REQUIRED` 并写 DENY 审计；机器 Bearer 和 Agent API Key 没有 step-up 路径，因此不能删除站点，且没有可授予的删除能力。通过 step-up 的删除沿用“暂停 → edge 确认 → 删除”流程，暂停修订的预授权由存储记录为绑定该修订的 `delete_step_up` 审批。控制台需要在删除前引导用户完成“重新验证高危操作”，并为 `CONTROL_SITE_DELETE_STEP_UP_REQUIRED` 提供提示。

- 修复站点回滚完全不可用且目标选择错误：存储的修订缺少 `policy_revision` 而回滚的请求反序列化要求它，所以每次 `POST /rollback` 都返回 400 `CONTROL_SITE_CONFIG_REQUEST_INVALID`；目标取 `active - 1`（上一个修订号），而不是先前 active 的修订，可能选中从未批准或从未服务的修订。现在修订保存完整配置（旧行由 `policy_revision` 列补全读回），目标按 edge 确认顺序取先前 active 的修订，存在未完成变更时取 active（即取消该变更）；回滚以该内容创建**新修订**（修订号不复用），与其他保存一样按基线评估审批、校验、写审计，并在目标解析之前识别同键重放（返回原结果，后续写入后重放返回 409 `CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED`）。端到端测试覆盖 mock edge 收到的配置与 r2 时完全一致、编号跳过未批准修订、取消待处理变更、重放和不可回滚。

- 修复站点四眼审批可被绕过的一组缺陷（新增迁移 0051）：`requires_approval` 过去按上一份 *desired* 修订重算并在每次保存时覆盖，所以风险变更第一次返回 `requires_approval=true` 且不应用，用新幂等键重放同一内容却返回 `false` 并发布到 edge；谓词还漏掉降级路由准入、清空 WAF 片段、关闭对象级校验和调高限额。现在写入事务内以 edge 正在服务的 active revision 配置为基线，用 `xshield-core` 的纯函数 `assess_change_risk` 判定：首次上线/取消暂停/draft→active、下线以及任何安全相关字段变化都需要审批，只有 `display_name`、`policy_revision` 标签和顺序变化不需要，且无法通过重提交清除；仅绑定 `(desired revision, 配置摘要, apply_id)` 的审批记录（追加式 `site_apply_approvals`）可清除。审批在持有租户锁和 intent 行锁的单个事务内读取 revision、apply_id 与作者：旧幂等键对新修订重放返回 409 `CONTROL_SITE_APPROVAL_REVISION_MISMATCH`（此前对未审阅的修订返回 200），可选 `X-Xshield-Expected-Config-Digest` 固定所审阅的配置，作者自批由事务内比较和数据库 CHECK 双重拒绝。`site.config.apply_direct` 语义保留，但直接应用写入 `direct_apply` 审批记录和 `EDGE_DIRECT_APPLY_*` 终态审计，并清除要求，不再留下阻塞其他站点的过期标记。
- 修复 draft 站点被当作线上站点发布：draft 不再进入快照也不被标成已应用，`POST /apply` 对 draft 返回 409 `CONTROL_SITE_DRAFT_NOT_APPLICABLE`；draft→active 需要审批。此前一个待审批站点会让租户内所有 apply 失败（`CONTROL_SITE_APPROVAL_REQUIRED`），现在快照把它保持在最后一次获批配置（从未应用的则缺席），其他站点照常发布；desired 无法编译的同级站点同样保持原配置并在自己的状态上标为失败，目标站点自身不满足条件时以 `CONTROL_SITE_POLICY_INVALID`/`CONTROL_SITE_PORT_UNAVAILABLE` 失败并写入其状态。读取租户状态与分配快照 revision 改为同一事务，使 revision 顺序与内容新旧一致。
- 修复幂等只覆盖最近一次写入：每个修订保存其幂等标识，重放更早写入的键返回 409 `CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED` 而不是用旧内容创建新修订（丢失更新）。限额调优、`policy_revision` 标签变化的审批判定随之改变（旧单测 `policy_approval_allows_bounded_tuning_but_blocks_security_downgrades` 编码的是被修复的行为，由 core 表驱动测试取代）；创建站点的契约测试改为创建 `active` 站点，因为 draft 不再有可申请的审批。
- 修复控制面校验接受 edge 编译器会拒绝的站点配置：edge 快照整体替换，一个站点含有空格或非 ASCII 路由路径、保留的 `/__xshield/` 前缀、同前缀的两条 `{param}` 路由、被 `{param}` 路由遮蔽的固定路由、超过 64 条 `{param}` 路由，或越界的请求/响应 crypto 参数、`SENSOR_HTML` 响应模式、IPv6 公开 origin、过长站点 ID、超过 5940 秒的匿名会话 TTL，就会让整个租户所有站点的 apply 返回 422。`xshield-core` 新增 `SiteConfig`（含 `validate`、有效策略与 edge 配置投影，由 control 视图直接复用），`SitePolicyConfig::validate` 拒绝 edge 会拒绝的一切；`xshield-gateway` 新增 `site_config_parity` 测试，把每个样本和数万个确定性组合经同一投影送入真实 edge 编译器，核心接受而 edge 拒绝即构建失败。控制面生成的 edge 配置随之修正：身份存储按有效路由实际需要输出，匿名会话创建速率随 TTL 缩放，sensor origin 去除末尾斜杠。

- 修复站点上游 SSRF 防护绕过：`Url::host_str()` 给 IPv6 加方括号，文本 IP 检查对 `[::1]`、`[fd00::1]`、`[fe80::1]`、`[::ffff:127.0.0.1]`、`[::ffff:169.254.169.254]` 从未命中，Observer 的 `GET /health` 曾借 `[::ffff:127.0.0.1]:PORT` 让控制面向回环监听器发送 `GET /secret-internal-path`；IP 字面量 `upstream_server_name`（如 `127.0.0.1`）加公网地址曾使探测连接 `127.0.0.1:80`，探测也忽略配置端口。现在上游地址按类型化套接字解析，保存与探测连接前由 `xshield_core::site::upstream` 按数值分类，拒绝回环、私网、共享地址、链路本地、唯一本地、组播、保留/文档段、云元数据以及 IPv4 映射、NAT64、6to4、Teredo；服务名必须被 URL 解析器读成域名；探测固定到已验证套接字和配置端口、不使用环境代理、不跟随重定向。`8.8.8.8:80`（http）与 `:443`（https）此前因 `Url::port()` 对默认端口返回空而被误拒，现在合法。`XSHIELD_ALLOW_LOOPBACK_UPSTREAM=1` 仍只为本地靶场放行 `127.0.0.0/8` 与 `::1`。

- 修复 control 与 edge 之间通道的两处认证缺口：edge 健康请求签名的是固定正文 `health-v1`，任何一次被捕获的请求永远有效、可随意重放；edge 对 apply 的确认是未签名的 JSON，能在路径上（或能应答该端口）的一方可以在 edge 什么都没应用时让控制面把 revision 标为 `active`。现在健康请求对 `xshield-edge-health-v2\n<unix 秒>\n<nonce>` 签名，随 `x-xshield-health-timestamp`、`x-xshield-health-nonce` 发送，edge 先验签，再检查 ±30 秒窗口，再在有界缓存（4096 条、保留 65 秒）中拒绝重复 nonce：401 `EDGE_HEALTH_REQUEST_REPLAYED`、401 `EDGE_HEALTH_REQUEST_EXPIRED`，缓存满时 429 `EDGE_HEALTH_RATE_LIMITED` 而不是遗忘旧 nonce，只有通过验签的请求占用缓存；apply 成功响应带 `x-xshield-apply-ack-signature`，对 `xshield-edge-apply-ack-v1\n<请求签名>\n<确认原始字节>` 做 HMAC，因此绑定到它回答的那次请求，控制面先验签再解析，失败即该次 apply 记为 failed，原因 `EDGE_APPLY_ACK_SIGNATURE_INVALID`。两侧消息字节统一定义在 `xshield_core::edge_channel`，并以 Python 独立计算的已知答案向量互相钉住。必须先升级 edge 再升级 control：新 control 会把旧 edge 未签名的确认判为失败，而新 edge 在 control 升级完成前拒绝旧的固定签名健康请求，控制台暂时显示 edge `unavailable`（apply 不受影响）。对 `EdgeApplyClient` 的改动限于 `health` 与 apply 响应处理两处（另有两个方法改为 `pub(crate)` 以便测试）。健康响应和 apply 的非 2xx 响应仍未签名；确认只绑定请求签名而非每请求随机数。

- 修复 edge 快照持久化与首个 apply：持久化的 pending/active 快照以默认权限创建（常见 umask 下为 0644），本机其他用户可读取完整的租户路由与策略；两次 rename 之后不 fsync 目录，掉电可能让已确认的快照回到旧版本；control 的第一份快照与 edge 启动占位快照同为 revision 1，占位快照没有摘要，“同 revision 摘要不同”被判为冲突，首个 apply 永远得到 409 `EDGE_APPLY_IDEMPOTENCY_CONFLICT`。现在快照文件创建时即为 0600（`create_new`，不跟随预置的同名文件），两次 rename 后都对目录 fsync，失败则拒绝 apply 或停止数据面监听；旧文件在加载时收紧为 0600；快照存储与监听器监督共用 `GatewaySnapshot::check_replacement`，只有两份已应用 payload 才会在同 revision 上冲突，占位快照可被首个 apply 替换且不能顶替已应用快照。目录 fsync 的真实落盘与掉电行为未在测试中验证。

- 为 edge 的未知 Host/端口拒绝补上审计：监听端口与 Host 没有命中任何站点快照的请求此前直接返回 503 `SITE_CONFIG_UNAVAILABLE`，没有任何审计事件、原因码或终态。因为这类请求没有站点作用域、逐请求写持久事件又会让洪峰写满 journal，网关按监听端口在内存中计数，每 60 秒为每个有计数的端口追加一条聚合的 `edge.unrouted_denied` 事件（新稳定原因码 `HOST_NOT_ROUTED`，含总数、首末时间和首个有界可打印 ASCII 的 Host 样本）；内存只随监听端口数增长，屏障关闭时计数保留、重开后合并写出。worker 发布器新增该事件类型的严格解析（拒绝其他原因码、零端口/零计数、时间颠倒、超界或含控制字符的 Host、未知/重复字段），须先升级发布器。客户端响应不变，窗口内逐请求明细有意不持久化，进程在两次写出之间退出会丢失该间隔内尚未写出的计数。

- 修复 edge 限流与审计屏障：WAF 拒绝的请求不经过限流器，却仍各写一条耐久审计记录，拒绝洪峰不受限地写满 journal；限流表在 65,536 个来源后拒绝每一个新来源（评审测得 200 个中 0 个放行），且每次拒绝都在全局 `std::sync::Mutex` 下 `retain` 遍历全表（约 1.3 ms）；审计屏障一旦因 journal 写满或写错误关闭就没有任何重开路径，网关停摆到重启。现在每个请求先于 WAF 取令牌（`pre_admission_denial`），限流表改为 16 分片、共 65,536 个桶的 CLOCK 淘汰表，插入摊销 O(1)、新来源永不因表满被拒，IPv6 按 /64 计量；屏障由后台监督在有界退避（1–30 秒）下重试：目录低于高水位时释放失败的写入器、经恢复流程重开 journal，并先耐久追加 `audit.recovered`（新稳定原因码 `AUDIT_BARRIER_REOPENED`，`truncated_bytes=0`）再恢复准入，期间继续以 503 `AUDIT_DURABILITY_FAILED` 拒绝。worker 发布器只接受 `AUDIT_TAIL_RECOVERED`（有截断字节）与 `AUDIT_BARRIER_REOPENED`（无截断字节）两种 `audit.recovered`，部署时先升级发布器。屏障关闭期间丢失终态的在途请求仍由下次启动对账补偿，不在重开时补偿。该屏障没有 Pingora 集成回归，只有单元级证明。

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
