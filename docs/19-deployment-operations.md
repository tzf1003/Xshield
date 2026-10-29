# 19 部署、隔离、升级与运行策略

## 19.1 首版部署

生产目标 Linux x86_64/aarch64 容器。macOS 可开发，Windows 使用 Linux 容器/WSL；不宣称所有 Pingora 平台具有同等支持。[S03]

基础部署：edge、control、worker；PostgreSQL；ClickHouse；S3 兼容证据库；可选独立 OpenJev 推理服务。所有版本固定镜像 digest、Cargo.lock、模型 revision 与适配包哈希，不使用 floating latest 作为发布依据。

## 19.2 网络与源站

域名流量进入 Xshield，源站限制直连/备用入口；API 子域、下载与业务 WS 列入覆盖表。入口与控制台分域/分网络，管理 API 不通过业务用户会话访问。内部调用认证并限制网络目的地，模型 worker 无源站管理网络权限。

WAF 终止 TLS 并重新验证上游证书，固定 upstream allowlist，不接受客户端任意 Host 变成开放代理。浏览器→WAF 与 WAF→源站的信任变化必须在站点接入说明中体现。

前置 WAF/CDN（ADR-013）：Xshield 不做 SQLi/XSS 等通用签名检测，生产与试点部署须放在现有 WAF/CDN 之后，链路为客户端 → WAF/CDN → Xshield edge → 源站。接入时确认：（1）前置层到 edge 使用 PROXY protocol，并把前置层出口地址列入 `XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED`，否则按来源限流只能按站点总量生效；（2）edge 数据面只放行前置层出口，源站只放行 edge，避免绕过任一层；（3）前置层到 edge 的 TLS 由前置层重新加密并校验 edge 证书（edge 原生 TLS 见下文）；（4）前置层拦截的请求不进入 Xshield 审计，事件调查需要同时查前置层日志；（5）前置层的缓存不得缓存带身份或资格的响应，按站点把受保护路径设为不缓存。

控制面拒绝指向回环、私网、链路本地、云元数据以及 IPv4 映射/NAT64 等转换形式的上游地址（规则见 29 章“上游地址校验”）。本地靶场的源站在回环地址上，因此需要显式设置环境变量 `XSHIELD_ALLOW_LOOPBACK_UPSTREAM=1`（`dev.sh` 已设置）；它只放行 `127.0.0.0/8` 与 `::1`，生产部署不得设置。源站在私网时，部署方可以用 `XSHIELD_ALLOWED_UPSTREAM_CIDRS` 显式列出源站所在的网段（逗号分隔的 CIDR，如 `10.20.0.0/16,fd12:3456::/48`，最多 32 个），只能是 RFC 1918 或 `fc00::/7` 内不含主机位的网段；它只解除列出网段内地址的“私网/唯一本地”拒绝，回环、链路本地、共享地址、云元数据（包括 `fc00::/7` 内的 `fd00:ec2::254`）、映射与转换形式照旧拒绝。默认不设置，行为与此前相同；列表不合法时控制服务拒绝启动。上游地址的任何变更仍需独立审批（`UPSTREAM_CHANGED`），所以放行网段是部署级边界，具体源站仍由两个人确认。

**当前实现状态（2026-10-05 核查）**：edge 的数据面监听器仍只绑定内网或 loopback 地址（`XSHIELD_EDGE_LISTEN_PORTS` 与站点端口的既有限制不变），部署可以启用两项传输加固（配置见下文“Edge 传输配置”）。其一是原生 TLS：同时设置 `XSHIELD_EDGE_TLS_CERT_PATH` 与 `XSHIELD_EDGE_TLS_KEY_PATH` 后，**每个**数据面端口都由 edge 终止 TLS（OpenSSL，Mozilla intermediate v5 配置，TLS 1.2 起，ALPN 依次为 `h2`、`http/1.1`，HTTP/2 下游由 Pingora 桥接到 HTTP/1.1 源站，不签发 session ticket，不允许重协商）；两个变量都未设置时行为与此前完全一致（明文 HTTP/1.1），配置不完整或证书/密钥不可用时拒绝启动，绝不退回明文。其二是 PROXY protocol v1/v2：`XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` 列出的负载均衡地址必须在连接起始处发送 PROXY 头，头中的源地址取代 TCP 对端，用于按来源限流和匿名会话来源指纹；未列出的对端发送的 PROXY 头从不被解析。主证书之外可用 `XSHIELD_EDGE_TLS_SNI_CERTS` 按 SNI 为其他主机名提供证书，证书与私钥文件变化后 edge 在运行中自动重载（2026-10-29 起，见下文）；SNI 只用于选证书，不参与路由，路由仍按监听端口加 Host/`:authority`。仍不在范围内：从秘密管理器解析证书、HTTP/3/QUIC、PROXY v2 TLV 的任何语义（全部跳过、不信任）以及 `X-Forwarded-For`/`Forwarded` 等转发头（仍不信任）。开发环境的本地 stunnel 终止器（见 `dev.sh`）不变。上游 TLS 的证书校验和固定 allowlist 已按本节实现。

站点策略的 waf.blocked_query_fragments 可配置最多 32 个 ASCII 片段；edge 对有查询串的请求先执行有界、单次严格百分号解码和加号空格转换，再做不区分 ASCII 大小写的匹配。命中返回 WAF_QUERY_BLOCKED/403，畸形编码返回 WAF_QUERY_INVALID/400，均发生在源站转发前并记录请求审计。该规则只适合经过站点验证的具体片段；上线前应使用正常业务查询样本检查误拒，并以新策略修订发布。撤回此规则只需发布移除片段的配置快照，不删除已经产生的审计。

按来源限流和匿名会话来源指纹使用 edge 归属的客户端地址：默认是 TCP 对端；对端属于 `XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` 时是它在 PROXY 头中声明的源地址。客户端转发头一律不信任。放在未启用 PROXY protocol 的代理或负载均衡之后时，其后的所有客户端仍会被归为同一来源，站点总限流照常生效。

多个 edge 副本：令牌桶在每个 edge 进程内计量。负载均衡按源地址保持亲和（或只有一个副本）时，站点的 `requests_per_second`/`burst` 按原值生效，`XSHIELD_EDGE_RATE_LIMIT_SHARE` 保持默认 1。负载均衡把同一来源轮流分到 N 个副本时，在每个副本上设 `XSHIELD_EDGE_RATE_LIMIT_SHARE=N`（1–64 的整数，其他值拒绝启动）：每个副本只放行 1/N 的速率与突发（突发至少 1 个请求），整组副本合计约等于策略值，而不是 N 倍。副本数变化时需同步调整该值；分流不均时，偏重的副本会比策略更早返回 429。没有跨副本共享计数：共享存储需要在每个请求（包括它要吸收的洪峰）之前做一次网络往返，见 21。

### 页面签发、动作描述供给与探针 1.1.0

新增网关配置字段（语义见 05 §5.3.1）：`SENSOR_HTML` 响应的 `page_actions: {"mapping_revision": "...", "max_active_pages": 1–1000}`，以及 `UI_ACTION_REQUIRED` 非资源 operation 的 `issued_by: {"page_operation_id": "...", "ttl_seconds": 1–86400}`。没有新增 edge 环境变量；页面签发沿用 `XSHIELD_DATABASE_URL` 与 `identity_store`。worker 新增 `XSHIELD_OUTBOX_FAMILY=ui_action`。

- 启动顺序：只要启动配置声明了 `page_actions`，edge 在绑定任何监听端口之前把由配置推导的动作描述与策略修订写入 PostgreSQL；数据库不可达、修订已存在但摘要不同或非 `active`、或任一描述字段不同，都以 `xshield gateway startup failed: UI_DESCRIPTOR_CONFLICT: ...` 或 `IDENTITY_STORE_UNAVAILABLE` 退出，绝不覆盖已有行。改变描述（路由、方法、目标、页面、mapping revision、`resource_grant` 目标的视图等）必须同时提升 `policy_revision`；只改 `ttl_seconds`、`max_active_pages` 不影响摘要。经控制面保存的站点由控制面强制这一点（见下文“处理 `EDGE_APPLY_DESCRIPTOR_CONFLICT`”）；手写的 `XSHIELD_CONFIG` 仍只由 edge 检查。启动供给最长等待 30 秒。
- 签名 apply：快照中的站点可以声明 `page_actions`/`issued_by`/`resource_grant`。edge 在 apply 锁内依次：判断新快照能否替换正在服务的快照（落后的 revision 或同 revision 异 payload 直接 409，不接触数据库）→ 按站点 ID 顺序为每个声明 `page_actions` 的站点供给动作描述（`Created`/`Existing` 均可；与正在服务的快照逐字节相同的重试不再访问数据库）→ 写签名 pending 文件 → 绑定端口并切换 → 提升为 active。任一站点摘要冲突、修订不是 `active` 或已有描述含义不同时返回 409 `EDGE_APPLY_DESCRIPTOR_CONFLICT`；数据库不可达、4 秒内没有完成（低于控制面 8 秒的请求超时，拒绝能先于传输超时送达）或 edge 的启动配置没有 `identity_store` 时返回 503 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE`。两种拒绝都不写 pending 文件、不改变正在服务的快照与 active 文件；应答体为 `{"error":"edge_apply_failed","reason_code":"…","site_id":"…"}`，其他拒绝的应答体不变、不含 `site_id`。拒绝不签名，`site_id` 只能解释失败，不能作为确认依据；成功确认照旧签名。控制面把这两个码原样记为站点 apply 失败原因，控制台给出中文说明：`EDGE_APPLY_DESCRIPTOR_CONFLICT` 点名的是本次快照以期望修订下发的其他站点时，失败记在被点名的站点上，触发 apply 的站点保持 `pending`；其余情况（以及 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE`）记在触发 apply 的站点上。
- 影响面：apply 对整个租户快照原子生效，因此一个站点的描述冲突或一次 PostgreSQL 故障会挡住同租户所有站点的本次变更（它们继续使用上一份快照）。控制面现在在发送之前就扣住会复用标签的站点（它自己的绑定记录或 edge 的 `policy_revisions` 行能说明冲突时），把它留在上一份已批准配置上并标为 `failed`（`CONTROL_SITE_POLICY_REVISION_REUSED`），其余站点照常应用；edge 仍然拒绝的那一次 apply（例如生效后才被停用的修订号、apply 期间由其他写入方建立的行、控制面与 edge 使用不同数据库）依旧挡住整个租户，控制面只把失败记在被点名的站点上，不会自动去掉它重发。拒绝之前已检查通过的站点保留各自的描述行（只表达“该修订对应该描述集”），下一次以 `Existing` 读回。
- 重启：恢复 `XSHIELD_EDGE_SNAPSHOT_PATH` 中的持久化快照时，edge 在绑定任何监听端口之前为其中每个声明 `page_actions` 的站点重新执行同一供给；数据库不可达或没有身份存储以 `IDENTITY_STORE_UNAVAILABLE: persisted snapshot site <站点> cannot supply its action descriptors` 退出，冲突以 `UI_DESCRIPTOR_CONFLICT: persisted snapshot site <站点> policy revision <修订> already binds other action descriptors` 退出，不覆盖已有行，也不退回启动配置。
- 处理 `EDGE_APPLY_DESCRIPTOR_CONFLICT`：同一策略修订号只能对应一组描述。改变上述任一描述字段后，为该站点设置新的 `policy_revision` 再保存并应用；不要修改或删除 PostgreSQL 中的描述行来“解除”冲突，已签发的引用指向这些行。回滚到与某个已登记修订完全相同的描述集会以 `Existing` 通过；被运维停用（`retired`）的修订不会被 edge 重新激活，需要换用新修订号。控制面现在强制这条规则：保存、校验、审批、直接应用与下发都会检查，复用一个已绑定其他描述集合（或已在 edge 停用）的修订号时以 `CONTROL_SITE_POLICY_REVISION_REUSED` 拒绝（写入与审批 409，校验 422，下发时该站点 `failed`），冲突因此在控制面就被拒绝而不会到达 edge；只改修订号本身仍不需要审批，草稿与暂停（下线）从不因修订号被拒绝。规则、绑定时机与例外见 29“策略修订号与动作描述集合的绑定”。处理 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE`：恢复 edge 到 PostgreSQL 的连接（或为 edge 配置身份存储）后重新应用。
- 身份运行时来自启动配置：edge 的身份存储连接与身份运行时由 `XSHIELD_CONFIG` 决定，而不是由 apply 快照决定。要由 apply 承载页面签发站点，启动配置必须声明 `identity_store`（并提供 `XSHIELD_DATABASE_URL`、`XSHIELD_FINGERPRINT_KEY_HEX`），并至少声明一条需要身份运行时的路由（真实浏览器回归用一条从不服务的 `AUTHENTICATED_ROOT` 占位路由）；缺少身份存储时 apply 以 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE` 拒绝，只缺身份运行时的受保护请求在准入时失败关闭。`dev.sh` 使用的 `examples/gateway-bootstrap-config.json` 已按此形态声明身份存储与占位路由，`dev.sh` 会为 edge 生成 `XSHIELD_FINGERPRINT_KEY_HEX`，并把此前生成的旧 bootstrap 文件升级到同样的形态，因此本地开发栈可以承载经 apply 下发的页面签发与其他受保护站点（本机无法运行 Docker 栈，该集成只验证了配置文件能让 edge 带身份运行时启动，见 gateway 的 `example_configs` 测试）。
- 控制面站点配置 API 已能保存、审批并下发 `page_actions`/`issued_by`/`resource_grant`、`SENSOR_HTML` 与 `AUTH_ENTRY`（契约见 29“站点浏览器来源流程配置契约”，这些变更只能由独立审批人批准）；控制台的路由抽屉可以编写这些字段（15“控制台编写浏览器来源流程”），未改动的块在读取与保存时原样保留。控制面用 `xshield_core::edge_descriptors` 在下发前算出 edge 将供给的摘要，描述集合变化而 `policy_revision` 未变时拒绝（见上一条）；控制台在该字段下说明修订号与页面动作描述绑定。
- 升级顺序：先应用迁移 `0053_m5_site_descriptor_bindings.sql`（新增控制面的修订号绑定表 `site_descriptor_bindings`；加法、可重复执行、无外键），再替换控制服务。旧控制服务不读写该表；混跑期间旧服务写入的修订由新服务在校验、审批与快照读取时复查，旧服务自己发送的快照仍由 edge 把关。开发环境由 `dev.sh` 的 reconciliation 自动补齐 0053。
- 分享入口路由：先应用迁移 `0054_m5_site_route_share_entry.sql`（把 `SHARE_ENTRY` 加入只写投影 `site_routes` 的准入 CHECK；加法、可重复执行），再替换控制服务；没有它，含分享入口路由的站点写入会在同一事务内整体回滚。`xshield.share_issuance_rules` 行由控制面在审批（或不需要审批的保存）的同一事务里按 `share_issue` 块写入，不再需要运维手工登记，也没有新迁移；控制服务使用的数据库角色需要对 `xshield.share_issuance_rules` 与 `xshield.policy_revisions` 有 INSERT 与 SELECT 权限（含页面签发的配置，控制面会先写 edge 之后同样会写的 `policy_revisions` 行）；控制面与 edge 使用不同数据库时需要两边都有这些行。行不可变：同一标签与规则 ID 下调整期限、视图或目标要换新的 `issuance_rule_id`，否则保存被 `CONTROL_SITE_SHARE_RULE_CONFLICT` 拒绝。edge 启动还需要 `XSHIELD_SHARE_TOKEN_KEY_HEX`（见 29“站点配置缺口审计”与“分享发放规则行由控制面写入”）。
- 升级顺序：先应用迁移 `0052_m5_site_route_provenance_flow.sql`（扩展只写投影 `site_routes` 的准入 CHECK 并新增 `issued_by` 列；加法、可重复执行），再部署新的控制服务；旧控制服务从不写入 `AUTH_ENTRY`，不受影响。新控制服务在缺少该迁移的数据库上写入认证入口路由时整笔事务回滚并返回 503 `CONTROL_SITE_CONFIG_UNAVAILABLE`。开发环境由 `dev.sh` 的 reconciliation 自动补齐 0052。
- 升级顺序：先部署能解析 `ui_action.issued` 的 worker 并为每个站点调度 `XSHIELD_OUTBOX_FAMILY=ui_action`，再启用带 `page_actions` 的网关配置；否则这些行停留在 outbox 中未发布（不影响准入，但调查看不到签发历史）。
- 探针版本：新页面注入 1.1.0（同步脚本 + 页面句柄）；1.0.0 资源仍按原字节提供，不带查询串的 bootstrap 仍返回 1.0.0 文档，prepare 同时接受两个版本，因此滚动升级期间旧实例交付的页面继续工作（仅观测，1.0.0 从不携带引用）。回滚到只提供 1.0.0 的旧网关后，新页面重新注入 1.0.0、不再获得页面引用（受控请求按默认拒绝处理）；回滚前已打开的 1.1.0 页面仍可出示已签发且未过期的引用，旧网关同样按服务端记录逐请求重验。页面 HTML 是 `no-store`，不会从缓存复活 1.1.0 标签。站点 CSP 若限制 `script-src`，仍由既有 nonce 改写覆盖两个同步标签。

### Edge 传输配置（原生 TLS 与 PROXY protocol）

以下变量只由 edge 进程在启动时读取并完整校验，作用于全部数据面端口（不按端口配置）；任一校验失败都以 `xshield gateway startup failed: ...` 退出，错误只包含变量名与路径，不回显文件内容。变量本身只在启动时读取；它们指向的证书与私钥文件在运行中会被重新读取（见下文“证书轮换与热加载”）。

| 变量 | 取值 | 未设置 | 校验与失败 |
| --- | --- | --- | --- |
| `XSHIELD_EDGE_TLS_CERT_PATH` | PEM 证书链，叶证书在前，可附中间证书 | 明文监听 | 必须与私钥变量同时设置；设置为空串、只设置一个、文件不可读、不是普通文件或超过 1 MiB、无法解析为证书、叶证书已过期或尚未生效，均拒绝启动 |
| `XSHIELD_EDGE_TLS_KEY_PATH` | 未加密的 PEM 私钥 | 明文监听 | 同上；文件权限含任何 group/other 位（`mode & 0o077 != 0`，如 0644、0640）、与证书公钥不匹配或被 TLS 库拒绝（如强度不足），均拒绝启动 |
| `XSHIELD_EDGE_TLS_SNI_CERTS` | 逗号分隔的 `证书路径:私钥路径` 对，每对的文件要求与上两项相同 | 只有主证书 | 必须同时设置主证书与私钥；空串、某项不是恰好一个 `:` 分隔的两个非空且不同的路径、文件不满足上两项任一条件、叶证书没有任何 DNS 名（SAN 的 dNSName，没有 SAN 时取 CN）、两张证书（含主证书）声明同一主机名，均拒绝启动 |
| `XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` | 逗号分隔的 IPv4/IPv6 地址或 CIDR，最多 64 项；单个地址即单主机块 | 关闭（空串同） | 空项、非法地址或前缀、主机位非零（如 `10.0.0.1/8`）、前缀长度 0、IPv4 映射的 IPv6 块均拒绝启动 |

原生 TLS：全部站点端口共用同一组证书。客户端 SNI 与某张附加证书的 DNS 名匹配时出示该证书（不区分大小写、忽略末尾点；精确名优先于通配符，`*.example.com` 只匹配一级标签）；SNI 不匹配任何附加证书或没有 SNI 时出示主证书，不因 SNI 拒绝握手。每张证书使用相同的 TLS 配置（版本、套件、ALPN）。SNI 只决定出示哪张证书，不参与路由：SNI 与 Host 指向不同站点的请求仍按 Host 路由，错误 Host 的请求与明文时一样以 503 `SITE_CONFIG_UNAVAILABLE` 拒绝并计入 `edge.unrouted_denied`。私钥文件须为 0600 或 0400；Kubernetes secret 卷默认 0644，需设置 `defaultMode: 0400`。

证书轮换与热加载：edge 每 30 秒检查一次全部证书与私钥文件的元数据（设备、inode、大小、修改与变更时间，跟随符号链接，因此原地改写、重命名覆盖和 Kubernetes secret 卷的符号链接切换都能发现）。有任一变化时重新读取并按启动时的全部规则校验整组文件：全部通过则新握手立即使用新证书，已建立的连接保留原证书直到关闭；任一失败（文件缺失、证书与私钥暂不匹配、已过期等）则继续使用当前证书，在标准错误输出一行只含变量名与路径的原因，并在文件再次变化时重试，所以先写证书后写私钥的轮换只会在中间记一次失败。轮换时应先写入新文件再原子重命名（或使用 secret 卷），不必重启 edge；新增或删除附加证书、修改变量本身仍需重启。每个连接的握手在独立任务中进行并限时 5 秒；握手连同 PROXY 头读取占用连接建立名额，每个监听端口 256 个、全进程 1024 个，名额用尽时新连接在 accept 时直接关闭，半开连接洪峰不会无界占用内存或任务；握手完成后 60 秒内没有任何请求字节的连接被关闭（HTTP/1 另有 Pingora 自身的 60 秒请求头读取上限，HTTP/2 的连接前言等待没有上限，此限制补上），没有活动流的 HTTP/2 连接空闲 60 秒后关闭。握手之后的准入、WAF、限流、审计屏障与快照路由不变。HTTP/2 请求按 `:authority` 路由（可以没有 Host）；Pingora 0.9 在 HTTP/1 与 HTTP/2 入口处已以 400 拒绝重复 Host、userinfo 以及 Host 与 `:authority`/绝对形式目标不一致的请求，路由层再以同一规范化（大小写、末尾点和端口不计）复核，任何歧义按未路由拒绝。源站始终收到 origin-form 请求目标和站点配置的 Host，不会收到客户端的 scheme 或 authority。`__Host-` 会话 Cookie 的 `Secure` 属性在原生 TLS 下直接满足；sensor 的 `origin` 仍是站点配置的 HTTPS 公开源，与连接方式无关。

PROXY protocol：负载均衡器必须只对 edge 的这些监听端口启用 PROXY protocol（v1 或 v2，TCP 模式）。同时启用原生 TLS 时，PROXY 头位于 TLS 握手之前，即均衡器以 TCP 直通加 PROXY 头的方式转发，edge 按此顺序处理。受信对端的判断只使用套接字的真实对端地址（IPv4 映射的 IPv6 对端按 IPv4 比较），与连接内容无关；受信对端必须在 3 秒内发送完整有效的头，缺失、格式错误、超长（v1 超过 107 字节、v2 超过 536 字节）或声明 UDP/UNIX 传输的头都会关闭连接，不回退为 TCP 对端地址。`LOCAL` 命令（均衡器健康检查）和 `UNKNOWN`/`UNSPEC` 地址族保留 TCP 对端地址；v2 的 TLV（包括 authority、SNI）全部跳过、不作任何信任依据。头中的源地址取代 TCP 对端用于 edge 归属客户端的所有位置（按来源限流键、匿名会话来源指纹），IPv4 映射地址按 IPv4 计量；审计事件本身不记录客户端 IP。客户端无法在 HTTP 流内自带 PROXY 头伪造地址：只解析连接最开头的一个头，其后的字节属于 TLS 或 HTTP，非受信对端发来的 PROXY 头同样只是会被 HTTP 解析拒绝的普通字节。

失败计数：握手失败或超时、受信对端的 PROXY 头被拒、因名额用尽被关闭的连接都没有到达准入，因此没有请求、也不产生逐请求审计事件；它们只在进程内计数，通过已认证的 loopback 健康接口 `/internal/v1/health` 返回（HMAC 请求认证不变，响应仍不签名、仅用于展示）：`tls_enabled`、`tls_certificates`（主证书加附加证书的对数）、`tls_reloads`（成功的热加载次数）、`tls_reload_failures`（被拒绝的文件变化次数）、`tls_handshake_failures`、`proxy_protocol_enabled`、`proxy_header_rejections`、`connection_setup_shed`。计数从进程启动累计、重启归零；`edge_state` 不受这些计数影响。edge 不记录失败连接的任何字节、证书或私钥材料。control 把健康 JSON 原样并入站点健康详情，控制台可直接展示这些字段，工作台仍只读取 `edge_state`。

## 19.3 密钥与秘密

独立管理 TLS、协议适配、WAF session HMAC、票据签名、证据 KEK、日志签名、模型 API key。按用途和站点隔离，轮换带 key_id、并行验证期、撤销与审计；不得把所有密钥装进一个共享配置 JSON。

管理 OIDC 由控制服务读取 `XSHIELD_CONTROL_OIDC_ISSUER`、`XSHIELD_CONTROL_OIDC_CLIENT_ID`、`XSHIELD_CONTROL_OIDC_CLIENT_SECRET`、`XSHIELD_CONTROL_OIDC_REQUIRED_ACR`、`XSHIELD_CONTROL_CONSOLE_ORIGIN` 与 `XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON`。只允许 HTTPS IdP 和 HTTPS 控制台 origin（开发例外仅 loopback）；discovery/token 请求限时且不跟随重定向，启动时 issuer metadata 不可用则控制服务不启动。subject→角色 JSON 是部署管理员维护的精确 allowlist，不能直接映射 IdP 自声明角色；当前每个控制服务实例将获准主体限定到其启动配置的单一 tenant/site。client secret 由秘密管理器按用途注入、轮换，不写入仓库或浏览器 bundle。

**真实 IdP 回归（开发 realm）**：`dev/keycloak/xshield-dev-realm.json` 是本地与 CI 回归用的 Keycloak 26.7.4 realm（`docker-compose.dev.yml` 以容器运行；`scripts/test_oidc_login.sh` 用官方发行包 zip 与 JDK 21 原生运行，不需要 Docker，见 docs/20 §20.20）。客户端 `xshield-console-dev` 强制 S256 PKCE（`pkce.code.challenge.method`），重定向 URI 固定为 `http://127.0.0.1:55173/control/v1/auth/oidc/callback`，`acr` 是写死的声明 `1`（所以对应 `XSHIELD_CONTROL_OIDC_REQUIRED_ACR=1`，不代表做过多因素认证）。用户均使用同一个开发口令 `xshield-dev-password`，只用于本地：`developer`（subject `00000000-0000-7000-8000-000000000001`，`dev.sh` 映射全部角色）、`observer-only`（`…0002`，回归里只映射 observer，用来验证无资格发起 step-up）、`unprovisioned`（`…0003`，故意不在 `XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON` 中，用来验证有效 IdP 用户不会自动获得角色）。该 realm 不得用于任何共享或生产环境。`scripts/test_oidc_browser.sh` 用同一个 realm（仅在测试副本里把重定向 URI 改为它启动的控制台端口）和真实 Chromium 验证控制台经同源代理的登录往返，范围与缺口见 docs/20 §20.20.1：它在 loopback 明文 HTTP 上运行，不替代 HTTPS 部署下的代理/Cookie/TLS 验收，也不验证真实 MFA。

### 本地受保护站点 HTTPS 入口

`dev.sh --all` 会为 `juice.local` 生成带 SAN 的短期自签证书，并启动本地 TLS 终止器，将 `https://juice.local:5443` 转发到 Gateway 的 HTTP 数据面 `127.0.0.1:56188`。证书和私钥只写入 `target/xshield-dev/tls/`，私钥权限为 `0600`。macOS 可执行 `scripts/generate_dev_tls_cert.sh target/xshield-dev/tls --install` 将证书加入当前登录钥匙串；未安装信任时使用 `curl -k` 做本地测试。该终止器只属于开发启动链，生产入口由 edge 原生 TLS（见 19.2“Edge 传输配置”）或受控 HTTPS 负载均衡器终止，并继续通过控制 API 发布站点配置。

多站点保存即应用还需要在 control 与 edge 同时配置 `XSHIELD_EDGE_APPLY_URL=http://127.0.0.1:9553/internal/v1/apply`、相同的 `XSHIELD_EDGE_APPLY_KEY_HEX`；edge 可用 `XSHIELD_EDGE_APPLY_LISTEN` 修改 loopback apply 地址，并用 `XSHIELD_EDGE_LISTEN_PORTS` 提供启动时的 bootstrap 监听集合。生产部署应再设置持久卷上的 `XSHIELD_EDGE_SNAPSHOT_PATH`；edge 会先把已验签的 pending 快照落盘，绑定端口并切换内存快照后再原子提升为 active，重启时只恢复最后一份 active 签名快照，损坏或作用域不符则拒绝启动。快照文件在创建时即以 0600 打开（不是先建后 chmod，不留下他人可读的窗口），pending 与 active 两次 rename 之后都会对所在目录 fsync；目录 fsync 失败时 pending 阶段拒绝该次 apply（503 `EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE`、保持原快照），promote 阶段按持久化失败处理并停止数据面监听。旧版本写出的 0644 快照在加载时收紧为 0600，只读卷上收紧失败仅向 stderr 报告而不阻止启动。control 的第一份快照与 edge 启动时的占位快照（`XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 的空快照或静态配置）同为 revision 1：占位快照从未经 apply 通道应用、没有 payload 摘要，首个 apply 会替换它；两份已应用的 payload 声明同一 revision 时，摘要一致视为幂等重试，不一致仍返回 409 `EDGE_APPLY_IDEMPOTENCY_CONFLICT`，占位快照永远不能顶替同 revision 的已应用快照。启用策略字段和独立审批前应用迁移 0046–0048；审批幂等摘要与 desired revision 一起清除/更新，作者自批由控制面拒绝，浏览器审批要求近期 step-up 重新认证。apply 请求是完整租户快照，edge 先校验 HMAC、租户、单调版本和每站点配置，为声明 `page_actions` 的站点供给动作描述（见上文“页面签发、动作描述供给与探针 1.1.0”），再绑定所需内部端口并一次性替换；并发请求中落后的版本会被拒绝，连接失败、端口冲突或校验失败时 PostgreSQL 保留上一份 active revision。

control 与 edge 之间的 HMAC 通道对三类消息分别认证，并共用同一个 `XSHIELD_EDGE_APPLY_KEY_HEX`，消息字节由 `xshield_core::edge_channel` 统一定义：apply 请求的 HMAC 覆盖请求体（不变）；apply 成功响应带 `x-xshield-apply-ack-signature`，其值是对 `xshield-edge-apply-ack-v1\n<请求签名 hex>\n<确认 JSON 原始字节>` 的 HMAC，因此确认被绑定到它回答的那一次请求（每次尝试都使用新的 snapshot revision，所以请求签名不会重复）；control 先验证再解析，签名缺失、重复、不是 64 位小写 hex、密钥不符、绑定到别的请求或确认字节被改动（哪怕只是多一个空格）都使该次 apply 记为 failed，原因码 `EDGE_APPLY_ACK_SIGNATURE_INVALID`，通过验证后才检查 apply_id、revision 与状态；健康请求不再对固定的 `health-v1` 签名，而是对 `xshield-edge-health-v2\n<unix 秒>\n<32 位小写 hex nonce>` 做 HMAC，并随 `x-xshield-health-timestamp`、`x-xshield-health-nonce` 发送。edge 依次验证签名、±30 秒时间窗口，再把 nonce 记入最多 4096 条、保留 65 秒（两倍窗口加余量）的缓存，重复的 nonce 返回 401 `EDGE_HEALTH_REQUEST_REPLAYED`，过期返回 401 `EDGE_HEALTH_REQUEST_EXPIRED`；缓存已满时返回 429 `EDGE_HEALTH_RATE_LIMITED` 而不是遗忘旧 nonce；只有通过验签的请求才占用缓存，没有密钥的调用方无法耗尽它；缺失、重复或非规范形态的头一律是 401 `EDGE_APPLY_SIGNATURE_INVALID`，不透露更多信息。两端墙钟需保持在 30 秒以内（建议启用 NTP）。

升级顺序必须是先 edge、后 control：新 edge 会为确认签名，旧 control 忽略该响应头；新 control 要求签名确认，旧 edge 的 apply 会被判为 failed（尽管 edge 实际已应用）。新 edge 拒绝旧 control 的固定签名健康请求，所以在 control 升级完成前控制台把 edge 显示为 `unavailable`（`EDGE_HEALTH_UNAVAILABLE`），apply 不受影响。两个限制需要知道：健康响应本身没有签名（它只用于展示，不参与任何决定）；apply 的非 2xx 响应没有签名（伪造它只能让一次 apply 失败，不能让它被误认为成功）。确认绑定的是请求签名而不是每请求随机数：同一份请求体被原样重发时，路径上的主动攻击者可以用先前捕获的确认应答；控制面每次尝试都生成新的 snapshot revision，所以实际不会原样重发。

浏览器仅持有 `Secure; HttpOnly; SameSite=Lax; Path=/` 的不透明随机会话 Cookie；PostgreSQL 仅以 SHA-256 摘要索引会话 token，保存单独的 CSRF token，并由数据库时钟执行 15 分钟闲置/8 小时绝对到期和撤销。`__Host-` Cookie 要求 TLS 且不得配置 Domain。身份会话数据进入数据库备份，故备份权限与恢复流程须按管理身份材料保护；恢复后先撤销不应复活的浏览器会话。控制台通过同源代理访问 API，代理只转发 Xshield 会话/短期 OIDC state Cookie，其他 Cookie 剥离。

从文件读取秘密：control、edge、worker、`xshield-outbox-worker`、`xshield-evidence-retain` 与 `xshield-audit-seal` 读取的每个秘密变量（数据库 URL、各 `*_KEY_HEX`、`XSHIELD_CONTROL_TOKEN`、`XSHIELD_CONTROL_OIDC_CLIENT_SECRET`、`XSHIELD_CLICKHOUSE_PASSWORD` 等）都可以改为设置 `<变量名>_FILE`，值为一个文件路径，进程从该文件读取秘密，适合 Docker/Kubernetes secret 卷，秘密因此不出现在 `/proc/<pid>/environ`、`docker inspect` 或编排器的环境变量展示里。规则：同时设置 `NAME` 与 `NAME_FILE` 拒绝启动（避免过期变量悄悄压过挂载的文件）；文件只去掉末尾一个换行（`\n` 或 `\r\n`），其余字节原样保留；文件必须是 UTF-8 且不超过 64 KiB；进程不检查文件权限，由部署方把文件设为只有服务用户可读（Kubernetes secret 卷可设 `defaultMode: 0400`）。错误信息只给出变量名，不包含值或文件内容。非秘密配置（监听地址、URL、开关）仍只读普通变量。

请求解密与响应加密密钥：启动配置站点使用 `request_crypto`/`response_crypto` 时，其 key-id 的密钥来自 `XSHIELD_REQUEST_DECRYPTION_KEY_HEX`、`XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX`（64 位小写 hex）。经 apply 下发的站点与轮换中的新 key-id 改用密钥环 `XSHIELD_REQUEST_DECRYPTION_KEYS`、`XSHIELD_RESPONSE_ENCRYPTION_KEYS`：值是 JSON 数组，每项 `{"tenant_id","site_id","key_id","key_hex"}`，每个方向 1–256 项，未知字段、重复的（租户、站点、key-id）、非法 key-id 或密钥都拒绝启动，错误只给出变量名与序号，不含密钥。推荐用 `_FILE` 挂载。单值变量与密钥环同时给出启动站点的同一 key-id 时拒绝启动；启动站点需要的 key-id 两处都没有时同样拒绝启动；同一密钥出现在两个方向时拒绝启动。轮换顺序：把新 key-id 加入密钥环并滚动重启 edge，发布引用新 key-id 的站点修订，确认客户端不再使用旧 key-id 后再从密钥环删除。密钥环在启动时读取，修改后需重启 edge。

密钥不进入 Git、普通日志、模板、测试 fixture 或 Crash dump。服务最小权限获取，KMS 故障不能退回硬编码默认密钥或明文证据。

edge 配置用 `audit.segment_max_bytes` 控制关闭段大小，达到阈值的持久批次完成后自动切换 producer boot。部署方预建仅封存身份可写的私有 manifest 目录，并周期运行 `xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY`。该进程读取 journal 密钥并独占日志签名私钥；edge 不取得签名私钥。重复任务会验证既有清单与关闭段完全一致，再处理新段。

常驻模式：`xshield-audit-seal`、`xshield-worker`（审计发布）与 `xshield-outbox-worker` 默认执行一轮有界处理后退出，适合 cron 或 Kubernetes CronJob。设置 `XSHIELD_RUN_INTERVAL_SECONDS`（1 到 86400 的整数）后进程常驻，每轮结束后等待该秒数再执行下一轮，适合 Compose 服务或 Kubernetes Deployment；单轮失败只向 stderr 报告并在下一轮重试，不退出（一次性模式下失败仍以退出码 1 结束）。`xshield-outbox-worker` 常驻时连接池跨轮复用，一轮领取满 `XSHIELD_OUTBOX_MAX_EVENTS` 条时不等待直接进入下一轮。可选 `XSHIELD_RUN_HEARTBEAT_FILE`（只能与间隔一起设置）：每轮成功后以“写临时文件再 rename”的方式写入当前 Unix 秒，探针据此判断进程是否仍在成功工作（例如文件超过三个间隔未更新即视为不健康），因为一直失败的常驻进程本身不会退出。每一轮本来就可以安全中断（outbox 租约到期后重领，发布检查点与封存清单都以 rename 替换），所以停止常驻进程直接发送默认的 SIGTERM 即可，没有额外的优雅退出逻辑。

## 19.4 配置与升级

草稿 → validate → 独立测试 → 审批 → 签名 → shadow → canary → active。数据面固定版本读，旧新构建并行范围明确。控制面丢失连接可使用未过期签名配置，但不得跳过身份/资格存储不可用。

数据库采用 expand-contract 迁移，先兼容再删旧字段；回滚版本不得复活撤销 epoch。ClickHouse 保留策略升级先执行 `retention_expires_at` 扩展和 active 视图 DDL，再部署显式写期限的新 worker；旧行沿用 30 天默认值。每次升级验证队列 drain、journal seal、未完成请求、插件终止与模型取消。

启用 OIDC 浏览器会话前先应用迁移 0035、更新控制 journal 发布器以识别 `console.auth.*` 事件，再部署控制 API、同源代理和静态控制台。启用原文 MFA step-up 前还须应用迁移 0036、部署识别 `console.auth.reauth.*` 的发布器，并确认代理为 `POST /control/v1/auth/oidc/reauth/start` 透传 `Set-Cookie` 且不缓存/记录正文。回滚 OIDC 前先停用其路由并撤销活动管理会话；单独回滚迁移 0036 前须先禁用原文内容路由，或保持 step-up-aware 控制服务运行，绝不可先移除 step-up 字段。

证据存储后端：默认本地私有目录（`XSHIELD_EVIDENCE_ROOT`）。设置 `XSHIELD_EVIDENCE_BACKEND=s3` 后改用 S3 兼容存储桶，多个网关与控制面实例可以共用；变量与语义见 docs/12 12.10。启用 Object Lock 须在创建存储桶时开启（之后无法再开），并先在测试桶上确认保留模式：`compliance` 到期前任何人都无法删除，包括误写入的对象。从本地切到 S3 不迁移已有对象，旧对象仍需在原目录上读取与清理，直到全部到期。

## 19.5 运行状态

liveness 仅说明进程存活；readiness 根据必要配置、状态存储和审计耐久性判断；推理不可用是否撤 readiness 依赖该节点承接的模型必需端点。拒绝流量尖峰不自动认定业务故障或自动降级。

edge 运维端点：设置 `XSHIELD_EDGE_OPS_LISTEN`（如 `127.0.0.1:9554`，未设置则不开启）后，edge 在该地址提供不需认证的 `GET /livez`、`GET /readyz` 与 `GET /metrics`，供编排器探针和 Prometheus 抓取。地址只接受 loopback、私有、链路本地或未指定地址，公网地址拒绝启动；端口仍应只对管理网络开放。因为不认证，这些响应**不包含任何拓扑**：没有租户、站点、主机名、端口、revision 或源站，标签只来自封闭集合（结果类别与稳定原因码）；站点级详情仍只走带 HMAC 的 `/internal/v1/health`。

- `/livez`：进程能响应即 200 `{"live":true}`。
- `/readyz`：审计屏障打开且至少绑定一个数据面监听器时 200 `{"ready":true}`；否则 503 `{"ready":false,"reason_code":"AUDIT_UNAVAILABLE"}` 或 `"NO_LISTENERS"`。审计屏障关闭时准入本就全部拒绝，撤出流量与其一致。
- `/metrics`（Prometheus 文本格式 0.0.4，`Cache-Control: no-store`）：`xshield_edge_ready`、`xshield_edge_audit_ready`；`xshield_edge_requests_total{outcome}`，outcome 为 `served`、`refused`、`proxy_failed`、`unadmitted`（在网关过滤器运行之前就结束的请求）、`observed`（observe 灰度下本应拒绝、仍被转发的请求，docs/32）；`xshield_edge_refusals_total{reason_code}`（准入拒绝与缓冲响应被扣留，按稳定原因码）；`xshield_edge_observed_refusals_total{reason_code}`（observe 转发的请求按本应生效的拒绝原因计数）；`xshield_edge_request_duration_seconds` 直方图；以及与健康接口同源的 `xshield_edge_tls_certificates`、`xshield_edge_tls_reloads_total`、`xshield_edge_tls_reload_failures_total`、`xshield_edge_tls_handshake_failures_total`、`xshield_edge_proxy_header_rejections_total`、`xshield_edge_connection_setup_shed_total`。启用证据采集时另有证据配额余量；启用网关内置证据清理时另有清理轮次、失败原因码、删除数与上次成功时间（docs/12 12.8）。计数从进程启动累计，重启归零，不替代审计事件。

控制面运维端点：设置 `XSHIELD_CONTROL_OPS_LISTEN`（如 `127.0.0.1:9555`，未设置则不开启）后，控制面在该地址另开一个不需认证的监听器，提供同样的 `GET /livez`、`GET /readyz` 与 `GET /metrics`；地址规则与不披露拓扑的约束与 edge 相同（没有租户、站点、主体、路径或地址，标签只来自封闭集合），管理 API 本身仍只监听 loopback 并要求认证。

- `/livez`：进程能响应即 200 `{"live":true}`。
- `/readyz`：最近 30 秒内有管理审计追加失败时 503 `{"ready":false,"reason_code":"AUDIT_UNAVAILABLE"}`（此时需要审计的接口都返回 `AUDIT_DURABILITY_FAILED`；之所以按时间窗而不是粘滞，是因为被摘除流量后没有请求能清除粘滞状态）；否则用连接池执行一次 `SELECT 1`（2 秒上限），失败为 503 `DATABASE_UNAVAILABLE`；都通过为 200 `{"ready":true}`。ClickHouse 与 OIDC 不参与就绪判断：它们只影响调查与登录，相应接口自己返回稳定错误码。
- `/metrics`：`xshield_control_ready`、`xshield_control_not_ready{reason}`、`xshield_control_responses_total{class="1xx".."5xx"}`、`xshield_control_request_duration_seconds`（与 edge 相同的 11 个桶）、`xshield_control_audit_append_failures_total`。每次抓取都会执行一次数据库探测。

自动化指标：资格发行失败、绑定串用、无来源操作、解密覆盖、兼容比例、模型低信心/超时、journal 剩余空间、索引延迟、证据缺失/摘要失败、原文读取与大导出。

针对以上 edge、control 两组 `/metrics` 的 Prometheus 告警规则见 19.11。

## 19.6 备份与恢复

PostgreSQL 配置/资格及 outbox 按恢复目标备份；证据库版本化与独立权限复制；签名验证材料和 KMS 恢复流程同样不可缺少。恢复演练包括身份 epoch、过期资格、保留 tombstone、未完成请求和重复投递。密钥丢失导致证据不可读应记录为不可恢复，而不是显示空白。

首版不作跨区域强一致承诺。新增多区域时先给出故障域、RPO/RTO、网络分区策略和实际演练报告。
# Edge 配置发布

设置 `XSHIELD_EDGE_APPLY_URL`、`XSHIELD_EDGE_APPLY_KEY_HEX`、`XSHIELD_EDGE_SNAPSHOT_PATH` 后，control 通过 loopback HMAC 发布快照。Gateway 可用 `XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 启动空快照；控制面不可用时继续使用最后一个签名快照，签名、租户、revision、摘要或监听端口不匹配时 fail-closed。

`XSHIELD_PUBLIC_HOSTS`（逗号分隔的主机名，可选）只作用于由 `XSHIELD_CONFIG` 启动的静态 bootstrap 站点：它列出该站点接受的 `Host`，缺省为配置里的 `origin.server_name`；监听地址是回环时，edge 还会接受该回环 IP 作为精确 Host，方便本地探测。已有签名快照时以快照为准，`XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 的空快照也不使用它；控制面发布的站点，公开主机来自各自的 `public_origin`。Host 不匹配的请求按 `HOST_NOT_ROUTED` 拒绝并计入 `edge.unrouted_denied`，不会因为设置了本变量而放宽。

## 19.7 发布打包

`scripts/package_release.sh` 构建 release 二进制（gateway、control、worker、outbox-worker、evidence-retain、model-eval、audit-seal）和控制台静态包，并与迁移、`sql/clickhouse.sql`、示例配置、部署与运行手册（19、26，另含审计可靠性 13、控制台与 API 15、性能与容量 21、接口目录 29）一起装配成 `xshield-<版本>-<系统>-<架构>.tar.gz`，同时写出文件级 `MANIFEST.sha256` 和压缩包的 SHA-256。该脚本没有默认输出位置：必须显式设置 `XSHIELD_DIST_DIR`（暂存树与压缩包）和 `CARGO_TARGET_DIR`（cargo 构建产物），且二者不得位于仓库内，因为 release 构建产物很大，应落在专用的大容量磁盘上。

在 macOS 上若使用外接 exFAT 磁盘，不要直接把 `CARGO_TARGET_DIR` 放在其上：exFAT 没有硬链接和 POSIX 权限，随附的 OpenSSL 源码构建会以 `Directory not empty` 失败。可以在该磁盘上创建 APFS 稀疏包（`hdiutil create -size 400g -type SPARSEBUNDLE -fs APFS -volname XshieldBuild -attach <磁盘>/xshield-build.sparsebundle`），把构建与打包目录放在其挂载点下；磁盘空间只在该外接盘上按需增长。

打包不运行测试、不签名、不发布也不部署；版本取自 `git describe`，工作区有未提交改动时会警告。它也不构建容器镜像；仓库根的 `Dockerfile` 给出 edge、control、worker 三个镜像目标（`docker build --target edge|control|worker .`，基础镜像按 digest 固定，运行用户 uid 10001，只含发布二进制与其链接的库，不带任何配置、密钥或证书），CI 的 `container-images` 作业在 Linux 上构建三个目标并检查每个二进制的共享库都能解析；CI 构建的镜像不推送。发布镜像由 `.github/workflows/release-images.yml` 完成。有两种触发方式：一是有人推送 `v*` 标签；二是在 Actions 页面运行 `release.yml` 并填入版本号（见下文），这样不需要任何人在本地推标签。release-images 的步骤如下：

- 把三个目标推到 `ghcr.io/<owner>/xshield-{edge,control,worker}:<标签>`，附带 BuildKit 构建来源证明（provenance，`mode=max`）与 SBOM；
- 对推送的 digest 做 Sigstore 无密钥签名，签名证书绑定该工作流与标签，并在同一作业里立即验证一次。

`release.yml`（workflow_dispatch，需要仓库写权限）依次完成三步：

1. 检查版本号与提交是否对应：提交必须在 main 上；该提交的 Cargo 工作区与 Helm chart 都是这个版本；CHANGELOG 有该版本的标题；main 上针对该提交的 CI 已通过。不指定提交时，取第一次加入该版本 CHANGELOG 标题的提交，也就是切版本的那个提交。检查通过后在该提交上创建 `v<版本>` 标签。
2. 以 workflow_call 调用 release-images 构建并签名镜像。用 `GITHUB_TOKEN` 推送的标签不会触发其他工作流，所以镜像在这一步构建。
3. 创建 GitHub Release，正文是该版本的 CHANGELOG 段落，附三个镜像的 digest。

标签已经在同一提交上时，重跑会复用它，适用于镜像步骤失败后重试；标签指向其他提交时，工作流拒绝运行，从不移动已有标签。

部署方应按 digest 引用镜像，并在使用前验证：`cosign verify <镜像>@sha256:… --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github\.com/<owner>/<repo>/\.github/workflows/release-images\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$'`。

v0.1.1 是第一个由 `release.yml` 发布的版本（[Release](https://github.com/tzf1003/Xshield/releases/tag/v0.1.1)，标签指向 5588652），三个镜像的 digest 列在 Release 正文里，用上面的命令在仓库外逐一验证通过。

签名身份与触发方式有关：

- 推送标签触发时，签名身份绑定到标签（`@refs/tags/v…`）。
- 经 `release.yml` 触发时，签名身份是 main 上的这个工作流文件（`@refs/heads/main`）。这时镜像的 `org.opencontainers.image.version` 与 `org.opencontainers.image.revision` 标签，以及构建来源证明，给出发布版本和源码提交。能以这一身份签名的，只有 main 上运行的 release-images。它只在推送 `v*` 标签或被 `release.yml` 调用时运行，而运行 `release.yml` 需要仓库写权限。

单机 Docker Compose 参考部署见 19.8，Kubernetes 的 Helm chart 见 19.9，systemd 参考部署见 19.10，CI 分别把三者整体拉起验证（systemd 一项因为不涉及容器或数据库，只做 `systemd-analyze verify` 加命名约定核对，见 `scripts/test_systemd_units.sh`）；TLS 仍是由 edge 原生终止或由前置终止器终止，见 19.2 的当前实现状态。

## 19.8 参考部署（Docker Compose）

`deploy/compose/` 是单机、单租户单站点的参考部署，用法与逐项说明见其 `README.md`。它不是高可用方案，目的是让试点能在一台主机上按本章的约束把全部组件跑起来，并作为编写其他编排（Kubernetes 等）时的对照。

- 拓扑：管理 API（`127.0.0.1:9443`）和 edge apply 通道（`127.0.0.1:9553`）按设计只监听 loopback，所以 edge 与 control 共享一个网络命名空间，由永不重启的 `net` 服务持有（相当于 Pod 的 pause 容器），重启 edge 或 control 不会让另一方失联；edge 的数据面监听器绑定在该命名空间的固定私网地址（默认 `172.30.0.10`，端口 6400–6409 发布给前置 WAF/CDN 或负载均衡），两个运维端口 9554/9555 只发布到宿主机 `127.0.0.1`。
- 秘密：`init.sh` 生成全部密钥（含两对 Ed25519 封存密钥），以 compose secrets 挂载到 `/run/secrets/`，进程全部经 `NAME_FILE` 读取（19.3），环境变量里没有秘密值。秘密目录 0700，文件本身 0444，因为 PostgreSQL、ClickHouse 与 uid 10001 的服务用户各不相同。
- 审计：edge 请求 journal 与 control 管理 journal 各有一组常驻的封存与发布任务（`XSHIELD_RUN_INTERVAL_SECONDS`，19.3），十个 outbox 家族各一个常驻发布任务，均写心跳文件；目录、密钥与检查点按 docs/13 互不混用。
- 引导凭据：`init.sh` 签发的管理 Bearer 有效期不超过 24 小时（控制面上限），角色由 `.env` 的 `XSHIELD_CONTROL_ROLES` 决定，默认只有 `observer`。日常管理走 OIDC 浏览器会话，Agent API Key 也只能由浏览器会话签发。
- 迁移：PostgreSQL 首次启动时按序执行 `migrations/`；之后的新迁移须由运维在升级对应版本前手工应用（本仓库尚无生产迁移执行器）。ClickHouse 首次启动执行 `sql/clickhouse.sql` 并按秘密文件创建 `xshield` 用户。
- 运维方自备：管理面的 HTTPS 同源代理与控制台静态文件（要求见 `web/console/README.md` 与 docs/15，代理须加入同一网络命名空间才能访问 loopback 管理 API）、企业 OIDC IdP（必须是 HTTPS）、edge 前置的 TLS/WAF/CDN、备份（19.6）与告警。

上游地址：控制面默认拒绝私网与回环上游（19.2、29“上游地址校验”）。源站只有内网地址时，在 `.env` 设置 `XSHIELD_ALLOWED_UPSTREAM_CIDRS` 列出源站网段；CI 冒烟就用这种方式接入一个私网源站，并检查网段外的私网地址仍被拒绝。

CI 的 `compose` 作业用仓库 `Dockerfile` 构建三个镜像后运行 `scripts/test_compose_deployment.sh`。脚本在 `compose.smoke.yaml` 叠加一个开发 Keycloak 和一个私网源站，检查以下各项：

- 两个运维端点就绪，数据面对未配置主机返回 `SITE_CONFIG_UNAVAILABLE`；
- 管理 API 只接受引导 Bearer；放行网段内的私网源站可以保存，网段外的被拒绝；control 经签名通道取到 edge 健康，首个 apply 等待独立审批；
- 控制面指标计数；
- edge 与 control 各自重启后恢复就绪；
- 管理审计事件经封存、发布进入 ClickHouse；
- 14 个常驻任务都有新鲜心跳。

**未覆盖**：站点经 edge 实际服务流量，因为首次 apply 需要 OIDC 浏览器会话的独立审批，这部分由控制面与网关的其他回归覆盖；管理代理与控制台；真实企业 IdP、TLS 与 MFA。

## 19.9 Kubernetes（Helm chart）

`deploy/helm/xshield/` 把一个租户、一个站点部署到 Kubernetes，用法见 `deploy/helm/README.md`。拓扑与 19.8 相同，按 Kubernetes 的方式落地：

- **Pod 拓扑**：edge、control 以及两组 journal 的封存与发布任务放在一个单副本 StatefulSet 的同一个 Pod 里。
  - 管理 API 与 apply 通道只监听 loopback，所以 edge 与 control 必须共享网络命名空间。
  - 封存和发布任务读写同一个持久卷 `state`。各目录 0700，由初始化容器以 uid 10001 创建。
  - 持久卷在卸载后保留。
  - 十个 outbox 发布任务是独立的 Deployment。
- **数据面**：
  - edge 的引导配置是 ConfigMap 模板，Pod 启动时由初始化容器填入 Pod IP，因为数据面监听器只绑定私网地址。Pod 网段必须在 RFC 1918 范围内。
  - 站点端口默认 6400–6409，由 Service `<release>-edge` 暴露。
  - 运维端点绑定在 Pod IP 上，由 Service `<release>-ops` 暴露；可选 ServiceMonitor。
- **就绪与存活**：
  - Pod 就绪只看 edge 的 `/readyz`，管理面异常不应把数据面撤出流量。control 只有 liveness 探针，它的 `/readyz` 供监控抓取。
  - 常驻任务没有就绪探针。它们的 liveness 探针检查心跳文件：启动宽限期过后，心跳超过三个间隔加一分钟未更新即重启该容器（19.3）。
  - **代价**：control 进程反复崩溃时（例如启动时 IdP 不可达），Pod 仍会未就绪，这是 loopback 设计带来的耦合。
- **秘密**：
  - 全部来自运维创建的 Secret，`deploy/helm/xshield-secrets.sh` 生成除数据库 URL、ClickHouse 密码与 IdP 客户端密钥以外的键。
  - 每个容器只投影自己用到的键，Secret 卷权限 0440，组为 fsGroup；进程仍经 `NAME_FILE` 读取。
  - 引导 Bearer 的签发与过期时间也在 Secret 里。
- **安全上下文**：所有 Xshield 容器以 uid 10001 运行，`runAsNonRoot`、根文件系统只读、去除全部 capability、禁止提权、seccomp `RuntimeDefault`，不挂载 ServiceAccount 令牌。符合 Pod Security `restricted` 的要求。
  - `fsGroupChangePolicy: OnRootMismatch` 防止 kubelet 给 journal 加组权限，审计读取方会拒绝组可读的文件。
- **可选 NetworkPolicy**：只放行站点端口与运维端口的入站，来源可分别限定。outbox Pod 不接受入站。出站不限制，因为源站、数据库与 IdP 因部署而异。
- **运维自备**：PostgreSQL 与 ClickHouse（迁移与 schema 由运维在安装和升级前执行）、企业 OIDC IdP、管理面 HTTPS 同源代理（以 `extraContainers` 加入 Pod）、edge 前置的负载均衡或 WAF/CDN、备份（19.6）与告警。

CI 的 `helm` 作业先做静态检查：缺少必填值时 schema 拒绝渲染；`helm lint --strict`；渲染结果与测试依赖清单用 kubeconform 按 Kubernetes 1.29 严格校验。随后在 kind 集群里装入仓库 `Dockerfile` 构建的三个镜像，运行 `scripts/test_helm_deployment.sh`。脚本用 `deploy/helm/smoke/` 部署测试用 PostgreSQL、ClickHouse、一个私网源站，并在 Pod 内加入开发 Keycloak 与 curl 工具容器，然后检查以下各项：

- 两个运维端点就绪，数据面经 Service 对未配置主机返回 `SITE_CONFIG_UNAVAILABLE`；
- 管理 API 只接受引导 Bearer；放行网段内的源站可以保存，网段外的被拒绝；control 经签名通道取到 edge 健康，首个 apply 等待独立审批；
- 管理审计事件经封存、发布进入 ClickHouse；
- 14 个常驻任务都有新鲜心跳，edge、任务与 outbox 容器没有重启；
- 删除 Pod 后，新 Pod（新 IP）在同一持久卷上恢复就绪，已保存的站点仍在。

**未覆盖**：
- 站点经 edge 实际服务流量（原因同 19.8）；
- 管理代理与控制台；
- 真实企业 IdP、TLS 与 MFA；
- 升级路径（`helm upgrade` 与迁移）；
- ServiceMonitor 与 NetworkPolicy 在真实监控和 CNI 下的效果，CI 只校验渲染结果，kind 默认 CNI 只做基本执行。

## 19.10 systemd 参考部署

`deploy/systemd/` 把同一拓扑（edge、control、两个来源的封存与发布、十个 outbox 发布家族、按需的证据保留清理）跑成 systemd 单元，供不经容器编排的单机或虚拟机部署使用，用法见 `deploy/systemd/README.md`。与 19.8 的差异：

- loopback 在同一主机上天然共享，所以不需要 Compose 的 `net` 占位容器：edge 的签名 apply 通道（`127.0.0.1:9553`）与 control 的管理 API（`127.0.0.1:9443`）直接互通。
- 常驻维护进程（`xshield-audit-seal`、审计发布、outbox 发布）在这里不是 19.4 描述的 `XSHIELD_RUN_INTERVAL_SECONDS` 常驻循环，而是 systemd 自带调度的 oneshot + timer 模板单元，对应本章给出的另一种选择（“一次性模式……适合 cron 或 Kubernetes CronJob”）；因此不设置 `XSHIELD_RUN_HEARTBEAT_FILE`（只能与常驻间隔一起设置），是否按时成功运行改读 systemd 自身状态（`systemctl list-timers`、单元的 `OnFailure=`、journal）。
- 证据保留清理（`xshield-evidence-retain`）不随任何 target 启用、没有配套 timer：按 26 的运行手册手工执行，确认节奏后再自行决定是否加定时器，因为它是删除路径。
- 服务账号固定为 uid/gid 10001，与容器镜像一致（`xshield.sysusers.conf`）；数据目录由 `xshield.tmpfiles.conf` 以 0700 创建一次，不在后续启动时被覆盖。
- 单元按角色加固：`User=xshield`、`NoNewPrivileges=yes`、`ProtectSystem=strict` 配合逐单元收紧的 `ReadWritePaths=`/`ReadOnlyPaths=`，以及去特权的 `Protect*`/`Restrict*` 系列；只有 edge、control 及需要连 ClickHouse/PostgreSQL 的发布与 outbox 单元保留网络，封存单元额外 `PrivateNetwork=yes`（对应 Compose 里 `edge-seal`/`control-seal` 的 `network_mode: none`）。

CI 的 `systemd` 作业只做 `scripts/test_systemd_units.sh`：不涉及容器或数据库，用 `systemd-analyze verify` 校验全部单元文件语法与依赖（临时在 `/opt/xshield/current/bin` 放置可执行占位文件满足存在性检查，之后清理），再核对每个 `EnvironmentFile=` 都有对应的 `*.env.example`、每个 `ExecStart=` 引用的二进制都是本仓库实际构建的目标。**未覆盖**：真实安装与启动（没有运行中的 systemd 实例校验 `User=`/`ReadWritePaths=` 等运行时行为）、反向代理与控制台（仍需操作方自备同源代理，见 `web/console/README.md`）、高可用（单机，限制同 19.8）。

## 19.11 Prometheus 告警规则

`deploy/prometheus/alerts.yml` 是针对 19.5 两组 `/metrics` 的告警规则，字段名直接取自导出代码而不是本章文字，用法与范围说明见 `deploy/prometheus/README.md`。要点：

- 覆盖 edge：抓取目标消失、未就绪、审计屏障关闭、高拒绝比例、代理失败、连接丢弃、TLS 握手/重载失败、p99 延迟、证据容量趋势性耗尽、证据清理失败/停滞；control：抓取目标消失、未就绪、数据库/审计不可用、管理审计追加失败、5xx 比例、p99 延迟。
- 不假定任何 `job`/`instance` 标注约定——Helm 的 ServiceMonitor 与手写 `scrape_configs` 打的标签不同，规则只按已经互不冲突的指标名前缀（`xshield_edge_*`/`xshield_control_*`）区分角色。
- 比例与延迟类阈值标注“按你的流量调整”，不是已验证的 SLO；docs/21 的延迟预算仍是待测目标。
- 证据与 TLS 相关规则在对应功能未启用时天然没有样本或恒为 0，不会误报，没有另外按配置条件化。
- 不覆盖 19.10 systemd 维护单元自身的运行状态（它们不暴露 `/metrics`，见 19.10 与 `deploy/systemd/README.md`），也不含 Alertmanager 路由/分组配置。

CI 的 `prometheus-alerts` 作业用 `scripts/test_prometheus_alerts.sh`，经官方 `prom/prometheus` 镜像运行 `promtool check rules` 校验规则文件本身的语法与结构；不校验表达式在真实指标数据上的数值效果。
