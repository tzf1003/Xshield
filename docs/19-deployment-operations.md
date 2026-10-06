# 19 部署、隔离、升级与运行策略

## 19.1 首版部署

生产目标 Linux x86_64/aarch64 容器。macOS 可开发，Windows 使用 Linux 容器/WSL；不宣称所有 Pingora 平台具有同等支持。[S03]

基础部署：edge、control、worker；PostgreSQL；ClickHouse；S3 兼容证据库；可选独立 OpenJev 推理服务。所有版本固定镜像 digest、Cargo.lock、模型 revision 与适配包哈希，不使用 floating latest 作为发布依据。

## 19.2 网络与源站

域名流量进入 Xshield，源站限制直连/备用入口；API 子域、下载与业务 WS 列入覆盖表。入口与控制台分域/分网络，管理 API 不通过业务用户会话访问。内部调用认证并限制网络目的地，模型 worker 无源站管理网络权限。

WAF 终止 TLS 并重新验证上游证书，固定 upstream allowlist，不接受客户端任意 Host 变成开放代理。浏览器→WAF 与 WAF→源站的信任变化必须在站点接入说明中体现。

控制面拒绝指向回环、私网、链路本地、云元数据以及 IPv4 映射/NAT64 等转换形式的上游地址（规则见 29 章“上游地址校验”）。本地靶场的源站在回环地址上，因此需要显式设置环境变量 `XSHIELD_ALLOW_LOOPBACK_UPSTREAM=1`（`dev.sh` 已设置）；它只放行 `127.0.0.0/8` 与 `::1`，生产部署不得设置，且不存在放行私网地址的开关。

**当前实现状态（2026-10-05 核查）**：edge 的数据面监听器仍只绑定内网或 loopback 地址（`XSHIELD_EDGE_LISTEN_PORTS` 与站点端口的既有限制不变），部署可以启用两项传输加固（配置见下文“Edge 传输配置”）。其一是原生 TLS：同时设置 `XSHIELD_EDGE_TLS_CERT_PATH` 与 `XSHIELD_EDGE_TLS_KEY_PATH` 后，**每个**数据面端口都由 edge 终止 TLS（OpenSSL，Mozilla intermediate v5 配置，TLS 1.2 起，ALPN 依次为 `h2`、`http/1.1`，HTTP/2 下游由 Pingora 桥接到 HTTP/1.1 源站，不签发 session ticket，不允许重协商）；两个变量都未设置时行为与此前完全一致（明文 HTTP/1.1），配置不完整或证书/密钥不可用时拒绝启动，绝不退回明文。其二是 PROXY protocol v1/v2：`XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` 列出的负载均衡地址必须在连接起始处发送 PROXY 头，头中的源地址取代 TCP 对端，用于按来源限流和匿名会话来源指纹；未列出的对端发送的 PROXY 头从不被解析。仍不在范围内：按站点（SNI）选择证书和从秘密管理器解析证书（全进程一张证书，SNI 不参与路由，路由仍按监听端口加 Host/`:authority`）、证书热更新（轮换证书需重启 edge）、HTTP/3/QUIC、PROXY v2 TLV 的任何语义（全部跳过、不信任）以及 `X-Forwarded-For`/`Forwarded` 等转发头（仍不信任）。开发环境的本地 stunnel 终止器（见 `dev.sh`）不变。上游 TLS 的证书校验和固定 allowlist 已按本节实现。

站点策略的 waf.blocked_query_fragments 可配置最多 32 个 ASCII 片段；edge 对有查询串的请求先执行有界、单次严格百分号解码和加号空格转换，再做不区分 ASCII 大小写的匹配。命中返回 WAF_QUERY_BLOCKED/403，畸形编码返回 WAF_QUERY_INVALID/400，均发生在源站转发前并记录请求审计。该规则只适合经过站点验证的具体片段；上线前应使用正常业务查询样本检查误拒，并以新策略修订发布。撤回此规则只需发布移除片段的配置快照，不删除已经产生的审计。

按来源限流和匿名会话来源指纹使用 edge 归属的客户端地址：默认是 TCP 对端；对端属于 `XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` 时是它在 PROXY 头中声明的源地址。客户端转发头一律不信任。放在未启用 PROXY protocol 的代理或负载均衡之后时，其后的所有客户端仍会被归为同一来源，站点总限流照常生效。

### 页面签发、动作描述供给与探针 1.1.0

新增网关配置字段（语义见 05 §5.3.1）：`SENSOR_HTML` 响应的 `page_actions: {"mapping_revision": "...", "max_active_pages": 1–1000}`，以及 `UI_ACTION_REQUIRED` 非资源 operation 的 `issued_by: {"page_operation_id": "...", "ttl_seconds": 1–86400}`。没有新增 edge 环境变量；页面签发沿用 `XSHIELD_DATABASE_URL` 与 `identity_store`。worker 新增 `XSHIELD_OUTBOX_FAMILY=ui_action`。

- 启动顺序：只要启动配置声明了 `page_actions`，edge 在绑定任何监听端口之前把由配置推导的动作描述与策略修订写入 PostgreSQL；数据库不可达、修订已存在但摘要不同或非 `active`、或任一描述字段不同，都以 `xshield gateway startup failed: UI_DESCRIPTOR_CONFLICT: ...` 或 `IDENTITY_STORE_UNAVAILABLE` 退出，绝不覆盖已有行。改变描述（路由、方法、目标、页面、mapping revision、`resource_grant` 目标的视图等）必须同时提升 `policy_revision`；只改 `ttl_seconds`、`max_active_pages` 不影响摘要。启动供给最长等待 30 秒。
- 签名 apply：快照中的站点可以声明 `page_actions`/`issued_by`/`resource_grant`。edge 在 apply 锁内依次：判断新快照能否替换正在服务的快照（落后的 revision 或同 revision 异 payload 直接 409，不接触数据库）→ 按站点 ID 顺序为每个声明 `page_actions` 的站点供给动作描述（`Created`/`Existing` 均可；与正在服务的快照逐字节相同的重试不再访问数据库）→ 写签名 pending 文件 → 绑定端口并切换 → 提升为 active。任一站点摘要冲突、修订不是 `active` 或已有描述含义不同时返回 409 `EDGE_APPLY_DESCRIPTOR_CONFLICT`；数据库不可达、4 秒内没有完成（低于控制面 8 秒的请求超时，拒绝能先于传输超时送达）或 edge 的启动配置没有 `identity_store` 时返回 503 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE`。两种拒绝都不写 pending 文件、不改变正在服务的快照与 active 文件；应答体为 `{"error":"edge_apply_failed","reason_code":"…","site_id":"…"}`，其他拒绝的应答体不变、不含 `site_id`。拒绝不签名，`site_id` 只能解释失败，不能作为确认依据；成功确认照旧签名。控制面把这两个码原样记为站点 apply 失败原因，控制台给出中文说明。
- 影响面：apply 对整个租户快照原子生效，因此一个站点的描述冲突或一次 PostgreSQL 故障会挡住同租户所有站点的本次变更（它们继续使用上一份快照）。应答点名出问题的站点，是为以后在控制面只扣住该站点、放行其余站点做准备，这一步尚未实现。拒绝之前已检查通过的站点保留各自的描述行（只表达“该修订对应该描述集”），下一次以 `Existing` 读回。
- 重启：恢复 `XSHIELD_EDGE_SNAPSHOT_PATH` 中的持久化快照时，edge 在绑定任何监听端口之前为其中每个声明 `page_actions` 的站点重新执行同一供给；数据库不可达或没有身份存储以 `IDENTITY_STORE_UNAVAILABLE: persisted snapshot site <站点> cannot supply its action descriptors` 退出，冲突以 `UI_DESCRIPTOR_CONFLICT: persisted snapshot site <站点> policy revision <修订> already binds other action descriptors` 退出，不覆盖已有行，也不退回启动配置。
- 处理 `EDGE_APPLY_DESCRIPTOR_CONFLICT`：同一策略修订号只能对应一组描述。改变上述任一描述字段后，为该站点设置新的 `policy_revision` 再保存并应用；不要修改或删除 PostgreSQL 中的描述行来“解除”冲突，已签发的引用指向这些行。回滚到与某个已登记修订完全相同的描述集会以 `Existing` 通过；被运维停用（`retired`）的修订不会被 edge 重新激活，需要换用新修订号。处理 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE`：恢复 edge 到 PostgreSQL 的连接（或为 edge 配置身份存储）后重新应用。
- 身份运行时来自启动配置：edge 的身份存储连接与身份运行时由 `XSHIELD_CONFIG` 决定，而不是由 apply 快照决定。要由 apply 承载页面签发站点，启动配置必须声明 `identity_store`（并提供 `XSHIELD_DATABASE_URL`、`XSHIELD_FINGERPRINT_KEY_HEX`），并至少声明一条需要身份运行时的路由（真实浏览器回归用一条从不服务的 `AUTHENTICATED_ROOT` 占位路由）；缺少身份存储时 apply 以 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE` 拒绝，只缺身份运行时的受保护请求在准入时失败关闭。`dev.sh` 使用的 `examples/gateway-bootstrap-config.json` 已按此形态声明身份存储与占位路由，`dev.sh` 会为 edge 生成 `XSHIELD_FINGERPRINT_KEY_HEX`，并把此前生成的旧 bootstrap 文件升级到同样的形态，因此本地开发栈可以承载经 apply 下发的页面签发与其他受保护站点（本机无法运行 Docker 栈，该集成只验证了配置文件能让 edge 带身份运行时启动，见 gateway 的 `example_configs` 测试）。
- 控制面站点配置 API 已能保存、审批并下发 `page_actions`/`issued_by`/`resource_grant`、`SENSOR_HTML` 与 `AUTH_ENTRY`（契约见 29“站点浏览器来源流程配置契约”，这些变更只能由独立审批人批准）；控制台的路由抽屉可以编写这些字段（15“控制台编写浏览器来源流程”），未改动的块在读取与保存时原样保留。`xshield_core::edge_descriptors` 让控制面以后能在下发前算出 edge 将供给的摘要，描述集合变化时强制提升 `policy_revision` 尚未实现。
- 升级顺序：先应用迁移 `0052_m5_site_route_provenance_flow.sql`（扩展只写投影 `site_routes` 的准入 CHECK 并新增 `issued_by` 列；加法、可重复执行），再部署新的控制服务；旧控制服务从不写入 `AUTH_ENTRY`，不受影响。新控制服务在缺少该迁移的数据库上写入认证入口路由时整笔事务回滚并返回 503 `CONTROL_SITE_CONFIG_UNAVAILABLE`。开发环境由 `dev.sh` 的 reconciliation 自动补齐 0052。
- 升级顺序：先部署能解析 `ui_action.issued` 的 worker 并为每个站点调度 `XSHIELD_OUTBOX_FAMILY=ui_action`，再启用带 `page_actions` 的网关配置；否则这些行停留在 outbox 中未发布（不影响准入，但调查看不到签发历史）。
- 探针版本：新页面注入 1.1.0（同步脚本 + 页面句柄）；1.0.0 资源仍按原字节提供，不带查询串的 bootstrap 仍返回 1.0.0 文档，prepare 同时接受两个版本，因此滚动升级期间旧实例交付的页面继续工作（仅观测，1.0.0 从不携带引用）。回滚到只提供 1.0.0 的旧网关后，新页面重新注入 1.0.0、不再获得页面引用（受控请求按默认拒绝处理）；回滚前已打开的 1.1.0 页面仍可出示已签发且未过期的引用，旧网关同样按服务端记录逐请求重验。页面 HTML 是 `no-store`，不会从缓存复活 1.1.0 标签。站点 CSP 若限制 `script-src`，仍由既有 nonce 改写覆盖两个同步标签。

### Edge 传输配置（原生 TLS 与 PROXY protocol）

以下变量只由 edge 进程在启动时读取并完整校验，作用于全部数据面端口（不按站点配置）；任一校验失败都以 `xshield gateway startup failed: ...` 退出，错误只包含变量名与路径，不回显文件内容。

| 变量 | 取值 | 未设置 | 校验与失败 |
| --- | --- | --- | --- |
| `XSHIELD_EDGE_TLS_CERT_PATH` | PEM 证书链，叶证书在前，可附中间证书 | 明文监听 | 必须与私钥变量同时设置；设置为空串、只设置一个、文件不可读、不是普通文件或超过 1 MiB、无法解析为证书、叶证书已过期或尚未生效，均拒绝启动 |
| `XSHIELD_EDGE_TLS_KEY_PATH` | 未加密的 PEM 私钥 | 明文监听 | 同上；文件权限含任何 group/other 位（`mode & 0o077 != 0`，如 0644、0640）、与证书公钥不匹配或被 TLS 库拒绝（如强度不足），均拒绝启动 |
| `XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED` | 逗号分隔的 IPv4/IPv6 地址或 CIDR，最多 64 项；单个地址即单主机块 | 关闭（空串同） | 空项、非法地址或前缀、主机位非零（如 `10.0.0.1/8`）、前缀长度 0、IPv4 映射的 IPv6 块均拒绝启动 |

原生 TLS：一张证书服务全部站点端口，证书应覆盖所有公开主机名；edge 不检查 SNI，错误 Host 的请求与明文时一样以 503 `SITE_CONFIG_UNAVAILABLE` 拒绝并计入 `edge.unrouted_denied`。私钥文件须为 0600 或 0400；Kubernetes secret 卷默认 0644，需设置 `defaultMode: 0400`。轮换证书时替换文件后重启 edge，不支持热加载。每个连接的握手在独立任务中进行并限时 5 秒；握手连同 PROXY 头读取占用连接建立名额，每个监听端口 256 个、全进程 1024 个，名额用尽时新连接在 accept 时直接关闭，半开连接洪峰不会无界占用内存或任务；握手完成后 60 秒内没有任何请求字节的连接被关闭（HTTP/1 另有 Pingora 自身的 60 秒请求头读取上限，HTTP/2 的连接前言等待没有上限，此限制补上），没有活动流的 HTTP/2 连接空闲 60 秒后关闭。握手之后的准入、WAF、限流、审计屏障与快照路由不变。HTTP/2 请求按 `:authority` 路由（可以没有 Host）；Pingora 0.9 在 HTTP/1 与 HTTP/2 入口处已以 400 拒绝重复 Host、userinfo 以及 Host 与 `:authority`/绝对形式目标不一致的请求，路由层再以同一规范化（大小写、末尾点和端口不计）复核，任何歧义按未路由拒绝。源站始终收到 origin-form 请求目标和站点配置的 Host，不会收到客户端的 scheme 或 authority。`__Host-` 会话 Cookie 的 `Secure` 属性在原生 TLS 下直接满足；sensor 的 `origin` 仍是站点配置的 HTTPS 公开源，与连接方式无关。

PROXY protocol：负载均衡器必须只对 edge 的这些监听端口启用 PROXY protocol（v1 或 v2，TCP 模式）。同时启用原生 TLS 时，PROXY 头位于 TLS 握手之前，即均衡器以 TCP 直通加 PROXY 头的方式转发，edge 按此顺序处理。受信对端的判断只使用套接字的真实对端地址（IPv4 映射的 IPv6 对端按 IPv4 比较），与连接内容无关；受信对端必须在 3 秒内发送完整有效的头，缺失、格式错误、超长（v1 超过 107 字节、v2 超过 536 字节）或声明 UDP/UNIX 传输的头都会关闭连接，不回退为 TCP 对端地址。`LOCAL` 命令（均衡器健康检查）和 `UNKNOWN`/`UNSPEC` 地址族保留 TCP 对端地址；v2 的 TLV（包括 authority、SNI）全部跳过、不作任何信任依据。头中的源地址取代 TCP 对端用于 edge 归属客户端的所有位置（按来源限流键、匿名会话来源指纹），IPv4 映射地址按 IPv4 计量；审计事件本身不记录客户端 IP。客户端无法在 HTTP 流内自带 PROXY 头伪造地址：只解析连接最开头的一个头，其后的字节属于 TLS 或 HTTP，非受信对端发来的 PROXY 头同样只是会被 HTTP 解析拒绝的普通字节。

失败计数：握手失败或超时、受信对端的 PROXY 头被拒、因名额用尽被关闭的连接都没有到达准入，因此没有请求、也不产生逐请求审计事件；它们只在进程内计数，通过已认证的 loopback 健康接口 `/internal/v1/health` 返回（HMAC 请求认证不变，响应仍不签名、仅用于展示）：`tls_enabled`、`tls_handshake_failures`、`proxy_protocol_enabled`、`proxy_header_rejections`、`connection_setup_shed`。计数从进程启动累计、重启归零；`edge_state` 不受这些计数影响。edge 不记录失败连接的任何字节、证书或私钥材料。control 把健康 JSON 原样并入站点健康详情，控制台可直接展示这些字段，工作台仍只读取 `edge_state`。

## 19.3 密钥与秘密

独立管理 TLS、协议适配、WAF session HMAC、票据签名、证据 KEK、日志签名、模型 API key。按用途和站点隔离，轮换带 key_id、并行验证期、撤销与审计；不得把所有密钥装进一个共享配置 JSON。

管理 OIDC 由控制服务读取 `XSHIELD_CONTROL_OIDC_ISSUER`、`XSHIELD_CONTROL_OIDC_CLIENT_ID`、`XSHIELD_CONTROL_OIDC_CLIENT_SECRET`、`XSHIELD_CONTROL_OIDC_REQUIRED_ACR`、`XSHIELD_CONTROL_CONSOLE_ORIGIN` 与 `XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON`。只允许 HTTPS IdP 和 HTTPS 控制台 origin（开发例外仅 loopback）；discovery/token 请求限时且不跟随重定向，启动时 issuer metadata 不可用则控制服务不启动。subject→角色 JSON 是部署管理员维护的精确 allowlist，不能直接映射 IdP 自声明角色；当前每个控制服务实例将获准主体限定到其启动配置的单一 tenant/site。client secret 由秘密管理器按用途注入、轮换，不写入仓库或浏览器 bundle。

### 本地受保护站点 HTTPS 入口

`dev.sh --all` 会为 `juice.local` 生成带 SAN 的短期自签证书，并启动本地 TLS 终止器，将 `https://juice.local:5443` 转发到 Gateway 的 HTTP 数据面 `127.0.0.1:56188`。证书和私钥只写入 `target/xshield-dev/tls/`，私钥权限为 `0600`。macOS 可执行 `scripts/generate_dev_tls_cert.sh target/xshield-dev/tls --install` 将证书加入当前登录钥匙串；未安装信任时使用 `curl -k` 做本地测试。该终止器只属于开发启动链，生产入口由 edge 原生 TLS（见 19.2“Edge 传输配置”）或受控 HTTPS 负载均衡器终止，并继续通过控制 API 发布站点配置。

多站点保存即应用还需要在 control 与 edge 同时配置 `XSHIELD_EDGE_APPLY_URL=http://127.0.0.1:9553/internal/v1/apply`、相同的 `XSHIELD_EDGE_APPLY_KEY_HEX`；edge 可用 `XSHIELD_EDGE_APPLY_LISTEN` 修改 loopback apply 地址，并用 `XSHIELD_EDGE_LISTEN_PORTS` 提供启动时的 bootstrap 监听集合。生产部署应再设置持久卷上的 `XSHIELD_EDGE_SNAPSHOT_PATH`；edge 会先把已验签的 pending 快照落盘，绑定端口并切换内存快照后再原子提升为 active，重启时只恢复最后一份 active 签名快照，损坏或作用域不符则拒绝启动。快照文件在创建时即以 0600 打开（不是先建后 chmod，不留下他人可读的窗口），pending 与 active 两次 rename 之后都会对所在目录 fsync；目录 fsync 失败时 pending 阶段拒绝该次 apply（503 `EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE`、保持原快照），promote 阶段按持久化失败处理并停止数据面监听。旧版本写出的 0644 快照在加载时收紧为 0600，只读卷上收紧失败仅向 stderr 报告而不阻止启动。control 的第一份快照与 edge 启动时的占位快照（`XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 的空快照或静态配置）同为 revision 1：占位快照从未经 apply 通道应用、没有 payload 摘要，首个 apply 会替换它；两份已应用的 payload 声明同一 revision 时，摘要一致视为幂等重试，不一致仍返回 409 `EDGE_APPLY_IDEMPOTENCY_CONFLICT`，占位快照永远不能顶替同 revision 的已应用快照。启用策略字段和独立审批前应用迁移 0046–0048；审批幂等摘要与 desired revision 一起清除/更新，作者自批由控制面拒绝，浏览器审批要求近期 step-up 重新认证。apply 请求是完整租户快照，edge 先校验 HMAC、租户、单调版本和每站点配置，为声明 `page_actions` 的站点供给动作描述（见上文“页面签发、动作描述供给与探针 1.1.0”），再绑定所需内部端口并一次性替换；并发请求中落后的版本会被拒绝，连接失败、端口冲突或校验失败时 PostgreSQL 保留上一份 active revision。

control 与 edge 之间的 HMAC 通道对三类消息分别认证，并共用同一个 `XSHIELD_EDGE_APPLY_KEY_HEX`，消息字节由 `xshield_core::edge_channel` 统一定义：apply 请求的 HMAC 覆盖请求体（不变）；apply 成功响应带 `x-xshield-apply-ack-signature`，其值是对 `xshield-edge-apply-ack-v1\n<请求签名 hex>\n<确认 JSON 原始字节>` 的 HMAC，因此确认被绑定到它回答的那一次请求（每次尝试都使用新的 snapshot revision，所以请求签名不会重复）；control 先验证再解析，签名缺失、重复、不是 64 位小写 hex、密钥不符、绑定到别的请求或确认字节被改动（哪怕只是多一个空格）都使该次 apply 记为 failed，原因码 `EDGE_APPLY_ACK_SIGNATURE_INVALID`，通过验证后才检查 apply_id、revision 与状态；健康请求不再对固定的 `health-v1` 签名，而是对 `xshield-edge-health-v2\n<unix 秒>\n<32 位小写 hex nonce>` 做 HMAC，并随 `x-xshield-health-timestamp`、`x-xshield-health-nonce` 发送。edge 依次验证签名、±30 秒时间窗口，再把 nonce 记入最多 4096 条、保留 65 秒（两倍窗口加余量）的缓存，重复的 nonce 返回 401 `EDGE_HEALTH_REQUEST_REPLAYED`，过期返回 401 `EDGE_HEALTH_REQUEST_EXPIRED`；缓存已满时返回 429 `EDGE_HEALTH_RATE_LIMITED` 而不是遗忘旧 nonce；只有通过验签的请求才占用缓存，没有密钥的调用方无法耗尽它；缺失、重复或非规范形态的头一律是 401 `EDGE_APPLY_SIGNATURE_INVALID`，不透露更多信息。两端墙钟需保持在 30 秒以内（建议启用 NTP）。

升级顺序必须是先 edge、后 control：新 edge 会为确认签名，旧 control 忽略该响应头；新 control 要求签名确认，旧 edge 的 apply 会被判为 failed（尽管 edge 实际已应用）。新 edge 拒绝旧 control 的固定签名健康请求，所以在 control 升级完成前控制台把 edge 显示为 `unavailable`（`EDGE_HEALTH_UNAVAILABLE`），apply 不受影响。两个限制需要知道：健康响应本身没有签名（它只用于展示，不参与任何决定）；apply 的非 2xx 响应没有签名（伪造它只能让一次 apply 失败，不能让它被误认为成功）。确认绑定的是请求签名而不是每请求随机数：同一份请求体被原样重发时，路径上的主动攻击者可以用先前捕获的确认应答；控制面每次尝试都生成新的 snapshot revision，所以实际不会原样重发。

浏览器仅持有 `Secure; HttpOnly; SameSite=Lax; Path=/` 的不透明随机会话 Cookie；PostgreSQL 仅以 SHA-256 摘要索引会话 token，保存单独的 CSRF token，并由数据库时钟执行 15 分钟闲置/8 小时绝对到期和撤销。`__Host-` Cookie 要求 TLS 且不得配置 Domain。身份会话数据进入数据库备份，故备份权限与恢复流程须按管理身份材料保护；恢复后先撤销不应复活的浏览器会话。控制台通过同源代理访问 API，代理只转发 Xshield 会话/短期 OIDC state Cookie，其他 Cookie 剥离。

密钥不进入 Git、普通日志、模板、测试 fixture 或 Crash dump。服务最小权限获取，KMS 故障不能退回硬编码默认密钥或明文证据。

edge 配置用 `audit.segment_max_bytes` 控制关闭段大小，达到阈值的持久批次完成后自动切换 producer boot。部署方预建仅封存身份可写的私有 manifest 目录，并周期运行 `xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY`。该进程读取 journal 密钥并独占日志签名私钥；edge 不取得签名私钥。重复任务会验证既有清单与关闭段完全一致，再处理新段。

## 19.4 配置与升级

草稿 → validate → 独立测试 → 审批 → 签名 → shadow → canary → active。数据面固定版本读，旧新构建并行范围明确。控制面丢失连接可使用未过期签名配置，但不得跳过身份/资格存储不可用。

数据库采用 expand-contract 迁移，先兼容再删旧字段；回滚版本不得复活撤销 epoch。ClickHouse 保留策略升级先执行 `retention_expires_at` 扩展和 active 视图 DDL，再部署显式写期限的新 worker；旧行沿用 30 天默认值。每次升级验证队列 drain、journal seal、未完成请求、插件终止与模型取消。

启用 OIDC 浏览器会话前先应用迁移 0035、更新控制 journal 发布器以识别 `console.auth.*` 事件，再部署控制 API、同源代理和静态控制台。启用原文 MFA step-up 前还须应用迁移 0036、部署识别 `console.auth.reauth.*` 的发布器，并确认代理为 `POST /control/v1/auth/oidc/reauth/start` 透传 `Set-Cookie` 且不缓存/记录正文。回滚 OIDC 前先停用其路由并撤销活动管理会话；单独回滚迁移 0036 前须先禁用原文内容路由，或保持 step-up-aware 控制服务运行，绝不可先移除 step-up 字段。

## 19.5 运行状态

liveness 仅说明进程存活；readiness 根据必要配置、状态存储和审计耐久性判断；推理不可用是否撤 readiness 依赖该节点承接的模型必需端点。拒绝流量尖峰不自动认定业务故障或自动降级。

自动化指标：资格发行失败、绑定串用、无来源操作、解密覆盖、兼容比例、模型低信心/超时、journal 剩余空间、索引延迟、证据缺失/摘要失败、原文读取与大导出。

## 19.6 备份与恢复

PostgreSQL 配置/资格及 outbox 按恢复目标备份；证据库版本化与独立权限复制；签名验证材料和 KMS 恢复流程同样不可缺少。恢复演练包括身份 epoch、过期资格、保留 tombstone、未完成请求和重复投递。密钥丢失导致证据不可读应记录为不可恢复，而不是显示空白。

首版不作跨区域强一致承诺。新增多区域时先给出故障域、RPO/RTO、网络分区策略和实际演练报告。
# Edge 配置发布

设置 `XSHIELD_EDGE_APPLY_URL`、`XSHIELD_EDGE_APPLY_KEY_HEX`、`XSHIELD_EDGE_SNAPSHOT_PATH` 后，control 通过 loopback HMAC 发布快照。Gateway 可用 `XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 启动空快照；控制面不可用时继续使用最后一个签名快照，签名、租户、revision、摘要或监听端口不匹配时 fail-closed。

`XSHIELD_PUBLIC_HOSTS`（逗号分隔的主机名，可选）只作用于由 `XSHIELD_CONFIG` 启动的静态 bootstrap 站点：它列出该站点接受的 `Host`，缺省为配置里的 `origin.server_name`；监听地址是回环时，edge 还会接受该回环 IP 作为精确 Host，方便本地探测。已有签名快照时以快照为准，`XSHIELD_EDGE_BOOTSTRAP_ONLY=1` 的空快照也不使用它；控制面发布的站点，公开主机来自各自的 `public_origin`。Host 不匹配的请求按 `HOST_NOT_ROUTED` 拒绝并计入 `edge.unrouted_denied`，不会因为设置了本变量而放宽。

## 19.7 发布打包

`scripts/package_release.sh` 构建 release 二进制（gateway、control、worker、outbox-worker、evidence-retain、model-eval、audit-seal）和控制台静态包，并与迁移、`sql/clickhouse.sql`、示例配置、部署与运行手册（19、26，另含审计可靠性 13、控制台与 API 15、性能与容量 21、接口目录 29）一起装配成 `xshield-<版本>-<系统>-<架构>.tar.gz`，同时写出文件级 `MANIFEST.sha256` 和压缩包的 SHA-256。该脚本没有默认输出位置：必须显式设置 `XSHIELD_DIST_DIR`（暂存树与压缩包）和 `CARGO_TARGET_DIR`（cargo 构建产物），且二者不得位于仓库内，因为 release 构建产物很大，应落在专用的大容量磁盘上。

在 macOS 上若使用外接 exFAT 磁盘，不要直接把 `CARGO_TARGET_DIR` 放在其上：exFAT 没有硬链接和 POSIX 权限，随附的 OpenSSL 源码构建会以 `Directory not empty` 失败。可以在该磁盘上创建 APFS 稀疏包（`hdiutil create -size 400g -type SPARSEBUNDLE -fs APFS -volname XshieldBuild -attach <磁盘>/xshield-build.sparsebundle`），把构建与打包目录放在其挂载点下；磁盘空间只在该外接盘上按需增长。

打包不运行测试、不签名、不发布也不部署；版本取自 `git describe`，工作区有未提交改动时会警告。它也不构建容器镜像：当前没有 Dockerfile、Helm 清单或 systemd 单元，生产部署仍需自行编排（TLS 由 edge 原生终止或由前置终止器终止，见 19.2 的当前实现状态）。

