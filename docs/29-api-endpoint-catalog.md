# 29 控制 API 与审计责任清单

本章定义自定义接口；当前 `GET /control/v1/audit/health`、`GET /control/v1/requests/{request_id}`、`GET /control/v1/requests/{request_id}/events`、`POST /control/v1/search`、`POST /control/v1/causality`、`GET /control/v1/requests/{request_id}/evidence`、`GET /control/v1/model-calls`、`GET /control/v1/model-calls/{model_call_id}`、`GET /control/v1/agent-runs/{agent_run_id}`、`GET /control/v1/grants/{grant_id}`、`GET /control/v1/auth-bindings/{binding_id}`、`GET /control/v1/artifacts/{artifact_id}`、`GET /control/v1/artifacts/{artifact_id}/content`、`POST /control/v1/cases`、`GET /control/v1/cases`、`POST /control/v1/cases/{case_id}/items`、`GET /control/v1/cases/{case_id}/items`、`POST /control/v1/cases/{case_id}/close`、`POST /control/v1/cases/{case_id}/analyze`、`GET /control/v1/jobs/{job_id}`、`POST /control/v1/exports`、`GET /control/v1/exports?view=mine|review`（29.33）、`GET /control/v1/exports/{export_id}`、导出批准/拒绝/下载、`POST /control/v1/artifacts/{id}/access`、证据访问批准/拒绝、OIDC 登录/会话/再认证及 29.21 的保留锁创建/释放/列表端点已由 `xshield-control` 实现，其余条目仍是设计契约。所有 `/control/v1` 接口经管理身份验证、tenant/site作用域检查与速率限制；用户数据API和控制API必须分网络/认证边界。状态变更使用CSRF或对应机器凭证防护，GET不得产生重放或生产业务副作用。

站点接入后台的配置写入要求 `SystemAdmin`，按固定 tenant/site 保存受保护站点、源站、安全入口、策略版本、状态和唯一监听端口；写入使用 `Idempotency-Key`，响应同时返回经过校验的 gateway 启动配置草稿。

多站点运营接口使用同一租户的站点范围：`GET /control/v1/sites?limit=1..100[&cursor=<signed>]` 返回有界站点元数据，游标绑定管理凭证摘要、主体、租户、页大小和最后站点 ID；`GET/PATCH /control/v1/sites/{site_id}` 与 `GET/PUT /control/v1/sites/{site_id}/config` 由服务端重新校验站点作用域。端口分配记录在独立租户端口租约表中，配置写入和端口租约在同一短事务内串行化；公网 origin 与内部 edge 监听端口分别保存。完整租户快照使用独立的单调 revision，edge 会在原子替换前拒绝落后的并发快照。写入会创建持久化 apply intent，并在没有认证 edge 确认时返回 `pending`、desired/active revision、apply_id 和稳定原因码；状态、健康、校验、应用、回滚和修订端点都暴露这条边界。健康端点同时探测已批准的固定上游 socket 与 health path，禁用重定向并把结果作为 `upstream_state` 返回。

端口请求为 `0` 时，新站点从租户端口池取得最小空闲端口；已有站点更新会复用原 active lease，只有显式指定新端口才迁移租约。迁移、释放和唯一性检查都在同一事务锁内完成。

上游地址校验（SSRF 防护）：`upstream_address` 必须是 IP 字面量套接字（`203.0.113.9:80`、`[2001:4860:4860::8888]:443` 之类），控制面从不代操作者解析名称；端口经类型化地址校验，80/443 等默认端口合法，0 被拒绝。保存时与健康探测连接前使用同一个纯函数（`xshield_core::site::upstream`）按解析后的数值分类，而不是检查文本：回环、未指定、RFC 1918 私网、RFC 6598 共享地址、链路本地、唯一本地、组播、保留/基准/文档段，以及云元数据地址（`169.254.169.254`、`168.63.129.16`、`100.100.100.200`、`192.0.0.192`、`fd00:ec2::254`）一律拒绝；IPv4 映射 IPv6（`::ffff:a.b.c.d`）和 NAT64、6to4、Teredo 等内嵌 IPv4 的形式不展开而直接拒绝。拒绝统一返回 400 `CONTROL_SITE_SSRF_BLOCKED` 并写入 DENY 审计，非 IP 字面量返回 `CONTROL_SITE_UPSTREAM_INVALID`。`upstream_server_name` 必须被探测所用的 URL 解析器识别为域名：`127.0.0.1`、`2130706433`、`0x7f.1` 等会被读成 IP 主机的写法同样返回 `CONTROL_SITE_UPSTREAM_INVALID`，因为 HTTP 客户端不对 IP 主机套用解析覆盖，会直接连接该地址。唯一的显式放行是部署环境变量 `XSHIELD_ALLOW_LOOPBACK_UPSTREAM=1`（`dev.sh` 为本地靶场设置），它只放行 `127.0.0.0/8` 与 `::1`，不放行私网、元数据、映射或转换形式。健康探测对已持久化的行再次校验，并且只连接已验证的套接字：固定到配置端口、不使用环境代理、禁用重定向，`Host` 携带配置的服务名和端口；升级前写入或被直接改库的行因此也不会让探测向内部地址转发请求。

配置校验与 edge 编译一致性：edge 快照是整体替换，任何一个站点配置被 edge 编译器拒绝都会使该租户所有 apply 失败，所以控制面校验必须不比 edge 宽松。`xshield-core` 的 `SiteConfig::validate`（含 `SitePolicyConfig::validate`）是唯一定义，拒绝 edge 编译器会拒绝的一切：路由路径只允许可打印 ASCII（空格、非 ASCII、控制字符、DEL 均拒绝），不得落入 edge 自用的 `/__xshield/` 命名空间；同方法同固定前缀的 `{param}` 路由（不论参数名）、被 `{param}` 路由同方法匹配的固定路径路由（不论声明顺序）、超过 64 条 `{param}` 路由；请求 crypto 仅限 POST/PUT/PATCH 且不用于 UI 来源操作，明文不超过信封一半、消息有效期不超过 3600 秒、标识符只含字母数字和 `_-.`；响应信封须不小于两倍明文加 1024 字节；`SENSOR_HTML` 响应模式因路由无法表达适配器元数据而拒绝；每站点最多一把请求解密密钥和一把响应加密密钥且不得共用；公开 origin 不接受 IPv6 字面量（edge 按主机名路由），开启 sensor 时明文 HTTP 只允许 `localhost` 与 `127.0.0.1`；站点 ID 加 `edge-` 前缀不得超过 128 字节。失败映射为稳定原因码：上游相关 `CONTROL_SITE_UPSTREAM_INVALID`，策略/路由 `CONTROL_SITE_POLICY_INVALID`，站点 ID `CONTROL_SITE_ID_INVALID`，其余 `CONTROL_SITE_CONFIG_REQUEST_INVALID`。控制面生成的 edge 配置同步调整：身份存储按有效路由的实际需要输出（任一路由需要身份或请求 crypto 即输出，而不只看顶层入口模式），匿名会话创建速率随 TTL 缩放以保持在 edge 的容量模型内（TTL 不超过 5940 秒时与此前一致），sensor origin 去除末尾斜杠。

本地开发启动会先执行 M5 schema reconciliation：`xshield.dev_schema_migrations` 以迁移文件 SHA-256 记录 0041–0051，单次执行持有 PostgreSQL advisory lock。已完整存在的对象只登记 ledger，缺失对象按顺序在事务中应用；半成品或 checksum 不一致会阻止控制服务启动，既不删除数据也不自动回退。站点错误保持稳定 `CONTROL_SITE_*` reason code，并由控制台映射为安全提示和 request ID。

| 方法与路径 | 用途 | 必需审计 |
|---|---|---|
| GET /control/v1/requests/{request_id} | 请求概要和完整性状态 | console.request.read |
| GET /control/v1/requests/{request_id}/events | 事件游标分页和阶段树 | console.events.read |
| GET /control/v1/requests/{request_id}/evidence | 证据manifest清单 | console.manifest.read |
| GET /control/v1/model-calls | 窗口内模型调用最新脱敏状态分页 | console.model.list |
| GET /control/v1/model-calls/{model_call_id} | 模型调用、实际输入输出引用 | console.model.read |
| GET /control/v1/grants/{grant_id} | 资格与当前绑定账本快照、来源请求引用 | console.grant.read |
| GET /control/v1/auth-bindings/{binding_id} | 当前身份与凭证代际、状态、期限 | console.binding.read |
| GET /control/v1/agent-runs/{agent_run_id} | Agent 运行及工具树（脱敏生命周期，已实现，29.30） | console.agent.read |
| GET /control/v1/site-config | 受保护站点配置与 gateway 启动配置草稿 | console.site.config.read |
| PUT /control/v1/site-config | 幂等写入受保护站点配置并分配监听端口 | console.site.config.write |
| GET /control/v1/sites | 租户范围的受保护站点列表 | console.sites.list |
| GET /control/v1/sites/{site_id} | 单站点配置兼容视图 | console.site.config.read |
| PATCH /control/v1/sites/{site_id} | 单站点幂等配置写入 | console.site.config.write |
| GET /control/v1/sites/{site_id}/config | 单站点配置与 gateway 草稿 | console.site.config.read |
| PUT /control/v1/sites/{site_id}/config | 单站点幂等配置写入并分配内部端口 | console.site.config.write |
| POST /control/v1/sites | 创建租户范围的受保护站点 | console.site.create |
| DELETE /control/v1/sites/{site_id} | 删除站点并释放内部端口租约；要求浏览器会话两分钟内完成 MFA step-up，机器凭证不可删除 | console.site.delete |
| GET /control/v1/sites/{site_id}/status | 读取 desired/active revision 和应用状态 | console.site.status.read |
| GET /control/v1/sites/{site_id}/health | 读取站点配置与 edge 应用健康边界 | console.site.status.read |
| GET /control/v1/sites/{site_id}/revisions | 读取当前发布边界 | console.site.status.read |
| POST /control/v1/sites/{site_id}/validate | 校验已持久化站点配置 | console.site.config.validate |
| POST /control/v1/sites/{site_id}/apply | 请求受保护的 edge 应用；draft 站点稳定拒绝，持有 `site.config.apply_direct` 的 Agent 可直接应用并留下审批记录 | console.site.config.apply |
| POST /control/v1/sites/{site_id}/approve | PolicyApprover 独立批准绑定到当前 desired revision 的高风险修订并触发应用；可选 `X-Xshield-Expected-Config-Digest` 固定所审阅的配置 | console.site.config.approve |
| POST /control/v1/sites/{site_id}/rollback | 以先前 active 修订的完整配置创建新修订（修订号不复用），按审批规则评估、幂等、写审计 | console.site.config.rollback |
| GET /control/v1/artifacts/{artifact_id} | 单个证据manifest | console.manifest.read |
| POST /control/v1/search | 受限查询AST，非任意SQL | console.query.executed |
| POST /control/v1/causality | 固定窗口内有界多跳因果摘要 | console.causality.read |
| POST /control/v1/artifacts/{id}/access | 申请解密/原文查看能力 | evidence.access.requested |
| GET /control/v1/evidence-access-requests | 本人申请历史与独立审批待办（已实现，29.24） | console.evidence.access.list |
| GET /control/v1/evidence-access-requests/{access_request_id} | 申请理由、目标与历史决策详情（已实现，29.23） | console.evidence.access.read |
| POST /control/v1/evidence-access-requests/{id}/approve | 独立批准并建立短时读取资格 | evidence.access.approved |
| POST /control/v1/evidence-access-requests/{id}/deny | 独立拒绝并终结申请 | evidence.access.denied |
| GET /control/v1/artifacts/{id}/content | 获批后读取，短时作用域能力 | evidence.read，含批准引用 |
| POST /control/v1/cases | 建立调查案例 | case.created |
| GET /control/v1/cases | 分页发现本人开放和已关闭案件 | console.case.list |
| POST /control/v1/cases/{id}/items | 把获准证据加入案例 | case.evidence.added |
| GET /control/v1/cases/{id}/items | 查询本人案件证据引用集合 | console.case.read |
| POST /control/v1/cases/{id}/close | 关闭本人案件并保留调查历史 | case.closed |
| POST /control/v1/cases/{case_id}/holds | 管理员保留案件成员证据 | console.evidence.hold.created |
| POST /control/v1/evidence-holds/{hold_id}/release | 管理员释放保留锁 | console.evidence.hold.released |
| GET /control/v1/cases/{case_id}/holds | 管理员分页查询保留历史 | console.evidence.hold.read |
| POST /control/v1/cases/{id}/analyze | 启动只读案件清单分析任务（MVP） | console.case.analyze |
| POST /control/v1/replays | 离线规则评估，不送原站（设计，尚未实现） | replay.requested/completed |
| POST /control/v1/exports | 带用途/范围/审批的导出任务 | export.requested/approved/downloaded |
| GET /control/v1/exports | 本人导出历史与独立审批待办（已实现，29.33） | console.export.list |
| GET /control/v1/exports/{export_id} | 读取本人或管理范围内的导出状态 | console.export.read |
| POST /control/v1/exports/{export_id}/approve | 独立批准并生成短时元数据包 | export.approved |
| POST /control/v1/exports/{export_id}/deny | 独立拒绝导出请求 | export.denied |
| GET /control/v1/exports/{export_id}/download | 领取加密元数据包（最多两次） | export.downloaded |
| GET /control/v1/jobs/{id} | 查看本人任务进度与错误 | console.job.read |
| POST /control/v1/sites/{id}/candidates | 提交配置候选（设计，尚未实现） | policy.proposed |
| POST /control/v1/candidates/{id}/validate | 受控验证（设计，尚未实现） | policy.tested |
| POST /control/v1/candidates/{id}/approve | 审批不等于部署（设计，尚未实现） | policy.approved |
| POST /control/v1/candidates/{id}/publish | 灰度签名发布（设计，尚未实现） | policy.published |
| POST /control/v1/sites/{id}/rollback | 回退已验证版本 | policy.rolled_back |
| GET /control/v1/audit/health | 各层watermark、gap与存储状态 | console.health.read |
| GET /control/v1/auth/oidc/start | 启动授权码 + PKCE 管理员登录 | console.auth.login |
| GET /control/v1/auth/oidc/callback | 消费 OIDC callback 并建立服务端会话 | console.auth.callback |
| POST /control/v1/auth/oidc/reauth/start | 为当前 OIDC 浏览器会话发起 MFA step-up | console.auth.reauth.start |
| GET /control/v1/session | 读取当前浏览器主体、作用域与 CSRF bootstrap | console.auth.session.read |
| POST /control/v1/session/logout | 撤销当前浏览器会话 | console.auth.session.logout |

## 29.1 查询契约

请求包含 tenant/site（服务端仍校验）、时间窗、类型化过滤器、允许的sort、limit、cursor。禁止自由SQL或可注入表达式。request_id精确查找不要求用户猜日期；先经热定位目录到所属时间桶。返回 index_watermark、as_of、has_gaps、next_cursor。分页令牌绑定调用者作用域和查询摘要，不能跨租户复用。

对未获权ID返回不泄露存在性的统一结果。证据读取另走授权，不因能查摘要就能解密原包。大内容预览与下载分离，浏览器不执行证据中的脚本。

## 29.2 任务语义

长任务返回202和job_id，调用方查询进度。任务状态为queued/running/succeeded/failed/cancelled；失败附稳定原因码、可重试性和最后耐久点。幂等键绑定主体、动作和参数摘要；不同参数不复用。取消保留此前产生的审计证据，禁止删掉历史伪装任务没有发生。

## 29.3 权限角色

Observer 看脱敏概要；Investigator 执行受限查询和申请证据；SensitiveEvidenceApprover 为其他主体批准/拒绝原文访问；SensitiveEvidenceReader 在获批短时范围看受限内容；PolicyAuthor 提交候选；PolicyApprover 批准策略；ReleaseOperator 发布；AuditAdministrator 管理保留与完整性；KeyAdministrator 管理密钥但默认不能解密业务证据。支持职责分离和紧急break-glass，但紧急操作也须理由、短时权限和独立审计。

## 29.4 错误契约

统一结构包含error_code、message_safe、request_id、retryable、next_action；禁止堆栈、凭证、资源归属和内部SQL进入客户端错误。401用于管理认证要求，403用于已认证的禁止操作，409用于代际/修订冲突，429用于预算限制，503用于必需依赖不可用。具体重试不自动重新执行生产业务。

案件创建等端点使用的通用管理错误审计路径将 4xx 记为 `DENY`、5xx 记为 `ERROR`，区分输入/权限/预算拒绝与依赖故障；HTTP 状态和稳定原因码保持对应的端点契约。历史事件保留原记录。

## 29.5 已实现的审计健康契约

`GET /control/v1/audit/health` 的 tenant/site 由服务启动配置固定注入，请求不能选择作用域。管理 Bearer 凭证只保存摘要并采用常量时间比对，签发和过期时间在启动时限制为最长 24 小时且每次请求重验；主体还须持有该精确作用域的 `AuditAdministrator`。服务仅监听 loopback，由独立管理 TLS 边界接入。

成功响应包含 request_id、tenant_id、site_id、观察时间、目标索引、元数据保留天数、关闭段数量与字节、published/pending/unsealed 数量、连续水位和 gap 状态，并设置 `Cache-Control: private, no-store`。401、403、429 和 503 使用 29.4 的统一错误结构。可审计尝试在响应前写入独立加密 journal 的 `console.health.read` 事件；该耐久写失败时返回 503。

## 29.6 已实现的请求事件契约

`GET /control/v1/requests/{request_id}/events` 要求 Observer 和服务端固定的 tenant/site 精确作用域；路径 ID 必须通过强类型校验。查询只访问去重且执行保留策略的 `audit_events_active`，以参数绑定注入作用域和请求 ID，并设置 2 秒执行、100 万扫描行及 1–1000 返回行上限。当前上限由 `XSHIELD_CONTROL_MAX_QUERY_EVENTS` 固定；响应以 `truncated=true` 和 `next_cursor` 明确还有后续数据。续页使用 `?cursor=` 原样传回服务端；游标为 URL-safe、不透明的 HMAC 令牌，由 `XSHIELD_CONTROL_CURSOR_KEY_HEX` 独立密钥签发，绑定管理主体、tenant/site、目标 request_id、查询版本、页大小及最后事件位置，不能跨主体、作用域、请求或配置复用。无效游标返回 `CONTROL_CURSOR_INVALID`，不会执行索引查询。

成功响应包含独立管理 request_id、目标 source_request_id、tenant/site、as_of、连续 index_watermark、has_gaps、truncated、next_cursor 和按 request_seq/event_id 排序的事件摘要。摘要不含 payload_json 或原文，只返回类型、阶段、结果、原因、证明类型、允许的 confidence、修订、证据引用和敏感级别；证据内容仍走独立审批。成功、拒绝和依赖故障写 `console.events.read` 管理审计并绑定已校验的目标请求 ID；审计失败返回 503。响应统一 `private, no-store`。

## 29.7 已实现的请求摘要契约

`GET /control/v1/requests/{request_id}` 复用 Observer、服务端 tenant/site 精确作用域、强类型路径 ID、固定 2 秒/100 万扫描行预算与 active 去重保留视图。发布器在事件契约校验通过后一次性提取 method、operation_id、origin_state、HTTP status 和终态标记；聚合查询不读取 `payload_json`。升级须先应用 `sql/clickhouse.sql` 的目标表/source 表扩展，再部署写入新列的发布器。

响应返回事件数、首末发生时间、可用的 method/operation、终态 decision/reason/status/origin/duration、是否产生转发意图及业务结果是否确认；`stages` 按首次 request_seq 排序，最多返回 128 个已观察阶段的最新结果、原因、证明、confidence 状态、序列范围、耗时和事件数，超界或索引行不满足事件契约时整次查询失败。缺失字段为 null。`completeness` 为 complete、pending、pending_index 或 not_found，并同时返回连续水位、gap 和 pending segment 数，避免在索引未追平时把缺失误报为不存在。成功、拒绝和依赖故障写 `console.request.read`；审计失败返回 503，响应统一 `private, no-store`。身份引用尚未进入 v3 脱敏事件契约，因此当前摘要不推断或伪造该字段。

## 29.8 已实现的请求证据 manifest 契约

`GET /control/v1/requests/{request_id}/evidence` 要求 Observer 与服务端固定 tenant/site 精确作用域；路径 ID 先转强类型，查询再绑定 tenant/site/request，只返回 PostgreSQL catalog 中 active、未删除且按数据库当前时钟未过期的行。响应包含独立管理 request_id、目标 source_request_id、作用域、`truncated`、`next_cursor` 及 typed manifest；不读取对象文件、不返回明文，也不把 catalog 元数据当作内容授权或完整性真值。

结果按规范 artifact UUIDv7 身份稳定排序，页大小由 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS` 固定在 1–128。游标由 `XSHIELD_CONTROL_CURSOR_KEY_HEX` 以 manifest 专用用途域签名，绑定管理 Bearer 摘要、主体、tenant/site、目标请求、页大小与最后 artifact，不能跨事件接口、主体、作用域、请求或配置复用。成功、拒绝、无效游标及数据库故障写 `console.manifest.read`；必需审计失败返回 503，所有响应设置 `private, no-store`。敏感内容仍须通过独立审批和短时 EvidenceReadPort 能力读取。

## 29.9 已实现的单证据 manifest 契约

`GET /control/v1/artifacts/{artifact_id}` 要求 Observer 与服务端固定 tenant/site 精确作用域；路径 ID 必须是规范 artifact UUIDv7。查询使用 catalog 主键前缀绑定 tenant/site/artifact，并按数据库时钟过滤 active、未删除和未过期状态。成功响应包含独立管理 request_id、目标 source_artifact_id、服务端作用域、`found` 和可选 typed manifest；不存在、删除、到期与其他作用域均返回 200、`found=false`、`artifact=null`。

有效目标 ID 会进入管理审计的 `target_artifact_id`，实际返回的对象才进入 `evidence_refs`。成功、拒绝和数据库故障均写 `console.manifest.read`；必需审计失败返回 503，响应统一 `private, no-store`。该接口不读取对象文件、manifest HMAC 或密文；后续内容接口仍须独立审批，并由 EvidenceReadPort 重验对象侧完整性与期限。

## 29.10 已实现的调查案件创建契约

`POST /control/v1/cases` 要求固定 tenant/site 作用域内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，只接受 `{"purpose":"..."}` 严格 JSON；purpose 去除首尾空白后必须保持原值，UTF-8 字节长度为 1–512，拒绝控制字符。`Idempotency-Key` 必填且须单值，只允许 16–128 字节 ASCII 字母、数字、`-_.:`。tenant、site、owner 与 case UUIDv7 均由服务端确定。

服务使用独立的 `XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX` 以用途域 HMAC 保存绑定主体、tenant/site、键和请求参数的摘要，不保存原始幂等键，也不复用分页密钥。每个 owner/tenant/site 的 open 案件数由 `XSHIELD_CONTROL_MAX_OPEN_CASES` 限制在 1–10000；并发服务实例必须使用相同上限。PostgreSQL 事务在同一锁域完成精确幂等检查、容量检查、案件写入和 `case.created` outbox。首次创建返回 201，精确重试返回原案件和 200，不同参数复用同一键返回 409，容量耗尽返回 429，依赖故障返回 503。

所有尝试写管理审计；成功及精确重试携带 `target_case_id`，失败不猜测目标。事务 outbox 记录业务创建事实，管理审计记录接口尝试，两者均不包含原始幂等键。创建案件仅建立后续审批上下文，不授予 manifest、脱敏内容、敏感原文或导出权限；这些能力仍须独立授权。

创建与案件关联/集合查询/关闭共享单实例一个执行许可，繁忙返回 `CONTROL_CASE_BUSY`/429。SQL 单语句及锁等待各限 5 秒，包含池等待的数据库整体操作限 15 秒；故障或超时为 `CONTROL_CASE_STORE_UNAVAILABLE`/503。准入后的任务在客户端断连后继续到数据库与耐久管理审计终态；许可持有至审计完成，本地 fsync 和进程退出仍为部署故障边界。超时或审计失败可能发生在事务提交之后，调用者须保留原键与 purpose 原样重试；不能由失败回复推断没有创建案件。创建响应保持既有无 schema_version 的契约；精确重试可返回已经 closed 的原案件。

## 29.11 已实现的证据访问申请契约

`POST /control/v1/artifacts/{artifact_id}/access` 要求固定 tenant/site 内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，严格接受 `case_id`、固定值 `access_kind=sensitive_raw` 和 1–512 UTF-8 字节且无首尾空白的 `justification`；路径 artifact、案件及申请 ID 均使用强类型 UUIDv7。`Idempotency-Key` 复用管理变更专用密钥但使用独立用途域，摘要绑定主体、作用域、路径 artifact、case、访问类型和理由，原始键不入库。

申请与批准/拒绝接口要求单值 Authorization 和 Idempotency-Key，拒绝任何查询串；重复认证头按未认证处理，重复幂等头按无效键处理。严格输入校验先于数据库准入。申请、批准、拒绝和内容读取与案件操作共享单实例在途许可，繁忙返回 `CONTROL_EVIDENCE_ACCESS_BUSY`/429；原有 pending 容量限制继续独立生效。

新申请必须引用请求主体自己拥有的 open 案件和同作用域 active、未删除、按数据库时钟未过期的 artifact。事务持有目标共享锁，按 tenant/site/subject 串行化精确重试与 pending 容量检查，并原子提交 `pending` 申请和 `evidence.access.requested` outbox。首次返回 201，精确重试返回原申请和 200，参数冲突 409，目标不可用统一 404，容量耗尽 429，依赖故障 503。

成功与失败尝试均写独立加密管理审计；成功及精确重试携带 artifact、case、access_request 目标和 artifact evidence ref。申请只建立待审批事实，不调用 EvidenceReadPort、不解密对象、不返回内容；后续独立审批必须绑定另一主体、明确期限与同一作用域。

申请与决策的数据库整体预算含连接池等待为 15 秒，事务内单语句和锁等待各限 5 秒。已准入任务在客户端断连后继续到数据库结果和管理审计终态，许可覆盖终态审计。超时、连接错误或审计失败不能证明事务未提交，应保留原键与完整参数确认结果；精确重试返回原记录。4xx 访问尝试记为 DENY，5xx 记为 ERROR；事务 outbox 与管理访问审计分别记录提交事实和接口尝试。进程退出仍是故障边界，预算不包含本地审计 fsync。

## 29.12 已实现的证据访问决策契约

`POST /control/v1/evidence-access-requests/{access_request_id}/approve` 与 `/deny` 要求固定 tenant/site 内的 `SensitiveEvidenceApprover` 和管理机器凭证。两者请求体上限 4 KiB、要求规范 `Idempotency-Key`，并严格接受 1–512 UTF-8 字节且无首尾空白的 `reason`；批准额外要求 `ttl_seconds` 在 1 到服务端 `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS` 之间，该启动上限最大 86400 秒。决策幂等摘要以独立用途域绑定主体、作用域、键、申请、动作、理由和 TTL，原始键与理由均不进入 outbox。

PostgreSQL 按 tenant/site/decider 串行化幂等键并锁定申请行；申请人不能决定自己的申请，且 pending 申请只允许一个终态。拒绝直接终结申请且不产生读取资格；批准还会持有案件与 artifact 共享锁，重新要求申请人拥有 open 案件及 active、未删除、按数据库时钟未过期的 artifact。有效期限取数据库决策时间加请求 TTL 与 artifact 到期时间中的较早值，终态和 `evidence.access.approved` 或 `evidence.access.denied` outbox 同事务提交。首次和精确重试均返回 200；幂等或终态冲突 409，自批 403，申请或批准目标不可用统一 404，依赖故障 503。

成功响应携带申请、case、artifact、申请人、决策人、终态、决策时间和可选资格期限。每次尝试写独立加密管理审计，成功与精确重试包含全部目标和 artifact evidence ref。批准行是后续 EvidenceReadPort 的服务端资格真值；当前端点不读取对象、不返回明文或下载 URL。

申请锁定目标后重新检查 artifact 期限，并在写入时再次检查；批准取得目标行锁后读取新的数据库时间，重新验证对象期限并从该时间计算 TTL。锁等待前的时间与期限条件不能作为锁后的有效性证明；精确决策重试保持原决策时间和原期限。准入、断连、超时与失败审计沿用 29.11。

## 29.13 已实现的证据内容读取契约

`GET /control/v1/artifacts/{artifact_id}/content` 要求固定 tenant/site 内的 `SensitiveEvidenceReader`、当前同源 OIDC 浏览器会话的两分钟 MFA step-up，以及 `X-Xshield-Evidence-Access-Request` 头中的强类型 access request ID。该会话须由部署方配置的 ACR 与最近 60 秒 OIDC `auth_time` 再认证；step-up 不替代逐申请独立审批。当前机器 Bearer 没有 step-up 凭据路径，不能读取原文。服务端要求申请的 `requested_by` 等于当前管理主体，状态为 `approved`，资格、案件和 catalog 均仍有效，且 artifact 仍 active、未删除并未过期；缺少、跨主体、跨作用域、拒绝、撤销、过期和删除统一返回 `CONTROL_EVIDENCE_READ_NOT_AVAILABLE`/404。未完成 step-up 时返回 `CONTROL_STEP_UP_REQUIRED`/403；管理 session 已在 middleware 校验，内容 handler 在获取证据读取许可、查询访问申请/catalog 或调用 vault 前拒绝。数据库检查通过后，EvidenceReadPort 重新认证 vault manifest HMAC、scope、期限、key-id、ciphertext digest 与 AEAD；目录与 vault manifest 不一致或认证失败不会返回内容。

Authorization 与访问申请头必须各自单值，不接受查询串；重复访问申请头按缺少申请引用拒绝，查询串返回 `CONTROL_EVIDENCE_READ_REQUEST_INVALID`/400。数据库授权读取的整体预算为 15 秒，短事务中语句/锁等待最多 5 秒，持有申请、案件与 catalog 共享锁后用新的数据库时间检查资格和对象两项期限。事务在访问 vault 前结束；获准在途读取沿用其授权观察，后续状态改变不撤回已经释放的字节。

成功响应为 `application/octet-stream` 的 `attachment`，设置 `Cache-Control: private, no-store` 与 `X-Content-Type-Options: nosniff`，不返回下载 URL。内容释放前写入独立加密管理审计 `evidence.read`，绑定 access request、artifact 和 evidence ref，并记录实际字节数；审计、数据库、vault 或完整性依赖失败返回 503，响应正文不泄露资源归属或内部错误。

二进制成功响应通过 `X-Xshield-Request-Id`、`X-Xshield-Tenant-Id`、`X-Xshield-Site-Id`、`X-Xshield-Artifact-Id`、`X-Xshield-Evidence-Access-Request` 提供管理请求、已认证范围和精确目标，并用 `Content-Length` 声明完整字节数。控制台须核对这些头、媒体类型、附件属性、实际长度及当前会话范围后才生成临时下载对象；代理需透传这些头。旧客户端可忽略新增头，新下载界面须在控制服务升级后启用。服务端读取审计证明内容已准备释放，不证明浏览器收到或用户保存成功。

本地整对象 MVP 每个 EvidenceReadPort 同时保留一个读取/响应对象：许可在调度解密前获取，并随清零明文缓冲交给 HTTP 响应，直到最后一个响应字节引用释放；取消请求不会提前归还仍在执行的解密许可。容量占满返回带独立审计的 `CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED`/503。缓冲直接移交给响应，避免额外完整明文复制；需要并发大对象下载时再引入按字节计费的共享预算和分块读取。

内容请求另持有 29.11 的共享操作许可，覆盖数据库授权、vault 解密及耐久读取审计；它在响应构造完成后释放，整对象许可继续随响应缓冲保留。已准入任务断连后仍完成终态审计并丢弃无人接收的清零缓冲，不记录为客户端已收到内容。15 秒预算仅覆盖数据库操作，本地有界文件读取、解密与审计 fsync 完成后才释放各自资源；审计失败始终扣留明文。

## 29.14 已实现的受限调查查询契约

此契约另支持 `{"kind":"trace_id","value":"018f2a3b4c5d70008000000000000003"}`：值严格为 32 个小写十六进制字符并精确匹配现有 ClickHouse `FixedString(32)` 列，无需 Schema 迁移。结构化搜索事件摘要回传并由 worker、浏览器分别校验该 trace 字段；控制台可从已选事件预填同 Trace 检索，仍由操作者提供时间窗并显式提交。trace 不编码可信时间或授权作用域，因此请求仍需有界 UTC 时间窗，服务端注入 tenant/site 并应用原有扫描预算、query_digest、签名游标和 `console.query.executed` 审计。结果只定位同 trace 的脱敏事件，不构成身份、资格或跨作用域关联证明。

分享签发另支持 `{"kind":"share_grant_id","value":"share_UUIDv7"}`，严格按 `ShareGrantId` 校验，只匹配固定 `share.issued` 事件的顶层 `payload.share_id`。服务端将 ID 参数绑定到固定 tenant/site、有界时间窗和 retention-aware 视图；查询复用 Investigator 权限、8 项预算、query_digest、签名游标和 `console.query.executed` 审计。结果只定位脱敏签发事件，不返回分享 bearer 凭证、不推断当前资格，也不改变分享访问或撤销权限。

`POST /control/v1/search` 要求固定 tenant/site 作用域内的 `Investigator` 和管理 Bearer。请求体上限 8 KiB，严格接受 `schema_version=3`、UTC RFC3339 的 `start`/`end`、`sort`、`limit`、可选 `cursor` 及有界 `filters`。时间边界采用整秒，半开区间 `[start,end)` 最长 31 天且位于 1970-01-01 至 2300-01-01；单页受 `XSHIELD_CONTROL_MAX_QUERY_EVENTS` 限制，硬上限 1000 行，最多 8 个过滤器。过滤器只对同一结果事件做 AND 匹配：规范 request/event/grant/auth binding/case/artifact/calibration-report/model-call/agent-run/job/evidence-access-request/evidence-hold/share-grant ID、直接因果边、受限 `subject_ref`、`event_type`/`stage`/`reason_code`/`operation_id`/`model_revision` 精确文本、`PASS/ALLOW/DENY/UNKNOWN/ERROR/SKIPPED/CANCELLED` outcome 枚举和 0–10000 整数 basis-points 置信度上限。`job_id` 只匹配 `console.job.read` 的固定 `target_job_id`，不返回任务投影或案件内容。规则事件的空置信度不会匹配数值阈值；API 只执行单条查询与直接因果定位，不执行跨事件聚合、多跳遍历或自然语言编译。控制台可在当前已授权并已加载的结果页内沿固定 `cause_event_ids` 展示局部因果邻域，最多 4 跳、每方向 16 个节点；未载入引用需操作者显式发起新的有界检索。未知字段、版本、控制字符和自由表达式均拒绝。

```json
{
  "schema_version": 3,
  "start": "2026-09-19T00:00:00Z",
  "end": "2026-09-20T00:00:00Z",
  "sort": "occurred_at_desc",
  "limit": 25,
  "filters": [
    {"kind": "text", "field": "stage", "value": "admission"},
    {"kind": "outcome", "value": "DENY"}
  ]
}
```

服务端将认证作用域注入参数化 ClickHouse retention-aware 视图，配置 2 秒执行预算、100 万扫描行、64 MiB 扫描字节、16 MiB 结果和 256 MiB 内存上限，并以 5 秒客户端 deadline 限制连接/响应停滞。索引 deadline 不包含现有本地段完整性扫描和审计 fsync；二者耗时须按保留数据量与磁盘情况另行度量。单个控制实例的 search 与 model-call 查询共用一个执行许可；客户端断开后已开始的有界查询继续完成终态审计并释放许可。多实例部署仍须为 ClickHouse 账户配置共享配额；进程退出恢复不属于该同步接口的保证。

结果只包含脱敏摘要、证据引用及 nullable `model_call_id`，不返回 `payload_json` 或解密对象；`model_call_id` 只会出现在 `proof_kind=model` 且必须为规范 `mdl_` UUIDv7，供调查界面跳转到 29.15 的独立详情查询。该投影不扩大 Investigator 的检索权限、Observer 的模型详情权限或证据读取权限。可选字段缺省返回 null，事件时间为 UTC RFC3339。按 `occurred_at,event_id` 稳定升/降序分页，HMAC 游标绑定主体、管理凭证摘要、tenant/site、完整 QueryPlan 摘要和微秒位置，不能跨查询或作用域复用。响应携带 `schema_version=3`、`query_digest`、`as_of`、`index_watermark`、`has_gaps`、`pending_segments`、`scanned_rows`/`scanned_bytes`、`truncated` 和 `next_cursor`。扫描统计来自索引响应，未报告时为 null；分页期间的新发布/到期可能改变后续可见集合，游标不表示冻结快照。

资格与身份定位分别使用 `{"kind":"grant_id","value":"grant_UUIDv7"}` 和 `{"kind":"auth_binding_id","value":"auth_UUIDv7"}`，value 必须为规范小写强类型 ID。资格过滤匹配 `grant.issued`、`response_grant.issued` 的 `grant_id`、`share.issued` 的 `issuer_grant_id`，以及 `control_access` 阶段 `console.grant.read` 的 `target_grant_id`。身份过滤匹配 `session.created`、`binding.created`、`identity.refreshed`、`epoch.changed`、`binding.revoked`、`grant.issued`、`response_grant.issued` 的 `binding_id`，`share.issued` 的 `issuer_binding_id`，以及 `control_access` 阶段 `console.binding.read` 的 `target_binding_id`。事件族、阶段和 JSON 键由服务端固定，索引内有界读取这些 payload 字段参与过滤；其他事件或阶段中的同名键不构成关联。两类过滤可组合并继续占用原有 8 项预算，完整类型和值纳入 query_digest 和游标签名，访问审计仍仅记录计划摘要。管理详情读取仍单独要求 `Observer`；历史命中不授予详情读取。

Agent 运行使用 `{"kind":"agent_run_id","value":"agt_UUIDv7"}`，值必须为规范小写强类型 ID。过滤器只匹配 `agent.started`、`agent.tool_called`、`agent.tool_result`、`agent.artifact_created`、`agent.finished` 的 payload `agent_run_id`，以及 `control_access` 阶段 `console.agent.read` 的 `target_agent_run_id`；事件族、JSON 键、tenant/site、stage 与 `agt_` 值由服务端固定并参数化。结果仅为脱敏历史摘要，不能读取 Agent 输入/输出、工具参数、产物正文或权限快照，不触发执行、回放或业务资格；详情端点另行要求 Observer 并写独立管理审计。

定位结果是保留窗口内已发布的直接引用事件，可通过返回的 request_id 继续查看请求时间线；不会自动遍历关联请求或报告当前 binding/grant 的有效状态。空结果可能来自未发布、到期或作用域不匹配，不能证明发行从未发生。响应中的水位只覆盖当前配置的 journal 源，不代表独立 outbox 生产者已追平。当前复用有界 payload 扫描，超出预算要求缩小时间窗；大规模索引列物化需另行容量测量。

案件使用 `{"kind":"case_id","value":"case_UUIDv7"}`，匹配固定阶段与事件组合中的直接引用：`case_management` 阶段的 `case.created/closed/evidence.added`、`evidence_access` 阶段的 `evidence.access.requested`、`evidence_hold` 阶段的 `evidence.hold.created/released` 读取 payload.case_id；`control_access` 阶段的 `case.created/closed/evidence.added`、`console.case.read`、`evidence.access.requested/approved/denied`、`console.evidence.access.read` 与 `console.evidence.hold.created/released/read` 读取 target_case_id。审批批准/拒绝事务 outbox 本身仅带申请引用，须通过其管理访问记录定位，不自动补关联。

证据使用 `{"kind":"artifact_id","value":"artifact_UUIDv7"}`，匹配所有事件的 evidence_refs 精确成员；另匹配 `control_access` 中 `console.manifest.read`、`case.evidence.added`、`evidence.access.requested/approved/denied`、`evidence.read` 和 `console.evidence.hold.created/released` 的 target_artifact_id，包含已校验目标但未返回证据的失败尝试。其他 payload 同名字段及嵌套引用不参与匹配；集合查询只匹配该页实际审计的 evidence_refs。

case/artifact 同样采用规范小写强类型校验、8 项总预算及完整计划摘要/游标绑定。组合要求同一事件直接引用两者，不展开案件成员的全部历史。检索沿用 Investigator 对固定 tenant/site 的脱敏审计权限，可观察该范围内其他主体的历史；当前案件集合仍单独检查所有者，保留管理与原文读取仍各自鉴权。关闭、到期、删除后保留的索引引用也可命中，不证明当前对象存在、可读或保留锁有效。新过滤器复用既有视图和事件，无需数据库迁移；新计划的管理日志仍只保存 query_digest。

校准报告使用 `{"kind":"calibration_report_id","value":"calr_UUIDv7"}`，值必须为规范小写强类型 ID。该计划仍先要求 Investigator；由于报告的保留和管理读取历史具有与 29.26 元数据调查相同的可见性边界，同一主体还必须在相同固定 tenant/site 持有 `AuditAdministrator`。缺少第二角色时，服务端在索引访问前返回 `CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED`/403，并以 `DENY` 终态写既有 `console.query.executed`；审计只包含计划摘要，绝不包含原始报告 ID。

通过双角色检查后，过滤器只匹配 `calibration.reported`、六种 `calibration.report_retention.*` 维护事实的 payload `report_id`，以及 `control_access` 阶段的 `console.calibration.report.read` 的 `target_calibration_report_id`。事件族、JSON 键、tenant/site、stage 与 `calr_` 值均由服务端固定并参数化；同名字段、其他事件和嵌套对象不构成关联。结果只为已发布的脱敏历史摘要，不能读取报告正文或样本、标签、概率、指标、提示词、能力、lease、存储定位、密钥、阈值/策略，也不产生任何校准、证据或业务资格。该过滤器与其他条件同样占用 8 项预算，并将完整 ID 纳入响应 query_digest 和游标签名；响应和审计摘要均不替代 29.26 的单报告重新鉴权。

模型调用使用 `{"kind":"model_call_id","value":"mdl_UUIDv7"}`，值必须为规范小写强类型 ID。它沿用单独的 Investigator 历史检索权限，不隐含也不要求 `Observer`；模型详情继续只能通过 29.15 重新鉴权。过滤器仅匹配 `model.started`、`model.requested`、`model.cache_hit`、`model.responded`、`model.failed`、`model.timeout`、`model.cancelled` 的 payload `model_call_id`，以及 `control_access` 阶段 `console.model.read` 的 `target_model_call_id`。事件族、JSON 键、tenant/site、stage 与 `mdl_` 值由服务端固定并参数化；同名字段、其他事件和嵌套对象不构成关联。结果是脱敏历史摘要，不能读取模型详情、生命周期正文、概率、供应商正文、证据内容或调用记录，也不产生重放、模型、证据或业务资格。该过滤器与其他条件同样占用 8 项预算，并将完整 ID 纳入响应 query_digest 和游标签名；审计仍只记录 query_digest。

访问申请使用 `{"kind":"evidence_access_request_id","value":"access_UUIDv7"}`，值必须为规范小写强类型 ID。它沿用单独的 Investigator 历史检索权限，不隐含申请详情、原文读取或 `SensitiveEvidenceApprover`；申请详情、审批和下载继续各自重新鉴权。过滤器仅匹配 `evidence.access.requested`、`evidence.access.approved`、`evidence.access.denied` 的 payload `access_request_id`，以及 `control_access` 阶段 `console.evidence.access.read` 的 `target_access_request_id`。事件族、JSON 键、tenant/site、stage 与 `access_` 值由服务端固定并参数化；同名字段、其他事件和嵌套对象不构成关联。结果是脱敏历史摘要，不能读取申请或审批理由、原文、证据内容或访问资格，也不产生审批、重放、证据或业务资格。该过滤器与其他条件同样占用 8 项预算，并将完整 ID 纳入响应 query_digest 和游标签名；审计仍只记录 query_digest。

保留锁使用 `{"kind":"evidence_hold_id","value":"ev_UUIDv7"}`，按 `EventId` 强类型验证其规范小写 UUIDv7。该计划除 Investigator 外，还要求同一主体在相同 tenant/site 持有 `AuditAdministrator`；缺少该角色时在索引访问前返回 `CONTROL_EVIDENCE_HOLD_HISTORY_SCOPE_DENIED`/403，并审计 `DENY` 与 query_digest。过滤器只匹配 `evidence.hold.created/released` 的 payload `hold_id`，以及 `control_access` 阶段 `console.evidence.hold.created/released` 的 `target_hold_id`。固定事件族、JSON 键和 tenant/site 条件服务端定义，ID 作为查询参数绑定；其他事件及嵌套字段不匹配。结果只包含脱敏已发布事件摘要，不返回保留理由、期限、正文或对象状态，也不替代 29.21 保留锁管理端点重新鉴权，不改变任何保留、审批、读取、重放或业务权限。该过滤器占用原有 8 项预算，完整 ID 纳入 query_digest 与游标签名，访问日志只保留 query_digest。

主体引用使用 `{"kind":"subject_ref","value":"…"}`，接受 1–256 UTF-8 字节并拒绝控制字符；只在固定 tenant/site 范围内对 payload 顶层 `subject_ref`、`principal_ref`、`authorization_context_ref`、`previous_principal_ref`、`previous_authorization_context_ref` 做参数化精确匹配。其他事件/载荷未包含这些固定字段时不匹配，嵌套和相似字段不参与搜索。该过滤器沿用 Investigator 权限和原有 8 项预算；脱敏结果不回显查询值。由于主体标识可能低熵，canonical plan 在纳入摘要前先以 cursor key 和独立用途域 `xshield/search/subject-ref/v1` 对值计算 HMAC，再生成 query_digest 与游标签名；审计不写过滤器值，仍保留标准调用者主体引用与 query_digest。浏览器无法重算该服务端密钥化摘要，只校验其 64 位小写十六进制响应形状；其他计划仍执行客户端与服务端摘要相等校验。

直接因果边使用 `{"kind":"caused_by_event_id","value":"ev_UUIDv7"}`，值以规范 `EventId` 校验。过滤器只匹配保留窗口内投影字段 `cause_event_ids` 含有该精确 ID 的事件；这是一个固定数组成员查询，不解析任意 payload、不增加关联表或迁移。事件详情可将某个已记录前驱预填为 `event_id` 检索，或将当前事件预填为 `caused_by_event_id` 以找直接后继；两者均由操作者填写时间窗并显式提交。该条件沿用 Investigator、固定 tenant/site、页数/时间/扫描预算、query_digest、签名游标和 `console.query.executed` 审计；审计只记录摘要。它不递归展开因果图、不证明关联完整性，也不授予 Observer、证据读取、回放或业务操作权限。未命中可能来自索引迟延或保留窗口，不能推断事件不存在。

无效计划返回 `CONTROL_QUERY_INVALID`/422，无效游标返回 `CONTROL_CURSOR_INVALID`/400，均在索引访问前拒绝。含校准报告或保留锁条件但缺少同作用域 AuditAdministrator 分别返回 `CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED`/403 或 `CONTROL_EVIDENCE_HOLD_HISTORY_SCOPE_DENIED`/403。确定的查询预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=narrow_query`；单实例容量占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端超时返回 `CONTROL_QUERY_TIMEOUT`/503，依赖故障返回对应 503。可审计尝试均写 `console.query.executed`；通过计划校验后的成功或失败审计携带 `query_digest`，不保存原始过滤条件或游标，但仍保留标准调用者主体引用。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果；响应统一 `Cache-Control: private, no-store`。

## 29.15 已实现的模型调用查询契约

`GET /control/v1/model-calls/{model_call_id}` 要求固定 tenant/site 作用域内的 `Observer` 和管理 Bearer。路径 ID 先按 `mdl_` UUIDv7 强类型校验；服务端再以 tenant/site 与固定事件类型集合查询 retention-aware `audit_events_active`，不接受客户端传入作用域或任意表达式。索引中的模型生命周期 payload 必须再次通过同一 typed Jev 校验，调用 ID、request ID、版本、状态和证据引用不一致时整次查询失败。

模型事件的三个 artifact 引用字段均须显式存在，尚未产生时为 null；Schema、发布、恢复与查询边界统一拒绝省略字段。因果链中允许保留期限造成的缺失，但已可见 send 的前后事件必须直接关联，矛盾前驱与因果环按损坏记录拒绝。

成功响应返回独立管理 `request_id`、固定作用域、`source_model_call_id`、`found` 与脱敏 `model_call`。后者只包含 provider、独立的 provider_model_id、生命周期状态、内部模型/提示版本、问题类型、置信度语义、耗时、按 request_seq 排序的生命周期摘要、因果前驱及输入/输出/调用记录的 artifact 引用；provider_model_id 不能被当作精确 resolved_model_revision。兼容读取旧事件时两字段均为 null，不从当前路由配置推断历史值。内部输入引用从事件 `evidence_refs` 和 manifest 父引用进一步定位。Noul 的 confidence 保持 null；响应不包含 `payload_json`、概率正文或供应商原文。证据内容仍须走 artifact manifest、独立审批和 EvidenceReadPort。

`completeness=complete` 仅表示可见 start、send、terminal 因果链完整（或 start 直接因果关联发出前的 failed）；进行中的可见前缀为 `pending`，已到终态但缺失前驱为 `partial`，未命中为 `not_indexed`。`found=false` 对尚未发布、不存在、过期和不同作用域保持统一结果，不证明源日志中不存在调用。`as_of`、`index_watermark`、`has_gaps`、`pending_segments` 是查询前检查的配置日志源健康快照，`watermark_scope=configured_journal` 明确其只覆盖该实例 source journal；模型与网关使用独立源时，网关水位不能用于判断模型是否已追平。发布和保留可能改变可见集合，响应不表示冻结快照。

当前按有界生命周期 payload 扫描精确 ID，读取最多 4 行以识别超出三事件生命周期的冲突。单 payload 上限 8 KiB，解码/服务端结果上限 128 KiB，跨事件证据引用去重后最多 256 个；配置 2 秒执行预算、100 万扫描行、64 MiB 扫描字节、256 MiB 内存和 5 秒客户端 deadline。deadline 只覆盖索引查询，本地健康检查及审计 fsync 另行度量。与 search 共用单实例执行许可，已准入请求在客户端断连后继续终态审计。

通过认证且路径校验成功的尝试以 `target_model_call_id` 绑定目标，实际返回的 artifact 引用进入 `evidence_refs`；可审计的成功、未命中、拒绝及依赖故障均写独立加密 `console.model.read`。无效 ID（含无法解码的 UTF-8 路径）返回 `CONTROL_MODEL_CALL_ID_INVALID`/400。预算耗尽返回 `CONTROL_QUERY_BUDGET_EXCEEDED`/429、`retryable=false`、`next_action=contact_operator`；许可占满返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，客户端 deadline 返回 `CONTROL_QUERY_TIMEOUT`/503，索引/健康依赖故障返回对应 503。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，所有响应设置 `Cache-Control: private, no-store`。

## 29.16 已实现的案件证据关联契约

`POST /control/v1/cases/{case_id}/items` 要求固定 tenant/site 内的 `Investigator` 与管理机器凭证。请求体上限 4 KiB，严格接受 `{"artifact_id":"artifact_UUIDv7"}`；case/artifact 均为规范强类型 ID，未知或重复字段拒绝。`Idempotency-Key` 必须单值且为 16–128 字节 ASCII 字母、数字、`-_.:`。复用管理变更专用密钥、独立用途域 HMAC，将键及请求摘要绑定主体、作用域、case 和 artifact；原始键不入库或审计。

事务先按 actor 串行化幂等，再锁定本人 open 案件；新关联要求同作用域 active、未删除的 artifact，取得行锁后及插入时重验数据库当前期限。每案最多 128 项，复合主键保证同案同证据唯一；关联与 `case.evidence.added` outbox 同事务提交。首次返回 201，响应只含 schema_version、request_id、固定作用域、case_id、artifact_id、added_by、added_at 和 replayed。精确重试返回 200、原 added_at 和 replayed=true，仍重验当前案件归属与 open 状态；即使 artifact 此后到期或删除，历史关联元数据也可返回，不表示证据仍可读取。

同键换参数，或同案同证据改用另一键，返回 `CONTROL_CASE_EVIDENCE_CONFLICT`/409，调用者应保留原键与请求。不存在、跨作用域、非本人/关闭案件及新关联的到期/删除证据统一为 `CONTROL_CASE_EVIDENCE_TARGET_UNAVAILABLE`/404。每案上限返回 `CONTROL_CASE_EVIDENCE_LIMIT_EXCEEDED`/429、retryable=false；单实例同时一个关联操作，忙时返回 `CONTROL_CASE_EVIDENCE_BUSY`/429、retryable=true。SQL 单语句和锁等待限 5 秒，包含连接池等待的数据库操作整体限 15 秒；故障或超时返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503，应使用相同键和参数确认结果。超时可能发生在 COMMIT 已耐久之后，不能据此认定操作未发生。

已准入操作在客户端断连后继续数据库终态与管理审计，许可覆盖至审计完成；本地 fsync 依赖健康存储，15 秒只限制数据库操作，进程退出仍是故障边界。每次可审计尝试写独立加密 `case.evidence.added` 管理事件，以 payload 的 outcome/reason 区分成功、拒绝和依赖故障；事务 outbox 只记录实际新增关联。经强类型校验的 case/artifact 进入目标字段，成功/精确重试的 artifact 进入 evidence_refs。管理审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留成功响应；已提交的事务及 outbox 保留，可用原请求重试确认。响应统一 `Cache-Control: private, no-store`。

部署前应用 `0017_m3_case_evidence.sql`，新增 `case_items` 及其约束。关联仅用于调查上下文，不授予 manifest/内容/导出权限，不改变对象期限、不建立 pin；原文读取继续走独立申请、批准和 EvidenceReadPort。保留锁存储与发布见 [12.9](12-evidence-capture-and-vault.md#129-案件证据保留锁存储与发布)，管理入口见 [29.21](#2921-已实现的案件保留锁管理契约)；集合浏览见 [29.17](#2917-已实现的案件证据集合查询契约)，关闭案件见 [29.18](#2918-已实现的案件关闭契约)。

## 29.17 已实现的案件证据集合查询契约

`GET /control/v1/cases/{case_id}/items` 要求固定 tenant/site 内的 `Investigator`、管理机器凭证和本人 owner。路径 case 使用规范强类型 ID；可选查询串只接受单个 `cursor`，其值为不透明 HMAC 游标，绑定管理凭证摘要、主体、服务端 tenant/site、case、查询版本/页大小和最后一个 artifact ID。缺失、越界、跨接口、跨主体、跨案件或签名不匹配的游标在访问 PostgreSQL 前统一返回 `CONTROL_CURSOR_INVALID`/400。

查询允许 open 与 closed 的本人案件；跨租户/站点、非本人和不存在案件统一返回 `CONTROL_CASE_NOT_AVAILABLE`/404，不泄露案件存在性。PostgreSQL 使用一条只读快照同时校验案件归属、成员行和 `case.evidence.added` outbox 关联，并按 artifact ID 升序取 `max_query_artifacts`（1–128）项及一个 lookahead；SQL 语句和锁等待各限 5 秒，连接池/事务整体限 15 秒。缺失或错绑 outbox、成员顺序/演员字段异常等可见持久化损坏返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503，不返回部分页面。

成功响应为 `schema_version=3`，包含管理 `request_id`、固定 tenant/site、案件 `case_id/status/purpose/created_at`、数据库 `as_of`、`items`、`truncated` 和 `next_cursor`。每项只包含 artifact ID、历史 `added_by/added_at` 和 catalog 状态：`active`（按同一 `as_of` 尚未到期）、`expired`、`deleted`（优先于到期）或 `unavailable`（防御性缺 catalog 状态；0017 外键和 retention tombstone 使正常路径使用 `deleted`）；不返回 manifest、storage locator、hash、key ref、请求元数据、密文或读取资格。读取不更新案件、membership、catalog、保留期限或审批状态。

成功、目标不可用、游标/鉴权拒绝及依赖故障均写独立 `console.case.read` 管理审计；成功事件的 `evidence_refs` 仅包含本页 artifact ID，拒绝/故障为空。审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。查询与 POST 关联共享单实例有界许可，繁忙返回 `CONTROL_CASE_EVIDENCE_BUSY`/429；数据库故障/超时返回 `CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE`/503。已准入查询在客户端断连后继续到数据库和管理审计终态，响应统一 `Cache-Control: private, no-store`。

## 29.18 已实现的案件关闭契约

`POST /control/v1/cases/{case_id}/close` 要求服务端固定 tenant/site 内的 `Investigator`、管理机器凭证和当前本人 owner。路径须为规范 case UUIDv7；请求体上限 4 KiB，严格接受 `{"reason":"..."}`，理由为 1–512 UTF-8 字节、无控制字符及首尾空白。单个 `Idempotency-Key` 必填，沿用 16–128 字节 ASCII 字母、数字、`-_.:` 规则；作用域和主体均由服务端确定。

幂等摘要使用既有管理幂等密钥及独立关闭用途域，绑定 owner、tenant/site 和键；参数摘要再绑定 case 与 reason。事务先取得与创建相同的主体容量 advisory lock，再锁本人案件行。首次关闭将 `status=closed`、`case_closures` 和 `case.closed` outbox 同时提交，释放该主体的 open 案件容量。成功与精确重试均返回 200，响应含 `schema_version=3`、管理 request_id、tenant/site、case_id、status、数据库 closed_at 和 replayed；精确重试返回原 closed_at，并重验当前归属、closed 状态及原 outbox 绑定。

同键更换案件/理由返回 `CONTROL_CASE_CLOSE_CONFLICT`/409；不存在、跨作用域、非本人，以及用另一键关闭已终结案件，统一返回 `CONTROL_CASE_NOT_AVAILABLE`/404。严格路径、DTO 或幂等键错误为带稳定原因码的 400。关闭与证据关联/集合读取共享单实例一个在途许可，繁忙返回 `CONTROL_CASE_CLOSE_BUSY`/429；数据库整体操作含池等待限 15 秒，单 SQL/锁等待限 5 秒，故障或超时返回 `CONTROL_CASE_STORE_UNAVAILABLE`/503。提交结果不确定时使用相同键和参数确认结果。

每次可审计尝试写独立加密 `case.closed` 管理事件，通过 outcome/reason 区分成功、重试、拒绝和依赖故障；事务 outbox 只记录实际状态转换。合法 case ID 进入目标字段，evidence_refs 为空；自由文本理由仅保存于案件关闭表，outbox 保存参数摘要。管理审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，已提交事务和 outbox 保留。已准入操作在客户端断连后继续到数据库和审计终态，许可覆盖审计 fsync；进程退出仍是故障边界。所有响应为 `private, no-store`。

部署先应用 `0018_m3_case_lifecycle.sql`，该扩展保留既有 open/closed 记录。回滚应用版本时保留关闭表、closed 状态和 outbox，避免恢复已终结案件的访问条件。关闭保留历史证据关联、catalog、审批行和原始保留期限；后续新增关联、访问申请/批准及读取资格校验要求案件仍 open。已有审批的幂等查询只返回历史决策；内容读取仍重验当前案件状态。已完成资格校验的在途读取可能继续，已释放内容不能通过关闭收回。本人 closed 案件的引用集合继续通过 29.17 查询。

关闭时已有的 `pending` 原文访问申请保持待决，并继续占用申请主体的 pending 配额。独立 `SensitiveEvidenceApprover` 可通过 29.12 的拒绝接口终结 closed 案件的申请、释放该配额并保留决策历史；关闭操作本身仅释放 open 案件配额。

## 29.19 已实现的资格账本调查契约

`GET /control/v1/grants/{grant_id}` 要求 `Observer` 与服务端固定 tenant/site 的管理 Bearer。路径 ID 必须为规范小写 `grant_` UUIDv7；接口不接受查询参数。无效 ID 返回 `CONTROL_GRANT_ID_INVALID`/400，查询参数错误返回 `CONTROL_QUERY_INVALID`/400，均在数据库访问前拒绝。

读取按完整作用域和 grant 主键执行，单条只读 SQL 快照连接 `resource_grants`、`auth_bindings` 和 `ui_actions`。返回 `schema_version=3`、独立管理 request_id、tenant/site、source_grant_id、found、数据库语句时间 as_of 和可选 grant。缺失与其他作用域统一为 200、found=false、as_of=null、grant=null；同域已过期或撤销的账本行仍可调查。关联或类型损坏关闭查询，不伪装成未找到。

grant 含资格 ID、发行 auth_epoch、stored_status、issued_at/expires_at、resource_type、operation_id、view_id、policy_revision 及来源 event/request ID；内嵌 binding 仅含绑定 ID、当前 auth_epoch、stored_status、expires_at 和 epoch_matches_grant。两者独立以 `expires_at <= as_of` 计算 time_expired，保留数据库持久状态，因此尚未清理的 active 行也可能 time_expired=true。当前绑定后续缩短期限、撤销或推进代际仍可观察。响应不包含主体、认证上下文、凭证/资源指纹、动作引用、幂等键、constraints 或事件正文。

这是调查时的账本观察，不是可转交给网关的准入结果；实际请求继续检查完整认证组合、动作/证据、策略、目标字段和当前期限。来源 request_id 可继续查询时间线，发行及分享历史通过 29.14 检索；详情不使用 ClickHouse 授权状态，也不附带其发布水位。身份绑定详情见 29.20；控制台账本与引用导航见 15.7，完整来源图继续交付。

整体数据库操作含连接池等待最多 15 秒，单语句和锁等待最多 5 秒。与 search/model-call 调查查询共享单实例许可，繁忙返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429；数据库故障、超时或解码损坏返回 `CONTROL_GRANT_STORE_UNAVAILABLE`/503。已准入查询在客户端断连后继续到数据库与审计终态；许可覆盖审计 fsync，进程退出仍为故障边界。所有响应 `Cache-Control: private, no-store`。

每次可审计尝试写 `console.grant.read`，已校验目标记录在 target_grant_id；成功（包括未找到）使用 `CONTROL_GRANT_READ`，不记录查询出的账本快照或业务来源请求作为管理请求目标，evidence_refs 为空。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。部署须给控制数据库角色授予上述三表所需 SELECT；无需新增 migration，先升级支持该事件的管理 journal 发布器，再启用新端点。

## 29.20 已实现的身份绑定调查契约

`GET /control/v1/auth-bindings/{binding_id}` 要求 `Observer` 与服务端固定 tenant/site 的管理 Bearer。路径必须为规范小写 `auth_` UUIDv7，不接受查询参数；类型错误返回 `CONTROL_BINDING_ID_INVALID`/400，查询参数错误返回 `CONTROL_QUERY_INVALID`/400，均在数据库访问前拒绝。

读取以完整作用域和 binding 主键查询 `auth_bindings`，单条只读快照仅投影绑定 ID、身份/凭证代际、持久状态、绝对期限和更新时间。返回 `schema_version=3`、管理 request_id、tenant_id/site_id、source_binding_id、found、数据库语句时间 as_of 和可选 binding。缺失及跨作用域统一返回 200、found=false、as_of=null、binding=null。保留在账本中的 anonymous/active/revoked/expired 行均可查询；已物理清理的匿名记录通过现有生命周期事件继续调查。

binding 包含 binding_id、current_auth_epoch、credential_generation、stored_status、time_expired、expires_at、updated_at。time_expired 独立按 `expires_at <= as_of` 计算，时间字段为 UTC RFC3339；更新时间可能晚于期限。匿名代际须为 0，active 代际须为正数，撤销或过期允许保留匿名的 0 代际；未知状态、非法计数和非有限或 Unix 起点之前的时间均视为损坏，整次查询关闭。查询不读取主体、授权上下文、WAF SID 或凭证指纹，不读取或续期业务凭证。返回值是调查观察而非在线认证结果。

使用 binding_id 可继续执行 29.14 的 auth_binding_id 历史检索，再从事件 request_id 打开时间线或从 grant_id 打开资格详情。查询本身不递归展开资格或历史、不附带 ClickHouse 水位；当前账本与后续历史查询不构成跨存储冻结快照。历史检索仍要求 Investigator 角色。

数据库整体操作含池等待限 15 秒，单语句和锁等待限 5 秒，与资格/search/model-call 共用单实例查询许可。忙时返回 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429，数据库故障、超时或损坏返回 `CONTROL_BINDING_STORE_UNAVAILABLE`/503。已准入请求在断连后继续完成数据库操作和审计，许可覆盖终态审计；进程退出仍是故障边界。响应统一为 `Cache-Control: private, no-store`。

每次可审计尝试写 `console.binding.read`，通过路径校验的目标写入 target_binding_id；成功（含未找到）原因为 `CONTROL_BINDING_READ`，evidence_refs 为空，审计中不保存查询快照。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果。部署需给控制数据库角色配置 `auth_bindings` 所需 SELECT，先升级管理 journal 发布器，再启用端点；无新增 migration 或依赖。

## 29.21 已实现的案件保留锁管理契约

创建、释放和历史列表均要求独立管理 Bearer、`AuditAdministrator` 及服务端固定 tenant/site。该角色可管理同作用域内其他所有者案件；保留只推迟物理删除，原始 catalog/vault expires_at、敏感内容审批与到期拒读继续生效。

`POST /control/v1/cases/{case_id}/holds` 严格接受 `artifact_id`、`reason`、`hold_until`；`POST /control/v1/evidence-holds/{hold_id}/release` 严格接受 `reason`。路径使用规范 case/ev UUIDv7，artifact 使用规范 artifact UUIDv7；JSON 上限 4 KiB，拒绝未知或重复字段、查询参数和重复认证头。理由为 1–512 UTF-8 字节、无首尾空白或控制字符。期限只接受可表示为有符号纳秒、Unix 起点之后的 `YYYY-MM-DDTHH:MM:SS.sssZ`（秒为 00–59）；新建时另按数据库时钟要求未来 720 小时内。过期的原期限可用于精确重试。

两个 POST 要求单值 `Idempotency-Key`，允许 16–128 字节 ASCII 字母、数字、`-_.:`。使用管理幂等密钥和创建/释放各自用途域，摘要绑定主体、作用域、键及全部参数；原键不入库或审计。首次创建返回 201，精确创建重试及释放返回 200。响应含 schema_version=3、管理 request_id、tenant/site、hold_id、case_id、artifact_id、created_by、reason、created_at、hold_until、可空 released_event_id/released_by/released_reason/released_at 和 replayed。重试返回已提交记录及当前释放事实，保持原始期限，不建立新锁。

新建须为同域 open 案件、已有成员、active catalog 且没有删除意图；对象内容到期不阻止保留。每案累计 128 条历史、每作用域 1000 条活动锁，过期但未释放的同案同证据记录仍占自然唯一位置。释放允许案件关闭、内容到期或删除。缺失、跨域及不可用目标统一为 `CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE`/404；同键参数偏差、未释放的同案同证据或另一释放请求占用目标为 `CONTROL_EVIDENCE_HOLD_CONFLICT`/409。期限/DTO 错误为 `CONTROL_EVIDENCE_HOLD_REQUEST_INVALID`/400，容量耗尽为 `CONTROL_EVIDENCE_HOLD_LIMIT_EXCEEDED`/429、retryable=false。

`GET /control/v1/cases/{case_id}/holds` 只接受可选 `cursor`，HMAC 用途域绑定凭证摘要、主体、作用域、案件、页大小及最后 hold ID。页大小复用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128）；缺失/越界/错绑游标在查库前返回 `CONTROL_CURSOR_INVALID`/400。单条只读 SQL 快照按 hold ID 升序读取历史，包含 open/closed、过期/已释放记录；同时验证创建/释放的完整 outbox 绑定，包括多取的一条预读记录，损坏时整页失败。现有空案件返回空 items，缺失或跨域案件统一 404。响应为 schema_version=3、request_id、tenant/site、case_id、case_status、数据库微秒 as_of、items（上述保留记录字段）、truncated 和 next_cursor。每页是实时快照，原始期限和释放时间供调查使用，不返回内容元数据、读取资格、摘要或 outbox 正文。

三个入口与案件关联/关闭/集合查询共享单实例在途许可，繁忙为 `CONTROL_EVIDENCE_HOLD_BUSY`/429。数据库整体含池等待最多 15 秒，SQL 与锁等待最多 5 秒；数据库故障、损坏和超时为 `CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE`/503。许可覆盖最终审计；已准入操作在客户端断连后继续到数据库和审计终态，进程退出仍为故障边界。事务提交可能先于超时或审计故障，使用原键和完整参数确认结果。

每次可审计尝试分别写 `console.evidence.hold.created/released/read`。创建/释放成功原因依次为 `CONTROL_EVIDENCE_HOLD_CREATED`、`CONTROL_EVIDENCE_HOLD_RELEASED`，重试为 `CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED`、`CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED`，列表为 `CONTROL_EVIDENCE_HOLD_READ`；失败使用对应稳定原因。写成功绑定 case/artifact/hold 及唯一 artifact 引用，列表只绑定 case 和本页去重 artifact 引用，失败只保留已校验目标且引用为空。管理 journal 不记录自由理由、期限、原键或响应正文；事务 outbox 独立记录实际状态转换。审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，已提交事务保留。所有响应 `private, no-store`。

部署遵循 12.9 的迁移 0020 和清理升级顺序，并先升级管理 journal 发布器再开放三个端点，旧发布器遇到新事件会保留待发布段并停止推进。复用已有幂等与游标密钥，跨实例须保持一致；本增量无新依赖或 migration。管理主体启动校验现拒绝首尾空白；升级前核对 `XSHIELD_CONTROL_SUBJECT` 为原始规范身份，程序不会自动去空白以改变身份。

## 29.22 已实现的本人案件列表契约

`GET /control/v1/cases` 要求独立管理 Bearer、`Investigator` 及服务端固定 tenant/site，只返回当前管理主体拥有的 open/closed 案件。请求仅允许缺省查询或单个 `cursor`，拒绝 owner、status、scope 等额外字段、重复参数及重复认证头。发现案件不授予内容访问或保留权限，打开案件集合及后续变更仍重新鉴权。

返回 schema_version=3、管理 request_id、tenant_id、site_id、数据库微秒 UTC `as_of`、items、truncated 和可空 next_cursor。每项只有 case_id、status、purpose、毫秒 UTC created_at；空页仍返回数据库观察时间。按规范 case ID 的 `C` 排序降序，不声称按 created_at 排序。页大小复用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128），每页独立观察；分页期间新增的更大 ID 须刷新首页才能看到。

游标为 `v1.case_UUIDv7.64lowerhex`，用途域 `xshield-control-cases-cursor-v1` 的 HMAC 绑定管理凭证摘要、主体、tenant/site、页大小和最后输出案件 ID。下一页只读取小于该 ID 的记录；游标不能跨凭证、作用域、配置或其他端点复用。坏游标查库前返回 `CONTROL_CURSOR_INVALID`/400，签名服务不可用返回 `CONTROL_CURSOR_UNAVAILABLE`/503。单 SQL 只读快照连接案件与创建 outbox，校验 ID、owner、用途、状态及 outbox 的作用域、类型和 aggregate 绑定；包括用于判定下一页的多取一行，任何损坏使整页失败。

入口与案件创建、关联、关闭、集合及保留锁操作共用单实例在途许可，繁忙返回 `CONTROL_CASE_BUSY`/429。数据库整体含连接池等待最多 15 秒，SQL/锁等待最多 5 秒；依赖故障、超时或损坏为 `CONTROL_CASE_STORE_UNAVAILABLE`/503。已准入读取在客户端断连后继续到数据库和管理审计终态，许可覆盖审计；进程退出仍是故障边界。每次可审计尝试写 `console.case.list`，成功含空页为 `CONTROL_CASES_READ`；4xx 为 DENY、5xx 为 ERROR。所有 target 字段、query_digest、bytes_read 缺省或 null，evidence_refs 为空，不记录用途、游标或列表正文。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果；响应统一 `private, no-store`。

部署先应用 `0021_m3_case_listing.sql` 的 tenant/site/owner/case ID 降序索引，并升级管理 journal 发布器，再启用 API 与界面。索引采用事务内非并发构建，期间阻塞案件写入，大表须安排维护窗口；可回滚应用并保留这个加法索引。控制数据库角色需对 investigation_cases 和 audit_outbox 提供已有查询所需 SELECT；复用现有游标密钥，无新增依赖。

## 29.23 已实现的证据访问申请详情契约

`GET /control/v1/evidence-access-requests/{access_request_id}` 返回审批所需的申请理由、目标及历史决策。单值管理 Bearer、凭证时效、角色、固定 tenant/site 和速率均由服务端校验。`Investigator` 或 `SensitiveEvidenceReader` 仅能查询自己发起的申请；`SensitiveEvidenceApprover` 可查询同作用域内的申请。审批人查看自身申请不改变禁止自批规则，Observer 与 SystemAdmin 不隐含这些角色。

路径使用规范 access UUIDv7；任何查询串（包括空 `?`）及非空请求体均拒绝。无效 ID 为 `CONTROL_EVIDENCE_ACCESS_ID_INVALID`/400，查询或正文无效为 `CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID`/400；重复认证头按未认证处理。不存在、跨作用域及非本人且无审批角色的记录统一为 `CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE`/404。

200 响应包含 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、数据库微秒 UTC `as_of`、当前服务端 `max_approval_ttl_seconds` 和 `access_request` 对象。对象字段为 access_request_id、case_id、artifact_id、requested_by、access_kind、justification、stored_status、requested_at、requested_event_id、decided_by、decision_reason、decision_ttl_seconds、decision_event_id、decided_at、access_expires_at、case_status、artifact_status、artifact_expires_at、artifact_time_expired 和 capability_time_expired。可选决策字段显式为 null；pending/denied 的 capability_time_expired 为 null。对象及资格期限分别与 as_of 比较，持久状态不会由查询改写；到期 approved、expired、revoked、closed 案件和 deleted catalog 的历史记录仍可调查。所有时间保持 UTC 微秒。

单条 PostgreSQL 只读快照在 SQL 内限定主体可见性，并同时连接案件、catalog 和申请/决策 outbox，验证 ID、归属、状态、规范文本、有限时间与事件绑定。内容、manifest、locator、密钥与摘要不进入查询投影。损坏可见记录使请求失败，读取不锁定业务行、不写 outbox、不延长期限；详情和配置 TTL 上限仅供复核，批准及下载仍各自重新鉴权和检查当前状态。

详情与案件及原文访问共用单实例在途许可，繁忙为 `CONTROL_EVIDENCE_ACCESS_BUSY`/429；数据库操作含池等待限 15 秒，事务内语句/锁等待限 5 秒。数据库故障、超时或损坏为 `CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`/503。已准入任务在客户端断连后继续到数据库结果和终态审计；事务结束后才写审计，许可持有至审计完成。进程退出和本地 fsync 仍是故障边界。

每次可审计尝试写独立 `console.evidence.access.read` 管理事件，成功原因 `CONTROL_EVIDENCE_ACCESS_READ`，绑定申请、case、artifact 和唯一 artifact 引用；失败按 4xx/DENY、5xx/ERROR 记录，仅保留已验证的申请 ID。理由、历史决策人、期限和响应正文不进入管理 journal。审计失败为 `AUDIT_DURABILITY_FAILED`/503 并扣留详情；所有响应 `private, no-store`。部署先升级管理 journal 发布器再开放端点，旧发布器遇到新事件将停止推进并保留段；复用现有数据库查询权限、索引和依赖，无新迁移。

## 29.24 已实现的证据访问申请列表契约

`GET /control/v1/evidence-access-requests?view=mine` 用于发现当前主体的全部申请历史；同一固定 tenant/site 下具备 `Investigator`、`SensitiveEvidenceReader` 或 `SensitiveEvidenceApprover` 之一即可读取。`view=review` 仅允许 `SensitiveEvidenceApprover`，列出同作用域其他主体的 pending 申请。Observer 与 SystemAdmin 不隐含上述角色；每页重新校验单值管理 Bearer、凭证时效、作用域、角色和速率。历史 closed 案件、到期或 deleted artifact 的申请仍可发现；pending 只表示持久状态，批准与下载各自重验当前权限、目标及期限。

请求必须显式提供规范 `view=mine` 或 `view=review`，随后可附一个 `&cursor=...`；缺少/未知视图、逆序或重复参数、附加参数、百分号编码的视图别名、空游标及非空正文为 `CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID`/400。形状或签名无效的游标为 `CONTROL_CURSOR_INVALID`/400；二者均提示重新开始查询。游标采用独立用途域 `xshield-control-evidence-access-list-v1`，以 HMAC 绑定管理凭证摘要、主体、tenant/site、视图、服务端页大小和最后申请 ID，不能跨视图或接口复用；轮换凭证/游标密钥或改变页大小后需重开查询。游标签名依赖失败为 `CONTROL_CURSOR_UNAVAILABLE`/503。

200 响应字段为 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、`view`、数据库微秒 UTC `as_of`、`items`、`truncated` 和可空 `next_cursor`。每个 item 仅投影 access_request_id、case_id、artifact_id、requested_by、access_kind、stored_status、requested_at、requested_event_id。access_kind 固定 sensitive_raw；mine 保留 pending/approved/denied/expired/revoked，review 固定 pending。申请理由、完整决策与目标状态由 29.23 详情端点获取；列表不提供内容访问资格。空页仍包含数据库观察时间。

页大小沿用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128），按规范申请 ID 的 `C` 字节序严格降序，以最后 ID 排他续查，最多多取一条预读判断下一页。单 SQL 只读快照同时限制可见性并连接案件、catalog 和申请/决策 outbox，所有可见记录含预读均复用详情一致性校验；坏行使整页失败。每页独立观察，后续批准/拒绝可使 review 项消失，新增高位 ID 需刷新首页发现；游标不是跨页数据库快照，也不保证列表刷新可以确认未知写入。打开行重新读取详情，审批与内容读取继续独立授权。

列表与案件及证据访问共用单实例在途许可，繁忙为 `CONTROL_EVIDENCE_ACCESS_BUSY`/429。数据库操作含连接池等待限 15 秒，事务内 SQL/锁等待限 5 秒；故障、超时或损坏为 `CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE`/503。只读事务结束后追加独立 `console.evidence.access.list` 管理审计，已准入任务断连后继续到结果和审计终态，许可覆盖审计；进程退出和本地 fsync 仍是故障边界。成功含空页为 `PASS/CONTROL_EVIDENCE_ACCESS_LIST_READ`；失败按 4xx/DENY、5xx/ERROR 使用 11.7 的精确原因集合。全部 target、query_digest 和 bytes_read 只允许缺省/null，evidence_refs 为空；事件只保存调用者与访问结果，列表视图、游标、记录及他人主体不进入载荷。必需审计失败为 `AUDIT_DURABILITY_FAILED`/503 并扣留响应数据，所有响应设置 `private, no-store`。

部署先应用 `0022_m4_evidence_access_listing.sql`，为 tenant/site/requested_by/access ID 建立降序索引，并为 tenant/site/access ID 建立 pending 部分索引；再升级管理 journal 发布器、控制 API 和控制台。索引在事务内非并发构建，期间阻塞该表写入，大表需维护窗口。数据库角色沿用详情所需的 evidence_access_requests、investigation_cases、artifact_catalog 和 audit_outbox 查询权限；无需新增密钥或依赖。回滚时先停用新界面/路由，继续使用可识别新事件的发布器直到相关积压已处理；应用可回退并保留两个加法索引，或仅移除本迁移的索引，保留所有申请和 outbox 历史。旧发布器遇到新事件会停止推进并保留待发布段。

## 29.25 已实现的模型调用列表契约

`GET /control/v1/model-calls?start=<UTC>&end=<UTC>&limit=<1..100>[&cursor=<signed>]` 仅允许固定 tenant/site 内的 `Observer` 与单值管理 Bearer。服务端拒绝页面传入 tenant/site；每页均重新验证凭证、时效、角色、范围与速率。`start`、`end` 必须是规范 `YYYY-MM-DDTHH:MM:SSZ` UTC 整秒，表示 `[start,end)`，范围在 1970–2300 且最长 31 天。`limit` 为无前导零的 1–100 十进制整数；参数各出现一次，未知参数、空值、非空请求体、非规范时间、重复 Bearer 或非法 UTF-8 均在索引访问前拒绝为 `CONTROL_MODEL_CALLS_REQUEST_INVALID`/400。无效或错绑游标为 `CONTROL_CURSOR_INVALID`/400。

查询仅从 retention-aware active view 读取固定 `model.*` 生命周期类型与 `proof_kind=model` 行。对每个 `mdl_`，它在请求窗口内以 `(occurred_at,event_id)` 选取最新可见事件，再整体按 `(occurred_at DESC, model_call_id DESC)` 取 `limit + 1` 行并做排他 keyset 分页。历史空索引列仅从同一已认证 model payload 回填强类型 `mdl_`；最新 payload、request、artifact envelope 绑定、范围、时间精度及返回顺序均重新校验，任一损坏或预算溢出均不返回部分页面。列表不是冻结快照：发布、保留或去重可改变后续页面；窗口内最新事件不表示当前状态、完整生命周期、调用存在性、模型已追平或证据读取权。

成功响应固定为 `schema_version=3`、管理 `request_id`、tenant/site、回显的 start/end、`watermark_scope=configured_journal`、独立 `as_of`、`index_watermark`、`has_gaps`、`pending_segments`、可空实际扫描统计、`items`、`truncated` 和可空 `next_cursor`。item 只含 `model_call_id`、来源 `request_id`、观察时间、provider/provider_model_id、模型/提示版本、question type、窗口内 `latest_status/latest_reason_code/latest_confidence_status`。不含数值 confidence、概率、payload、供应商正文、证据引用、artifact ID 或完整生命周期。Noul 只以 `latest_confidence_status=not_applicable` 表示；provider model ID 不是精确 resolved revision。打开 item 继续调用 29.15，并重新鉴权和审计。

游标使用独立用途域 `xshield-control-model-call-list-cursor-v1`，以 HMAC 常量时间比较绑定管理凭证摘要、主体、服务端 tenant/site、窗口、页大小、固定排序及最后的微秒时间和 model call ID。它不能跨凭证、主体、范围、窗口、页大小、位置、接口或游标密钥轮换复用；签名依赖失败为 `CONTROL_CURSOR_UNAVAILABLE`/503。列表与 search/单项模型查询共用每实例一个在途许可；已准入查询在客户端断连后仍执行至索引和终态审计。容量为 `CONTROL_QUERY_CAPACITY_EXHAUSTED`/429；确定性预算溢出为 `CONTROL_QUERY_BUDGET_EXCEEDED`/429，`retryable=false`、`next_action=narrow_query`；超时、索引依赖或水位检查故障分别为 `CONTROL_QUERY_TIMEOUT`、`CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE`、`CONTROL_MODEL_CALLS_HEALTH_UNAVAILABLE`/503。

所有已认证且可审计的尝试都追加独立 `console.model.list` 管理 journal：成功为 `PASS/CONTROL_MODEL_CALLS_READ`，失败按相应稳定原因码区分 DENY/ERROR。事件没有 target、query digest、evidence refs、游标、窗口、返回模型 ID 或页面数据；因此它不把列表观察伪装成单项读取、模型执行或证据授权。必需审计写入失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留任何结果；所有响应 `Cache-Control: private, no-store`。发布器必须先升级到支持 `console.model.list` 后开放路由；无 PostgreSQL migration 或新依赖。回滚时先停用路由和界面，保持可识别该管理事件的发布器直至已封存段发布完毕。

## 29.26 已实现的校准报告调查契约

`GET /control/v1/calibration-reports/{report_id}` 仅允许独立管理 Bearer、`AuditAdministrator` 与服务端固定 tenant/site。`report_id` 必须是规范 `calr_` UUIDv7；任何查询串（包括空 `?`）、非空 body、重复认证头或无效路径均在投影读取前拒绝。该接口不接受页面传入 scope、报告正文或读取资格；角色也不替代专用 report body 的访问授权。

成功响应为 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、`source_report_id`、`found`、可空 `as_of` 与可空 `report`。未找到及跨 tenant/site 均返回 200、`found=false`、`as_of=null`、`report=null`，不形成对象枚举 oracle。找到时 `report` 仅包含 report/artifact ID、completed/reported 时间及事件 ID、body expiry、approval、dataset/label/task/threshold-policy/mapping revision、四份 manifest artifact ID、provider/wire model/model/prompt/resolved revision、可空 lineage review ID 与 `body_status=active|deleted`。`body_status` 只说明专用密文 body 的保留 tombstone，绝不代表正文读取权。

查询只使用专用 `calibration_reports`、`calibration_report_artifacts`、capability/review 绑定与完成、报告、retention outbox；不访问 `artifact_catalog`、vault、`EvidenceReadPort`、capability session 或 lease。投影会重验 tenant/site、事件 aggregate/type、完整不可变 report envelope、冻结时间、body retention 事件以及 report 与四份 manifest 的互异性。任一缺失、损坏或超时返回 `CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE`/503，且不返回部分 metadata。响应从不包含 capability、lease、token、storage locator、key ref、完整性摘要、正文、样本、标签、概率、指标、提示词、evidence refs 或 URL。

有效读取与现有 search/model 查询共用单实例在途许可，繁忙为 `CONTROL_CALIBRATION_REPORT_BUSY`/429；连接池等待计入 15 秒总时限，SQL/锁等待上限 5 秒。已准入读取在客户端断连后仍完成投影与终态审计，许可持有至审计完成。每个可审计尝试追加 `console.calibration.report.read`：成功为 `PASS/CONTROL_CALIBRATION_REPORT_READ`，路径/请求拒绝和依赖故障使用 11.13 的稳定原因码。审计中仅可写经验证的 report target；不记录 report metadata 或访问结果正文。必需审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，所有响应设置 `Cache-Control: private, no-store`。

部署先升级管理 journal 发布器以识别 `console.calibration.report.read`，再启用控制 API；无新增 migration、依赖或 secret。回滚先停用路由，保留新发布器直到已封存的管理事件完成发布；数据库 projection、report retention 与 outbox 历史继续按既有策略保留。

## 29.27 已实现的 OIDC 管理会话契约

`GET /control/v1/auth/oidc/start` 使用启动配置的唯一 issuer/client/redirect，发起 authorization-code flow，包含随机一次性 state、nonce 与 S256 PKCE；state Cookie 为 `Secure; HttpOnly; SameSite=Lax; Path=/` 且有效 5 分钟。未认证 OIDC/session 端点共用进程级未认证速率预算。浏览器禁止提交回跳地址、角色、tenant/site 或 redirect target。

`GET /control/v1/auth/oidc/callback` 仅接受单值、有限长度的 `code/state/error/iss` 与 OIDC 标准的可选 `error_description/error_uri`；拒绝重复和未知参数。callback 必须同时匹配 state query 与 host-only state Cookie，并以单条 `DELETE ... RETURNING` 原子消费尚未过期的 PKCE verifier/nonce。code 通过 HTTPS token endpoint 兑换，重定向禁用；OIDC 库以 discovery JWKS 验证 ID token 签名、issuer、audience 与 nonce。控制服务再要求精确的部署方 MFA `acr`、校验存在的 `at_hash`，并拒绝未在 subject-role allowlist 精确登记的主体。IdP claim 不提供授权角色。

登录成功后创建独立 256-bit 随机 session/CSRF token。浏览器只收到 `__Host-xshield-session` 不透明 Cookie；PostgreSQL 以随机 session token 的 SHA-256 摘要查找会话，并以 DB clock 执行 8 小时绝对期限、15 分钟闲置期限及显式撤销。CSRF token 独立绑定服务端 session，仅由同源 `GET /control/v1/session` 返回；响应同时返回服务端签名断言中的角色名，供统一后台隐藏无权页面和操作，但服务端仍对每个请求重新鉴权。每个非安全方法还必须提交唯一且精确匹配的 `Origin` 与 `X-Xshield-CSRF`。未认证 principal 不信任任何浏览器输入。当前进程的 subject-role mapping 在每个请求重新读取，完成部署配置变更后，相关实例的新请求即按新映射授权；principal 范围固定为该实例配置 tenant/site。

内部 middleware 将有效 Cookie 映射为最多 30 秒的进程内 HMAC 身份断言以复用既有授权函数；断言不能由外部 caller 签发或持久化。静态 Bearer 仍按已有机器认证契约处理；同一请求并带 Cookie 与 Authorization 会拒绝。login、callback、session bootstrap 与 logout 均写独立管理 journal `console.auth.login/callback/session.read/session.logout`；audit 失败扣留成功结果。session 创建在 audit 失败时撤销。所有认证响应均为 `no-store`，logout 只接受带有效 CSRF 的浏览器 session。数据库 schema 由迁移 0035 提供；OIDC 代码、Rustls HTTP 与 URL 依赖版本/许可证/升级策略见 README。

## 29.28 已实现的 MFA 再认证契约

`POST /control/v1/auth/oidc/reauth/start` 仅接受当前活动的 OIDC 浏览器 session，要求 `SensitiveEvidenceReader`、精确 Origin 与 CSRF token；拒绝查询串和非空正文。请求使用固定部署 issuer/client/redirect，发起授权码 + S256 PKCE，并附加部署要求的 ACR、`max_age=0` 与 `prompt=login`。五分钟一次性 state/nonce/PKCE 事务同时绑定当前 session token digest；响应只包含固定字段与 `authorization_url`，设置 host-only HttpOnly state Cookie 并使用 `no-store` / `no-referrer`。

复用 29.27 callback 完成签名、issuer、audience、nonce、`at_hash`（存在时）、ACR 和精确 subject allowlist 校验；step-up 额外要求 OIDC `auth_time` 存在、年龄不超过 60 秒、未来偏差不超过 30 秒，并要求 issuer/subject 与事务绑定的当前活动 session 精确相同。PostgreSQL 只更新该未撤销且未超时 session 的 `last_reauthenticated_at`；有效期以数据库时钟计算为两分钟。被撤销、绝对到期或超过 15 分钟闲置的 session 不能续期。当前登录 `GET /control/v1/session` 不回传 step-up 标志，服务端每个原文请求独立检查。

再认证开始写 `console.auth.reauth.start`；OIDC 身份、ACR、auth_time 验证通过后，服务端先耐久写 `console.auth.reauth.callback` 的 `CONTROL_OIDC_REAUTH_VERIFIED`，再更新 session 时间戳。该 PASS 只证明声明已验证，不是原文读取或审批事实；session 存储故障会另记 reauth callback ERROR。state、签名、身份或新鲜度拒绝沿用通用 `console.auth.callback` 拒绝，不记录授权码、state、token 或原始 ACR。证据原文的独立审批始终不变。原文内容端点经管理 session 与强类型参数校验后，在获取证据读取许可、查询访问申请/catalog 或调用 vault 前要求 step-up；未满足返回 `CONTROL_STEP_UP_REQUIRED`/403。当前机器 Bearer 尚无用途绑定的再认证凭据，因此不能通过该端点读取原文，自动化读取需待后续安全凭据设计。

部署需先应用迁移 0036，再升级控制服务、能识别新增 `console.auth.reauth.*` 事件的管理 journal 发布器、同源代理与控制台；代理须透传 reauth-start 的 `Set-Cookie`，禁止缓存与记录其请求/响应正文。迁移回退前须禁用原文内容路由或确保活动版本仍强制 step-up；不得先移除该字段再回退应用。

## 29.29 已实现的有界因果查询契约

`POST /control/v1/causality` 要求固定 tenant/site 内的 `Investigator` 和单值管理 Bearer。请求体上限 4 KiB，严格接受 `schema_version=3`、UTC RFC3339 整秒 `start`/`end`、规范 `ev_` `event_id`、`direction`（`both`、`predecessors` 或 `successors`）、`max_depth`（1–4）和 `max_nodes`（1–16）；未知字段、非 UTC、带小数秒、非法 ID、逆序/越界窗口均在索引访问前返回 `CONTROL_CAUSALITY_REQUEST_INVALID`/400。服务端不接受页面传入 tenant/site 或任意表达式。

服务端先以根 ID 精确查询固定时间窗，再沿已发布投影中的 `cause_event_ids` 做有界 BFS：前驱按记录引用逐个定位，后继使用固定的 `caused_by_event_id` 成员条件。查询最多返回 `max_nodes` 个非根节点；达到上限、后继页被截断或触达深度上限时标记 `truncated=true`，深度超过 `max_depth` 不再扩展。根不存在、过期、跨作用域或尚未发布统一返回 `found=false`，不泄露对象存在性；缺失引用不会由时间或 payload 猜测。每个索引请求复用结构化查询的 tenant/site、参数绑定、扫描预算和单实例共享许可，总期限 15 秒。

200 响应包含 `schema_version=3`、管理 `request_id`、固定作用域、`root_event_id`、请求方向/上限、`found`、`truncated`、`as_of`、`index_watermark`、`has_gaps`、`pending_segments`、可空 `scanned_rows`/`scanned_bytes` 及 `nodes`。节点只含结构化搜索的脱敏 `SearchEventSummary`、相对 `depth` 和 `direction`；不含 `payload_json`、证据正文、存储地址、密钥或授权上下文。响应不表示跨页冻结快照，也不替代请求、模型、案件、保留或证据端点的重新鉴权。

每次认证尝试追加 `console.causality.read` 管理事件：成功为 `PASS/CONTROL_CAUSALITY_READ`，无效计划、容量或确定性预算拒绝为 `DENY`，超时/索引/健康故障为 `ERROR`。通过计划后的审计携带独立用途域 HMAC `query_digest`，原始根 ID、窗口、方向和节点限制不写入 journal；计划解析失败可省略摘要。审计写入失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，响应统一 `Cache-Control: private, no-store`。该端点只提供有界调查摘要，不提供自然语言编译、无上限完整图、回放、导出、证据读取或业务权限。

部署先升级能够识别 `console.causality.read` 的管理 journal 发布器，再启用路由；无新增迁移或依赖。控制台事件详情已提供显式查询表单，只有在操作者填写 UTC 窗口并提交后才调用该端点；已加载事件集合的即时邻域仍独立展示。

## 29.30 已实现的 Agent 运行脱敏详情契约

`GET /control/v1/agent-runs/{agent_run_id}` 要求固定 tenant/site 内的 `Observer` 和单值管理 Bearer。路径 ID 先按 `agt_` UUIDv7 强类型校验；查询只访问 retention-aware `audit_events_active` 中固定的 `agent.started`、`agent.tool_called`、`agent.tool_result`、`agent.artifact_created`、`agent.finished` 事件，并以参数绑定注入服务端 tenant/site 与目标 ID。事件 payload 先拒绝重复 JSON 键，再只解码并比较 `agent_run_id`；未知的工具参数、结果、提示、权限快照和正文不会进入返回 DTO。

成功响应返回独立管理 `request_id`、固定作用域、`source_agent_run_id`、`found`、`completeness`、配置 journal 的 `as_of`/`index_watermark`/`has_gaps`/`pending_segments`，以及按 `request_seq,event_id` 排序且 `request_seq` 严格递增的脱敏生命周期事件。每个事件仅含 event/request/trace ID、时间、序号、类型、结果/原因、证据引用、直接因果引用和 sensitivity；`lifecycle_complete` 只有在可见片段首事件为启动、随后按序出现终态且二者均在同一查询内时为 true，保留后缀保持 `partial`。证据引用仍需独立 manifest、审批和 EvidenceReadPort；详情不会触发执行、回放、导出、证据读取或业务资格。

查询固定最多解码 64 个事件、单 payload 16 KiB、结果 1 MiB、2 秒索引预算及 5 秒客户端 deadline，并与其他分析读取共享单实例许可。已认证且路径有效的成功、未命中、容量/预算拒绝和依赖故障均追加独立 `console.agent.read`；通过路径校验的目标写入 `target_agent_run_id`，成功的去重 evidence refs 才进入审计引用。无效 ID 为 `CONTROL_AGENT_RUN_ID_INVALID`/400，容量/预算、超时、索引或健康故障沿用受限查询错误族；审计失败返回 `AUDIT_DURABILITY_FAILED`/503 并扣留结果，响应统一 `Cache-Control: private, no-store`。

该接口只交付历史脱敏观察，不等同于调查 Agent 执行器；自然语言计划、完整工具树、只读回放与导出仍保持未实现的设计契约。

## 29.31 已实现的案件清单分析与任务状态契约（MVP）

`POST /control/v1/cases/{case_id}/analyze` 要求固定 tenant/site 内的 `Investigator`、单值管理 Bearer、规范 `Idempotency-Key` 和空请求体。服务端先校验案件 UUIDv7、主体/案件归属和幂等摘要，再在 PostgreSQL 同一事务中读取案件状态、案件成员总数与当前 active catalog 引用数，写入迁移 0038 的 `control_jobs`。该 MVP 是确定性的只读清单分析：不调用模型、不读取 vault 内容、不创建证据资格，也不声称完成 Agent 工具树或回放。

事务以主体/作用域锁串行化同一幂等域；相同主体、作用域、键和案件返回原 `job_id` 与原完成时间，改案件或参数返回 `CONTROL_IDEMPOTENCY_CONFLICT`/409。目标不属于本人或当前作用域统一为 `CONTROL_CASE_ANALYSIS_TARGET_UNAVAILABLE`/404，不泄露案件存在性；连接池、SQL/锁等待和审计均有有界预算。首次与精确重试返回 202，响应包含 `job_id`、`kind=case_analysis`、`status=succeeded`、`checkpoint=inventory_committed`、案件 ID、两个计数、稳定完成原因和时间戳。

`GET /control/v1/jobs/{job_id}` 仅允许同一固定作用域内的 `Investigator` 读取本人任务；未知、跨主体或跨作用域的规范 ID 统一返回 200 `found=false`。成功、未命中、路径/认证拒绝和存储故障均写独立 `console.job.read`，成功目标写 `target_job_id`，审计不保存原幂等键、计数以外的案件内容、凭证或正文。结果和管理 journal 均设置 `private, no-store`；后续长任务可复用此状态机，但必须新增明确的 producer、checkpoint、终态原因和资源预算，不得把该 MVP 伪装成通用执行器。

部署先应用 `0038_m4_control_jobs.sql`，再升级能识别 `console.case.analyze`、`console.job.read` 和 `target_job_id` 的管理 journal 发布器，最后开放控制路由与界面。回滚先停用分析入口，保留新发布器直至已封存管理事件发布完成；任务历史与案件事实继续按各自保留策略保存。

## 29.32 已实现的调查导出契约（MVP）

`POST /control/v1/exports` 要求固定 tenant/site 内的 `Investigator`、单值管理凭证、规范幂等键和严格 JSON `{case_id,purpose}`；案件必须属于请求人且为 open/closed。服务端创建迁移 0039 的 `metadata_only` 行并返回 202；精确主体、作用域、键和参数重试返回同一 `export_id`，复用键改参数返回 `CONTROL_IDEMPOTENCY_CONFLICT`，其他案件统一为 `CONTROL_EXPORT_TARGET_UNAVAILABLE`。请求审计为 `export.requested`，不保存原始幂等键或用途正文。

`GET /control/v1/exports/{export_id}` 允许请求人读取自己的状态，也允许同作用域的 SensitiveEvidenceApprover、SensitiveEvidenceReader 或 AuditAdministrator 复核；缺失、跨范围和权限不足使用同构安全错误。成功读取追加 `console.export.read`。读取不返回包正文、vault locator、密钥引用、事件载荷或证据读取资格。

`POST /approve` 与 `/deny` 只接受独立 Approver；请求人不能自批，审批人必须具有对应 action 角色和 `SensitiveEvidenceApprover`，且同一浏览器 session 最近完成 step-up。请求体只含 1–512 字节、无控制字符且无首尾空白的 reason，原键绑定用途隔离的 HMAC 摘要；批准固定生成 15 分钟期限，拒绝无期限。批准事务返回案件与 catalog 的只读快照，随后控制层把最多 128 个成员的元数据、缺失清单和 omitted 列表序列化成 `investigation_export_metadata` JSON，用现有 vault 写入 `Restricted`/`Redacted` 加密 artifact，并原子发布 `evidence.cataloged` 后将导出置为 `ready`。包请求 ID 固定由 `export_id` 派生；批准已提交但包完成结果未知时，重试按固定请求 ID、包类型、父引用和期限复用已发布目录对象，避免重复活动包。数据库已有 `ready` 事实时，只有 artifact、包请求、摘要和字节数四元组全部精确一致才视为重试；错绑提交按存储损坏扣留。任何 vault/catalog/数据库不确定均返回可重试 503，不把 approved 状态冒充 ready。

`GET /download` 只接受独立 Reader 和近期 step-up。数据库先在 `ready`、期限有效且下载计数小于 2 时原子 claim；随后比较导出行、active catalog manifest 和 vault authenticated manifest 的 artifact/request/digest/bytes 四元关系，再读取并返回带 `X-Content-Type-Options: nosniff` 的 JSON attachment。读取前不加载证据正文；返回的包只包含案件/证据目录元数据与 missing/omitted 清单，不含事件 JSONL、请求响应版本、模型输入输出、规则/构建引用、存储定位、密钥、连接凭据或任何业务资格。成功、失败和审计故障分别写固定管理事件，审计不保存原始包或用途；控制台只接收与最近一次 `ready` 状态一致的 artifact 和精确字节数。

部署顺序为应用 `0039_m4_investigation_exports.sql`、`0040_m4_investigation_export_package_claims.sql`，升级可识别 `export.requested`、`export.approved`、`export.denied`、`export.downloaded` 和 `console.export.read` 的管理 journal，再开放 API 与控制台固定代理路由。迁移 0040 的 claim 使用 tenant/site/export 复合键、固定 package request ID、长度前缀 parent_refs 摘要和短 lease；并发 writer 返回 Busy，参数变化返回 Conflict，过期 lease 可回收，旧 lease 不能完成 ready，claim 与 ready 绑定在同一事务。该 MVP 仍是 metadata-only，不提供完整事件/正文取证包、自然语言查询、安全回放、自动轮询或机器 step-up；工作台仅显式读取状态、提交冻结的幂等操作并下载有界 JSON Blob，完整包能力保留为独立 backlog。

## 29.33 已实现的调查导出列表契约

`GET /control/v1/exports?view=mine` 用于发现当前主体的全部导出历史；同一固定 tenant/site 下具备 `Investigator`、`SensitiveEvidenceReader` 或 `SensitiveEvidenceApprover` 之一即可读取。`view=review` 仅允许 `SensitiveEvidenceApprover`，列出同作用域其他主体仍待决定（持久状态 `pending_approval`）的导出。Observer、SystemAdmin 与 AuditAdministrator 不隐含上述角色；Reader 与 AuditAdministrator 虽可按 ID 读取他人导出（29.32），列表不扩大枚举范围。每页重新校验单值管理 Bearer 或同源浏览器会话、凭证时效、作用域、角色和速率；GET 不要求 CSRF。列表只发现、不授权：批准/拒绝仍要求独立 Approver 与近期 step-up，下载仍要求 Reader 与近期 step-up，且各自重验当前状态。

请求必须显式提供规范 `view=mine` 或 `view=review`，随后可附一个 `&cursor=...`；缺少/未知视图、逆序或重复参数、附加参数（含 tenant_id、site_id）、百分号编码的视图别名、空游标、超过 256 字节的游标及非空正文为 `CONTROL_EXPORT_LIST_REQUEST_INVALID`/400。形状或签名无效的游标为 `CONTROL_CURSOR_INVALID`/400；二者均提示重新开始查询。游标为 `v1.export_UUIDv7.64lowerhex`，采用独立用途域 `xshield-control-export-list-v1`，以 HMAC 绑定管理凭证摘要、主体、tenant/site、视图、服务端页大小和最后导出 ID，不能跨视图、主体、接口复用，也不能用证据访问申请或案件游标替代；轮换凭证/游标密钥或改变页大小后需重开查询。游标签名依赖失败为 `CONTROL_CURSOR_UNAVAILABLE`/503。

200 响应字段为 `schema_version=3`、管理 `request_id`、`tenant_id`、`site_id`、`view`、数据库微秒 UTC `as_of`、`items`、`truncated` 和可空 `next_cursor`。每个 item 仅投影 export_id、case_id、requested_by、status、requested_at、decided_by、decided_at、expires_at。status 是 29.32 的持久状态（`pending_approval`、`approved`、`ready`、`rejected`、`expired`、`failed`），查询不改写它：`approved`/`ready` 行是否已过 `expires_at` 由客户端与 `as_of` 比较。`requested_at` 即详情的 `created_at`；与详情一致，item 时间为毫秒 UTC，仅 `as_of` 保留微秒。decided_by/decided_at 在未决定时为 null，expires_at 仅在批准后存在。`mine` 保留全部六种状态；`review` 固定为 `pending_approval`，已 `approved` 但尚未 `ready` 的导出已有决定，其包生成只能由原批准人按原键精确重试完成，不再属于待办。用途、决定理由、包 artifact/请求 ID、摘要、字节数、下载计数、幂等材料和 updated_at 不进入列表，仍由详情读取。空页仍包含数据库观察时间。

页大小沿用 `XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`（1–128），按规范导出 ID 的 `C` 字节序严格降序，以最后 ID 排他续查，最多多取一条预读判断下一页。单条 PostgreSQL 只读快照只投影元数据列（包列仅在 SQL 内折算为“是否已附包”的一致性标志，用途、理由和包标识不离开数据库），不 JOIN 案件、catalog 或 outbox：导出行以复合外键绑定案件，其状态转换不使用 outbox，管理访问另有 journal。所有可见记录含预读均校验 ID、规范主体、持久状态与决定/期限/包的一致性、请求人与决定人分离、时间单调，并再按视图复核可见性；任何坏行使整页失败。每页独立观察，后续批准/拒绝可使 review 项消失，新增高位 ID 需刷新首页发现；游标不是跨页数据库快照，列表刷新也不能确认未知写入。

列表与案件及证据操作共用单实例在途许可，繁忙为 `CONTROL_EXPORT_BUSY`/429。数据库操作含连接池等待限 15 秒，事务内 SQL/锁等待限 5 秒；故障、超时或损坏为 `CONTROL_EXPORT_STORE_UNAVAILABLE`/503。只读事务结束后追加独立 `console.export.list` 管理审计，已准入任务断连后继续到结果和审计终态，许可覆盖审计；进程退出和本地 fsync 仍是故障边界。成功含空页为 `PASS/CONTROL_EXPORTS_READ`；拒绝仅限 `CONTROL_AUTH_REQUIRED`、`CONTROL_SCOPE_DENIED`、`CONTROL_RATE_LIMITED`、`CONTROL_CURSOR_INVALID`、`CONTROL_EXPORT_LIST_REQUEST_INVALID`、`CONTROL_EXPORT_BUSY`；故障仅限 `CONTROL_CURSOR_UNAVAILABLE`、`CONTROL_EXPORT_STORE_UNAVAILABLE`、`CONTROL_RATE_UNAVAILABLE`、`CONTROL_CLOCK_UNAVAILABLE`、`CONTROL_SESSION_UNAVAILABLE`（共享鉴权在会话验证密钥不可用时产生；29.24 的原因集合未登记它，本变更不修改）。全部 target（含 `target_export_id`）、query_digest 和 bytes_read 只允许缺省/null，evidence_refs 为空；事件只保存调用者与结果，视图、游标、导出记录及他人主体不进入载荷。必需审计失败为 `AUDIT_DURABILITY_FAILED`/503 并扣留响应数据，所有响应设置 `private, no-store`。

部署先应用 `0050_m4_investigation_export_listing.sql`，为 tenant/site/requested_by/export ID 建立 `C` 序降序索引，并为 tenant/site/export ID 建立 `pending_approval` 部分索引；迁移 0039 的 requester 索引按 created_at 排序、主键使用库默认排序规则，均无法服务字节序键集分页。索引使用 `IF NOT EXISTS` 在事务内非并发构建，期间阻塞该表写入，大表需维护窗口。随后升级管理 journal 发布器、控制 API 和固定代理路由。数据库角色沿用详情所需的 investigation_exports 查询权限；无需新增密钥或依赖。回滚时先停用路由，继续使用可识别新事件的发布器直到相关积压已处理；应用可回退并保留两个加法索引，或仅移除本迁移的索引，保留所有导出、包 claim 和审计历史。旧发布器遇到新事件会停止推进并保留待发布段。

## 站点诊断与控制台契约补充（2026-09-27）

found=false 的站点配置响应可以包含 requires_approval=null；客户端不得将其解读为发布许可或格式错误。持久化 listen_port 范围为 6100–65535；请求值 0 是自动分配指令。

依赖故障响应在现有 error_code、message_safe、request_id、retryable、next_action 外附加可选 stage：配置存储为 site_config_store，发布/回滚存储为 site_apply_store，健康观察存储为 site_health_store。字段描述边界而非具体数据库错误；权限拒绝不标为存储故障。稳定原因码和审计终态保持兼容。

控制台错误字典的契约测试检查后端 CONTROL_SITE_* 失败原因码集合；成功终态单独登记。GET 失败可以人工刷新；写入结果未知时由操作者确认后按原正文和幂等键重试。站点 status/health/revisions 与配置读取使用各自角色规则，前端不会用配置读取代替 Observer 只读接口。

本地 schema manifest 位于 scripts/dev_postgres_schema.sql，由 scripts/generate_dev_postgres_schema.py 在独立临时数据库中按原 SQL 生成。修改迁移文件后必须审查 SQL 及 manifest 的共同变化；不要通过改写 ledger 绕过 checksum。生产升级由部署流程执行加法迁移；界面/API 可回滚，数据库历史不做破坏性回滚。
# Agent API Key 端点

| 方法 | 路径 | 用途 |
|---|---|---|
| POST/GET | `/control/v1/agent-api-keys` | 创建或查看非秘密 Key 元数据 |
| POST | `/control/v1/agent-api-keys/{id}/revoke` | 立即撤销 |
| POST | `/control/v1/agent-api-keys/{id}/rotate` | 撤销旧 Key 并签发新 Key |

Agent 站点操作使用 `/control/v1/sites` 及其 config、validate、apply、health、rollback 子路径。
