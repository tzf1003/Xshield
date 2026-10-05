# 05 界面操作来源验证：Xshield 核心准入机制

## 5.1 语义

Xshield 执行 UI 流程准入，不要求还原完整业务 ACL。当前身份即便具有源站权限，没有通过当前有效会话中认可的界面入口取得对应操作依据，也拒绝。已有有效资格内的再次访问可以通过，不必每次出现新的鼠标点击。

“返回界面”必须指 WAF 确认来自批准流程的 HTML、组件所需数据及已验证构建映射。客户端截图、DOM 上报和 Error.stack 只提供线索，不是远程真实性证明。[S01][S02]

## 5.2 三种对象

PageEvidence：站点、页面实例、认证快照、来源请求、响应对象、构建指纹、有效期、验证状态。

ActionDescriptor：action_id、页面模板、业务 operation、方法与路由、目标提取及约束、允许字段、状态前提、证据引用、mapping_revision。

ActionGrant：当前主体在特定 scope、期限和使用次数内可以使用哪个 ActionDescriptor；随后与资源操作资格共同检查。

根入口由策略显式批准。一般链路为：登录/公开/分享等根 → 获准页面 → 列表/查询/创建等动作 → 精确资源 → 详情或写动作。链路可以复用，但不能从一次被拒绝的访问自行补出前置资格。

## 5.3 发行流水线

1. WAF 先准入页面/数据请求；响应验真、解密、格式和构建校验通过。
2. 站点适配器从可信模板位置提取操作候选，排除用户内容和未启用组件。
3. Jev 可在固定候选中判断语义对应，保存全分布和证据；NONE/UNKNOWN 不发行。
4. 代码验证候选属于已批准 mapping、目标和字段不扩张、身份快照未过期。
5. 写入 ActionGrant 与资源资格，附带 page_evidence_id/model_call_id/rule_revision。
6. 提交完成后交付页面或必要的后续操作描述。延迟过高的站点预先编译映射，不每次全页在线分析。

纯前置接入中，自动注入探针用 `X-Xshield-Action-Ref` 携带 WAF 已发行的不透明 `action_ref`。该值只用于定位服务端记录，不能自行授权；网关必须结合租户、站点、当前认证 binding/epoch、活动策略、页面证据、动作描述、方法、路由、目标、字段和期限重新验证。重复、畸形、未知或已失效引用均按 `UI_ACTION_NOT_AVAILABLE` 拒绝，转发源站前删除该边缘专用请求头。`action_hint`、DOM 事件和普通客户端遥测不得填充此字段或替代服务端记录。

模型识别界面动作是允许的；模型直接编造新动作或只因高分扩大 scope 是禁止的。首版高危动作必须对应独立验证的操作模板。对模型只能识别、无法确定验证的动态 UI，强制模式拒绝或要求重新走已支持入口。

页面来源持久化库入口 `ProvenancePersistence` 以动作期限作为身份与页面证据期限的收缩边界。在持有身份锁、策略/动作描述共享锁后，以及新建提交或精确重试返回前，按数据库当前时间复验动作期限；语义匹配但等待期间到期返回 `UI_ACTION_NOT_AVAILABLE`，本次页面证据、动作和 outbox 写入全部回滚。已有页面证据与动作保持共享锁至事务结束，撤销等语义冲突优先返回 `UI_ACTION_ISSUANCE_CONFLICT`；策略或描述退休返回 `UI_ACTION_NOT_AVAILABLE`。页面交付的 HTTP 发行适配见 5.3.1，它逐项复用该命令的跨对象校验。

### 5.3.1 已实现的页面签发与真实浏览器闭环

**配置。** `SENSOR_HTML` 页面根（`GET`、`AUTHENTICATED_ROOT`、精确路径）在响应上声明 `page_actions: {mapping_revision, max_active_pages}`（1–1000）；由它签发的每个 `UI_ACTION_REQUIRED` 非资源 operation 声明 `issued_by: {page_operation_id, ttl_seconds}`（1–86400）。未知页面、未被引用的 `page_actions`、资源型或非 UI 目标、单页超过 16 个动作、同一 `(action_id, mapping_revision)` 两种含义，均在启动编译时拒绝。页面签发的动作没有目标、没有字段，`field_profile` 固定为 `none`。

**动作描述由配置推导并绑定摘要。** 只要有页面声明 `page_actions`，该策略修订即由 edge 管理：页面签发的描述（`page_template` = 页面 operation ID）与 `response.resource_grant` 目标的描述（`page_template` = 目标 operation ID，响应证据不比较页面模板）一起推导，按规范编码计算 SHA-256，写入 `policy_revisions.content_digest`。edge 在绑定任何监听端口之前于单事务内供给：修订不存在则以 `active` 创建；已存在时状态必须为 `active` 且摘要相同，否则拒绝启动（`UI_DESCRIPTOR_CONFLICT`）；每条描述不存在则插入、已存在则逐字段比较（允许字段按集合比较），任何差异整体回滚并拒绝启动；从不更新已有行，并发启动的同配置 edge 收敛为 `Existing`；数据库不可达同样拒绝启动。没有 `page_actions` 的配置保持外部供给（例如靶场种子），也不需要数据库。

**同一供给覆盖配置开始服务的每条路径。** 推导与摘要是 `xshield_core::edge_descriptors` 中的纯函数（无 I/O，编码以域分隔标签 `xshield-edge-descriptors-v1` 版本化），edge 与日后的控制面因此得到逐字节相同的摘要。edge 在三处执行同一幂等供给：启动时供给 `XSHIELD_CONFIG` 的启动配置；控制面经签名 `/internal/v1/apply` 下发快照时，在 apply 锁内、快照编译完成之后、写签名 pending 文件之前，按站点 ID 顺序为每个声明 `page_actions` 的站点供给（落后或同 revision 异 payload 的快照先被拒绝，不接触数据库；与正在服务的快照逐字节相同的幂等重试不再访问数据库，因为它开始服务前已供给）；重启恢复持久化快照时，在绑定任何监听端口之前逐站点再次供给。`Created` 与 `Existing` 都算成功。apply 中任一站点摘要不同、修订不是 `active` 或已有描述字段不同，整份快照以 409 `EDGE_APPLY_DESCRIPTOR_CONFLICT` 拒绝；数据库不可达、4 秒内未完成或 edge 启动时没有身份存储，以 503 `EDGE_APPLY_DESCRIPTOR_UNAVAILABLE` 拒绝；两者都不写 pending 文件、不改变正在服务的快照，应答体带出问题的 `site_id`。重启时同类失败拒绝启动（`UI_DESCRIPTOR_CONFLICT: persisted snapshot site …` 或 `IDENTITY_STORE_UNAVAILABLE: persisted snapshot site …`）。apply 对整个租户快照原子生效，一个站点的冲突或数据库故障会挡住同租户其他站点的本次变更，这是保持原子性的代价；运维处理见 19 §19.2。控制面目前仍拒绝编写 `page_actions`，这条 apply 路径由直接签名的快照（真实浏览器回归）使用。

**控制面表达（2026-10-06）。** 控制面的站点配置现在可以保存、校验、审批并投影这条链路的全部配置：路由准入 `auth_entry` 与 `auth_binding`、登出路由的 `auth_revoke`、`SENSOR_HTML` 页面的 `sensor_html` 构建适配、`page_actions`、`issued_by` 与 `resource_grant`，上述每条 edge 规则（含跨路由规则）都在 `xshield_core::site::flow` 中镜像，并由 gateway 一致性测试以真实编译器核对；真实浏览器闭环的配置由控制面投影后与 `scripts/test_browser_loop.sh` 的 operations 逐项相同（契约与原因码见 29“站点浏览器来源流程配置契约”）。这些路由的变更另有 `AUTH_ENTRY_CHANGED`、`SENSOR_HTML_CHANGED`、`PAGE_ACTIONS_CHANGED`、`RESOURCE_GRANT_CHANGED` 审批原因，只能由独立审批人批准，`site.config.apply_direct` 不能代替。edge 在 apply 时供给描述的能力尚在另一项工作中实现；合入前真实 edge 仍按上一段拒绝含 `page_actions` 的快照，控制面也尚未要求描述变化时同步提升 `policy_revision`。

**页面根准入。** 浏览器顶层导航只携带 `HttpOnly` WAF Cookie，永远不会携带应用自己的 `Authorization`。对声明了 `page_actions` 的页面根，请求不带 `Authorization` 时按 WAF 会话识别 binding：必须是 `active`、未过期且仍持有有效业务凭证的 binding，准入原因 `PAGE_ROOT_SESSION_ALLOWED`；匿名会话 401 `AUTH_REQUIRED`，未知、撤销或过期会话 403 `AUTH_BINDING_MISMATCH`。一旦请求带了 `Authorization`，仍走完整凭证校验，错配照常拒绝。这样放宽是安全的，因为 `SENSOR_HTML` 只释放预先固定摘要的静态字节，不会把按用户生成的源站内容交给仅持有会话的一方；而由此签发的一切都绑定该 binding 与 epoch，并在使用时按完整凭证组合重新校验，单独被盗的 WAF Cookie 得不到可用权限。

**交付时签发。** 精确页面字节通过摘要与注入校验后、正文释放前，edge 在一个事务内写入一条 PageEvidence（模板 = 页面 operation，构建指纹 = 已验证的源站摘要，响应对象引用 = 注入后正文的 SHA-256）和该页声明的全部 ActionGrant 与逐项 `ui_action.issued` outbox。动作期限为配置 TTL 与 binding 绝对期限的较小值，证据期限为其中最长者；引用与事件 ID 由请求、页面实例和动作 HMAC 派生，精确重试得到相同结果。事务先锁 binding 行，再统计同一 binding、epoch 与页面模板下其他未过期页面实例，达到 `max_active_pages` 时返回 `UI_ACTION_CAPACITY_EXCEEDED`；任何一项不合格整体回滚。签发失败从不扣留已验证的页面：页面照常交付但不持有引用，其受控请求随之被拒绝，失败原因写入 `ui_action_issue` 阶段（DENY 或依赖故障 ERROR）。

**交付给浏览器。** 注入的 loader 标签携带本次交付的页面句柄 `pgh_<UUIDv7>`，其 UUID 即页面证据 ID；句柄本身不是凭证。`GET /__xshield/v1/bootstrap?page=<句柄>`（`private, no-store`）只在同源 fetch（`Sec-Fetch-Site` 缺省或为 `same-origin`）且 WAF 会话属于拥有该页面实例的 `active` binding、epoch 一致时，返回该页仍有效的 `actions: [{action_ref, method, path_template, expires_in_seconds}]`（至多 16 条）；另一会话拿到同一句柄只会得到空列表。引用从不进入 HTML、静态资源或日志，journal 只以 `sensor_bootstrap` 阶段记录是否交付了引用。

**发放响应资格的列表不接受查询串。** 列表响应里的每个条目都会成为当前 binding 的资格，所以调用者不能借查询参数（例如 `?customer=B`）选择“列出谁的对象”，哪怕源站自己存在越权缺陷：配置了 `response.resource_grant` 的 `AUTHENTICATED_ROOT` 路由收到任何查询串即以 `FIELD_NOT_ALLOWED` 拒绝，请求不转发到源站；非资源的 `UI_ACTION_REQUIRED` 路由早已按同一规则拒绝。代价是这类列表目前不能带分页等参数，需要时应由站点另设无参数入口，或等待按路由声明查询参数白名单的能力（尚未实现）。

**浏览器侧出示，网关侧重验。** 探针 1.1.0 只把这些服务端引用原样放进 `X-Xshield-Action-Ref`：页面动作匹配精确的同源方法与路径（带查询串不匹配），列表 → 详情的响应派生引用按 bootstrap 下发的 `resource_grant` 提取提示从已批准列表的 JSON 响应中读取（见 07 §7.4）。网关的 `admit_ui_action` 未作任何放宽：对每个请求重新加载服务端记录并校验 binding、epoch、策略、页面证据、方法、路由、目标、字段与期限，资源路由再精确匹配 ResourceGrant，转发前删除该请求头。真实浏览器回归见 20 §20.19。

## 5.4 页面中存在代码不等于存在入口

公共 bundle 中的管理员组件、隐藏模板、注释、广告、评论和用户富文本不自动构成当前会话的操作来源。SPA 的菜单/弹窗应结合获得它的受控请求、服务器返回的功能数据与固定构建映射。若展示条件只能来自可任意修改的本地状态，没有其他约束，记录 evidence_quality=client_claimed，不当作强制资格来源。

CSS 可见性也不是最终安全判据；通过受控映射确认哪类操作被提供给当前流程。按钮名称相同不代表路由、对象和字段相同。

## 5.5 高权限操作示例

A 浏览 B 的评论：产生 comment.read:C1，按规则可产生 profile.public.read:B；不会产生 user.password.admin_reset:B。

A 的设置页面提供 change_self_password：目标约束必须是当前已验证主体；把目标换成 B 即 TARGET_SCOPE_MISMATCH。页面没有 admin_reset 候选则 UI_ACTION_NOT_AVAILABLE；即使 A 在业务系统是真管理员也拒绝。

管理员页面为 B 提供 reset action：只发行该 scope 的资格，不能重置 C 或隐藏增加 role 字段。若配置允许一个管理列表针对列表中的多个对象执行同类操作，则明确记录该集合、范围和创建规则。

## 5.6 异常与失效

新构建、页面规则升级、账号变更、权限上下文变化、来源撤销或 TTL 到期使相关资格失效或重新评估。后台页冻结不直接撤销已有有效资格。新浏览器没有旧账本，必须重新获取；这属于产品规则，不属于误报。

若认可流程本身向普通用户错误地提供了高权限按钮且没有任何可靠限制，流程检查无法恢复隐藏的真实 ACL。这类站点需显式限制高危入口/映射；没有证据时不让模型补全。日志区分 FLOW_ADMITTED 与 BUSINESS_AUTHZ_VERIFIED，不将两者混成一个“已鉴权”。
