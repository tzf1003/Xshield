# 07 自动注入探针、心跳与请求关联

## 7.1 部署与职责

使用 TypeScript 开发、发布固定版本普通 JS。网关只改写已识别 HTML/批准 JS；不要求业务方修改代码。注入、Hook、错误提示、页面实例和请求关联是探针职责；实际放行、身份、资格和秘密钥匙由 WAF 控制。

探针资源走同源固定路径，bootstrap 动态内容 no-store。静态 HTML 不嵌入跨会话共享的凭证。压缩、ETag、Content-Length、缓存、CSP nonce、script-src/connect-src 与 SRI 必须同步适配；不能为注入而全局关闭 CSP/SRI。SRI 会检查资源内容，改写后须维护对应完整性信息。[S13]

网关在固定版本路径 `/__xshield/v1/sensor/1.0.0.js` 和 `/__xshield/v1/sensor/1.0.0-loader.js` 直接提供普通 JavaScript，使用长期 immutable 缓存、同源资源隔离、`nosniff`、固定版本头和 WAF request_id。启用站点 sensor 配置后，`/__xshield/v1/bootstrap` 以 `private, no-store` 返回服务端固定的页面构建指纹、心跳间隔、prepare 路径及每次请求生成的页面/导航句柄；loader 同源获取该动态配置后启动探针，静态资源不携带会话数据。`POST /__xshield/v1/events/prepare` 仅接收匹配配置 Origin、当前版本和构建的严格 JSON 批次，要求当前未过期 WAF 会话，限制为 16 KiB、16 条连续事件；记录绑定、身份代际和 `client_claimed` 观测，但不产生授权效果。四条路径均属于保留命名空间，站点 operation 不能覆盖，不生成源站转发意图，并以各自稳定原因进入耐久审计。

首个 HTML 自动注入适配器使用 operation 级 `SENSOR_HTML` 响应模式，并在配置中固定 `adapter_revision`、规范小写 SHA-256 `origin_sha256`、`injection_offset` 与正文上限；`additional_adapters` 可额外声明至多 15 个修订，修订和摘要均不得重复。它只接受状态 200、`text/html; charset=utf-8`、identity 编码、无 trailer、无下载处置且无 CSP/CSP-Report-Only 的 UTF-8 正文；运行时只计算一次完整源站摘要并选择对应批准修订，再验证该修订偏移处精确 `</head>` 后插入上述两个同源外链脚本。任何构建、偏移、类型或策略偏差均在释放正文前关闭；成功响应移除旧长度、实体校验和摘要头，固定为 `private, no-store`，并以选中修订及原文/注入后摘要写入耐久审计。当前适配器面向无 CSP 的批准静态构建；动态 HTML、nonce-aware CSP 与 SRI 映射须由后续版本化适配器显式支持，不做启发式降级。

## 7.2 事件契约

字段：sensor_version、build_ref、page_handle、navigation_id、action_hint、client_request_id、client_event_seq、visibility、event_type、callsite_fingerprint。WAF 另生成 request_id，且用服务端时间判定期限。客户端 action_hint 不等于已授予的 action_id。

同一次 action 可以产生多个请求。服务端关联键包含 site、auth_binding、epoch、page、request；不能只使用“最新心跳”。HTTP 与 WSS 到达乱序时记录 pending/unknown，严格票据可通过 HTTPS prepare 建立屏障。

## 7.3 WSS/HTTPS

初始建议活跃页 15 秒心跳加抖动，单消息 16 KiB、单页短时 64 条摘要。HTTPS 批量上报作为后备。浏览器后台冻结会暂停 JS 执行，因此缺心跳不自动等于攻击，也不能保证网页永远在线。[S14]

WSS 限制 Origin、连接票据、身份代际、消息率和长度，连接失效要关闭/重认证。[S12] 原始 Cookie 仅在握手等适用请求中自动传送，后续消息以服务端连接上下文关联。

## 7.4 Hook 的覆盖声明

按站优先完整请求封装入口，保持 Promise、类型、错误语义及密钥轮换。预先保存的函数引用、Worker、WASM、iframe、Service Worker 缓存等需逐项测试。不在“全局 fetch Hook 安装成功”后声称所有加密已接管。

前端调用栈仅作调用点线索，不是函数入参内存快照。所谓明文必须来自实际接管的请求实体或可信转换，而不是仅来自客户端报告。

## 7.5 采集与体验

默认不记录逐键输入和鼠标轨迹。可追溯界面优先来自 WAF 实际响应与结构化操作描述；客户端 DOM 快照若用于调试须明确 client_claimed，进入受限证据库。前端审计日志不能带密码、OTP、原始 Cookie。

拒绝响应由网关产生，探针仅展示原因码和安全恢复入口。弹窗不能遮挡已交付的敏感信息后声称拦截成功。request_id 可提供给用户报障，但不构成读取后台日志的访问凭证。
