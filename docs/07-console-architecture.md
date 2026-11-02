# 07 控制台与请求追溯：技术方案

版本 4.1｜2026-11-01｜状态：设计稿，待实现。界面见 [06 控制台界面设计](06-console-ui.md)，可点击原型在 [design/console-v4](../design/console-v4/README.md)。本章取代 [03.4](03-admin-config-audit.md#34-判定日志) 中判定日志的字段清单和 [03.5](03-admin-config-audit.md#35-控制台范围) 的控制台范围，并定义 [03.2](03-admin-config-audit.md#32-站点配置) 新增的 `advanced` 段。判定规则本身（[01](01-request-flow.md)、[02](02-jev.md)）不变。

## 7.1 目标与约束

### 7.1.1 四项要求的技术含义

| 要求 | 技术含义 |
|---|---|
| 保留高级配置 | 站点的全部字段都能在界面上改，包括会话凭证用请求头、`bypass`、`on_jev_unavailable`；可以直接编辑 YAML/JSON；每次修改有版本号、差异和回滚；新增站点级判定参数 `advanced`（Jev 超时、调用限额、放行缓存时长、追加脱敏字段、同义词，[7.6](#76-站点级判定参数advanced)）；其余运行参数只读展示网关的实际值 |
| 兼顾便捷性 | 常用操作不进表单：从一条请求直接“登记为入口 / 加入绕过”，保存前给出影响预估；观察模式下自动汇总调优建议，建议可以一键应用（包括调整判定参数）；按请求 ID、会话、路径一个搜索框直达；批量粘贴请求 ID 对照结论 |
| 每个请求都可追溯 | 网关处理的**每个**请求都有一条记录，包括目前不记录的绕过、413、未知站点（第四轮试跑里有两个探针因为命中 `/assets/*` 绕过而查不到记录，[04.5.4](04-deployment-testing.md#454-第四轮548-条记录)）；记录之间可以跳转：值从哪个响应学到（来源请求 ID）、缓存放行复用了哪次 Jev 结论、会话由哪个登录请求签发、判定时用的是哪个配置版本；网关队列拥堵时先丢绕过的简记录并计数，缺口在控制台如实显示（[7.4.1](#741-每个请求一条)） |
| Jev 调用可查看详细上下文 | 保存发给 Jev 的 `state` 原文、指令版本（可还原完整请求）、原始响应、概率、耗时、超时、裁剪级别和失败码；控制台按结构化、JSON、原文三种视图展示，并把 `state` 里的每个值和最近访问链接到对应的请求 |

### 7.1.2 不变的约束

- 单管理员，口令登录，没有角色和审批（[03.1](03-admin-config-audit.md#31-单管理员)）。
- 判定逻辑不因控制台改变：发给 Jev 的 `state` 逐字节不变，新增的追溯信息走旁路结构（[7.5.2](#752-state-与追溯信息的对齐)）。站点不写 `advanced` 时，判定行为与现在完全相同。
- 会话凭证、口令类字段不落日志，不发给 Jev；判定日志不作为授权依据（AGENTS.md）。
- 存储只用 PostgreSQL，不引入 ClickHouse、消息队列或对象存储。
- 不新增环境变量、角色或 crate。

### 7.1.3 新增项必要性审查

AGENTS.md 要求新增配置项、表、依赖之前先确认现有机制不够用。本方案的新增项：

| 新增 | 为什么现有机制不够 |
|---|---|
| 站点配置 `advanced` 段 | 管理员 2026-11-01 决定把 Jev 超时、调用限额、放行缓存时长、追加脱敏字段、同义词做成站点可选项：慢链路（第一轮 83 次超时）、未登录轮询耗尽地址限额（第二轮）、同义词（`paymentId` ↔ `/api/Cards`，第三轮）此前都只能改环境变量或代码 |
| `decision_log` 新增列和 `trace` JSON | 现有行只有路径、结论和 Jev 状态，快速放行的请求看不出“凭什么放行”，也无法跳到来源请求 |
| 表 `edge_status`（网关心跳） | 控制台要回答“网关在线吗、新配置生效了吗、日志有没有丢”。这些只在网关进程内存和 stderr 里，控制面读不到；[03.5](03-admin-config-audit.md#35-控制台范围) 要求的 Jev 连通状态也需要它 |
| 表 `jev_prompts`（指令版本） | 指令文本随版本发布、每次调用都一样，每行重复存约 3 KiB 浪费；不存又无法还原 Jev 看到的完整请求 |
| `site_config_history` 按版本号存全文 | PR #73 只存修改前后，判定记录引用的“配置版本 N”无法直接打开 |
| `decision_log` 按天分区 | 绕过请求也要记录后行数会增加一个数量级，7 天保留用删分区代替大批量 `DELETE` |
| 前端依赖 `yaml`、`@codemirror/*`（懒加载） | YAML 编辑需要解析器和带行号、错误标记的编辑器；见 [7.10.1](#7101-技术栈与依赖) |
| 后端依赖 `rust-embed`（或等价方案） | 控制面同端口提供控制台静态文件，部署少一个服务、少一组 CORS 配置；见 [7.2.3](#723-部署) |
| `objects.learning` 段（学习开关、阈值、代理上限） | 学习要按站点调：低流量站点需要更少的使用次数，个别站点要能暂停学习而不发版。默认值写在代码里，与默认全部相同时不写入配置；`auto_tighten`、`auto_pause` 要到 PR-3d 才生效，`agent` 段要到学习代理（PR-5）才生效，在此之前只保存、不起作用 |
| 表 `object_evidence`（学习证据） | 判定要数 7 天窗口内的会话和拒绝，控制面可能多实例运行，证据必须在库里共享且重启不丢；放进站点配置会让每次投票都产生一个配置版本 |
| 表 `object_positions`（位置判定状态） | 管理员对提议的确认、驳回和歧义标记要跨重启保留；提议只是建议，写进 `site_configs` 会改变网关轮询的版本号，每个提议都触发一次配置变更 |
| 表 `object_learning_cursor`（决策日志读取进度） | 每个站点读到哪一条记录必须持久化，否则重启后重读或漏读；`decision_log` 是网关的只追加日志，控制面只读它，进度只能记在别处。删除站点时游标移到删除时刻，同名重建的站点不会学习旧站点的日志；学习写入都核对配置的创建时间（代际），删除前开始的批次写不进同名重建的站点 |

## 7.2 总体架构

### 7.2.1 组件

```text
 浏览器 / 测试套件                     管理员浏览器
       │  X-Xshield-Request-Id 回传          │  同源 HTTPS，Cookie 会话
       ▼                                     ▼
┌──────────────────┐   读 site_configs   ┌──────────────────────────────┐
│  xshield-edge    │◀────────────────────│  xshield-control              │
│  ├ xshield-judge │   写 decision_log   │  ├ /api/*  JSON API           │
│  │  上下文 + Jev │────────────────────▶│  ├ /       控制台静态文件      │
│  └ sink（批量）  │   写 edge_status    │  ├ 迁移、分区维护、保留期清理  │
└────────┬─────────┘   写 jev_prompts    │  └ 建议、影响预估、统计（只读）│
         │                               └──────────────┬───────────────┘
         ▼                                              ▼
      源站                                         PostgreSQL
```

- **xshield-edge**：判定并转发；对每个请求产出一条记录，批量写入 `decision_log`；每 10 秒（以及站点表变化后立即）写一次 `edge_status`；启动时登记指令版本到 `jev_prompts`。
- **xshield-control**：唯一写 `site_configs` / `site_config_history` 的进程；提供控制台 API 和静态文件；启动时执行迁移；每小时维护分区和保留期。控制面不调用 Jev，也不持有 Jev 密钥。
- **web/console**：React 单页应用，所有数据来自 `/api/*`。

### 7.2.2 一个请求的数据流

1. 网关为请求分配 `request_id`（[7.3.1](#731-请求标识)），在响应头 `X-Xshield-Request-Id`、拦截响应体和转发给源站的请求头里带上它。
2. 判定过程把每一步的依据写进记录的 `trace`；调用 Jev 时把交换内容写进 `jev`。
3. 源站响应结束时，网关把“这个响应教给会话什么”写进 `trace.response`。
4. Pingora `logging` 阶段补上状态码和耗时，记录进入发送队列；后台任务每 250 ms 或攒满 500 条批量插入。
5. 控制台按请求 ID、会话、路径、结论等查询；详情页沿记录里的请求 ID 链跳转。

### 7.2.3 部署

参考部署仍是单机 Docker Compose（[04.1](04-deployment-testing.md#41-部署形态)），三个服务：`postgres`、`xshield-control`、`xshield-edge`。变化：

- `xshield-control` 在同一端口提供控制台静态文件（构建时嵌入 `web/console/dist`，开发时仍用 Vite 代理），控制台和 API 同源，生产不需要 `XSHIELD_CONTROL_CONSOLE_ORIGIN`（保留给前后端分开托管的情况）。Dockerfile 的 control 镜像增加一个 Node 构建阶段。
- `xshield-control` 启动时执行 `migrations/`（sqlx `migrate` 特性），网关不执行迁移；表缺失时网关报错退出，交给 Compose 重启。
- 管理员 Cookie 带 `__Host-` 前缀和 `Secure`，控制台必须经 HTTPS 或 `localhost`（例如 SSH 隧道）访问。唯一例外是设置 `XSHIELD_CONTROL_PLAIN_HTTP=true`：Cookie 改为不带前缀、不带 `Secure`，只用于经 tailnet 等已加密网络的纯 HTTP 访问（[03.3](03-admin-config-audit.md#33-部署级环境变量)）。

## 7.3 请求标识与追溯链路

### 7.3.1 请求标识

`request_id` 沿用现有格式：`req_` 加 UUIDv7 的 32 位小写十六进制（`uuid::Uuid::now_v7().simple()`）。前 12 位十六进制是毫秒时间戳，例如 `req_01a19741107477ff9224781077354552` 生成于 2026-11-01 13:16:26.100 UTC。控制面按 ID 查询时先解出时间 `t`，查 `at_millis BETWEEN t − 60 秒 AND t + 60 秒` 且 `request_id` 相等的行：`at_millis` 取自请求到达时刻，与 ID 生成时刻只差几毫秒，留 60 秒余量是为了不依赖这个假设；跨午夜时窗口自然落在相邻两个分区，PostgreSQL 只扫这两个。解不出时间的输入（不是 `req_` 加 32 位十六进制）不按 ID 查询。

请求 ID 出现在：网关返回给客户端的每个响应头 `X-Xshield-Request-Id`；拦截响应体 `{"error":"forbidden","request_id":"req_…"}`；转发给源站的请求头 `X-Xshield-Request-Id`（源站日志可以用它关联）。用户反馈“被拦了”时，让他提供这个 ID。

### 7.3.2 追溯链路

一条记录内部说明“这个请求为什么得到这个结论”；记录之间的链接说明“依据从哪里来”：

| 链接 | 存在哪里 | 控制台怎么用 |
|---|---|---|
| 值 → 来源请求 | `trace.values[].sources[].request_id` | 值 `7` 以 `id` 出现在 `GET /api/patients` 的响应里，点击打开那个请求 |
| 缓存放行 → 原判定 | `trace.cache_source` | 缓存放行复用的是哪一次 Jev 放行 |
| 最近访问 → 请求 | `trace.session.recent[].request_id` | Jev 看到的“最近访问”逐条可点 |
| 经过的入口 → 请求 | `trace.session.entries_passed[].request_id` | 会话第一次经过某个入口的请求 |
| 登录请求 → 新会话 | `trace.response.issued_session` | 登录响应下发了凭证，链接到新会话的时间线 |
| 记录 → 配置版本 | `site_version` | 判定时的站点配置（含 `advanced`），打开该版本的全文和差异 |
| 记录 → 会话 | `session` | 会话时间线 |
| 记录 → Jev 指令版本 | `jev.prompt` | 还原发给 Jev 的完整请求体 |

```text
POST /login ──签发会话──▶ 会话 7c1e9a40…
   │                         │
   ▼                         ▼
GET /api/patients ──响应里出现 id=7──┐
                                     ▼
                     GET /api/patients/7  快速放行（7 已核验，来源 = 上一行）
                     GET /api/patients/8  Jev 拒绝（8 只以 age 出现过，来源 = …/7）
```

来源请求 ID 保存在网关内存的会话上下文里（[7.7.1](#771-会话上下文增加请求-id)）。上下文在网关重启时整体清空（[01.2](01-request-flow.md#12-会话与上下文)），所以正常情况下每个来源都带请求 ID；没有 ID 的来源只会出现在导入的旧格式记录和测试数据里，界面照常显示来源说明，只是不可点。来源请求本身可能已过保留期（7 天），那时详情接口的 `sources` 里没有它，界面显示“已过保留期”。

## 7.4 判定记录（DecisionRecord v2）

### 7.4.1 每个请求一条

网关处理的每个请求都写一条记录。现在不记录的三类改为写简记录：

| `decision_path` | 含义 | `outcome` | 记录级别 |
|---|---|---|---|
| `unknown_site` | Host 不属于任何站点，返回 404（新增） | `blocked` | 简记录 |
| `body_not_inspectable` | 需判定的请求体超过 48 KiB 或没有 `Content-Length`，返回 413（新增） | `blocked` | 简记录 |
| `bypass` | 命中 `bypass`，直接转发（新增） | `allowed` | 简记录 |
| `no_session` | 没有会话凭证且不是入口 | `blocked` / `would_block` | 判定记录 |
| `fast_allow` | 全部请求值已核验 | `allowed` | 判定记录 |
| `cached_allow` | 缓存时长内同一请求已由 Jev 放行 | `allowed` | 判定记录 |
| `jev_allow` | Jev 通过 | `allowed` | Jev 记录 |
| `jev_deny` | Jev 判越权或攻击 | `blocked` / `would_block` | Jev 记录 |
| `jev_unavailable` | Jev 超时、出错、限额用尽或答 UNKNOWN | `blocked` / `would_block` / `unjudged` | Jev 记录（限额用尽时没有 `state`） |

`413` 和 `404` 与模式无关，观察模式下也拒绝（现有行为，[01.7](01-request-flow.md#17-网关对请求和响应的处理边界)）。源站不可达等转发错误不是新的判定路径：记录照常写，`status` 为网关返回的 502/504，`trace.upstream_error` 写原因。

“简记录”只有请求行、状态码、耗时和命中的规则；“判定记录”另有请求值、核验结果和会话摘要；“Jev 记录”再加 `jev` 交换内容和最近访问。

**“已判定”的范围**：`bypass`（静态资源，常占流量的大半）和 `unknown_site`（公网网关会收到大量扫描器发来的任意 Host，没有站点可归属）不是对某个站点请求的判定。列表、计数和统计默认把它们排除在外，其余路径合称“已判定”（含 `body_not_inspectable`：拒绝本身是一次判定）。这两类记录照常保存、可以查到，API 用 `scope` 参数切换（[7.9.3](#793-请求列表)）。

**记录并非绝对不丢**：发送队列有界，整批写入失败只重试一次，仍失败就丢弃整批（[7.7.4](#774-日志发送)）。网关在队列超过 80% 时先丢弃 `bypass` 简记录并计入 `dropped_bypass`，判定记录只在队列满时才丢；丢失的区间通过心跳上报，控制台如实提示“这段时间的请求可能查不到”，而不是让用户误以为没有发生。

### 7.4.2 顶层字段

`xshield_core::context::log::DecisionRecord` 扩展为下表（新增字段都带 `#[serde(default)]`，旧格式的 JSON 行仍能读入，见 [7.9.9](#799-导入与导出)）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `request_id` | string | 见 7.3.1 |
| `at_millis` | u64 | 请求到达网关的 Unix 毫秒 |
| `site` | string \| null | 站点名；`unknown_site` 为 null（原来是必填字符串） |
| `site_version` | i64 \| null | 判定时网关加载的站点配置版本（新增）；文件模式下是配置文本的哈希 |
| `edge` | string | 网关实例名，取 `HOSTNAME`（Windows 取 `COMPUTERNAME`），缺省 `edge`（新增） |
| `host` | string | `Host` 头，小写，最长 253（新增） |
| `client` | string | 客户端 IP（新增）；保留 7 天，用于按来源排查攻击 |
| `session` | string | 上下文标签：会话键 HMAC 的前 8 字节，16 位十六进制（原来 4 字节）；无上下文为空串 |
| `context` | `session` \| `address` \| null | 上下文来自会话凭证，还是未登录入口请求的客户端地址（新增） |
| `method` / `path` | string | 请求方法、路径（不含查询） |
| `query` | string \| null | 查询串，按 [7.4.4](#744-脱敏与上限) 脱敏，最长 2 KiB（新增） |
| `status` | u16 \| null | 返回给客户端的状态码 |
| `decision_path` / `outcome` | enum | 见 7.4.1 |
| `trace` | object | 见 7.4.3（新增） |
| `jev` | object \| null | 见 [7.5](#75-jev-调用上下文的保存) |

### 7.4.3 trace 结构

```json
{
  "v": 1,
  "entry": null,
  "bypass": null,
  "refused": null,
  "values_truncated": false,
  "values": [
    { "at": "path[0]", "key": null, "value": "api", "kind": "route", "inert": true,
      "seen": false, "verified": false, "sources": [] },
    { "at": "path[1]", "key": null, "value": "patients", "kind": "route", "inert": true,
      "seen": false, "verified": false, "sources": [] },
    { "at": "path[2]", "key": null, "value": "8", "kind": "reference", "inert": false,
      "seen": true, "verified": false,
      "sources": [ { "field": "age", "request": "GET /api/patients/7",
                     "request_id": "req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4", "at_millis": 1793538874154 } ] }
  ],
  "session": {
    "age_seconds": 640,
    "known_values": 318,
    "entries_passed": [ { "path": "/login", "at_millis": 1793538346000, "request_id": "req_…" } ],
    "recent": [ { "method": "GET", "path": "/api/patients/7", "status": 200,
                  "request_id": "req_…", "at_millis": 1793538874154 } ]
  },
  "cache_source": null,
  "timing": { "total_ms": 524, "judge_ms": 515, "origin_ms": null },
  "response": {
    "content_type": null, "bytes": 0,
    "observed": "skipped", "skip": "not_forwarded",
    "values": 0, "new_values": 0, "fields": [],
    "issued_session": null, "entry_passed": false, "after_would_block": false
  },
  "upstream_error": null
}
```

网关写出 trace 时省略下面这些键，读取方（控制台、导出）把缺省的键当作 null、false 或空列表处理。上面的示例为了看清结构把所有键都列了出来，所以和实际输出不完全一致。

- 顶层 `entry`、`bypass`、`refused`、`cache_source`、`session`、`response`、`upstream_error` 为 null 时省略；`values_truncated`、`trimmed` 为 false 时省略；`values` 为空时省略。
- `values[].len` 为空、`values[].clipped` 为 false 时省略；`response.skip` 为空时省略；`session.entries_passed`、`session.recent` 为空时省略。
- 其余的 null 照常写出，例如 `values[].key`、`sources[].request_id`、`timing.origin_ms`、`response.content_type`。

| 字段 | 说明 |
|---|---|
| `entry` / `bypass` | 命中的入口、绕过模式原文（不止是布尔值，界面要显示“命中 `/share/*`”） |
| `refused` | 网关自己回的错误码：`unauthenticated`、`forbidden`、`body_not_inspectable`、`unknown_site` |
| `values[]` | 请求里拆出的**全部**值，按提取顺序，含惰性值（`inert: true`）；最多 200 个（`REQUEST_VALUES_MAX`） |
| `values[].kind` | `reference` / `route` / `input`，与 `state` 里的 `kind` 同一函数（`values::value_kind`） |
| `values[].seen` / `verified` | 会话里见过这个值 / 网关已按同类对象核验（快速放行的依据） |
| `values[].sources[]` | 最多 3 个来源，顺序与 `state` 里的 `seen_as` 相同（最相关的在前，[7.5.2](#752-state-与追溯信息的对齐)）；`request_id`、`at_millis` 正常情况下都有（上下文随网关重启清空，[7.3.2](#732-追溯链路)），只有导入的旧格式记录和测试数据可能为 null；同一 `(field, request)` 再次出现时保留最早的那次（[7.7.1](#771-会话上下文增加请求-id)） |
| `values_truncated` | 请求体未结构化、超过 64 KiB 解析上限或值数到上限（即 `ExtractedRequest::truncated`） |
| `session` | 判定记录才有。`recent` 和 `entries_passed` 只在 Jev 记录里写（与 `state` 对应，最多 10 条和 16 条）；`known_values` 是会话已见值数量 |
| `cache_source` | 缓存放行复用的那次 Jev 放行的请求 ID |
| `timing` | `total_ms` 从收到请求头到响应写完；`judge_ms` 是判定耗时（含 Jev）；`origin_ms` 从发出上游请求到收到响应头 |
| `response.observed` | `json` / `html` / `skipped`；`skip` 给原因：`status`（非 2xx）、`content_type`、`compressed`、`too_large`（超过 1 MiB，[01.2](01-request-flow.md#12-会话与上下文) 要求日志注明）、`head`、`not_forwarded` |
| `response.values` / `new_values` | 从响应里取出的值数、其中会话原先没有的值数 |
| `response.fields` | 出现次数最多的 12 个字段名及次数，形如 `[{ "field": "id", "count": 3 }]`；不存值本身 |
| `response.issued_session` | 响应下发了新凭证（登录）时，新会话的标签 |
| `response.entry_passed` | 这个响应让会话第一次经过某个入口 |
| `response.after_would_block` | 这次请求是“本应拦截”但在观察模式下被转发，它的响应仍被学进上下文（[7.4.6](#746-附带发现观察模式下本应拦截请求的响应仍进入上下文)） |

### 7.4.4 脱敏与上限

- 值和查询串的脱敏与 `state` 用同一函数：字段名或位置含内置 9 个词（`password`、`passwd`、`pwd`、`secret`、`token`、`otp`、`credential`、`authorization`、`cvv`）或站点 `advanced.secret_fields` 中的词的值，以及含会话凭证原文的值，写成 `<redacted>`，另记 `len`。查询串按 `k=v` 逐对脱敏后重新拼接。
- 单个值最长保存 256 个字符，超出截断并标 `clipped: true`、原长 `len`。
- `trace` 序列化后不超过 16 KiB；超出时依次去掉惰性值、把来源减到 1 个、值截到 64 字符，并标 `trimmed: true`。
- 响应只存字段名和计数，不存响应里的值；请求头只存 `Host`。

### 7.4.5 简记录示例

```json
{
  "request_id": "req_01a197413fd073fa8b85a3cd89d3009b",
  "at_millis": 1793538998224, "site": "juice", "site_version": 7, "edge": "edge-1",
  "host": "juice.example.com", "client": "192.168.1.20", "session": "", "context": null,
  "method": "GET", "path": "/assets/public/images/products/apple_juice.jpg", "query": null,
  "status": 200, "decision_path": "bypass", "outcome": "allowed", "jev": null,
  "trace": { "v": 1, "bypass": "/assets/*", "timing": { "total_ms": 6, "judge_ms": 0, "origin_ms": 5 } }
}
```

### 7.4.6 附带发现：观察模式下本应拦截请求的响应仍进入上下文

`Judge::observe` 对所有转发出去的 2xx 响应学习，不看这次请求的结论。观察模式下“本应拦截”的请求照常转发，它的响应也被学进会话，之后引用这些值的请求会被快速放行；切到拦截模式后，前一个请求被拦，后面这些请求也会因为值未见而交给 Jev。因此观察期的“本应拦截”数量可能少于拦截模式下的真实拦截数。

这不是控制台能修的问题，记录在这里交给判定线程决定（例如本应拦截的响应不学习）。控制台的做法：用 `trace.response.after_would_block` 标出这种学习，模式切换前的就绪检查里单列“由本应拦截请求学到的值被后续请求引用 N 次”。

## 7.5 Jev 调用上下文的保存

### 7.5.1 JevRecord v2

| 字段 | 说明 |
|---|---|
| `state` | 发出的 `state` 原文（已脱敏，≤ 8 KiB），与现有字段相同。**以字符串保存**（紧凑 JSON，就是发出的字节），不要改成嵌套对象：`jsonb` 会重排键、丢掉空白，无法逐字节还原。格式化只在控制台展示时做，所以“原文”视图和“复制 state”拿到的是网关实际发出的内容 |
| `prompt` | 指令版本 ID：`jq_` 加 `questions` JSON 的 SHA-256 前 16 位十六进制；全文在 `jev_prompts` 表（新增）。完整请求体由 `model`、`state`、`questions` 三者拼回，是“还原值”：键的顺序可能与实际发出的不同，字节数以 `request_bytes` 为准 |
| `model` / `route` | 线上模型名（`typesafe-ai/jev`、`jev-1.13.0` 或 `XSHIELD_JEV_MODEL`）；线路 `gateway` / `direct` / `custom`（新增） |
| `timeout_ms` | 这次调用实际使用的超时：站点 `advanced.jev_timeout_ms`，没写时取 `XSHIELD_JEV_TIMEOUT_MS`（新增） |
| `trim` | `state` 裁剪级别 0–4（新增，见 7.5.3） |
| `request_bytes` | 完整请求体字节数（新增） |
| `http_status` | 模型服务的 HTTP 状态；超时和连接失败为 null（新增） |
| `response` | 模型服务原始响应体，按 UTF-8 宽松解码，最多 8 KiB（新增）；超时和连接失败为 null |
| `usage` | 响应里的 `usage` 对象原样保存（新增），用于估算费用 |
| `access` / `attack` | 两个问题的完整概率，与现有字段相同 |
| `conclusion` | `allow` / `deny` / `unknown`（新增，[02.3](02-jev.md#23-结论规则) 的结论） |
| `millis` | 往返耗时，与现有字段相同 |
| `failure` | 失败码，与现有字段相同，见 7.5.4 |

`decision_log` 另有 `jev_access`、`jev_attack`（各自概率最高的选项）、`jev_confidence`（两个问题最高概率中较小的一个）、`jev_ms`、`jev_failure` 五列，供列表筛选和统计，避免查询时解析 JSON。

### 7.5.2 state 与追溯信息的对齐

`state` 不带请求 ID，也不因控制台改变（Jev 不需要 ID，多写只增加 token）。控制台展示时把 `state` 和 `trace` 对齐：

- `state.request.values` 由非惰性值按提取顺序构成，所以 `state.request.values[i]` 对应 `trace.values` 中第 i 个 `inert == false` 的元素。不用 `at` 对齐，因为数组元素会共享同一个 `at`（`body.ids[]`）。
- `state.request.values[i].seen_as[j]` 对应该值 `sources[j]`：`seen_as` 是 `sources` 的前缀，裁剪级别 3、4 只发 1 个来源，所以可以更短，不要求等长。
- `state.recent` 是最近访问的最后 N 条（N 由裁剪级别决定），对应 `trace.session.recent` 的最后 N 条。
- `state.session.entries_passed[k]` 对应 `trace.session.entries_passed[k]`。
- `state.entry` 只有 `matched`（布尔值），没有规则原文：命中的是哪条入口规则只在 `trace.entry`，结构化视图的“入口”一行以 `trace.entry` 为准。`state` 里的值也没有 `key` 字段，字段名取 `trace.values[].key`。
- `seen_as` 是该值全部来源按相关度排序（`Seen::ranked`）后反过来取前 N 个，最相关的在前，N 由裁剪级别决定（[7.5.3](#753-裁剪级别)）。`trace.values[].sources` 必须用同一个函数、同一个顺序生成，对齐才是按下标而不是按内容猜。

**对不上时不猜**：`align.ts` 先校验非惰性值个数等于 `state.request.values` 长度，且每个下标上的 `at` 相同；每个值的 `seen_as` 不比 `sources` 长（`trace.trimmed` 为真时来源可能已被减到 1 个，只比较公共前缀，多出的 `seen_as` 条目没有来源链接），且 `seen_as[j]` 逐字等于 `` `${sources[j].field} @ ${sources[j].request}` ``（网关生成 `seen_as` 的格式，`engine.rs`）——只比个数会放过次序互换，要求等长又会让裁剪过的正常记录失去来源链接；`recent`、`entries_passed` 的条数不超过 `trace` 里的条数。任何一项不成立就返回 `aligned: false`，结构化视图只按 `state` 渲染，并在顶部提示“追溯信息与发出的 state 对不上，来源链接不可用”，原文、JSON、指令视图不受影响。旧格式记录（`trace.v == 0`）同样走这条路径。

实现要求：`build_state` 的输入和输出不变，新增一个单元测试固定一组输入的 `state` 字节（黄金样本），并断言 `state` 不含 `req_`；另一个测试用同一组输入生成 `trace`，断言按上面的规则能对齐，并覆盖脱敏值、被截断的长值、数组元素共享同一个 `at` 三种情形。

### 7.5.3 裁剪级别

`build_state` 依次尝试以下组合，取第一个不超过 8 KiB 的（现有代码 `state.rs`）：

| `trim` | 最近访问条数 | 每个值的来源数 | 单值最长字符 |
|---|---|---|---|
| 0 | 10 | 3 | 512 |
| 1 | 3 | 3 | 512 |
| 2 | 0 | 3 | 512 |
| 3 | 0 | 1 | 512 |
| 4 | 0 | 1 | 128 |

`build_state` 改为同时返回级别。控制台在 Jev 视图顶部写明“为满足 8 KiB 上限，最近访问从 10 条减到 3 条”这类说明。

### 7.5.4 失败码

| 失败码 | 含义 | 有无 `state` |
|---|---|---|
| `JEV_TIMEOUT` | 超过 `timeout_ms`（站点值或 `XSHIELD_JEV_TIMEOUT_MS`，默认 2000 ms） | 有 |
| `JEV_RATE_LIMITED` | 模型服务返回 429 | 有 |
| `JEV_TRANSPORT` | 连接、TLS 或协议错误 | 有 |
| `JEV_HTTP_ERROR` | 其他非 200 状态，状态码在 `http_status` | 有 |
| `JEV_RESPONSE_TOO_LARGE` | 响应超过 64 KiB | 有 |
| `JEV_RESPONSE_INVALID` | 响应结构不符合约定，原文在 `response` | 有 |
| `JEV_UNKNOWN` | 最高项是 UNKNOWN 或两项并列 | 有 |
| `JEV_STATE_TOO_LARGE` | 裁剪到级别 4 仍超过 8 KiB | 无 |
| `JEV_CALL_LIMIT` | 会话或地址每分钟调用次数用完（默认 60 / 30，站点可调） | 无 |

### 7.5.5 指令版本表

网关启动时计算 `questions` JSON（两个问题的 `instructions` 和 `criteria`，代码常量）和它的 ID，执行 `INSERT INTO jev_prompts … ON CONFLICT (id) DO NOTHING`。控制台按 `jev.prompt` 读出指令全文，与 `model` 和 `state` 拼回完整请求体。同一份指令无论调用多少次只存一行；修改提示词（例如 [04.5](04-deployment-testing.md#45-首次真实-jev-调用记录) 的几轮修复）会产生新 ID，旧记录仍能还原当时的指令。

## 7.6 站点级判定参数（advanced）

### 7.6.1 字段

管理员 2026-11-01 决定：站点可以覆盖下列判定参数。`advanced` 段和其中每一项都可省略，省略的项取代码默认值，判定行为与现在相同。

```yaml
advanced:
  jev_timeout_ms: 3000           # 单次 Jev 调用超时
  session_calls_per_minute: 60   # 每个会话每分钟最多调用 Jev 次数
  address_calls_per_minute: 30   # 无会话请求按客户端地址每分钟最多次数
  allow_cache_minutes: 10        # Jev 放行结论复用时长，0 表示不缓存
  secret_fields: [ssn, idcard]   # 追加的脱敏词
  synonyms:                      # 字段名与展示它的接口指同一类对象
    - [payment, card]
  field_kinds:                   # 字段名或参数名装的是哪类对象，覆盖按名字的推断
    - {field: doc_id, kind: doctor, in: ["/api/appointments*"]}
```

| 字段 | 默认 | 取值 | 作用 | 调整的代价 |
|---|---|---|---|---|
| `jev_timeout_ms` | `XSHIELD_JEV_TIMEOUT_MS`，未设时 2000 | 100–30000 | 本站点每次 Jev 调用的超时 | 调大：慢链路下少按 `on_jev_unavailable` 处理，但要判定的请求最多多等这么久；调小：反之 |
| `session_calls_per_minute` | 60 | 1–600 | 每个会话每分钟 Jev 调用上限，超出按 `on_jev_unavailable` 处理 | 调大：单个会话能消耗的模型费用上限提高 |
| `address_calls_per_minute` | 30 | 1–600 | 没有会话的请求（登录、注册等入口）按客户端地址的同一上限 | NAT 或代理后多个用户共用一个地址时需要调大；调大后未登录请求能消耗的额度也提高 |
| `allow_cache_minutes` | 10 | 0–60 | 同一会话、同一请求被 Jev 放行后直接复用结论的时长 | 调大：调用次数减少；修改配置或提示词后，旧的放行结论仍复用到期。已缓存的条目按写入时的时长到期 |
| `secret_fields` | 空 | 最多 32 个词，每个 3–32 个字符，小写字母、数字、`_`、`-` | 追加在内置 9 个脱敏词之后（不能删除内置词），按“字段名或位置包含该词”匹配；命中的值发给 Jev 和写日志时都写成 `<redacted>` | 被脱敏的值 Jev 只看到长度，无法判断它是否越权。只加纯输入字段（身份证号、银行卡号），不要加对象引用字段；最短 3 个字符就是为了挡住 `id`、`no` 这类会把所有 ID 都脱敏的词 |
| `synonyms` | 空 | 最多 32 组，每组两个不同的词，每个 3–24 个小写字母 | 追加在内置的 `payment ↔ card` 之后。字段名里的词与展示该值的接口名属于同一类对象时，短值（少于 8 个字符）也算已核验，来源排序也按同类处理 | 加错会让短 ID 跨对象类型被当成已核验，放宽越权判定。只加确实指同一对象的词，例如字段 `paymentId` 的值来自 `/api/Cards` |
| `field_kinds` | 空 | 最多 32 条。`field` 1–32 个字符（字母、数字、`_`、`-`；大小写和分隔符不计）；`kind` 3–24 个小写字母（去掉结尾 `s` 后仍至少 3 个字母，且不是 `api`、`rest`、`data`、`value` 等通用词）；`in` 可省略（全站），否则最多 8 个路径模式，空列表无效 | 声明某个字段名或参数名装的对象类别。只作用于字段名和参数名，不作用于路径词；单向；命中的字段只算声明的类别，不再同时算名字里的词。展示侧按返回该值的请求匹配 `in`，使用侧按当前请求匹配 `in` | 声明错类别会放宽或收紧判定。同一字段名在重叠路径上不能声明两个类别（保存时报错）。站点里同名字段指两种对象时必须写 `in`，否则两处都按声明的同一类别判定 |

词的比较方式与现有代码一致：字段名、路径按驼峰和非字母拆词，转小写，去掉复数 `s`（`/api/Cards` 得到 `card`）。

`field_kinds` 与 `synonyms` 不同：`synonyms` 是双向、全站的词对，`field_kinds` 只说明一个字段名装的是哪类对象，例如 `doc_id` 装的是医生，不说明 `doc` 和 `doctor` 是一回事。所以 `GET /docs/2` 这类文档路径仍按路径词 `doc` 判定，不会因为医生 id 在别处出现而放行。字段名比较时忽略大小写、`_` 和 `-`（`doc_id`、`docId`、`DocID` 是同一个）；裸 `id` 按父对象名比较（`doc.id` 看 `doc`）。

其余代码默认值（上下文容量 5000 个值、来源 6 个、会话 24 小时过期、长值 8 个字符、请求体 48 KiB、响应解析 1 MiB、`state` 8 KiB）仍不做配置：它们影响网关内存或与 Jev 的输入契约，与单个站点的业务无关。控制台只读展示网关上报的实际值（[7.9.8](#798-系统)）；以后确有需要，可以按本节的方式逐项加入 `advanced`。

### 7.6.2 校验

- `SiteSpecDto` 增加 `#[serde(default)] advanced: AdvancedDto`，`AdvancedDto` 带 `deny_unknown_fields`，每项都是 `Option`。
- 新错误码 `ConfigError::Advanced` → `SITE_CONFIG_ADVANCED_INVALID`，覆盖越界数值、非法或过短的词、重复或自身成对的同义词、超过条数上限。与其他错误码一样不回显配置值；控制台本地校验指出具体哪一项（[06.4.9](06-console-ui.md#649-站点详情)）。
- 保存时规范化：词转小写、去重、按字母序排列；同义词每组内按字母序，组间去重。规范化后的配置才计算版本差异，避免只改顺序也产生新版本。

### 7.6.3 判定代码的改动

| 位置 | 改动 |
|---|---|
| `xshield-core` `SiteSpec` | 新增 `advanced()`，返回已校验的 `Advanced`；提供取有效值的方法（传入代码默认值） |
| `xshield-judge` `jev.rs` | `JevPort::ask(body, timeout)` 增加超时参数；`JevClient` 保留环境变量给出的值作为 `default_timeout()` |
| `xshield-judge` `engine.rs` | 调 Jev 时传入站点超时；限流用站点的会话、地址上限；放行缓存按站点时长写入，时长为 0 时不查也不写缓存；`JevRecord.timeout_ms` 记下实际超时 |
| `xshield-judge` `context.rs` | `Seen::is_specific`、`Seen::ranked` 及其内部的 `affinity`、`related` 增加站点同义词参数，与内置 `SYNONYMS` 合并使用；站点的词在加载时按 `kind_words` 的规则去掉结尾的 `s`，否则 `address` 永远匹配不上拆词得到的 `addre`；`cache_allow` 增加时长参数 |
| `xshield-judge` `state.rs` | `StateInput` 增加站点脱敏词；`is_secret_name` 同时检查内置词和站点词；`trace` 的脱敏调用同一函数 |

改动后已有测试不变；新增用例：站点超时生效（假 Jev 延迟介于默认值和站点值之间）、站点限额生效、缓存为 0 时每次都调用 Jev、追加脱敏词出现在 `state` 和 `trace` 中都被替换、站点同义词让短值通过核验而不加同义词时不通过。

### 7.6.4 生效与追溯

- 参数是站点配置的一部分，修改后与其他字段一样产生新版本，网关 5 秒内重新加载；判定记录的 `site_version` 指向当时生效的参数。
- 控制台对每项显示默认值、本站点的值和最近 24 小时的相关证据（Jev 耗时 p95 和超时次数、触发调用上限的次数、缓存放行次数），保存前的影响预估覆盖这些参数（[7.9.10](#7910-影响预估)），调优建议也会推荐参数调整（[7.9.11](#7911-调优建议与就绪检查)）。

## 7.7 网关改动（xshield-judge / xshield-edge / xshield-core）

站点级判定参数的改动见 [7.6.3](#763-判定代码的改动)，本节是追溯相关的改动。

### 7.7.1 会话上下文增加请求 ID

`crates/xshield-judge/src/context.rs`：

| 结构 | 新增字段 |
|---|---|
| `Origin` | `request_id: u128`（0 表示未知）、`at_ms: u64` |
| `Recent` | `request_id: u128`、`at_ms: u64` |
| 经过的入口 | `Vec<String>` 改为 `Vec<EntryPass { path, at_ms, request_id }>` |
| 放行缓存 | `HashMap<Digest16, u64>` 改为 `HashMap<Digest16, CachedAllow { until_ms, source: u128 }>` |

`SessionContext::remember` 返回本次新增的值数。内存影响：每个来源多 24 字节；单会话上限 5000 值 × 6 来源时多约 0.7 MiB，典型会话远小于此。`ContextStore` 的上限、淘汰规则不变。

**来源去重只比较 `(field, request)`**。现在 `Origin` 派生了 `PartialEq`，`remember` 用 `origins.contains(&origin)` 去重；给 `Origin` 加上 `request_id`、`at_ms` 后直接沿用派生，同一个列表接口刷新十次就会因为请求 ID 不同而追加十个来源，6 个名额被同一条说明占满，真正不同的来源被挤掉，`state` 里的 `seen_as` 随之改变，违反“`state` 逐字节不变”。要求：手写 `PartialEq`（或在 `remember` 里显式比较 `field` 和 `request`），重复出现时保留最早那次的 `request_id`，不覆盖。界面把这个 ID 标为“首次学到于”。新增单元测试：同一 `(field, request)` 连续出现 10 次，`origins` 长度为 1 且 `request_id` 是第一次的；`state` 与加字段前的黄金样本相同。

### 7.7.2 Judge 接口

- `RequestFacts` 已有 `request_id`，判定时把它解析为 `u128` 用于写入缓存来源。
- `Judgement.record` 对绕过路径不再是 `None`，而是简记录；判定记录填写 `trace.values`、`trace.session`、`trace.cache_source`、`trace.entry`、`trace.bypass`。
- `Observation` 增加 `request_id` 和这次请求的结论；`Judge::observe` 返回 `ObservationSummary`（7.4.3 的 `response` 对象），代理把它写进同一请求的记录。
- `build_state` 返回 `(String, trim)`；`request_body` 改为使用启动时构建一次的 `questions`，并暴露 `prompt_id()`。
- 判定层在 `JEV_RESPONSE_INVALID`、`JEV_HTTP_ERROR` 时保存响应体前 8 KiB 和状态码。

### 7.7.3 代理

`crates/xshield-edge/src/proxy.rs`：

- `request_filter` 开始时记下时间；未知站点（404）和请求体不可判定（413）各写一条简记录，`site_version` 取匹配到的站点。
- `upstream_request_filter` 记下上游开始时间，`response_filter` 计算 `origin_ms`。
- `response_body_filter` 结束时调用 `observe`，把摘要合入 `ctx.record.trace.response`；未转发的请求写 `skip: "not_forwarded"`。
- `logging` 写 `status`、`total_ms`；`error` 参数非空时按 Pingora 错误类型写 `upstream_error`（`connect_refused`、`connect_timeout`、`read_timeout`、`tls`、`other`）。
- `EdgeSite` 保存配置版本和加载时间（进程把这个版本装进路由表的时刻，Unix 毫秒），`SiteLoader` 记录每个站点的加载结果（成功版本及其加载时间、校验失败的错误码、因 Host 冲突落选），供心跳上报。同一版本再次读到时沿用原来的加载时间，只有版本变化才重新计时；校验失败时仍在服务的旧版本保留它的加载时间。

### 7.7.4 日志发送

`crates/xshield-edge/src/sink.rs`：

- 后台任务攒满 500 条或等满 250 ms 后一次多行 `INSERT`（`sqlx::QueryBuilder::push_values`），替换现在的逐行插入。整批失败时 500 ms 后重试一次（数据库瞬断、主从切换），仍失败才丢弃整批并计入 `write_errors`，不再重试，以免队列堵住。
- **队列压力下先丢简记录**。`QUEUE_CAPACITY` 仍是 10,000。`send` 在队列已用超过 80% 时，对 `decision_path == bypass` 的记录不入队，只给 `dropped_bypass` 加一；其他记录照常入队，队列满时才丢弃并给 `dropped` 加一。取舍：绕过记录量大、价值低（静态资源），判定记录（含拦截、Jev 调用）是追溯的核心，必须尽量保住。
- 计数器：`written`、`dropped`（队列满丢弃）、`dropped_bypass`（压力下主动丢弃的绕过记录）、`write_errors`（写入失败丢失的行数），经心跳上报。
- **缺口历史**。心跳只有累计计数，看不出“什么时候丢的”。sink 按分钟累计丢失数（只保留最近 24 小时、有丢失的分钟），心跳把连续的分钟合并成区间 `gaps: [{from_ms, to_ms, dropped, dropped_bypass, write_errors}]`，最多 50 个最新的。控制台列表上方的“日志缺口”提示、系统页的缺口列表都读它。网关重启后历史清空，累计计数也重新开始，这是已知限制。
- 文件模式（`XSHIELD_EDGE_SITES_FILE`）仍把完整记录按 JSON 行写到标准输出，内容与数据库行一致，可以导入控制台（[7.9.9](#799-导入与导出)）。

### 7.7.5 心跳

`crates/xshield-edge/src/status.rs`（新增模块）每 10 秒、以及站点表变化后立即 upsert `edge_status` 一行：实例名、启动时间、构建版本、监听端口、是否 TLS、每个站点加载的版本、加载时间（`loaded_at_millis`，Unix 毫秒；没有版本的站点不带这个键）和错误、会话数、队列长度、四个计数器（`written`、`dropped`、`dropped_bypass`、`write_errors`）、缺口历史 `gaps`（[7.7.4](#774-日志发送)）、Jev 线路配置（线路、端点主机名、模型、默认超时、指令 ID，不含密钥）和运行参数（[7.9.8](#798-系统)）。文件模式下不写。

控制面认为一个实例“在线”的条件是 `seen_at` 在 30 秒内；超过 24 小时没有心跳的行被清理（[7.8.2](#782-分区与保留)）。多个实例各写一行，控制台按实例分别显示，不求平均。

### 7.7.6 测试要求

- judge：`state` 黄金样本不变；`trace.values` 与 `state.request.values` 能按 7.5.2 对齐；来源请求 ID、缓存来源、经过入口的 ID 正确；脱敏覆盖 `trace.values` 和 `query`；16 KiB 上限的裁剪顺序；7.6.3 的站点参数用例；来源去重只比较 `(field, request)`（7.7.1）。
- edge（`tests/scenarios.rs`）：绕过、413、未知站点各产生一条记录；A1 的快速放行记录里值 `7` 的来源 ID 等于列表请求的 ID；登录请求的 `issued_session` 等于后续请求的 `session`；源站关闭时记录 502 和 `upstream_error`。
- edge（`sink.rs` 单元测试）：队列用到 80% 以上后 `bypass` 记录被丢弃并只增加 `dropped_bypass`，判定记录照常入队；队列满时增加 `dropped`；缺口按分钟合并成区间，最多 50 个。
- edge（`tests/postgres.rs`）：批量写入、整批失败后重试一次、心跳 upsert、指令登记；目标日期没有分区时插入失败并计入 `write_errors`（没有默认分区兜底，7.8.2）。

## 7.8 数据库

### 7.8.1 表

一份新的基线迁移 `migrations/0001_v4_baseline.sql`，取代 PR #73 中的同名文件和全部 v3 迁移（产品未上线，[05.2](05-v3-removal.md#52-代码模块去留)）：

```sql
CREATE TABLE site_configs (
    name        text PRIMARY KEY,
    spec        jsonb NOT NULL,              -- 含可选的 advanced 段
    version     bigint NOT NULL,             -- 等于该站点 site_config_history 的最大版本
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE site_config_history (
    site        text NOT NULL,
    version     bigint NOT NULL,             -- 每个站点从 1 递增；删除后重建继续递增
    spec        jsonb,                       -- 修改后的全文；删除时为 NULL
    change      text NOT NULL,               -- create | update | rollback | delete | import
    rollback_of bigint,                      -- change = rollback 时恢复的版本
    note        text,                        -- 可选备注，最长 500 字符
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site, version)
);

CREATE TABLE decision_log (
    id             bigint GENERATED ALWAYS AS IDENTITY,
    at_millis      bigint NOT NULL,
    request_id     text NOT NULL,
    site           text,
    site_version   bigint,
    edge           text NOT NULL,
    host           text NOT NULL,
    client         text NOT NULL,
    session        text NOT NULL DEFAULT '',
    context        text,
    method         text NOT NULL,
    path           text NOT NULL,
    query          text,
    status         smallint,
    decision_path  text NOT NULL,
    outcome        text NOT NULL,
    total_ms       integer,
    jev_ms         integer,
    jev_access     text,
    jev_attack     text,
    jev_confidence real,
    jev_failure    text,
    trace          jsonb NOT NULL,
    jev            jsonb,
    PRIMARY KEY (at_millis, id)
) PARTITION BY RANGE (at_millis);

-- 故意不建默认分区：已在 PostgreSQL 16 上验证，默认分区里一旦有某天范围内的行，
-- 就无法再创建那一天的分区（"updated partition constraint for default partition
-- would be violated by some row"），分区维护会从此卡死。没有对应分区时插入直接失败，
-- 由网关计入 write_errors 并在控制台显示缺口，比悄悄堆进默认分区更容易发现和修复。

CREATE INDEX decision_log_request_idx ON decision_log (request_id);
CREATE INDEX decision_log_site_idx    ON decision_log (site, at_millis DESC);
CREATE INDEX decision_log_session_idx ON decision_log (session, at_millis) WHERE session <> '';
CREATE INDEX decision_log_path_idx    ON decision_log (site, path text_pattern_ops, at_millis DESC);
CREATE INDEX decision_log_attention_idx ON decision_log (at_millis DESC)
    WHERE outcome IN ('blocked', 'would_block', 'unjudged');
CREATE INDEX decision_log_jev_idx     ON decision_log (at_millis DESC) WHERE jev IS NOT NULL;

CREATE TABLE edge_status (
    edge         text PRIMARY KEY,
    started_at   timestamptz NOT NULL,
    seen_at      timestamptz NOT NULL,
    build        text NOT NULL,
    listen       text NOT NULL,
    tls          boolean NOT NULL,
    sites        jsonb NOT NULL,             -- {"emr":{"version":12},"bad":{"error":"SITE_CONFIG_ORIGIN_INVALID"}}
    sessions     integer NOT NULL,
    queue        integer NOT NULL,
    written      bigint NOT NULL,
    dropped      bigint NOT NULL,            -- 队列满丢弃
    dropped_bypass bigint NOT NULL,          -- 队列压力下主动丢弃的绕过简记录（7.7.4）
    write_errors bigint NOT NULL,
    gaps         jsonb NOT NULL,             -- [{"from_ms":…,"to_ms":…,"dropped":37,"dropped_bypass":0,"write_errors":0}]，最近 24 小时
    jev          jsonb NOT NULL,
    params       jsonb NOT NULL
);

CREATE TABLE jev_prompts (
    id          text PRIMARY KEY,
    questions   jsonb NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now()
);
```

与 PR #73 草稿的差异：`site_config_history` 从“修改前 / 修改后”改为“版本号 + 全文 + 变更类型 + 备注”；`decision_log` 加列、分区；新增 `edge_status`、`jev_prompts`。网关与控制面之间的表契约以本节为准，`crates/xshield-edge/tests/postgres.rs` 的建表语句随之更新。

### 7.8.2 分区与保留

- 按 UTC 自然日分区，分区名 `decision_log_pYYYYMMDD`，范围 `[当日 00:00, 次日 00:00)` 的毫秒值。
- 控制面启动时和之后每小时：确保从 7 天前（保留窗口的起点）到 7 天后的分区都存在（`CREATE TABLE IF NOT EXISTS … PARTITION OF … FOR VALUES FROM … TO …`）；删除上界早于“现在 − 7 天”的分区（先 `DETACH PARTITION … CONCURRENTLY` 再 `DROP TABLE`，不长时间锁父表）。
- **往回补齐到保留窗口的起点，是为了导入**：首次部署控制面之后，网关文件模式留下的、仍在保留期内的较早记录（[7.9.9](#799-导入与导出)）也要有分区可写；空分区几乎没有成本。早于 `now − 7 天` 的日期不建分区，对应的记录不入库。
- **提前 7 天建分区，是因为没有默认分区兜底**：控制面停机期间网关照常写入，提前量就是控制面最长能停机的时间；超过它网关的插入会失败，控制台显示日志缺口（[7.7.4](#774-日志发送)）。系统页在“今天没有分区”或“未来分区不足 2 天”时告警，`GET /api/system` 返回每个分区的范围。
- 时钟严重偏离的行（`at_millis` 落在任何分区之外）无处可写，插入失败并计入 `write_errors`，不为它们留默认分区。
- 保留期 7 天是代码默认值（[03.4](03-admin-config-audit.md#34-判定日志)），不做配置。
- `site_config_history`、`jev_prompts` 不清理；`edge_status` 中 24 小时没有心跳的实例行删除。
- 测试要求（`xshield-postgres`，空库）：分区维护跑完后，分区覆盖 `now − 7 天` 到 `now + 7 天`；再跑一次不报错（幂等）；导入一条 5 天前的文件模式记录成功，导入一条 9 天前的记录计入 `out_of_range` 而不是出错。

### 7.8.3 查询模式

| 查询 | 用到的索引 |
|---|---|
| 按请求 ID 打开详情 | 解出时间 `t` → `at_millis BETWEEN t ± 60 秒` 加 `request_id = $1`（[7.3.1](#731-请求标识)）→ 一两个分区的 `decision_log_request_idx` |
| 列表（站点 + 时间窗 + 结论 / 判定路径 / 方法 / 状态） | `decision_log_site_idx`，其余条件在扫描中过滤；没有站点条件时走主键 `(at_millis, id)` 的范围扫描 |
| 路径前缀或精确路径 | `decision_log_path_idx`（`path LIKE '/rest/%'`，`%`、`_` 需转义） |
| 会话时间线 | `decision_log_session_idx`，SQL 里必须逐字写 `AND session <> ''` |
| 需要关注的记录（拦截、本应拦截、未经判定） | `decision_log_attention_idx`，SQL 里必须逐字写 `AND outcome IN ('blocked','would_block','unjudged')` |
| Jev 调用列表与统计 | `decision_log_jev_idx`，SQL 里必须逐字写 `AND jev IS NOT NULL` |
| 快捷筛选计数 | 一次扫描、用 `count(*) FILTER (WHERE …)` 同时算出全部标签，不要每个标签一条查询 |
| 实时模式 | 主键范围扫描：`at_millis >= 已收到的最新值 − 60 秒`（[7.9.3](#793-请求列表)） |

列表按 `(at_millis, id)` 倒序做游标分页，`next_cursor` 是最后一行的 `at_millis` 和 `id`。

**部分索引的使用条件**。三个部分索引（会话、需要关注、Jev）只有在查询里出现与索引谓词逐字相同的条件时才会被用上。用参数绑定表达同样意思（`outcome = ANY($1)`）时，PostgreSQL 在泛型计划里证明不了谓词成立，会退回主键索引加过滤；sqlx 的预备语句执行几次后就可能切到泛型计划，平时用小数据量看不出来。已在 PostgreSQL 16 上验证过这一点。所以控制面对这三类查询拼接字面条件，其余值才用参数；`tests/postgres.rs` 对三类查询各设一次 `plan_cache_mode = force_generic_plan` 后 `EXPLAIN`，断言用到了对应索引。

**实时模式不用 `id` 做增量游标**。`id` 在 `INSERT` 时取号，提交顺序不一定等于取号顺序：多个网关实例并发批量写入时，取号小的批次可能后提交，`id > 上次最大 id` 会永远漏掉它们；记录又是在响应结束后才写入，慢响应的行出现得比它的 `at_millis` 晚得多。做法是按 `at_millis` 回看 60 秒重新拉取，客户端按 `request_id` 去重合并。

**数据量与耗时（PostgreSQL 16 实测）**：单日分区 40 万行、合计 120 万行、索引按 7.8.1 建好时，按 ID 打开、24 小时窗口列表首页、路径前缀、Jev 列表、实时模式拉取都不到 1 ms；会话时间线约 50 ms（合成数据里单个会话的行数很多）；快捷筛选计数是整天分区的顺序扫描，约 90 ms。都在 [7.10.7](#7107-性能预算) 的预算之内。更大的数据量见 7.8.4。

### 7.8.4 容量估算

| 行类型 | 单行（含索引）约 |
|---|---|
| 简记录（绕过、413、404） | 0.3 KiB |
| 判定记录（快速放行、缓存放行、无会话） | 1–2 KiB |
| Jev 记录 | 5–10 KiB（`state` ≤ 8 KiB，`response` 通常 < 1 KiB） |

以 Juice Shop 第四轮为参照（548 条判定记录中 66 次 Jev 调用），日均 100 万请求、其中 70% 是静态资源的站点，7 天约 2–4 GiB。统计接口直接扫描时间窗内的行，日均千万级请求以上需要加分钟级汇总表，首版不做。

## 7.9 控制面 API

### 7.9.1 通用约定

- 前缀 `/api`，JSON，`snake_case`。时间字段：`*_millis` 为 Unix 毫秒整数，其余为 RFC 3339 UTC 字符串。
- 除登录、`/api/session`、`/health` 外都要求管理员 Cookie；未登录返回 401 `UNAUTHENTICATED`。写操作要求 `Content-Type: application/json`。
- 错误体 `{"error": "CODE", "field": "entries[2]"?, "current_version": 14?}`，界面按错误码映射中文（[06.6](06-console-ui.md#66-文案与词汇)）。
- 列表：`limit` 默认 100、最大 500；时间窗最长 7 天，缺省最近 24 小时；游标 `cursor` 不透明，响应给 `next_cursor`。
- 统计和建议接口单次最多扫描 200 万行，超出返回 `complete: false` 和已扫描行数，界面如实显示“按前 N 条计算”。
- 写站点配置都带 `expected_version`，不一致返回 409 `VERSION_CONFLICT` 和 `current_version`。
- 错误码沿用 PR #73 的 `UNAUTHENTICATED`、`INVALID_PASSWORD`、`SITE_NOT_FOUND`、`SITE_EXISTS`、`SITE_NAME_MISMATCH`、`ROLLBACK_TARGET_DELETED`、`INTERNAL` 和 `SITE_CONFIG_*`，新增：`LOGIN_RATE_LIMITED`（429）、`REQUEST_NOT_FOUND`（404，取代 `DECISION_NOT_FOUND`）、`SITE_HOST_TAKEN`、`VERSION_CONFLICT`（409）、`INVALID_FILTER`（400，取代 `INVALID_OUTCOME`，`field` 指出哪个参数）、`WINDOW_TOO_LARGE`（400）、`TOO_MANY_IDS`（400）、`BODY_TOO_LARGE`（413）。界面文案见 [06.6.5](06-console-ui.md#665-错误码文案)。

### 7.9.2 端点一览

| 方法与路径 | 用途 |
|---|---|
| `POST /api/login`、`POST /api/logout`、`GET /api/session` | 口令登录（沿用 PR #73：PBKDF2 哈希、HMAC 签名的无状态 Cookie、12 小时）；同一来源 IP 10 分钟内失败 10 次返回 429 |
| `GET /api/requests` | 请求列表（7.9.3） |
| `GET /api/requests/counts` | 同样的筛选条件下一次扫描算出各快捷筛选标签的计数（7.9.3） |
| `GET /api/requests/{request_id}` | 请求详情（7.9.4） |
| `POST /api/requests/lookup` | 批量对照，最多 1000 个 ID（7.9.5） |
| `GET /api/requests/export` | 按筛选导出 JSONL 或 CSV，最多 10 万行，流式输出 |
| `POST /api/import` | 导入网关文件模式输出的 JSON 行（7.9.9） |
| `GET /api/stats/summary`、`GET /api/stats/timeseries` | 总览指标、按判定路径堆叠的时间序列 |
| `GET /api/sessions`、`GET /api/sessions/{label}` | 会话列表（按时间窗聚合）、会话时间线（7.9.6） |
| `GET /api/jev/status`、`GET /api/jev/stats`、`GET /api/jev/prompts/{id}` | Jev 健康、耗时与置信度分布、指令全文（7.9.7） |
| `GET /api/sites`、`POST /api/sites` | 站点列表（含每个实例加载的版本和加载时间、生效进度 `rollout` 和 24 小时计数，7.9.13）、新建 |
| `GET/PUT/DELETE /api/sites/{name}` | 读取（含 `rollout`）、整体替换、删除 |
| `GET /api/sites/{name}/versions`、`GET /api/sites/{name}/versions/{v}` | 版本列表（含自动生成的变更摘要）、某个版本全文 |
| `POST /api/sites/{name}/rollback` | 以某版本全文生成新版本 |
| `POST /api/sites/validate` | 校验一份配置，返回错误码和出错字段 |
| `POST /api/sites/{name}/preview` | 改动的影响预估（7.9.10） |
| `GET /api/sites/{name}/insights` | 调优建议和切换模式的就绪检查（7.9.11） |
| `GET /api/sites/{name}/evidence` | 判定参数旁边显示的证据：最近 24 小时 Jev 耗时 p50/p95/p99、超时次数、调用上限触发次数和每分钟最高调用数、缓存放行次数 |
| `GET /api/status` | 顶栏状态灯和“配置生效”需要的轻量状态，每 15 秒轮询一次（7.9.13） |
| `GET /api/system` | 网关实例、日志存储、运行参数（7.9.8）；只在系统页按需读取，不轮询 |

`GET /api/stats/summary` 的 `spark` 是概览的小趋势线：把时间窗（两端都计入）均分为 12 段，按时间从早到晚排列。`judged`、`blocked`、`would_block`、`unjudged`、`jev_calls` 是每段的计数，12 段相加等于同名的总量。`jev_p95_ms` 是每段 Jev 往返的 95 分位，取整到毫秒；该段没有 Jev 调用时为 0。`spark` 与总量读自同一批行，超过 200 万行时都只计最新的 200 万行。

### 7.9.3 请求列表

`GET /api/requests` 查询参数：`site`、`since_millis`、`until_millis`、`scope`、`outcome`（逗号分隔多选）、`decision_path`（多选）、`method`、`status`（`404` 或 `4xx`）、`path`（精确；以 `*` 结尾为前缀）、`session`、`client`、`request_id`、`jev_access`、`jev_attack`、`jev_failure`、`max_confidence`、`min_ms`、`site_version`、`entry`（`true`/`false`，读 `trace.entry`，没有索引，靠时间窗和其他条件缩小范围）、`cursor`、`limit`。

`scope`：`judged`（缺省）不含 `bypass` 和 `unknown_site`（[7.4.1](#741-每个请求一条)）；`all` 含全部。`decision_path` 明确列出这两类之一时按列出的返回，不受 `scope` 限制。控制台按请求 ID、会话标签、精确路径查找时发 `scope=all`，避免第四轮试跑那种“查不到”（[06.4.3](06-console-ui.md#643-请求追溯)）。

```json
{
  "rows": [
    {
      "id": 91234,
      "request_id": "req_01a19741107477ff9224781077354552",
      "at_millis": 1793538986100,
      "site": "juice", "site_version": 7,
      "method": "GET", "host": "juice.example.com", "path": "/rest/basket/6", "query": null,
      "status": 200, "decision_path": "jev_deny", "outcome": "would_block",
      "session": "7c1e9a40d2b35f61", "context": "session", "client": "192.168.1.20",
      "total_ms": 812,
      "jev": { "access": "DENY", "attack": "BENIGN", "confidence": 0.86, "ms": 512, "failure": null }
    }
  ],
  "next_cursor": "1793538986100.91234"
}
```

列表行不含 `trace` 和 `jev` 全文，只从列读取。

**实时模式**用同一个接口：每 2 秒带上其余筛选条件，`since_millis = 已收到的最新 at_millis − 60000`、`limit=200`，客户端按 `request_id` 去重后插到顶部。回看 60 秒是因为记录在响应结束后才写入（慢响应、Jev 调用、批量写入、多个网关实例各自成批提交），且 `id` 的提交顺序不可靠（[7.8.3](#783-查询模式)）；比 60 秒更晚写入的记录刷新列表后可见。返回满 200 行且最旧一行仍在回看范围内时，界面提示“新请求太多，实时模式只显示最新 200 条，请增加筛选条件”。

**快捷筛选计数**：`GET /api/requests/counts` 接受与列表相同的参数（`cursor`、`limit`、`scope`、`outcome`、`decision_path` 除外：它们就是各标签自己的条件），一次扫描返回：

```json
{ "judged": 6204, "attention": 37, "blocked": 23, "would_block": 14, "unjudged": 0,
  "jev": 412, "no_session": 96, "bypass": 12000, "unknown_site": 0, "complete": true }
```

除 `bypass` 和 `unknown_site` 外，每个数都在“已判定”范围内计算：`attention` 是 `outcome` 为 `blocked`、`would_block`、`unjudged` 之一，`jev` 是有 Jev 记录（含没有发出调用的限额、上下文过大），`no_session` 是 `decision_path = no_session`。

### 7.9.4 请求详情

`GET /api/requests/{request_id}` 返回：

```json
{
  "summary": { "...": "同列表行" },
  "edge": "edge-1",
  "trace": { "...": "7.4.3" },
  "jev": { "...": "7.5.1，没有调用时为 null" },
  "neighbors": { "prev": "req_…", "next": "req_…" },
  "sources": { "req_01a1973f5b2a…": { "method": "GET", "path": "/api/patients/7", "status": 200,
                                       "decision_path": "fast_allow", "at_millis": 1793538874154 } }
}
```

`neighbors` 是同一会话的前一个、后一个请求；`sources` 是 `trace` 里引用到的所有请求 ID 的摘要（值的来源、缓存来源、最近访问、经过的入口、签发的会话），一次返回，界面悬停即可显示，不必逐个请求。已过保留期的 ID 不出现在 `sources` 里，界面显示“已过保留期”。

### 7.9.5 批量对照

`POST /api/requests/lookup`，请求体 `{"ids": ["req_…", …]}`（最多 1000 个，去重保序），返回 `{"rows": [{"request_id": "…", "found": true, "summary": {…}}, …]}`。界面负责从粘贴文本里提取 ID、保留 TSV 的其他列和预期结论（[06.4.3](06-console-ui.md#643-请求追溯)）。

### 7.9.6 会话

- `GET /api/sessions?site=&since_millis=&until_millis=&flag=blocked|jev&limit=`：在时间窗内按 `session` 聚合，返回标签、上下文类型、站点、首末时间、请求数、Jev 调用数、拦截与本应拦截数、签发它的请求 ID（来自 `trace.response.issued_session`），按最后活动倒序，最多 200 个。时间窗缺省 24 小时。
- `GET /api/sessions/{label}?site=&only=judged|jev|blocks&cursor=`：会话摘要和按时间正序的请求行；每行附带 `learned`（`trace.response.new_values`）、`entry_passed`、`issued_session`，供时间线标注。签发这个会话的登录请求发生在会话建立之前，按客户端地址记账（`context = address`），带的不是这个会话标签；时间线把它按 `trace.response.issued_session = {label}` 另外查出，排在第一行。

### 7.9.7 Jev

`GET /api/jev/status`：

```json
{
  "health": "ok",
  "window_minutes": 5,
  "calls": 42, "ok": 42, "failures": {},
  "p50_ms": 540, "p95_ms": 910,
  "last_ok_at": "2026-11-01T13:17:24Z",
  "last_failure": null,
  "config": { "route": "gateway", "endpoint_host": "ai-gateway.vercel.sh",
              "model": "typesafe-ai/jev", "default_timeout_ms": 2000, "prompt": "jq_5c2e81d07a4b9f13" }
}
```

`health` 由最近 5 分钟的 Jev 记录计算：没有调用为 `idle`；失败率 ≥ 20% 或 p95 ≥ 所用超时的 90% 为 `degraded`；失败率 ≥ 80% 或最近 5 次全部失败为 `down`；其余 `ok`。`config` 取在线网关心跳里的值；站点自己的超时见站点详情。

`GET /api/jev/stats?site=&since_millis=&until_millis=` 返回调用数、按结论计数、失败码计数、耗时直方图（100 ms 一档到超时为止）、置信度直方图（0.1 一档）。`GET /api/jev/prompts/{id}` 返回 `questions` 全文和首次出现时间。

### 7.9.8 系统

`GET /api/system` 返回控制面构建版本、PostgreSQL 版本、每个网关实例的心跳内容（含四个计数器和 `gaps` 缺口历史）和是否在线（30 秒内有心跳）、判定日志按分区的范围、行数和大小、最早记录时间、保留期，以及网关上报的运行参数。每个实例的 `sites` 给出站点加载的版本、加载时间（`loaded_at_millis`，Unix 毫秒）和错误码，不带加载时间的旧心跳只是不返回这个键。它比 `/api/status` 重（要统计分区），只在系统页读取。参数分两组：可按站点覆盖的默认值，和不可配置的代码默认值：

```json
{
  "params": {
    "site_overridable": {
      "jev_timeout_ms": 2000, "session_calls_per_minute": 60, "address_calls_per_minute": 30,
      "allow_cache_minutes": 10, "secret_fields": ["authorization", "credential", "cvv", "otp",
      "passwd", "password", "pwd", "secret", "token"], "synonyms": [["card", "payment"]]
    },
    "fixed": {
      "seen_max": 5000, "sources_max": 6, "recent_max": 50, "idle_hours": 24, "sessions_max": 20000,
      "long_value_chars": 8, "state_bytes_max": 8192, "request_body_max": 49152,
      "response_parse_max": 1048576, "request_values_max": 200, "queue_capacity": 10000
    }
  }
}
```

### 7.9.9 导入与导出

- 导出：`GET /api/requests/export?format=jsonl|csv&…`。JSONL 每行一条完整记录，格式与网关文件模式的标准输出相同，已有的离线分析脚本可以直接用；CSV 只含列表列，单元格以 `=`、`+`、`-`、`@` 开头时前置 `'`，防止表格软件执行公式。
- 导入：`POST /api/import`，请求体为 JSON 行（`application/x-ndjson`，最大 100 MiB），逐行解析为 `DecisionRecord`，`edge` 记为 `import`，同一 `request_id` 与时间已存在的跳过。v4 当前格式（没有 `trace`）的行也接受，`trace` 记为 `{"v":0}`，界面标“旧格式记录”。`at_millis` 超出保留窗口（早于 `now − 7 天`，或晚于 `now + 7 天`）的行没有分区可写，不入库，单独计入 `out_of_range`，不算出错。返回导入、跳过、超出保留窗口、出错的行数和前 20 个错误行号。用途：把 Windows 文件模式试跑的 `decisions.jsonl` 放进控制台看。

### 7.9.10 影响预估

`POST /api/sites/{name}/preview`，请求体 `{"spec": {…}}`。控制面读取该站点最近 24 小时的记录，按 `(method, path, 有无会话, 原判定路径)` 分组（最多 5000 组），用新旧两份配置的 `PathPattern` 重新判断每组会走的分支，返回变化：

```json
{
  "window_hours": 24, "rows": 548, "groups": 120, "complete": true,
  "changes": [
    { "kind": "no_session_to_entry", "count": 312,
      "top": [["GET", "/rest/admin/application-configuration", 312]], "sample": "req_…" },
    { "kind": "judged_to_bypass", "count": 892, "would_block": 12,
      "top": [["GET", "/assets/i18n/en.json", 401]], "sample": "req_…" },
    { "kind": "jev_timeout", "count": 3, "detail": { "old_ms": 2000, "new_ms": 1000 } }
  ],
  "patterns": {
    "entries": { "/rest/user/login": 41, "/rest/admin/application-configuration": 312 },
    "bypass":  { "/assets/*": 892 }
  },
  "warnings": ["SESSION_CHANGED"]
}
```

`kind` 取值：

| `kind` | 含义 | 怎么算 |
|---|---|---|
| `no_session_to_entry` / `entry_to_no_session` | 无会话请求改为按入口判定 / 反之 | 按路径重新匹配入口 |
| `judged_to_bypass` / `bypass_to_judged` | 不再判定 / 开始判定 | 按路径重新匹配绕过 |
| `would_block_to_blocked` / `blocked_to_would_block` | 观察切拦截 / 反之 | 按模式 |
| `jev_timeout` | 改超时后：耗时超过新超时、会变成超时的调用数；或原来超时、调大后可能不再超时的调用数 | `jev_ms` 列与 `jev_failure = JEV_TIMEOUT` |
| `call_limit` | 改上限后：会触发上限的调用数和涉及的会话、地址数；或原来触发上限、调大后能调用的次数 | Jev 记录按 `(session, 分钟)` 计数，加上 `JEV_CALL_LIMIT` 行 |
| `cache` | 缓存改为 0 时，原来的缓存放行都会变成 Jev 调用 | `cached_allow` 行数；调大无法预估，只给警告 |
| `secret_fields` | 新增脱敏词会影响的 Jev 调用数和值数；`detail.fields` 列出受影响最多的 10 个字段名及次数，界面据此警告“像标识的字段也会被脱敏” | 解析时间窗内 Jev 记录的 `state`，最多 2 万条 |
| `api_split` | 草稿给路径加上接口名后，按接口区分的请求数，`top` 列出这些路径 | 按 URL 路径匹配草稿路由；路由是新增的，或与现在的 `name_from` 不同即计入。历史记录没有接口名，只按路径计数 |
| `entry_unreachable` | 入口仍登记在 URL 路径上，但请求的逻辑路径多了接口名，入口不再命中的请求数 | 草稿路由覆盖的路径按 `URL/~` 重新匹配入口（`~` 是占位名）：精确入口不再命中，前缀入口仍命中；子路径的接口名未知，不作入口 |
| `cache_by_api` | 放行缓存的键加上接口名后，原来命中缓存放行的请求数 | 被草稿路由按接口区分的路径上，原为 `cached_allow` 的行数；缓存时长为 0 时不计 |

`api_split`、`entry_unreachable` 和 `cache_by_api` 三类总是估算，它们的 `detail` 为 `{ "approximate": true }`，控制台据此说明估算的原因。草稿路由覆盖了有请求的路径（即 `api_split` 有计数）时，`warnings` 还包含 `INTERFACE_UNVERIFIED`：这些请求的接口名历史记录里没有，前缀入口下的无会话请求可能漏报，路由影响都只是估计。

会话凭证、Host 或同义词改变时只给警告（`SESSION_CHANGED`、`HOSTS_CHANGED`、`SYNONYMS_CHANGED`）：会话凭证换了以后现有会话上下文全部作废，Host 换了以后流量路由改变，同义词改变核验结果，都无法从历史记录可靠预估。

### 7.9.11 调优建议与就绪检查

`GET /api/sites/{name}/insights?window_hours=24`：

- `suggestions[]`：每条含 `id`、`kind`、`method`、`path`、`count`、`sample`（示例请求 ID）、`action`（应用后对配置的改动）、`reason`。规则：
  - `entry_candidate`：`no_session` 的路径，不像静态资源。默认推荐精确路径；同一父路径下 3 个以上时另给前缀模式，并标注“前缀入口会放大无会话可达的范围”。
  - `bypass_candidate`：被判定或因无会话被拒的静态资源路径（扩展名 `.js .css .map .png .jpg .jpeg .gif .svg .ico .woff .woff2 .ttf .webp .avif`，或位于 `/static/`、`/assets/`、`/public/`、`/fonts/`、`/images/` 下）。按目录合并为前缀；根目录下同前缀的打包文件（`/chunk-ABC.js`、`/chunk-DEF.js`）合并为 `/chunk-*`。
  - `upload_candidate`：`body_not_inspectable` 的路径，推荐加入绕过并明确提示“绕过后该接口不做越权判定”。
  - `raise_jev_timeout`：本站点 `JEV_TIMEOUT` 占 Jev 调用 1% 以上，或 p95 超过所用超时的 80%。推荐值为 p99 的 1.5 倍向上取整到 500 ms，不超过 30000。
  - `raise_call_limit`：出现 `JEV_CALL_LIMIT`。推荐值为观察到的每分钟最高调用数加 20%，不超过 600；理由里提醒先看触发的是不是未登录页面的轮询，那种情况把接口登记为入口或绕过通常更合适（[04.5.2](04-deployment-testing.md#452-第二轮修复后重跑572-条记录)）。
  - `secret_field_candidate`：Jev 记录的 `state` 里出现未脱敏、字段名明显是敏感个人信息的输入值（含 `ssn`、`idcard`、`id_card`、`passport`、`cardnum`、`card_number`、`cvc`、`iban`、`bankaccount`），推荐加入 `secret_fields`，理由里说明被脱敏的值 Jev 无法判断越权。
  - `hot_would_block`：本应拦截最多的路径模板（数字、十六进制、UUID 段替换为 `{id}`），不给配置动作，只链接到筛选后的请求列表。
  - `route_rule_candidate`：同一路径（没有路由、不是旁路、路径不含 `*`）有 20 个以上请求，且请求头名以 `-` 分隔的最后一个词，或正文字段路径的最后一个键（`body.<键路径>`），是方法词（`method`、`action`、`operation`、`op`、`cmd`、`command`、`rpc`、`func`、`function`、`service`、`api`，不分大小写）时，推荐动作为 `add_route`，即把该来源写成路由规则的 `name_from`。每条路径最多给 3 个来源，按请求数从多到少排序；每个来源都先按保存校验检查，网关会拒绝的不推荐。数字值的正文字段不算接口名。只读这些路径最近 2 万条请求，超过时 `complete` 为 false。入口路径也可能收到这条建议，应用前的影响预估会用 `entry_unreachable` 显示入口是否失效。建议的 `detail` 给出路径占本站点请求的比例（`share`）；推荐的来源里有正文字段时，还给出其中排在最前的一个（`field`，不含 `body.` 前缀）及它的不同取值数（`values`）。控制台的路由规则卡片读取这些数值。
- `readiness`：观察开始时间（最近一次切到观察或创建站点的版本时间）、时间窗内本应拦截按判定路径计数、未处理建议数、Jev 健康、7.4.6 的“由本应拦截请求学到的值被引用次数”。

忽略某条建议只存在浏览器 `localStorage`（按建议 `id`），不进数据库。

### 7.9.12 站点写操作的补充校验

- `name` 与路径参数不一致：400 `SITE_NAME_MISMATCH`。
- `hosts` 中有其他站点已占用的主机名：409 `SITE_HOST_TAKEN`，`field` 指出哪一项。现状是网关按站点名顺序先到先得、落选站点只写 stderr，控制面在保存时就拒绝。
- 请求体最大 64 KiB；`note` 最长 500 字符。
- `SiteSpec::from_json` 的错误码（`SITE_CONFIG_*`，含新增的 `SITE_CONFIG_ADVANCED_INVALID`）原样返回；错误信息不回显配置值（现有约定）。界面另做逐项的本地校验，指出具体哪一行（[06.4.9](06-console-ui.md#649-站点详情)）。

### 7.9.13 状态灯与配置生效

`GET /api/status` 是顶栏两个状态灯和总览“需要处理”共用的轻量接口，只读 `edge_status`、`site_configs` 和最近 5 分钟的 Jev 记录，每 15 秒轮询一次：

```json
{
  "gateway": {
    "light": "warn",
    "edges": { "online": 2, "total": 3 },
    "problems": [
      { "kind": "site_load_failed", "edge": "edge-2", "site": "shop", "error": "SITE_CONFIG_ORIGIN_INVALID" },
      { "kind": "version_behind", "edge": "edge-2", "site": "emr", "expected": 13, "loaded": 12, "saved_at_millis": 1793538900000 },
      { "kind": "edge_offline", "edge": "edge-3", "last_seen_ms": 1793528224000, "loaded": { "emr": 11, "juice": 7 } },
      { "kind": "log_gap", "edge": "edge-1", "from_ms": 1793538120000, "to_ms": 1793538300000,
        "dropped": 37, "dropped_bypass": 0, "write_errors": 0 },
      { "kind": "queue_pressure", "edge": "edge-1", "queue": 8400, "capacity": 10000 },
      { "kind": "partition_missing", "days_ahead": 1 }
    ]
  },
  "jev": { "health": "ok", "calls": 42, "failures": {}, "p50_ms": 540, "p95_ms": 910 }
}
```

`gateway.light` 的规则：

| 值 | 条件 |
|---|---|
| `down`（红） | 没有在线实例：`edges.online` 为 0 |
| `warn`（琥珀） | `problems` 非空 |
| `ok`（绿） | 其余 |

`problems` 的产生规则：`site_load_failed`：任一在线实例的 `sites[x].error` 非空（含 Host 冲突落选，错误码 `SITE_HOST_TAKEN`）；`version_behind`：在线实例加载的版本低于 `site_configs.version`，**且最新版本已保存超过 30 秒**（刚保存后的前 30 秒是正常的生效过程，不告警）；`edge_offline`：24 小时内发过心跳、现在 `seen_at` 超过 30 秒前的实例，带最后心跳时间和它停在的各站点版本（离线实例不参与 `version_behind` 判断，免得同一件事报两次）；`log_gap`：最近 15 分钟内有缺口；`queue_pressure`：发送队列超过容量的 80%；`partition_missing`：今天没有分区或未来分区不足 2 天（[7.8.2](#782-分区与保留)）；`heartbeat_late`：在线实例的心跳间隔超过 15 秒。

“在线”指 `seen_at` 在 30 秒内。`edges.total` 包含 24 小时内发过心跳的全部实例，离线的计入 `total` 而不计入 `online`，所以“2/3 在线”能被看到。`jev` 与 `GET /api/jev/status` 的同名字段相同（[7.9.7](#797-jev)），省略 `config`。

**生效进度**。`GET /api/sites` 的每一行和 `GET /api/sites/{name}` 都带 `rollout`：

```json
"rollout": {
  "version": 13,
  "edges_online": 2, "edges_loaded": 1,
  "edges": [ { "edge": "edge-1", "online": true, "loaded_version": 13, "error": null },
             { "edge": "edge-2", "online": true, "loaded_version": 12, "error": null } ]
}
```

`edges_loaded` 是在线且 `loaded_version == version` 的实例数。界面显示“N/M 个网关已生效”：两者相等且大于 0 时是“● v13 已生效”；`edges_online` 为 0 时是“没有在线的网关，配置已保存，网关上线后加载”；有实例报错时显示该实例的错误码文案。离线实例不拖住进度，只在摘要里另注“edge-3 离线”。保存后界面每秒轮询 `GET /api/sites/{name}`，全部生效或 30 秒后停止。

## 7.10 控制台前端架构

### 7.10.1 技术栈与依赖

沿用现有 `web/console`：React 19、TypeScript、Vite、TanStack Router、TanStack Query、antd 6、dayjs、Biome、Playwright、axe-core。新增：

| 依赖 | 用途 | 许可证 | 加载方式 |
|---|---|---|---|
| `yaml` | 配置的 YAML 与 JSON 互转、报错行列 | ISC | 进入配置编辑时懒加载 |
| `@codemirror/state`、`@codemirror/view`、`@codemirror/lang-yaml`、`@codemirror/lang-json` | YAML/JSON 编辑器：行号、高亮、错误标记 | MIT | 同上 |

图表（堆叠柱、折线、直方图、概率条）用手写 SVG 组件，不引入图表库；JSON 树查看器自己实现（只渲染文本节点，见 7.10.6）。

### 7.10.2 目录结构

```text
web/console/src/
  main.tsx  router.tsx
  api/        client.ts（fetch 封装、错误码）  types.ts（7.9 的类型）  queries.ts（查询键与 hooks）
  app/        Shell.tsx  Sidebar.tsx  Topbar.tsx  CommandPalette.tsx  ShortcutHelp.tsx  theme.ts
  features/
    overview/        OverviewPage.tsx  NeedsAttention.tsx
    requests/        RequestsPage.tsx  RequestTable.tsx  FilterBar.tsx  filter-dsl.ts
                     PeekPanel.tsx  BatchLookupDialog.tsx  LiveToggle.tsx
    request-detail/  RequestDetailPage.tsx  Pipeline.tsx  ValuesTable.tsx  SourceChip.tsx
                     ContextPanel.tsx  RawRecord.tsx  RelatedRail.tsx  explain.ts
    jev/             JevPage.tsx  JevInspector.tsx  StateStructured.tsx  JsonTree.tsx  RawText.tsx
                     AnswerBars.tsx  PromptView.tsx  align.ts（7.5.2）  health.ts
    sessions/        SessionsPage.tsx  SessionTimeline.tsx
    sites/           SitesPage.tsx  SiteWizard.tsx  SiteDetailPage.tsx  ConfigForm.tsx  YamlEditor.tsx
                     PatternListEditor.tsx  PatternTester.tsx  AdvancedParams.tsx  DiffView.tsx
                     ImpactPreview.tsx  InsightsTab.tsx  HistoryTab.tsx  ModeSwitchDialog.tsx
                     QuickRuleDialog.tsx
    system/          SystemPage.tsx  ImportDialog.tsx
  ui/         vocab.ts（判定路径、结论、类型、失败码的文案与颜色）  DecisionChip.tsx  OutcomeBadge.tsx
              KindChip.tsx  Mono.tsx  CopyButton.tsx  TimeCell.tsx  Duration.tsx  Bytes.tsx
              StackedBars.tsx  Sparkline.tsx  Histogram.tsx  EmptyState.tsx  ErrorBanner.tsx
  lib/        patterns.ts（PathPattern 的 TS 移植）  site-validate.ts（含 advanced）  time.ts  format.ts
              shortcuts.ts  storage.ts（localStorage 容错封装）
```

### 7.10.3 路由与 URL 状态

筛选、标签页、视图模式都放在 URL 查询参数里（TanStack Router `validateSearch`，手写校验函数，不引入 zod），刷新、后退、复制链接都能还原。路由表见 [06.2](06-console-ui.md#62-信息架构)。全局范围（`site`、`range`，以及 `range=custom` 时的 `since`/`until`，见 [06.2.2](06-console-ui.md#622-路由)）也只放在 URL，不存 `localStorage`。读：地址里没有 `site` 就是全部站点，`since`/`until` 只在 `range=custom` 时读。带：页内链接、导航按钮、命令面板和快捷键跳到没有写明范围的地址时，把当前范围带过去（`keepScope`），目标自己写明的不改；顶栏切换站点用替换历史项，不新增。这样后退、前进回到的地址就是当时的范围，不会被内存里“上一次的选择”改写。

### 7.10.4 数据获取

| 数据 | 查询键 | 缓存策略 |
|---|---|---|
| 请求列表 | `['requests', filters]` | `staleTime` 10 s；实时模式每 2 s 用 `since_millis = 最新 at_millis − 60 s` 重新拉取，按 `request_id` 去重后插到顶部（7.9.3），10 分钟无操作自动停止 |
| 请求详情 | `['request', id]` | 记录不会再变，`staleTime: Infinity`；列表行悬停 150 ms 预取 |
| 计数、统计 | `['counts', filters]`、`['stats', …]` | 30 s |
| 网关与 Jev 状态 | `['status']` | 每 15 s 轮询 `/api/status`（顶栏状态灯、总览“需要处理”）；`['system']`、`['jev-status']` 只在系统页、Jev 页读取 |
| 站点、版本 | `['sites']`、`['site', name]`、`['versions', name]` | 保存后失效；保存后每 1 s 轮询 `['site', name]` 直到 `rollout` 显示全部在线网关已加载新版本，最长 30 s（7.9.13） |
| 参数证据 | `['evidence', name]` | 60 s，只在打开“高级”分组时请求 |
| 指令全文 | `['prompt', id]` | `Infinity` |

不使用 SSE 或 WebSocket。

### 7.10.5 共享词汇与解释

- `ui/vocab.ts` 是判定路径、结论、值类型、失败码、建议类型、判定参数的唯一定义处：中文名、简称、颜色令牌、图标、一句话说明。所有组件从这里取，不在组件里写死文案。
- `request-detail/explain.ts` 根据记录生成一句话结论（[06.4.4](06-console-ui.md#644-请求详情)），纯函数、有单元测试；不调用模型。

### 7.10.6 安全渲染

判定日志里到处是攻击载荷（`<script>`、`' OR 1=1--`、模板注入），控制台本身不能被它们攻击：

- 禁止 `dangerouslySetInnerHTML`；JSON 树、原文视图、差异视图都只生成文本节点。
- 链接只由校验过格式的 ID 拼出（`req_` + 32 位十六进制、16 位十六进制会话标签、站点名规则）；记录里的路径、Host、值从不作为链接地址。
- 搜索高亮在文本节点上切分，不拼 HTML。
- 控制面给控制台的响应加 `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'`（antd 的运行时样式需要 `unsafe-inline`），以及 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。
- 导出 CSV 防公式注入（7.9.9）。

### 7.10.7 性能预算

- 首屏 JS（gzip）不超过 400 KiB；编辑器、YAML、图表按路由懒加载。
- 请求列表用 antd Table 的 `virtual` 模式，一次最多保留 2000 行，超出提示“缩小时间范围或继续加载”。
- 服务端：24 小时窗、带站点条件的列表首页 300 ms 内；按 ID 打开详情 100 ms 内（单分区索引查找）。

### 7.10.8 测试

- 单元（`node --test`）：`filter-dsl.ts` 解析与序列化往返；`explain.ts` 覆盖每种判定路径和失败码；`patterns.ts` 与 Rust `PathPattern` 共用一组用例（从 `crates/xshield-core/src/context/config.rs` 的测试复制，含 `;` 路径参数）；`site-validate.ts` 的 `advanced` 范围与词规则，Host（不带端口）、源站地址、凭证名和路径规则与 Rust 的 `valid_host`、`valid_origin`、`valid_token`、`PathPattern::parse` 共用一组边界用例（Host 带端口或含 `..`、源站地址带路径或端口越界、路径含 `\\`、超过 256 字节；路径长度按 UTF-8 字节算（`TextEncoder`），不是 `String.length`，中文、emoji 跨过 256 字节的用例要有；Rust 只拒绝空格和 ASCII 控制字符，不拒绝全角空格等其他空白）；`yaml.ts` 在 YAML/JSON 转成配置对象后先检查字段类型（Host、入口、绕过是文本列表，名称、源站、模式是文本，`session`、`advanced` 是键值），缺少必填字段、写了键却留空（`hosts:`、`bypass:`、`mode:` 读出来是 null，不能当成空列表或默认值）、数字 Host、`hosts: a.example.com`（单个文本）、列表里夹数字或嵌套列表都要变成指出字段的报错（能定位时带行号），只有 `advanced` 和它下面的参数可以留空，`validateSpec` 对任何类型的输入都不抛异常，也不会把类型不对的值当成合法，这一组用例要有；`scope.ts` 的 `keepScope` 把当前范围带到不含 `site` 的地址、已含 `site` 的地址不改，缺省的 `site` 读成全部站点；`align.ts` 处理裁剪（`seen_as` 比 `sources` 短仍对得上）、次序互换（对不上）、数组值和对不上时的 `aligned: false`（7.5.2）；实时模式的合并去重（按 `request_id`，回看窗口内重复行不重复插入）；YAML↔JSON 往返；CSV 防公式注入。
- 端到端（Playwright，`page.route` 返回固定数据，不需要后端）：登录；⌘K 输入请求 ID 打开详情；筛选本应拦截并用 j/k、Enter 浏览；Jev 视图三种模式切换和来源跳转；从无会话记录“登记为入口”、看影响预估、保存、等到“已生效”；改 Jev 超时并看影响预估；版本差异与回滚；观察切拦截；粘贴 TSV 批量对照。每个页面跑一次 axe，明暗两种主题。
- 契约：Rust 侧对 `DecisionRecord`、API 响应做 serde 往返测试，样例 JSON 与前端端到端测试使用同一批文件（放在 `web/console/tests/fixtures/`）。

## 7.11 安全与隐私

- 判定日志里的请求值、查询串、客户端 IP 是业务数据和个人信息，保留 7 天；导出文件同样包含这些内容，界面在导出前提示。需要不外发、不落日志的字段用 `advanced.secret_fields` 追加。
- 会话凭证原文从不进入记录；`session` 是带密钥的 HMAC 截断值，不能反推凭证。
- 控制台只读日志，日志不参与任何放行决定（AGENTS.md）。
- 控制面所有查询都有时间窗、行数和扫描上限，防止一个请求压垮数据库。
- 登录限速、Cookie `__Host-`/`Secure`/`HttpOnly`/`SameSite=Lax` 沿用 PR #73，并要求写操作为 JSON 请求体。

## 7.12 实施计划

建议拆成三个可以并行的开发线程，以本章的表结构和 API 为契约：

| 线程 | 范围 | 依赖 |
|---|---|---|
| A 网关追溯与判定参数 | 7.4–7.7：`xshield-core` 记录类型和 `advanced`、`xshield-judge` 上下文、追溯与站点参数、`xshield-edge` 简记录、计时、批量写、心跳、指令登记、测试；同步 [03.2](03-admin-config-audit.md#32-站点配置) 的示例 | 无 |
| B 控制面 | 7.8–7.9：以 PR #73 的分支为起点（合并最新 `main`），替换基线迁移，版本化站点历史，全部 API、分区维护、建议与预估、导入导出、同源提供静态文件 | 表结构以 7.8.1 为准，可先用手写的样例行开发；`SiteSpec` 的 `advanced` 校验来自 A，B 可先合入 A 的这部分提交 |
| C 控制台 | 06 全部页面和 7.10，先用 `page.route` 和 `tests/fixtures` 的样例数据开发，B 完成后联调 | API 以 7.9 为准 |

每个线程的完成标准：`cargo fmt`、`cargo clippy --workspace --all-targets -- -D warnings`、相关 `cargo test`（PostgreSQL 用例在 CI 的 `validate` 任务里执行）；控制台 `npm run lint`、`npm test`、`npm run build`、`npx playwright test` 全部通过；`scripts/validate_library.py`、`scripts/check_env_docs.py` 通过。

**优先级与里程碑**。P0 是四项要求的最小闭环，但一次交付太大，所以按里程碑切开：三个线程对齐到同一个里程碑，每个里程碑结束时控制台都能单独使用，也能尽早暴露接口分歧。

| 里程碑 | 用户得到什么 | A 网关 | B 控制面 | C 控制台 |
|---|---|---|---|---|
| **M1 能追溯**（P0） | 每个请求都能按 ID 打开，看到判定依据和 Jev 的完整上下文（结构化、JSON、原文、指令四视图）；会话时间线；⌘K 按 ID 直达；网关与 Jev 状态灯 | 记录与 `trace`、简记录、计时、心跳（含缺口历史）、指令登记、批量写、压力下丢简记录 | 登录、分区维护、`requests`（含 `scope`、`counts`）、详情、`sessions`、`jev/*`、`status`、`system`、导入 | 框架与主题、请求追溯、请求详情、Jev 查看器、会话、系统（只读）、`vocab.ts` 与 `explain.ts` |
| **M2 能配置**（P0） | 站点的全部字段在表单和 YAML 里都能改，高级判定参数带证据和影响预估，版本差异与回滚，保存后看到“N/M 个网关已生效” | `advanced` 校验与判定代码改动（7.6.3） | 站点 CRUD、版本表、`validate`、`preview`、`evidence`、`rollout` | 站点列表与详情、表单与 YAML 编辑、高级判定参数、保存对话框、变更历史 |
| **M3 更便捷**（P0） | 从一条请求直接登记入口、加入绕过、调参；切拦截模式前的就绪检查；批量对照；实时模式；总览；新建站点（粘贴 YAML 或表单） | — | `lookup`、`insights` 的 `readiness` | 快捷规则对话框、模式切换、批量对照、实时模式、总览、命令面板完整功能与快捷键 |
| **P1** | 接入向导四步、调优建议页签、导出与导入、Jev 对比视图和统计图、会话列表筛选 | — | `insights` 的 `suggestions`、`export`、`import`、`jev/stats` | 对应页面 |
| **P2** | 分钟级汇总表（数据量超过 7.8.4 的估算时） | — | 汇总表与查询 | — |

M3 里的实时模式和命令面板的非查找类命令可以最后做；它们不影响四项要求的闭环。

PR #73 的去向：线程 B 合并它的后端（登录、站点存储、判定日志查询）和对 v3 控制台的删除，前端按 06 重写；B 的 PR 合并后关闭 #73。
