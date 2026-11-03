# 03 管理员、配置与判定日志

## 3.1 单管理员

系统只有一个管理员角色。管理员登录控制台后可以新建和修改站点、切换观察和拦截模式、查看判定日志，改动保存后立即生效，不需要第二人审批，也没有分级角色。

管理员口令在部署时通过环境变量 `XSHIELD_ADMIN_PASSWORD_HASH` 设置（口令哈希，不是明文）。v3 的 OIDC 登录、多角色、step-up 认证、管理 API Key 都删除；以后确实需要接企业登录时再加回。

## 3.2 站点配置

一个站点的全部配置：

```yaml
name: emr
hosts: [emr.example.com]
origin: http://10.0.0.5:8080
session:
  cookie: SESSIONID            # 或者 header: Authorization
entries:                       # 不需要事先有上下文即可访问，仍做攻击判定
  - /login
  - /api/home
  - /api/patients
  - /share/*
bypass:                        # 不判定，只记一条简记录
  - /static/*
  - /favicon.ico
mode: observe                  # observe（默认）或 enforce
on_jev_unavailable: deny       # deny（默认）或 allow
advanced:                      # 可选：站点级判定参数，省略的项取代码默认值
  jev_timeout_ms: 3000
  secret_fields: [ssn, idcard]
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 站点名 |
| `hosts` | 是 | 网关按 Host 头把请求分配到站点 |
| `origin` | 是 | 源站地址 |
| `session` | 是 | 会话凭证所在的 Cookie 名或请求头名，二选一 |
| `entries` | 是 | 入口路径，`*` 匹配任意后缀；登录、首页、起始列表、分享兑换接口都写在这里 |
| `bypass` | 否 | 静态资源等无需判定的路径，默认空 |
| `mode` | 否 | 默认 `observe` |
| `on_jev_unavailable` | 否 | 默认 `deny`；设为 `allow` 时，未经判定放行的请求在判定日志里单独标注 |
| `advanced` | 否 | 站点级判定参数：`jev_timeout_ms`、`session_calls_per_minute`、`address_calls_per_minute`、`allow_cache_minutes`、`secret_fields`、`synonyms`、`field_kinds`。每项都可省略，省略时取代码默认值，判定行为不变。取值范围、作用和调整的代价见 [07.6](07-console-architecture.md#76-站点级判定参数advanced) |
| `objects` | 否 | 对象表：`classes`（对象类别，`id`、`name`、可选 `description`）和 `slots`（已确认的位置，`key` 形如 `GET /doctor/{id} path[1]`（路径须为规范拼写，见 [07.4.7](07-console-architecture.md#747-档位在判定中的使用)），`class`，`source` 为 `admin`、`rule` 或 `agent`；响应位置可选 `identity`，取 `user`、`org` 或 `role`，声明它携带本会话的用户、机构或角色，见 [07.9.15](07-console-architecture.md#7915-对象表的身份位置w1)；可选的 `tier`、`accepts_public`、`reliability`，以及为真时暂停位置的 `paused`（判断保留但不被使用），见 [07.9.16](07-console-architecture.md#7916-对象表的档位与可靠性w3)）。省略时为空，判定与之前相同；学习提议只在学习状态里，确认后才写入这里。`learning` 段省略即默认（学习开启，20 次使用、5 个会话，代理关闭）；与默认全部相同时不写入。`agent.enabled` 为真时，控制面只在配置了学习代理模型时提问，没有模型时位置照常等待，不会出错 |

Jev 超时、调用限额、放行缓存时长、追加脱敏字段、同义词可以按站点在 `advanced` 里覆盖（管理员 2026-11-01 决定，原因见 [07.1.3](07-console-architecture.md#713-新增项必要性审查)）。上下文容量、会话过期时间、请求体和响应的解析上限、`state` 大小等其余参数仍是代码默认值，不出现在配置里；控制台只读展示网关的实际值。

站点配置保存在 PostgreSQL，每次修改产生一个新版本（版本号、修改后的全文、变更类型、可选备注），控制台可以查看任意两个版本的差异并回滚，判定日志记下判定时生效的版本，见 [07.8.1](07-console-architecture.md#781-表)。

## 3.3 部署级环境变量

v4 目标状态必需的环境变量只有这些（TLS 多证书、PROXY 协议、运维监听等 v3 部署项不再提供，见 [05.3](05-v3-removal.md#53-环境变量去留)）：

| 变量 | 用途 |
|---|---|
| `XSHIELD_DATABASE_URL` | PostgreSQL 连接 |
| `XSHIELD_EDGE_LISTEN_PORTS` | 网关监听端口，逗号分隔，监听所有网卡 |
| `XSHIELD_EDGE_TLS_CERT_PATH` / `XSHIELD_EDGE_TLS_KEY_PATH` | 可选：证书和私钥文件，两者同时设置时所有端口都走 TLS（只有一张证书；多域名证书请用前置负载均衡终结 TLS）。不设置则监听明文 |
| `XSHIELD_EDGE_SITES_FILE` | 仅开发和测试：站点配置 JSON 数组文件。设置它且不设 `XSHIELD_DATABASE_URL` 时，网关不连数据库，判定日志以 JSON 行写到标准输出 |
| `XSHIELD_CONTROL_LISTEN` | 控制台监听地址 |
| `XSHIELD_CONTROL_PLAIN_HTTP` | 可选：控制台只经 `http://` 访问时设为 `true`。管理员 Cookie 改为不带 `__Host-` 前缀、不带 `Secure`，因为浏览器不保存 HTTP 下的 Secure Cookie。只用于网络本身已加密或可信的情况，例如经 Tailscale 访问 `http://主机名:端口`；其余情况保持默认 |
| `XSHIELD_ADMIN_PASSWORD_HASH` | 管理员口令哈希（新增） |
| `XSHIELD_CONTEXT_KEY_HEX` | 会话键和已见值哈希用的密钥（新增）。控制面也读它，用来加密控制台保存的模型密钥（3.3.1）；网关和控制面必须设成同一个值 |
| `AI_GATEWAY_API_KEY` | Jev 调用凭证。控制台保存了 Jev 密钥（3.3.1）后以控制台为准，这个变量不再使用 |
| `XSHIELD_JEV_ENDPOINT` / `XSHIELD_JEV_MODEL` | 可选：Jev 调用地址和线上模型名，换私有部署模型时设置（新增，默认 Vercel AI Gateway）。地址必须是 https，回环地址可用 http |
| `XSHIELD_JEV_ROUTE` / `XSHIELD_JEV_API_KEY` | 可选：直连 TypeSafe |
| `XSHIELD_JEV_TIMEOUT_MS` | 可选：单次 Jev 调用超时，100 到 30000 毫秒，默认 2000；到模型服务链路慢时调大 |

### 3.3.1 模型配置在控制台保存

Jev 判定模型和学习代理模型在控制台“系统”页的“模型”标签里配置（`tab=models`）。线路、地址、模型名和超时存在 `model_config` 表里（迁移 `0006_model_config.sql`）。密钥用 AES-256-GCM 加密后存库，数据库和日志里只出现末 4 位。每次保存都写一行 `model_config_history`，并要求带上读取时的版本号，版本不一致返回 409 `VERSION_CONFLICT`。

- 网关每 5 秒读取一次 Jev 配置。控制台保存了 Jev 密钥时以它为准；没有时网关继续读上表的环境变量，已有部署不用改。
- 新版本加载失败（例如密钥无法解密）时，网关继续用上一版，并在心跳的 `config_error` 里报告失败码；控制台的总览出现“模型配置未加载”的事项。
- 启动时没有任何 Jev 密钥不会退出。网关照常服务，判定记为 `JEV_NOT_CONFIGURED`（07.5.4），直到控制台保存了密钥或设置了环境变量。
- 加密密钥由 `XSHIELD_CONTEXT_KEY_HEX` 经 HMAC-SHA256 派生（标签 `xshield model config key v1`），每次加密用新的随机 96 位 nonce，列名作为附加数据，所以密文不能挪到别的列用。更换 `XSHIELD_CONTEXT_KEY_HEX` 后，已保存的密钥无法解密，需要在控制台重新保存。
- 控制面没有设置 `XSHIELD_CONTEXT_KEY_HEX` 时，模型页仍可查看和修改地址、模型名、超时，但不能保存密钥（503 `MODEL_KEY_UNAVAILABLE`）。
- 学习代理模型只由控制台进程调用，不经网关。

v3 代码目前读取 109 个 `XSHIELD_*` 变量，逐个的去留见 [05.3](05-v3-removal.md#53-环境变量去留)。

## 3.4 判定日志

网关处理的每个请求都在 PostgreSQL 写一行，包括命中 `bypass` 的请求、请求体不可判定（413）和未知站点（404）的请求（这三类只写简记录）：

- 时间、站点和配置版本、请求 ID、会话标签（不是凭证）、方法、路径、脱敏后的查询串、状态码、耗时；
- 判定路径：绕过 / 快速放行 / 缓存放行 / Jev 通过 / Jev 拒绝 / Jev 不可用后按配置处理（含超出调用限额）/ 无会话拒绝 / 请求体不可判定 / 未知站点；
- 结论：放行、拦截、观察模式下的“本应拦截”，或 Jev 不可用时按配置放行的“未经判定”；
- 判定依据：每个请求值是否见过、是否已核验、从哪个请求的响应学到（来源请求 ID）；
- 调用了 Jev 时，附带发送的 `state`（已脱敏）、指令版本、原始响应、两个问题的完整概率、耗时、超时和失败码。

写日志从不拖慢请求：网关的发送队列有界，队列压力大时先丢弃绕过的简记录，队列满了才丢判定记录，丢失的数量和时间段会通过心跳上报，控制台如实提示“这段时间的请求可能查不到”（[07.7.4](07-console-architecture.md#774-日志发送)）。

完整字段、追溯链路和存储方式见 [07.4](07-console-architecture.md#74-判定记录decisionrecord-v2)、[07.5](07-console-architecture.md#75-jev-调用上下文的保存)。日志默认保留 7 天。控制台按时间、会话、路径、结论筛选，能打开单条记录查看判定过程、Jev 看到的内容和给出的概率，并沿来源请求 ID 跳转，用来在观察模式下排查误判。

v3 的封存 journal、ClickHouse 索引、加密证据库、outbox 发布、案件与证据访问审批、导出和保全全部删除，见 [05](05-v3-removal.md)。

## 3.5 控制台范围

控制台的界面见 [06](06-console-ui.md)，技术方案见 [07](07-console-architecture.md)。页面分六块：总览、请求追溯（判定日志的列表与详情）、会话、Jev 调用、站点（配置表单与 YAML 编辑、判定参数、调优建议、版本差异与回滚、模式切换）、系统（网关与 Jev 状态、日志存储、运行参数）。
