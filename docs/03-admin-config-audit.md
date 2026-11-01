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
bypass:                        # 不判定、不记录
  - /static/*
  - /favicon.ico
mode: observe                  # observe（默认）或 enforce
on_jev_unavailable: deny       # deny（默认）或 allow
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

上下文容量、Jev 超时、调用限额、缓存时长等全部是代码里的默认值，不出现在配置里。需要调整时改代码默认值，而不是给每个站点加一个选项。

站点配置保存在 PostgreSQL，每次修改保留一份历史（时间、修改前后的完整配置），控制台可以查看和回滚。

## 3.3 部署级环境变量

v4 目标状态必需的环境变量只有这些（TLS 多证书、PROXY 协议、运维监听等 v3 部署项不再提供，见 [05.3](05-v3-removal.md#53-环境变量去留)）：

| 变量 | 用途 |
|---|---|
| `XSHIELD_DATABASE_URL` | PostgreSQL 连接 |
| `XSHIELD_EDGE_LISTEN_PORTS` | 网关监听端口，逗号分隔，监听所有网卡 |
| `XSHIELD_EDGE_TLS_CERT_PATH` / `XSHIELD_EDGE_TLS_KEY_PATH` | 可选：证书和私钥文件，两者同时设置时所有端口都走 TLS（只有一张证书；多域名证书请用前置负载均衡终结 TLS）。不设置则监听明文 |
| `XSHIELD_EDGE_SITES_FILE` | 仅开发和测试：站点配置 JSON 数组文件。设置它且不设 `XSHIELD_DATABASE_URL` 时，网关不连数据库，判定日志以 JSON 行写到标准输出 |
| `XSHIELD_CONTROL_LISTEN` | 控制台监听地址 |
| `XSHIELD_ADMIN_PASSWORD_HASH` | 管理员口令哈希（新增） |
| `XSHIELD_CONTEXT_KEY_HEX` | 会话键和已见值哈希用的密钥（新增） |
| `AI_GATEWAY_API_KEY` | Jev 调用凭证 |
| `XSHIELD_JEV_ENDPOINT` / `XSHIELD_JEV_MODEL` | 可选：Jev 调用地址和线上模型名，换私有部署模型时设置（新增，默认 Vercel AI Gateway）。地址必须是 https，回环地址可用 http |
| `XSHIELD_JEV_ROUTE` / `XSHIELD_JEV_API_KEY` | 可选：直连 TypeSafe |
| `XSHIELD_JEV_TIMEOUT_MS` | 可选：单次 Jev 调用超时，100 到 30000 毫秒，默认 2000；到模型服务链路慢时调大 |

v3 代码目前读取 109 个 `XSHIELD_*` 变量，逐个的去留见 [05.3](05-v3-removal.md#53-环境变量去留)。

## 3.4 判定日志

每个经过判定的请求（即没有命中 `bypass` 的请求）在 PostgreSQL 写一行：

- 时间、站点、请求 ID、会话键前缀（不是凭证）、方法、路径、状态码；
- 判定路径：快速放行 / 缓存放行 / Jev 放行 / Jev 拦截 / Jev 不可用后按配置处理 / 超出调用限额 / 无会话拒绝；
- 结论：放行、拦截，或观察模式下的"本应拦截"；
- 调用了 Jev 时，附带发送的 `state`（已脱敏）、两个问题的完整概率和耗时。

日志默认保留 7 天。控制台按时间、会话、路径、结论筛选，并能打开单条记录查看 Jev 看到的内容和给出的概率，用来在观察模式下排查误判。

v3 的封存 journal、ClickHouse 索引、加密证据库、outbox 发布、案件与证据访问审批、导出和保全全部删除，见 [05](05-v3-removal.md)。

## 3.5 控制台范围

控制台只保留四块：站点列表与配置表单（含配置历史和回滚）、模式切换、判定日志、Jev 连通状态。
