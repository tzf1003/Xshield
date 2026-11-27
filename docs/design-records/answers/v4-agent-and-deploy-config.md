# Xshield v4：agent 怎么配，以及 compose 部署要设哪些变量

依据：仓库 HEAD `82ef557`，以及 docs/00–05 和代码核对。控制台 6180，网关 6190，PostgreSQL 三个服务。

## 1. v4 里的 agent 是什么

v4 里唯一叫 agent 的是**学习代理**，用在对象表的学习设置里：规则判不了某个位置的对象类别时，可以把问题交给 agent。每日调用上限是 `objects.learning.agent.daily_limit`，默认 200。

**它还没有上线，目前没有任何配置能打开它。** 三处代码都能对上：

- 控制台接口返回的 `agent_configured` 写死为 `false`（`crates/xshield-control/src/object_map.rs:279`）。
- 控制台的开关常量 `AGENT_SAVE_READY = false`（`web/console/src/features/sites/objects/LearningSettings.tsx:32`）。
- 网关拒绝保存 `objects.learning.agent.enabled: true`（`crates/xshield-core/src/context/objects.rs` 的 `valid_learning`）。

所以学习设置里 agent 开关置灰，并提示“没有配置模型，agent 暂不可用”，是预期现象。这句提示也不会因为你配了模型而改变，因为上面那个 `false` 是写死的。文档里也没有为 agent 定义任何环境变量（docs/03 3.3）。按 docs/07，它要到学习代理上线（PR-5）才生效。

v4 里没有其他需要单独安装或配置的 agent：

- v3 的探针（sensor）和 Agent 管理 API 已经删除（docs/05）。
- 网关直接看得到源站的每个响应，不需要探针。
- 源站不需要接入 SDK，也不需要注入脚本（docs/04 4.1）。

**真正要配的是判定模型 Jev 的密钥，以及控制台和网关两个服务的环境变量。** 如果你指的是这个，见下面的第 2 到 4 节。

## 2. 控制台（xshield-control，6180）的环境变量

| 变量 | 是否必填 | 说明 |
|---|---|---|
| `XSHIELD_DATABASE_URL` | 是 | `postgresql://用户:密码@postgres:5432/库名`，compose 里用服务名。网关也要指向同一个库。 |
| `XSHIELD_CONTROL_LISTEN` | 是 | 代码默认是 `127.0.0.1:8081`。容器里要写 `0.0.0.0:6180`，宿主机才访问得到。 |
| `XSHIELD_ADMIN_PASSWORD_HASH` | 是 | 管理员口令的哈希，不是明文。生成方法：`printf '%s\n' '你的口令' \| xshield-control hash-password`，输出的一行就是它。 |
| `XSHIELD_CONTROL_PLAIN_HTTP` | 看访问方式 | 只用 `http://` 访问（例如 `http://localhost:6180`）时设为 `true`。否则浏览器不保存管理员 Cookie，登录态留不住。用 https 访问则不设。 |
| `XSHIELD_CONTROL_CONSOLE_ORIGIN` | 否 | 只在前端和 API 分开托管时用，单容器部署不要设。 |

控制台启动时会自动执行 `migrations/` 里尚未记录的迁移，所以先启动控制台让它建表，再启动网关。

## 3. 网关（xshield-edge，6190）的环境变量

| 变量 | 是否必填 | 说明 |
|---|---|---|
| `XSHIELD_DATABASE_URL` | 是 | 同上，指向同一个库。网关每 5 秒从库里重新加载站点。 |
| `XSHIELD_EDGE_LISTEN_PORTS` | 是 | 写 `6190`，监听所有网卡。 |
| `XSHIELD_CONTEXT_KEY_HEX` | 是 | 至少 64 位十六进制。用 `openssl rand -hex 32` 生成一次，之后不要再改。改了以后，已有会话的上下文会失效，判定日志里的哈希也对不上。只有网关用它，控制台不需要。 |
| `AI_GATEWAY_API_KEY` | 默认路线必填 | Vercel AI Gateway 的 API key。没有它网关启动就会退出。 |
| `XSHIELD_JEV_ROUTE` | 否 | 默认 `gateway`。设为 `direct` 时改用下面的 `XSHIELD_JEV_API_KEY` 直连 TypeSafe。docs/04 4.5.2 记录过：项目在 Windows 上直连返回 451 地区限制，所以一般保持默认。 |
| `XSHIELD_JEV_API_KEY` | 仅 `direct` 时必填 | 直连 TypeSafe 用的 key。 |
| `XSHIELD_JEV_TIMEOUT_MS` | 否 | 单次 Jev 调用超时，默认 2000，允许 100 到 30000。链路慢、系统页看到超时时再调大。 |
| `XSHIELD_JEV_ENDPOINT` / `XSHIELD_JEV_MODEL` | 否 | 只在换私有部署的模型时设。默认是 `https://ai-gateway.vercel.sh/typesafe/v1/systemone` 和 `typesafe-ai/jev`。 |
| `XSHIELD_EDGE_TLS_CERT_PATH` / `XSHIELD_EDGE_TLS_KEY_PATH` | 否 | 要在网关上直接做 TLS 才设，且必须成对出现。家里局域网可以不设。 |

不要设置 `XSHIELD_EDGE_SITES_FILE`，它只给开发和测试用。

### compose 里的写法（示意，密钥放进 `.env`，不要提交）

```yaml
control:
  environment:
    XSHIELD_DATABASE_URL: postgresql://xshield:${PG_PASSWORD}@postgres:5432/xshield
    XSHIELD_CONTROL_LISTEN: 0.0.0.0:6180
    XSHIELD_ADMIN_PASSWORD_HASH: ${ADMIN_PASSWORD_HASH}
    XSHIELD_CONTROL_PLAIN_HTTP: "true"        # 只用 http:// 访问时
  ports: ["6180:6180"]

edge:
  environment:
    XSHIELD_DATABASE_URL: postgresql://xshield:${PG_PASSWORD}@postgres:5432/xshield
    XSHIELD_EDGE_LISTEN_PORTS: "6190"
    XSHIELD_CONTEXT_KEY_HEX: ${CONTEXT_KEY_HEX}
    AI_GATEWAY_API_KEY: ${AI_GATEWAY_API_KEY}
  ports: ["6190:6190"]
```

用户名、库名和密码按你现在的 compose 替换。

## 4. 控制台里要设置的地方

1. 打开 `http://localhost:6180`，用管理员口令登录。
2. 点“站点”→“新建站点”（或进入站点后，在“配置”标签里用 YAML 编辑）。需要填这些项：
   - `name`：站点名。
   - `hosts`：你在浏览器里访问网关时用的主机名，不带端口。网关匹配时会去掉端口，例如写 `localhost`。
   - `origin`：源站地址，必须从**网关容器内部**能访问到。写 `localhost` 指的是网关容器自己，要写宿主机的局域网 IP 或 `host.docker.internal`（后者需要在 compose 里配 `extra_hosts`）。
   - `session`：源站登录凭证所在的位置。`cookie: SESSIONID` 或 `header: Authorization`，二选一。
   - `entries`：不登录也能访问的入口，例如 `/login`、`/api/home`、`/api/patients`。`*` 可以匹配任意后缀。
   - `bypass`：静态资源，例如 `/static/*`、`/favicon.ico`，这些不做判定。
   - `mode`：默认 `observe`，只判定和记录，不拦截。
   - `on_jev_unavailable`：默认 `deny`，Jev 超时或失败时拦截。
3. 保存后大约 5 秒，网关会自动加载新站点。
4. 对象表 →“学习设置 ⚙”：保持 agent 开关关闭，其余可以用默认值。
5. “系统”页能看到网关和 Jev 的状态。

## 5. 验证

1. `curl http://localhost:6190/...` 能返回源站内容（观察模式下照常转发）。如果返回 404，说明 `hosts` 和你访问的主机名对不上。
2. 控制台“请求追溯”里能看到记录。
3. 观察期内，在判定日志里查看“本应拦截”的记录。确认是真攻击还是漏登记的入口，再把漏掉的入口补进 `entries`。
4. 误判可以接受之后，再切到拦截模式。切换前先在“系统”页确认 Jev 状态正常。`on_jev_unavailable: deny` 时，Jev 失败会直接拦截请求。

`curl http://localhost:6180/health` 返回 `ok` 说明控制台已经起来（代码 `crates/xshield-control/src/lib.rs:161`，`dev.sh` 的就绪检查也用这个地址）。

## 6. 常见问题

- **网关启动后立即退出**：多半是没设 `AI_GATEWAY_API_KEY`（direct 时没设 `XSHIELD_JEV_API_KEY`），或者 `XSHIELD_CONTEXT_KEY_HEX` 不是 64 位十六进制。
- **控制台启动失败**：没设 `XSHIELD_ADMIN_PASSWORD_HASH`，或者迁移失败。迁移失败时控制台会打印失败的版本号并退出。
- **登录后刷新就掉**：用 http 访问却没设 `XSHIELD_CONTROL_PLAIN_HTTP=true`。
- **网关所有请求都是 404**：`hosts` 和浏览器访问的主机名不一致。
- **源站连不上**：`origin` 写成了 `localhost`，这是网关容器自己的地址。
- **观察期 `no_session` 很多**：未登录就会拉取的引导接口和静态资源没有登记。补进 `entries` 或 `bypass`。

提醒：把 compose 或 `.env` 贴到聊天里时，请先把口令、密码和 API key 打码。
