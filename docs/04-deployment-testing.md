# 04 部署与验收

## 4.1 部署形态

首版参考部署只有一种：单机 Docker Compose，包含网关、控制台和 PostgreSQL 三个服务。它就是仓库根目录的 `docker-compose.yml`，两个角色的镜像由 `Dockerfile` 构建（`docker-compose.dev.yml` 是另一份，只启动开发用的 PostgreSQL）。源站不需要接入 SDK，也不需要注入脚本。

多实例部署需要先把会话上下文换成共享存储（见 [01.2](01-request-flow.md#12-会话与上下文)），在那之前不提供 Helm、systemd 等其他参考部署。v3 的 `deploy/helm`、`deploy/systemd`、`deploy/prometheus` 已删除。

### 4.1.1 启动参考部署

在仓库根目录：

```sh
cp .env.example .env
openssl rand -hex 24      # 填入 XSHIELD_POSTGRES_PASSWORD
openssl rand -hex 32      # 填入 XSHIELD_CONTEXT_KEY_HEX
docker compose build xshield-control
printf '%s\n' '管理员口令' | docker compose run --rm --no-deps -T xshield-control hash-password
                          # 输出填入 XSHIELD_ADMIN_PASSWORD_HASH，保留单引号（值里有 $）
docker compose up -d --build
```

Windows（PowerShell）没有 `openssl` 和 `printf`，同样的步骤写成：

```powershell
Copy-Item .env.example .env
# 各输出一行随机十六进制：先取 48 位填入 XSHIELD_POSTGRES_PASSWORD，再取 64 位填入 XSHIELD_CONTEXT_KEY_HEX
$b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') })
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') })
docker compose build xshield-control
# Windows PowerShell 5.1 按 ASCII 发送管道里的文本，非 ASCII 字符会变成 ?。同一窗口里先把输出编码设为 UTF-8
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
# 输出填入 XSHIELD_ADMIN_PASSWORD_HASH，保留单引号
'管理员口令' | docker compose run --rm --no-deps -T xshield-control hash-password
docker compose up -d --build
```

- 控制台只监听本机的 `127.0.0.1:8081`。管理员 Cookie 带 `Secure`，所以在本机用 `http://localhost:8081` 打开，或经 SSH 隧道，或在前面放一个 HTTPS 反向代理（[07.2.3](07-console-architecture.md#723-部署)）。
- 控制台前面放了反向代理时，在 `.env` 里设置 `XSHIELD_CONTROL_TRUSTED_PROXIES`（代理的地址或网段，逗号分隔，[03.3](03-admin-config-audit.md#33-部署级环境变量)），并让代理追加 `X-Forwarded-For`。不设置时，所有登录失败都按代理的地址计数，任何人输错口令都会把所有人（包括管理员）锁住 10 分钟。
- 网关监听所有网卡的 `8080`（明文）。要让网关自己终结 TLS，在 `docker-compose.yml` 的 `xshield-edge` 里挂载证书和私钥并设置 `XSHIELD_EDGE_TLS_CERT_PATH`、`XSHIELD_EDGE_TLS_KEY_PATH`（[03.3](03-admin-config-audit.md#33-部署级环境变量)）。
- Jev 密钥可以写在 `.env` 的 `AI_GATEWAY_API_KEY`（取消该行注释后填写），也可以启动后在控制台“系统”页的“模型”标签里保存；控制台保存的密钥优先。两处都没有时判定记为 `JEV_NOT_CONFIGURED`。
- 网关在表还没建好时会退出，由 Compose 重启，直到控制台执行完迁移。
- 数据在卷 `xshield_postgres-data` 里；`docker compose down` 保留它，加 `-v` 才删除。
- 启动后 `docker compose ps` 应显示 `postgres` 为 healthy，`xshield-control` 和 `xshield-edge` 为运行中；在本机打开 `http://localhost:8081/health` 应返回 `ok`。
- 默认端口 8080 或 8081 被本机其他程序占用时，在 `.env` 里设置 `XSHIELD_EDGE_PORT` 或 `XSHIELD_CONTROL_PORT`（见 `.env.example`）。

## 4.2 上线步骤

1. 部署网关、控制台和 PostgreSQL，设置 [03.3](03-admin-config-audit.md#33-部署级环境变量) 列出的环境变量。控制台启动时先执行 `migrations/` 里尚未记录的迁移，迁移编译进二进制，记录在 `_sqlx_migrations` 表中，然后才开始服务。不需要手动执行 SQL，也不要把迁移挂到 PostgreSQL 的 `docker-entrypoint-initdb.d`。迁移失败时控制台打印失败的版本并退出，由 Compose 的重启策略重试。
2. 在控制台新建站点，填写源站、会话凭证位置、入口和静态资源路径。站点默认处于观察模式。
3. 把流量切到网关，正常使用一段时间。
4. 在判定日志里查看"本应拦截"的记录：确认是真正的越权或攻击，还是漏登记的入口、Jev 误判。漏登记的入口补到 `entries`。
5. 误判可以接受之后，切到拦截模式。

### 已有数据库的一次性处理

产品未上线前，有些库是用 `initdb` 挂载或手动 `psql` 建好基线表的，它们没有迁移记录。新版控制台会在 `0001` 处报 `already exists` 并退出，事务回滚，库里的内容不变。两种处理方式：

- 库里没有要保留的数据：删除数据卷（`docker compose down -v` 会删除卷里的全部数据），让新版控制台重建。
- 要保留数据：按下面 1 到 4 步补记这一条迁移，每一步都在仓库根目录执行。库是 Compose 容器时，把 `psql`、`pg_dump`、`createdb`、`dropdb` 换成 `docker compose exec -T postgres …`（用 `-U` 指定用户），并把 `-f 文件` 换成 `< 文件`。

**1. 启动一次新版控制台。** 它会在 `0001` 处失败并退出，这是预期的；失败前它已经建好 `_sqlx_migrations` 表。确认：`psql "$XSHIELD_DATABASE_URL" -c '\dt _sqlx_migrations'`。由 Compose 自动重启时，表建好后即可停掉重启循环。

**2. 核对结构。** 用 0001 在临时库里建表，再比较五张基线表。分区不参与比较，运行时会建 `decision_log` 的每日分区。

```sh
DB=<控制台使用的库名>
T="-t site_configs -t site_config_history -t decision_log -t edge_status -t jev_prompts"
createdb xshield_check && psql -d xshield_check -v ON_ERROR_STOP=1 -f migrations/0001_v4_baseline.sql
for d in xshield_check "$DB"; do
  pg_dump -s --no-owner --no-privileges $T "$d" | grep -v '^\\\(un\)\?restrict ' > "$d.sql"
done
test -s xshield_check.sql && test -s "$DB.sql" && diff xshield_check.sql "$DB.sql" && echo "结构一致"
dropdb xshield_check
```

最后只应看到“结构一致”。`diff` 有输出就是有差异；`pg_dump` 出错时输出文件为空，`test -s` 会拦住这种假通过。`pg_dump` 每次都会输出不同的 `\restrict` 行，所以要过滤掉。有差异（例如库里还有 v3 的表或列）就不要补记，也不要删数据卷。先保留数据，再看 `diff` 的输出：以 `>` 开头的是库里有、基线里没有的，以 `<` 开头的是基线有、库里没有的。找出差异的来源后再决定怎么处理。

**3. 补记这一条迁移。**

```sh
checksum=$(sha384sum migrations/0001_v4_baseline.sql | cut -d' ' -f1)  # macOS: shasum -a 384 ...
psql "$XSHIELD_DATABASE_URL" -v ON_ERROR_STOP=1 -c "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (1, 'v4 baseline', true, decode('$checksum', 'hex'), 0)"
```

**4. 再启动控制台。** 它只检查已记录的迁移，不会再执行基线。日志应无错误；`SELECT version, description, success FROM _sqlx_migrations` 应为 `1 | v4 baseline | t`。如果 0001 的校验和与记录不一致，控制台会拒绝启动，不会静默通过。

## 4.3 验收场景

以医生和患者为例，至少覆盖：

| 编号 | 场景 | 预期 |
|---|---|---|
| A1 | 医生 A 浏览"我的患者"列表后打开患者 B | 放行 |
| A2 | 医生 A 把地址改成患者 D | 拦截 |
| A3 | 医生 A 新开会话，直接打开患者 B | 拦截 |
| A4 | 医生 A 删除患者 D | 拦截 |
| A5 | 医生 A 在"我的患者"接口上加别的医生参数 | 拦截 |
| A6 | 接收者兑换患者 A 的分享码后打开患者 A | 放行 |
| A7 | 接收者未兑换分享码，直接打开患者 A | 拦截 |
| A8 | 医生 A 新建患者后打开新患者详情 | 放行 |
| A9 | 医生 A 在搜索结果里看到医生 B 的患者后删除；没搜到的患者直接删除 | 搜到的：拦截（尝试越权，交 Jev 判 DENY）；没搜到的：拦截 |
| A10 | 医生 A 搜到医生 B 的患者后，在它的备注接口上写入 | 放行（备注位置接受公共来源） |
| A11 | 没有标注档位的站点，同样的搜索后删除 | 与标注前相同（放行） |
| A12 | 医生 A 搜到医生 B 的患者 D（慢速 id `PT-7004`）后按这个 id 删除 | 拦截（尝试越权，交 Jev 判 DENY） |
| B1 | 搜索框、表单里输入正常中文和英文文本 | 放行 |
| B2 | 参数里带注入、命令执行、路径穿越类内容 | 拦截 |
| B3 | 医生 A 在搜到的自己新建患者上提交两批以上的长备注（路径里带编号） | 放行，判定记录 `batches` 不少于 2 |
| B4 | 同样的长备注发给医生 B 的患者，医生 A 没见过这个编号 | 拦截 |
| C1 | Jev 超时或不可用，`on_jev_unavailable=deny` | 拦截，日志注明 |
| C2 | 同上，`on_jev_unavailable=allow` | 放行，日志注明"未经判定" |
| C3 | 观察模式下的 A2 | 转发，日志记"本应拦截" |
| C4 | 登录请求 | 口令字段不出现在发给 Jev 的内容里 |
| C5 | 同一会话一分钟内超过调用上限 | 超出部分拒绝，回 429（`rate_limited`），不论 `on_jev_unavailable` |
| C6 | JSON 凭证站点：用户 A 登录后第一次进入入口，再读取自己的购物车（登录响应里的 `bid`） | 放行，登录响应的值已记入会话；读取他人购物车仍拦截 |
| C7 | 同一地址的两个用户先后登录，两份登录响应的值不同，各自的请求只带各自的凭证 | 各自会话只记入自己的登录值，互不串值 |
| C8 | 请求带的凭证没有对上任何待绑定登录（伪造，或登录来自别处） | 不绑定，判定日志注明 `login_unmatched`，之后的判定与现在相同 |
| C9 | 同一来源地址的 11 个会话（站点设为每会话 2 次，合计 20 次）各调用 | 前 10 个会话各调用 2 次放行；第 11 个会话一次没用过也拒绝，回 429（`rate_limited`），Jev 没有被调用；另一个地址的会话不受影响 |
| G1 | JSON 凭证站点（凭证为 `Authorization` 头）：登录响应里超过 128 字符的长令牌绑定会话；列表放行；登录响应和列表都没给过的患者 D 交 Jev | 登录放行；列表的 `login_request_id` 为该次登录，没有 `login_unbound`；患者 D 拦截，源站不收到请求 |
| G2 | 同一站点：源站没发过的长令牌访问入口 | 放行到源站（源站答 401），判定记录的 `login_unbound` 为 `login_unmatched` |
| W1 | 站点声明 `GET /api/home doctor.id` 为用户身份（[07.9.15](07-console-architecture.md#7915-对象表的身份位置w1)） | 判定记录带会话的用户标签，换账号标签不同；未声明的站点不写身份 |
| W4a | 管理员站点声明管理档搜索 `GET /api/admin/search` 和 `GET /api/home role`：管理员在管理档搜索里搜到医生 B 的患者后删除 | 放行（管理档对管理员会话算正证） |
| W4b | 管理员没在管理档搜索里见过的患者，直接删除 | 拦截（角色不是放行理由） |
| W4c | 管理员在公共搜索里搜到医生 B 的患者后删除 | 拦截（公共档的见过不证明删除） |
| W4d | 管理员在管理档搜索里搜到患者后写备注（POST 子路径） | 放行（备注位置接受公开来源） |
| W4e | 站点声明“我的患者”`GET /api/patients patients[].id` 为 `self`、`DELETE` 不接受公共来源：医生 A 新开会话，看自己的列表后打开、删除自己的患者 | 放行（本人档的展示证明会话见过对象，不调用 Jev） |
| W4f | 同一站点：医生 A 在公共搜索里搜到医生 B 的患者后删除 | 拦截（尝试越权，交 Jev 判 DENY；本人档不放行别人的患者） |
| W4g | 同一站点：医生 A 先在搜索里搜到自己的患者，删除被拦；之后它出现在自己的列表里，再删除 | 第一次拦截（尝试越权）；列表之后再删除放行 |
| W6 | 站点声明身份，评论接口返回另一位医生的手机号与邮箱（[07.9.17](07-console-architecture.md#7917-属性越权告警w6)） | 放行；判定记录的 `trace.response.exposure` 记一条告警且不含值；读取本人资料、未声明身份的站点不告警 |
| F5 | 医生登录后 `POST /api/admin/export`（功能表里的管理档功能） | 拦截，交 Jev 判为越权尝试（Jev 收到的 `function.attempt` 为 `over_privilege`），源站没收到；判定记录的 `trace.function` 带 `tier` 和 `attempt` |
| F5b | 医生新建患者后 `POST /api/patients/{新编号}`，并带请求头 `X-HTTP-Method-Override: DELETE` | 拦截，按更严的 `DELETE /api/patients/{id}` 判为越权尝试；`trace.function.key` 仍是 `POST /api/patients/{id}` |
| F6 | 管理员登录、访问首页后 `POST /api/admin/export` | 放行，快速放行，不交 Jev；`trace.function` 有 `tier`，没有 `attempt` |
| F7 | 医生新建患者后 `DELETE` 它（编号在响应里见过） | 拦截：值已核验，但越权尝试不因此快速放行，交 Jev 判为越权尝试 |
| F8 | 医生 `GET /api/admin/search`（管理档条目可靠性为中） | 与没有条目时相同：不收紧，Jev 收到的 `state` 没有 `function`，源站答 403，网关放行 |
| F9 | 基线站点（开关为真）的医生 `GET /metrics`，功能表里没有它 | 拦截：交 Jev 判为未知功能（`function.known` 为 `false`），Jev 判 DENY |
| F10 | 基线站点的医生 `GET /api/comments`，连续两次 | 第一次交 Jev 放行；第二次走放行缓存，不新增 Jev 调用 |
| F11 | 不带凭证的 `DELETE /api/patients`（入口路径，基线里没有这个方法） | 交 Jev：`state.entry.matched` 为真，`function` 为 `{"known":false}`；Jev 放行，源站答 401 |
| F12 | 没有功能表的站点：医生 `POST /api/admin/export`、`GET /metrics` | 都快速放行，不交 Jev，判定记录没有 `trace.function`（与 F5、F9 对照） |
| F13 | 观察模式的功能表站点：医生 `POST /api/admin/export`、`GET /metrics` | 都转发（源站收到），记为本应拦截 |
| F14 | 基线站点（开关为真，功能表有 `GET /api/patients/{id}`）的医生 `GET /api/patients/export-all`（路由词，不被 `{id}` 覆盖） | 交 Jev：`function.known` 为 `false`，Jev 判 DENY（假 Jev 的 `export-all` 规则），拦截，源站没收到；有效性回归 `p0-3-function-route-word` 的同一请求 |
| F15 | 基线站点（有角色身份位置，开关为真）的管理员 `admin_root` 登录、访问首页后 `GET /metrics` | 放行（源站答 404），不交 Jev，判定记录没有 `trace.function`：管理员会话不判未知功能 |

靶场的站点把地址限额设为最大值 600：每次登录都从同一地址来，同一地址的调用共用一个限额，靶场只测会话限额（`limit.lab`）。会话合计的总额度按来源地址算（[02](02-jev.md) 2.5），所以 `limit.lab` 上的 C5、C9 各自从回环的另一个地址（127.0.0.2、127.0.0.3、127.0.0.4）发请求，其他场景的会话不占它们的总额度。

## 4.4 测试方式

- **CI**：用本地假 Jev 服务（按脚本返回固定概率）跑完 4.3 的全部场景，验证网关的流程、缓存、限流、降级和脱敏。v3 已有的 IDOR 靶场（`tests/security-lab`、`scripts/test_idor_lab.py`）改造成这组场景，不从零重写。
- **真实 Jev**：用同一组场景加一批正常业务流量调用真实 Jev，记录误拦和漏拦。没有实测数据之前，不对外宣称准确率。

  `crates/xshield-judge/tests/live_jev.rs` 是这组真实调用的测试（默认忽略）：`XSHIELD_JEV_ROUTE=direct XSHIELD_JEV_API_KEY=... cargo test -p xshield-judge --test live_jev -- --ignored --nocapture`，每个场景打印一行判定、概率和耗时。

  功能表的真实调用是其中的 `live_function_table`：75 例加 2 条管理员会话的请求（期望放行，不带 `function`），发给四个站点（两个 emr 站点、一个带管理员身份位置的站点、一个商店），每条核对网关送给 Jev 的 `function`。其中 5 例是已知做不到的（`KnownGap`，只打印，不算失败）。同一文件里的 `function_cases_reach_jev_as_intended` 不需要密钥，CI 里用桩模型运行：它只核对每条请求是否带着用例写明的 `function` 送到了模型面前，不核对模型的结论。
- **代码质量**：沿用 `cargo fmt`、`cargo clippy`、`cargo test` 和 `scripts/verify_all.sh`。

v3 的 78 项验收用例目录、性能基线、多浏览器回归、OIDC 回归已随对应功能一起删除。

## 4.5 首次真实 Jev 调用记录

用 TypeSafe `jev-1.13.0` 直连跑了 4.3 的 A1 到 A7、B1、B2 和 31 条场景（包括约 10 条正常业务流量和注入、SSRF、模板注入、NoSQL、批量赋值等变体）：模型调用耗时约 150 到 450 毫秒，其余请求走快速放行不调用模型。第一次跑出两处误判，已修复后全部符合预期：

- 带撇号的正常备注（`O'Brien`）被越权问题判为 DENY：越权指令没有说明自由文本不选择对象，已补充。
- NoSQL 注入 `{"username":{"$ne":null}}` 没有任何值，请求被快速放行：字段名携带语法（`$`、引号、分号等）时，字段名本身作为请求值交给判定。

样本很小，只说明流程和提示词在这组场景上可用，不构成准确率。上线前仍要按 4.2 在观察模式下积累真实流量。

### 4.5.1 Juice Shop 观察模式试跑（Windows，约 4600 条记录）

在用户的 Windows 机器上让 `xshield-edge` 以观察模式挡在 Juice Shop 前面，用浏览器套件（注册、登录、搜索、加购、结算、下单加上约 30 个挑战探针）跑了一遍。良性请求 9/9 放行（观察模式不拦截）；日志里“本应拦截”的 3541 条按原因归类：

- 3323 条 `no_session`：未登录就拉取的引导接口和静态资源（`/rest/admin/application-configuration`、`/socket.io/`、`/api/Challenges/`、`/chunk-*.js` 等）没有登记为入口或放行路径。这是站点配置问题，补进 `entries` 和 `bypass` 即可，不是判定错误。
- 83 条 `jev_unavailable`：全部是 2 秒超时（链路到 TypeSafe 慢）。新增 `XSHIELD_JEV_TIMEOUT_MS`。
- 135 条 `jev_deny`：其中注入登录、`q='` 等是真攻击；误判来自驼峰路由名（`Addresss`、`BasketItems`）被当成未见过的对象值，以及小数字 id 跨对象撞号（篮子 1 与商品 1）。已修：纯字母的非末段路径是路由名；短 id 只有在来源字段或来源请求与当前请求是同一类对象时才算“已见”；嵌套 id 记为 `BasketItem.id`。
- 仍有的已知误判：`POST /rest/basket/N/checkout` 里的 `paymentId` 只以卡片 id 出现过，模型仍以约 0.55 判 DENY。

### 4.5.2 第二轮（修复后重跑，572 条记录）

同一套件、同一站点（补了公共引导接口和静态资源），走 Vercel AI Gateway（TypeSafe 直连在这台机器上返回 451 地区限制）：日志从 4603 条降到 572 条，`no_session` 从 3323 降到 19，剩下的全是真攻击或泄露路径（`/ftp/`、`/metrics`、`/infrastructure/` 等）。Jev 调用中位数约 0.5 秒，p95 约 0.7 秒。25 个预期拦截的探针里 22 个标了“本应拦截”，但其中 8 个（7 个注入加空用户注册）是因为 Jev 地址限流（每分钟 30 次）被未登录页面轮询耗尽，按 `on_jev_unavailable=deny` 记的，并没有真正判定（当时的记录方式；现在超出调用限额的请求一律回 429，不论该设置，见 docs/01 第 1.4 节第 7 步）。由此修了：

- 未登录入口请求的“已判定为无害”结果按地址缓存，重复轮询不再消耗调用额度。
- 列表接口（`/api/Addresss`、`/api/Cards`）被判 DENY：集合名是路由词，`kind` 提示新增 `route`，说明集合名不选择任何对象。
- 商品 id 的来源被库存、ETA 之类的噪声挤出前 3 个来源：来源上限提到 6，满了先丢非 id 字段的来源，排序时同类对象的来源排在最后（模型只看最后几个）。
- 字段名决定对象类别（`ProductId` 是商品，`deliveryMethodId` 是配送方式），裸 `id` 才看所在响应的路径；`Products.id` 出现在购物车响应里也不再让 `/rest/basket/1` 通过。
- 日期值（`Sun Nov 01 2026`、ISO 时间）不再送模型，除非走在 id 类字段名下。

真实 Jev 回归 50 个场景连续 3 次全部符合预期。

### 4.5.3 第三轮（561 条记录）

同一套件、同一站点。日志 561 条：`fast_allow` 395、`cached_allow` 82、`jev_allow` 39、`jev_deny` 26、`no_session` 19，没有 `jev_unavailable`。24 个预期拦截探针里 20 个会被拦（9 个由 Jev 判 DENY：5 个登录注入、2 个搜索注入、跨账号读购物车、空用户注册；11 个是未登录访问 `/ftp/`、`/metrics`、`/redirect` 等的 `no_session`），2 个因 `/assets/*` 绕过没有记录，2 个注册逻辑探针（缺少 passwordRepeat、`role` 批量赋值）按“请求本身无害”判了通过，这类业务规则校验不在 IDOR 和攻击检测的范围内。10 个正常业务请求里只有结算 `POST /rest/basket/N/checkout` 被判 DENY（0.77），另外注册流程里 3 个 `POST /api/SecurityAnswers/` 被判 DENY（0.50 到 0.77），还有未登录取的 `/hacking-instructor-*.js` 静态块被记为 `no_session`。由此修了：

- 没有凭据的入口请求以客户端地址为上下文：注册页对这个地址展示的安全问题和新用户 id 被记住，随后的 `SecurityAnswers` 请求能核对 `UserId`、`SecurityQuestionId`，没展示过的 id（别人的用户）仍然 DENY。
- 网关已经核对过的值（响应里展示过同一个值，且字段与来源同属一类对象）在状态里标 `verified`，提示词要求模型只判断其余的值。结算里 `addressId`、`deliveryMethodId`、`paymentId`、篮子 id 全是展示过的，模型原来仍给 DENY 0.8，现在只剩 `couponData` 一个输入值，判 ALLOW。
- `paymentId` 视为 `/api/Cards` 展示过的卡 id（同义词表），提示词说明字段可以按角色而不是按来源接口命名对象。
- 站点配置：`/hacking-instructor-*` 加入绕过列表（静态懒加载块）。

真实 Jev 回归：新增注册流程和自己结算两个场景，共 52 个。

### 4.5.4 第四轮（548 条记录）

第三轮修复后重跑同一套件：`fast_allow` 386、`cached_allow` 78、`jev_allow` 45、`jev_deny` 21、`no_session` 18，Jev 调用 66 次，中位数 0.55 秒，p95 0.9 秒，无失败、无限流。10 个正常业务请求全部放行，其中结算、注册各步（含 `SecurityAnswers`）和 `/hacking-instructor-*` 都不再误判，没有一条误报。24 个预期拦截探针里 19 个会被拦：7 个注入（2 个搜索、5 个登录）、跨账号读购物车和 11 个未登录访问 `/ftp/`、`/metrics`、`/redirect` 等；其余 5 个中，2 个因 `/assets/*` 绕过没有记录，3 个注册探针（缺 passwordRepeat、`role` 批量赋值、空用户，后者源站也返回 400）判为请求本身无害，属于业务规则校验，不在 IDOR 和攻击检测的范围。不在 24 个探针清单里的 `would_block` 行全是遍历他人购物车（`/rest/basket/N`）以及目录浏览（`/ftp/`、`/infrastructure/`），都是套件自己的探针。

第四轮里 `/assets/*` 绕过掉的两个探针是 `GET /assets/i18n/tlh_AA.json`（源站真实存在的 35 KB 克林贡语翻译文件）和 `GET /assets/public/images/uploads/<未编码的文件名>`（源站对它返回单页应用首页）。两者都只是读静态资源，不涉及对象引用或注入内容，所以按设计跳过判定和记录。随后用 `/assets/../rest/basket/1`、`/assets/%2e%2e/rest/basket/1`、`/assets/..%2frest/basket/1`、`/assets/public/../../ftp/acquisitions.md` 实测：点段、编码的点和斜杠都不命中绕过，照常判定（未登录的记 `no_session`）；`/assets/..;/rest/basket/1`（Tomcat 一类容器把 `..;` 当作点段）原来会命中绕过，现在路径里出现 `;` 一律不命中绕过和入口。

### 4.5.5 功能表回归（2026-11-13，三遍共 222 次调用）

用 TypeSafe `jev-1.13.0` 的直连端点、提示词 `jq_77be488d34440d84`，把 4.4 的 `live_function_table` 连跑三遍。每遍 77 条请求，74 条调用模型，3 条快速放行。调用耗时 170 到 520 毫秒，中位数 210 毫秒，没有超时，也没有限流。

69 条必须符合预期的请求，三遍全部符合：

- 管理档功能上的尝试越权 4 条（`POST /api/admin/export`、`GET /api/audit-logs`、`PUT /api/staff/{id}/role`、`GET /api/settings/clinic`）全部被拦，DENY 概率不低于 0.98。最后一条的路径名看不出是管理功能，靠的是功能表里的管理档。
- 功能表里没有、名字显示管理或运维功能的 29 条（`/metrics`、`/actuator/env`、`/.env`、`/backup.sql`、`/ftp/` 等）全部被拦。其中 `DELETE /api/patients`（DENY 0.64 到 0.73）和 `POST /api/permissions/grant`（0.63 到 0.77）离平局较近。
- 功能表里没有的普通接口 30 条全部放行，DENY 概率最高的是 `GET /api/wards/occupancy`（0.21 到 0.37）。
- 不带 `function` 的对照 6 条不受新指令影响：没展示过的病人编号仍被拦（DENY 1.00），其余 5 条放行。

6 条已知做不到的（`KnownGap`，只记录，不算失败）：

| 请求 | 想要的结论 | 三遍的结果 | 原因 |
|---|---|---|---|
| `GET /api/patients/export-all` | 拦 | 三遍都放行，没有问模型 | 功能表里 `GET /api/patients/{id}` 的 `{id}` 盖住了 `export-all` 这个路由词，请求被当成已知功能快速放行 |
| `GET /trace` | 拦 | 拦了一遍（DENY 0.44 到 0.50） | 接近平局 |
| `GET /api/accounts/all` | 拦 | 拦了两遍（DENY 0.47 到 0.53） | 接近平局 |
| 商店 `GET /api/Users` | 拦 | 三遍都放行（DENY 0.05 到 0.07） | 路径名看不出是全部用户的列表 |
| 商店 `GET /redirect?to=https://example.org/x` | 拦 | 三遍都放行（`access` 答 ALLOW 约 0.90，`attack` 的 ATTACK 概率 0.41 到 0.45） | 功能表管不到开放重定向，要靠 `attack` 问题，而它在这条上接近平局 |
| `GET /api/config/ui` | 放行 | 三遍都被拦（DENY 0.92 到 0.95） | 普通接口，路径里的 `config` 被当成配置功能。这是误拦 |

另外两条只记录的请求：被认作管理员的会话请求功能表里没有的 `GET /api/admin/reports` 和 `GET /api/admin/users/export`，三遍都被拦（DENY 0.99 和 1.00）。这说明打开“未知功能交 Jev”之后，管理员用到没有进功能表的管理接口也会被拦，打开之前要先把这些接口加进功能表。

样本很小，只说明这组请求上的表现，不构成准确率。

合入 PR 209 之后提示词变为 `jq_d5df87392a92b44d`，2026-11-13 在合并后的代码上又跑了一遍（74 次调用，耗时 179 到 370 毫秒）：69 条必须符合预期的请求全部符合。`DELETE /api/patients`（DENY 0.64）和 `POST /api/permissions/grant`（0.62）仍离平局较近；普通接口里 DENY 最高的仍是 `GET /api/wards/occupancy`（0.29）。6 条已知做不到的结果与前三遍在同一范围：`GET /trace` 这一遍被拦（DENY 0.53），`GET /api/accounts/all` 放行（0.44），商店 `/redirect?to=` 放行（ATTACK 0.37），`GET /api/config/ui` 仍被误拦（0.92），其余两条放行。
