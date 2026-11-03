# 04 部署与验收

## 4.1 部署形态

首版参考部署只有一种：单机 Docker Compose，包含网关、控制台和 PostgreSQL 三个服务。源站不需要接入 SDK，也不需要注入脚本。

多实例部署需要先把会话上下文换成共享存储（见 [01.2](01-request-flow.md#12-会话与上下文)），在那之前不提供 Helm、systemd 等其他参考部署。v3 的 `deploy/helm`、`deploy/systemd`、`deploy/prometheus` 在代码改造时删除。

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
| B1 | 搜索框、表单里输入正常中文和英文文本 | 放行 |
| B2 | 参数里带注入、命令执行、路径穿越类内容 | 拦截 |
| C1 | Jev 超时或不可用，`on_jev_unavailable=deny` | 拦截，日志注明 |
| C2 | 同上，`on_jev_unavailable=allow` | 放行，日志注明"未经判定" |
| C3 | 观察模式下的 A2 | 转发，日志记"本应拦截" |
| C4 | 登录请求 | 口令字段不出现在发给 Jev 的内容里 |
| C5 | 同一会话一分钟内超过调用上限 | 超出部分按 `on_jev_unavailable` 处理 |
| W1 | 站点声明 `GET /api/home doctor.id` 为用户身份（[07.9.15](07-console-architecture.md#7915-对象表的身份位置w1)） | 判定记录带会话的用户标签，换账号标签不同；未声明的站点不写身份 |
| W4a | 管理员站点声明管理档搜索 `GET /api/admin/search` 和 `GET /api/home role`：管理员在管理档搜索里搜到医生 B 的患者后删除 | 放行（管理档对管理员会话算正证） |
| W4b | 管理员没在管理档搜索里见过的患者，直接删除 | 拦截（角色不是放行理由） |
| W4c | 管理员在公共搜索里搜到医生 B 的患者后删除 | 拦截（公共档的见过不证明删除） |
| W4d | 管理员在管理档搜索里搜到患者后写备注（POST 子路径） | 放行（备注位置接受公开来源） |

靶场的站点把地址限额设为最大值 600：每次登录都从同一地址来，同一地址的调用共用一个限额，靶场只测会话限额（`limit.lab`）。

## 4.4 测试方式

- **CI**：用本地假 Jev 服务（按脚本返回固定概率）跑完 4.3 的全部场景，验证网关的流程、缓存、限流、降级和脱敏。v3 已有的 IDOR 靶场（`tests/security-lab`、`scripts/test_idor_lab.py`）改造成这组场景，不从零重写。
- **真实 Jev**：用同一组场景加一批正常业务流量调用真实 Jev，记录误拦和漏拦。没有实测数据之前，不对外宣称准确率。

  `crates/xshield-judge/tests/live_jev.rs` 是这组真实调用的测试（默认忽略）：`XSHIELD_JEV_ROUTE=direct XSHIELD_JEV_API_KEY=... cargo test -p xshield-judge --test live_jev -- --ignored --nocapture`，每个场景打印一行判定、概率和耗时。
- **代码质量**：沿用 `cargo fmt`、`cargo clippy`、`cargo test` 和 `scripts/verify_all.sh`。

v3 的 78 项验收用例目录、性能基线、多浏览器回归、OIDC 回归在代码改造时随对应功能一起删除。

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

同一套件、同一站点（补了公共引导接口和静态资源），走 Vercel AI Gateway（TypeSafe 直连在这台机器上返回 451 地区限制）：日志从 4603 条降到 572 条，`no_session` 从 3323 降到 19，剩下的全是真攻击或泄露路径（`/ftp/`、`/metrics`、`/infrastructure/` 等）。Jev 调用中位数约 0.5 秒，p95 约 0.7 秒。25 个预期拦截的探针里 22 个标了“本应拦截”，但其中 8 个（7 个注入加空用户注册）是因为 Jev 地址限流（每分钟 30 次）被未登录页面轮询耗尽，按 `on_jev_unavailable=deny` 记的，并没有真正判定。由此修了：

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
