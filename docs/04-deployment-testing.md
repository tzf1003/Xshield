# 04 部署与验收

## 4.1 部署形态

首版参考部署只有一种：单机 Docker Compose，包含网关、控制台和 PostgreSQL 三个服务。源站不需要接入 SDK，也不需要注入脚本。

多实例部署需要先把会话上下文换成共享存储（见 [01.2](01-request-flow.md#12-会话与上下文)），在那之前不提供 Helm、systemd 等其他参考部署。v3 的 `deploy/helm`、`deploy/systemd`、`deploy/prometheus` 在代码改造时删除。

## 4.2 上线步骤

1. 部署网关、控制台和 PostgreSQL，设置 [03.3](03-admin-config-audit.md#33-部署级环境变量) 列出的环境变量。
2. 在控制台新建站点，填写源站、会话凭证位置、入口和静态资源路径。站点默认处于观察模式。
3. 把流量切到网关，正常使用一段时间。
4. 在判定日志里查看"本应拦截"的记录：确认是真正的越权或攻击，还是漏登记的入口、Jev 误判。漏登记的入口补到 `entries`。
5. 误判可以接受之后，切到拦截模式。

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
| B1 | 搜索框、表单里输入正常中文和英文文本 | 放行 |
| B2 | 参数里带注入、命令执行、路径穿越类内容 | 拦截 |
| C1 | Jev 超时或不可用，`on_jev_unavailable=deny` | 拦截，日志注明 |
| C2 | 同上，`on_jev_unavailable=allow` | 放行，日志注明"未经判定" |
| C3 | 观察模式下的 A2 | 转发，日志记"本应拦截" |
| C4 | 登录请求 | 口令字段不出现在发给 Jev 的内容里 |
| C5 | 同一会话一分钟内超过调用上限 | 超出部分按 `on_jev_unavailable` 处理 |

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
