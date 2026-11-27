# 实现规划 T6：功能表的真实 Jev 回归用例

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 9、16 节。预检的脚本和用例在 [function-level-authz-probe/](function-level-authz-probe/)（`jev_probe.py` 的 `CASES` 34 例和 `HELD` 41 例）。上线那版指令的原始结果 `out_draft3.json`、`held_draft3.json` 没有入库，见 [导入说明](../README.md)。
- 前置：T4（PR 215，判定使用功能表）合入 `main`。不依赖 T5a、T5b。开工前 `git fetch origin main`，以最新 `main` 为准。
- 范围：`crates/xshield-judge/tests/live_jev.rs`、docs/04 4.4。**不改**任何 `src/` 下的代码、判定指令、`fake_jev.py`、靶场、`migrations/`、`.github/`、`deny.toml`，不加依赖。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审，**真实模型的那一遍由验收人来跑**。
- **密钥**：实现线程不需要密钥，不要向任何人要，也不要运行带 `--ignored` 的真实调用。本规划里的每一步都能在没有密钥的情况下完成和验证（2.4 的不忽略测试就是为此设的）。
- 规格里写了 **STOP** 的地方，停下来在 PR 或线程里问验收人。

## 1. 要解决的问题

判定指令里说明 `state.request.function` 的那一段是对着真实模型调出来的，逐字保留。但调它用的 75 个用例只在一个临时脚本里，脚本自己拼 `state`，不经过网关的代码。以后有人改指令、改 `state` 的形状、换模型版本，没有东西能告诉他第 2、3 层的判断变没变。本 PR 把这 75 例搬进 `live_jev.rs`，让请求真的走 `Judge`：站点带功能表，会话由 `observe` 建立，`state` 由网关生成。

## 2. 规格

### 2.1 三个站点

写成 `live_jev.rs` 里的三个函数，都是拦截模式，`session` 为 Cookie `SID`。对象表的 JSON 写法照 `crates/xshield-judge/src/engine.rs` 测试里的 `functions_site`、`asking_site`（T4 加的）。

| 站点 | 入口 | 功能表 | 用途 |
|---|---|---|---|
| `emr-base` | `/login`、`/api/home`、`/api/patients` | 已知功能：`GET /login`、`POST /login`、`GET /api/home`、`GET /api/patients`、`POST /api/patients`、`GET /api/patients/{id}`、`GET /api/patients/{id}/notes`。没有管理档。`ask_unknown_functions: true` | 第 3 层的用例和对照 |
| `emr-admin` | 同上 | 上面七条，加四条 `tier: admin`、`reliability: high`：`POST /api/admin/export`、`GET /api/audit-logs`、`PUT /api/staff/{id}/role`、`GET /api/settings/clinic`。`ask_unknown_functions: true` | 第 2 层的用例 |
| `shop` | `/rest/user/login`、`/rest/user/whoami` | 已知功能：`POST /rest/user/login`、`GET /rest/user/whoami`、`GET /rest/products/search`、`GET /api/BasketItems`、`GET /rest/basket/{id}`、`GET /rest/order-history`。`ask_unknown_functions: true` | 仿 Juice Shop 的那 13 例 |

`shop` 的 `GET /rest/order-history` 在脚本里是未知功能（“该放”的一例）。这里要让会话先看到订单号，所以它必须是已知的：这一例改成对照（不带 `function`），2.3 的表里已按此计数。

### 2.2 会话

每个站点一个普通用户的会话，用 `observe` 建立（照本文件现有测试的写法，`Observation` 的字段以届时代码为准）：

- `emr-base` 和 `emr-admin`，凭证 `doctorA`：依次观察 `GET /api/home`（200，`{"doctor":{"id":"DR-A"}}`）、`GET /api/patients`（200，含 `{"id":"7005"}` 在内的三四个患者）、`GET /api/patients/7005`（200）、`GET /api/patients/7005/notes`（200）。这样 `7005` 是见过的值，最近请求与脚本里的 `RECENT` 相同。
- `shop`，凭证 `shopper`：依次观察 `GET /rest/user/whoami`、`GET /rest/products/search`、`GET /api/BasketItems`、`GET /rest/basket/6`、`GET /rest/order-history`（200，含 `{"orderId":"5267-f73dcd000abcc353"}`）。

两个 `emr` 站点都不声明身份位置：没有角色声明的站点上所有会话都不是管理员，第 2 层的四例因此都是尝试越权，与脚本一致。

### 2.3 用例

把 `jev_probe.py` 的 `CASES` 和 `HELD` 逐条搬过来，路径、方法、请求值与脚本相同（脚本里手写的 `values` 换成真实的查询串或 JSON 正文，让网关自己提取）。每条用例在现有的 `Case` 之外多声明两样：

- `function`：期望网关送给 Jev 的 `state.request.function`，三选一：`Unknown`（`{"known":false}`）、`Attempt`（`{"tier":"admin","attempt":"over_privilege"}`）、`None`（没有这个字段）。
- `status`：`Must`（真实模型的结论必须与 `expect_block` 一致）或 `KnownGap`（今天做不到，见下表）。

分到三个站点：

| 站点 | 来源 | 条数 | 说明 |
|---|---|---|---|
| `emr-base` | `CASES` 的 `L3-deny` 13、`L3-allow` 12、`control` 5 | 30 | 对照 5 例的 `function` 是 `None`；其中“登录表单”不带凭证，走入口 |
| `emr-admin` | `CASES` 的 `L2-deny` 4 | 4 | `function` 是 `Attempt` |
| `emr-base` | `HELD` 里不带 `shop` 前缀的：该拦 15、该放 13 | 28 | `function` 是 `Unknown` |
| `shop` | `HELD` 里带 `shop` 前缀的：该拦 6、该放 7 | 13 | `GET /rest/order-history` 是 `None`（见 2.1），其余 `Unknown`；`GET /rest/track-order/5267-f73dcd000abcc353` 是未知功能加一个会话见过的订单号 |

合计 75 例。`KnownGap` 只有这三条，照预检的结果定：

| 用例 | 想要的结论 | 今天的结论 | 原因 |
|---|---|---|---|
| `GET /trace` | 拦 | 放（ALLOW 0.50 对 DENY 0.49） | 接近平局 |
| shop `GET /api/Users` | 拦 | 放（ALLOW 0.90） | 路径只是集合名，模型看不出是管理接口；这类靠第 2 层 |
| `GET /api/config/ui` | 放 | 拦（DENY 0.94） | 名字像配置接口 |

其余 72 例是 `Must`。其中 shop `GET /redirect?to=https://example.org/x` 的预期是拦：预检里 `access` 答 ALLOW，`attack` 答 ATTACK，结论仍是拦，用例只看是否转发。

另外加两条**只记录、不判对错**的用例（`status` 为 `Observe`），用来回答一个还没定的问题：管理员会话请求一个功能表里没有、名字像管理接口的路径，会不会被第 3 层拦住。为它们加第四个站点 `emr-role`：与 `emr-admin` 相同，另声明一个角色身份位置，会话 `adminA` 的 `GET /api/home` 响应声明角色 `admin`（写法照 `engine.rs` 里 T4 的管理员会话测试）。两条用例：`adminA` 请求 `GET /api/admin/reports` 和 `GET /api/admin/users/export`。期望的 `function` 是 `Unknown`。

### 2.4 两个测试

**(a) 不忽略的测试 `function_cases_reach_jev_as_intended`**（CI 会跑，不需要密钥）。在本文件里写一个 `JevPort` 的桩实现：每次都答 ALLOW、BENIGN（应答的字节格式照 `engine.rs` 测试里 `FakeJev` 的 `ask`），不发网络请求。用它建 `Judge`，把四个站点的会话建好，逐条判定 77 个用例，对每条断言：

- `function` 为 `Unknown` 或 `Attempt` 的用例：调用了 Jev，判定记录里 `jev.state` 的 `request.function` 与期望逐字相等，`trace.function` 存在。
- `function` 为 `None` 的用例：如果调用了 Jev，`jev.state` 的 `request` 里没有 `function`；`trace.function` 为空。
- 标了“`7005` 已见”的用例：`jev.state` 里那个值的 `verified` 为真。
- 没有一条是 `JevUnavailable`（下面的调用上限没有被碰到）。

这个测试证明用例真的把想测的情况送到了模型面前。它失败说明用例或站点写错了，不是模型的问题。

**(b) 忽略的测试 `live_function_table`**（`#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]`，与本文件其他测试相同）。同样的站点、会话和用例，`Judge` 用 `JevClient::from_environment()`。逐条打印一行（沿用 `run` 的格式，另加 `status` 和 `access` 的三个概率），然后：

- `Must` 的结论与 `expect_block` 不一致：记入错误列表，最后 `assert!` 失败并列出名字。
- `KnownGap`：打印今天的结论。与“想要的结论”一致时多打印一行 `now as wanted: <名字>`，**不算失败**（接近平局的答案会来回变，不能让它决定测试的成败）。
- `Observe`：只打印。
- 任何一条得到 `JevUnavailable` 且 `Unjudged`：失败（沿用 `run` 里“the live provider must answer”的断言）。

两个测试共用同一份用例表和同一套建站点、建会话的函数，不要各写一份。

### 2.5 调用上限

一个会话每分钟最多 60 次 Jev 调用，`emr-base` 上有 58 例，`run` 现在让相邻用例只差 1 毫秒。不要改上限，也不要改 `run` 影响别的测试：把每个站点的用例分成不超过 20 条一组，各组的 `start_ms` 相隔 120,000 毫秒。会话 24 小时不活动才过期，不受影响。

### 2.6 不做的

- 不改指令。真实模型的结果与预期不符时，本 PR 不去调指令：把结果交给验收人（见第 5 节）。
- 不把真实调用接进 CI，不加工作流。
- 不动 `jev_probe.py`：它留在设计目录里作为当时的记录。

## 3. 检查

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`（其中 `cargo test -p xshield-judge --test live_jev` 应显示 (a) 通过、(b) 和原有的真实调用测试被忽略）、`cargo test --workspace --doc`
- 只改了测试文件，靶场、`test_postgres.sh`、`fuzz/`、控制台、`cargo deny` 可以不跑，在 PR 里写明。
- **不要运行** `-- --ignored`。

不加 `#[allow]`（本文件开头已有的 `clippy::too_many_lines` 不算新增；函数过长时把用例表拆成几个返回 `Vec<Case>` 的函数）。测试文件里可以用 `expect`、`unwrap`。用例里的凭证、令牌都是一眼看得出的合成值（`doctorA`、`shopper`、`adminA`），不要写像真密钥的字符串；`check_secrets.py` 报了就改值，不要往 `ALLOW` 里加。

## 4. 文档

- docs/04 4.4“真实 Jev”一条：补一句，功能表的回归是 `live_function_table`，75 例加 2 条只记录的，其中 3 条是已知做不到的；并说明 (a) 那个不需要密钥的测试是做什么的。
- docs/04 4.5 的实测记录由验收人在跑完之后补（见第 5 节），实现线程不写数字。
- 只加测试，没有用户可见的行为变化，不写 CHANGELOG。
- PR 描述按 `templates/pull-request.md` 的五个标题写，写明真实调用没有运行、由验收人运行。提交标题用英文 Conventional Commits，例如 `test(judge): regress the function table against the live model`。提交信息、PR、代码注释里不写模型名（`jev-1.13.0` 这样的被测模型版本可以写）。

## 5. 验收

1. 2.3 的 77 条用例都在，路径、方法、请求值与 `jev_probe.py` 逐条对得上（验收人用脚本比对）；`KnownGap` 恰好是那三条。
2. (a) 在 CI 里通过。验收人做一次变异：把 `emr-base` 的 `ask_unknown_functions` 去掉，(a) 必须失败。
3. `git diff main --stat` 里只有 `crates/xshield-judge/tests/live_jev.rs` 和 `docs/04-deployment-testing.md`。
4. 第 3 节的检查都跑过并通过。
5. **真实调用由验收人执行**：用户提供的密钥只经环境变量传入，不进文件、提交、PR、日志。连续跑三遍 `live_function_table`（每遍 77 次调用，共约 231 次，开跑前先告诉用户这个数）。通过的标准：72 条 `Must` 三遍都与预期一致。
   - 有 `Must` 用例三遍里结论不一致，或稳定地与预期相反：验收人把三遍的概率贴进 PR，决定是把它降为 `KnownGap`（接近平局、且不是运维或管理类的硬指标）还是判定这一版指令或模型有退步而不合并。实现线程不自行改 `status`。
   - 两条 `Observe` 的结果由验收人整理后报给用户，用来决定管理员会话是否豁免第 3 层。
6. 验收人把这次实测的日期、模型版本、三遍的结果和 `KnownGap` 清单补进 docs/04 4.5，随本 PR 合并（这一处文档由验收人给出文字，实现线程提交）。
7. 有效性回归用例：本 PR 不改判定，没有对应用例。

## 6. 依赖和顺序

- **依赖**：T4 合入。
- **会改变预期的在途改动**：WAF 批次 7（置信度门槛）合入后，接近平局的答案可能按门槛处理成“答不上来”，`POST /api/users/{id}/impersonate`（0.76）、`GET /api/accounts/all`（0.58）、`POST /api/permissions/grant`（0.61）、`GET /api/wards/occupancy`（0.71）这四条 `Must` 的结论可能随之变化。批次 7 先合入时，这四条按届时的行为重新定预期，在 PR 里写明并 **STOP** 请验收人确认；本 PR 先合入时，批次 7 的验收会用到这个测试。T1（未认可的凭证）合入后会话仍由入口的 2xx 建立，2.2 的写法不受影响；`shop` 的第一个观察要落在入口上（`/rest/user/whoami` 是入口）。
- **冲突热点**：`live_jev.rs` 末尾。其他在途改动给 `RequestFacts`、`Observation` 加字段时，后合并的一方补齐字面量。
