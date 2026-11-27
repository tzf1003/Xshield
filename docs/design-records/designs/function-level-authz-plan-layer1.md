# 实现规划 T1：凭证被源站认可才算会话（功能级越权第 1 层）

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 4 节。用户在 2026-11-13 确认了第 15 节第 1 题。
- 基线：`main` `d9cf90a`（2026-11-13 16:55Z 复核：WAF 批次 1、2、4、11 和 PR #213、#228、#211 都已合入，第 2、4、7、8 节按它们改过；第 1 节的现象、`Turn::unconfirmed`、`SessionContext::unconfirmed`、`observe` 开头“入口 2xx 就建会话”和后面 `seeded` 对任意 2xx 建会话的写法都还在）。开工前先 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-judge`、`xshield-core`（一个小函数和一个 trace 字段）、docs、靶场、CHANGELOG。**不改** `xshield-control`、`web/console`、`migrations/`、`.github/`、`deny.toml`。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。

## 1. 要解决的问题

在 `main` 上实测（拦截模式，假 Jev）：

| 请求 | 不带 Cookie | 带 `SID=made-up` |
|---|---|---|
| `GET /metrics` | 401 `no_session` | `fast_allow`，0 次 Jev |
| `GET /api/admin/export` | 401 `no_session` | `fast_allow`，0 次 Jev |
| `GET /users/alice` | 401 `no_session` | `fast_allow`，0 次 Jev |

而且这个被放行的请求一旦得到源站的 2xx，`observe` 就为假凭证建了会话。原因：PR 193 之后，没有会话的凭证按“一个空会话”判定（`engine.rs` 里的 `Turn::unconfirmed`），没有请求值时仍然走 `FastAllow`；`observe` 里的 `seeded` 对任意路径的 2xx 都建会话。

PR #213（`6e5b55f`）没有改变这张表：它只让源站**拒绝**的凭证（非 2xx）不再建会话，并把这类凭证的请求值放进会话表之外的暂存（`context.rs` 的 `PendingSent`）。公开页面答 2xx 时假凭证照样建会话（WAF 规划 11a 节在 `main` 上实测过）。

## 2. 行为规格

用词：**已认可**指网关里有这个凭证的活会话（`ContextStore::existing` 返回 `Some`）。**未认可**指请求带了非空凭证，但没有活会话。**用户身份站点**指对象表里至少有一条未暂停、`identity: user` 的条目。

### 判定（`Judge::judge`）

- **R1 先尝试登录绑定，任何路径都试。** 凭证没有活会话时调用 `ContextStore::start_from_login`。现在这一步只在入口请求上做，改为不看是不是入口。绑定成功，凭证即已认可，会话带着登录响应的值和身份。
- **R2 未认可的凭证按没有凭证处理。** R1 之后仍未认可的：
  - 非入口路径：`DecisionPath::NoSession`，401，不调用 Jev，不创建任何上下文。
  - 入口路径：用客户端地址的上下文判定（与没带凭证的入口请求走同一条路），Jev 额度记在地址上。
  - 不查也不写放行缓存里属于这个凭证的条目（它没有会话）；管理员判断为否。
  - 功能表（PR 215 的 `function_view`）不需要特别处理，与没带凭证的请求一致：非入口的 401 发生在功能表判定之前，判定记录里有没有 `trace.function` 以没带凭证的同一请求为准；入口上照常算功能视图，管理员判断为否。
  - 删除“空会话”这条路：`Turn::unconfirmed` 和 `SessionContext::unconfirmed` 不再需要。
- **R3 判定记录。** 未认可的凭证：`record.session` 为空串，`record.context` 在入口上是 `address`、其他路径是空，与没带凭证的请求相同。另在 trace 上加一个布尔字段 `unrecognized_credential`（`xshield-core` 的 `Trace`，`#[serde(default, skip_serializing_if = …)]`，为假时不写出），请求带了未认可的凭证时为真。这样现有 SQL 里“`session <> ''` 即有会话”的含义不变，而“带了凭证却没有会话”的请求可以按这个字段数出来。
- **R4 绑定失败的原因照旧记录。** 入口请求上绑定失败时，`trace.session.login_unbound` 仍写 `login_unmatched`、`login_expired` 或 `login_ambiguous`。非入口请求被 R2 拒绝，没有 `trace.session`，不记原因。

### 学习（`Judge::observe`）

- **R5 本应拦截的请求，其响应不建立也不认可任何会话。** “不学值、不暂存登录、不声明身份、不记入口和近期访问”由另一份规划的批次 4 实现（[waf-p0-fix-plan.md](../plans/waf-p0-fix-plan.md) 第 5 节，P1-5 的学习部分），**本 PR 以批次 4 已合入为前提，不重做那部分**。本 PR 在它之上只补一条：`observation.would_block` 为真时，不为请求上的凭证建立会话（S3、S4 都不算），也不为响应下发的凭证建立会话。批次 4 的测试 3 现在断言“新凭证的会话没有任何已见值”，本 PR 把它改成“新凭证没有会话”。理由：拦截模式下这个请求到不了源站，这次下发根本不会发生。
  - 响应下发的凭证不建会话之后，这次请求发出的值仍要记到下发的那个凭证名下（`ContextStore::note_sent`，落进暂存 `PendingSent`，请求凭证已有的暂存照旧带过去），它之后被认可时带入。现在 `would_block` 分支里是建了会话再 `inherit_sent`、`note_sent`，改成只记暂存。测试：观察模式下本应拦截的登录请求发出值 X 并得到下发的凭证，凭证之后在入口被认可，响应回显 X，X 没有被学成已见。
  - 也不认领暂存的登录：`observe` 开头“入口 2xx 就 `start_session`”的那一段（它会 `held.claim`）在 `would_block` 时不执行。批次 4（PR #208）有意没动这一段，留给本条。判定阶段 R1 的 `start_from_login` 不受这一条限制：它发生在结论之前，凭的是凭证与登录响应里的令牌相符，不是这次响应。
- **R6 认可的依据。** 请求带着未认可的凭证、响应不是 `would_block` 时，按下面的顺序判断这次响应是否认可它：
  - S1 下发：响应下发了凭证（`issued_credential`）。下发的那个凭证建立会话，现有逻辑不变。
  - S3 身份声明：用户身份站点上，这个 2xx 响应在 `identity: user` 的位置上声明了用户，并且这个值不是请求自己发出的（不在 `observation.sent` 和 `observation.echo` 里）。认可请求上的凭证，建立会话。
  - S4 入口应答：**不是**用户身份站点，请求路径是入口，响应是 2xx。认可请求上的凭证，建立会话（沿用 `ContextStore::start_session`）。
  - 其余情况不认可。尤其是：用户身份站点上，入口的 2xx 如果没有声明用户，不认可；任何站点上，非入口路径的 2xx 都不认可。
- **R7 新会话先记下本次请求发出的值，再学这个响应。** 由 S3、S4 建立的会话，在 `remember` 和 `declare_identity` 之前先 `note_sent(observation.sent)`，与现在下发凭证时的做法一致，免得请求里的值靠回显变成“见过”。PR #213 之后这件事多半已经由暂存做到：`note_request_sent` 先把值记进凭证的暂存，`ContextStore::session` 建会话时带入。实现时核对 S3、S4 和判定阶段 `start_from_login` 这三条建会话的路径都带入了暂存，并各有测试；规则不变，写法以届时代码为准。
- **R8 没被认可时响应进地址上下文。** 请求带未认可的凭证、落在入口上、响应 2xx 而没有认可它时，值按“没带凭证的入口响应”处理：记入客户端地址的上下文；满足现有条件的 JSON 登录响应照常暂存为待绑定登录。
- **R9 未认可凭证的请求值记在哪。** PR #213 之后 `note_request_sent` 和判定阶段的 `stop_learning` 已经不为凭证创建上下文：它们走 `ContextStore::note_sent`、`ContextStore::stop_learning`，凭证没有会话时写进暂存 `PendingSent`，会话建立时带入。**这层暂存保留，本 PR 不删也不绕开**：它要挡的事在本 PR 之后仍然存在（观察模式下本应拦截的请求照常到源站，它发出的值之后可能被别的响应回显；凭证后来被认可时，新会话不能把这些回显学成见过）。在它之上只补一条：
  - 凭证已认可：记进它的会话（现状）。
  - 未认可，请求落在入口上：请求按 R2 在地址上下文里判定，响应按 R8 可能学进地址上下文，所以 `sent` 和 `stop_learning` **两处都记**，凭证的暂存和地址上下文。只记暂存的话，R8 学进地址上下文的值里会混进这次请求的回显。
  - 未认可，不在入口上（只会是观察模式下本应拦截的请求）：只记进凭证的暂存（现状）。拦截模式下这类请求在判定阶段就被 R2 拒绝，到不了 `observe`，暂存不会增长。
  - WAF 批次 5 会把 `sent` 和这层暂存整体删除。它先合入的话本条随之消失，只剩“不为未认可的凭证创建上下文”这一句要成立。

### 不变的行为

- 已认可的会话：判定、缓存、额度、学习都与现在相同。
- 没带凭证的请求：与现在相同。
- `bypass` 路径：与现在相同。
- 登录跳转下发 Cookie（302 加 `Set-Cookie`）：与现在相同。
- 提示词和 `state`：不变，`Prompt` 的 id 不变（测试 `the_prompt_id_is_fixed_and_follows_the_questions` 不应改动）。

## 3. 改动位置

| 文件 | 改什么 |
|---|---|
| `crates/xshield-core/src/context/objects.rs` | 新增 `ObjectMap::declares_user_identity(&self) -> bool`（未暂停且 `identity == Some(IdentityRole::User)` 的条目存在）。带单元测试：有、没有、只有暂停的、只有 `org` 或 `role` 的 |
| `crates/xshield-core/src/context/trace.rs` | `Trace` 增加 `unrecognized_credential: bool`（R3） |
| `crates/xshield-judge/src/engine.rs` | `judge`：R1 到 R4。`plan`、`admit`、`ask_jev` 里凡是用 `turn.session_id` 取会话的地方改用“已认可的会话 id”。`observe`、`note_request_sent`、`stop_learning`：R5 到 R9 |
| `crates/xshield-judge/src/context.rs` | 删除 `SessionContext::unconfirmed`；如有需要，为 S3 增加“为凭证建立会话并记下 `sent`”的方法 |
| `crates/xshield-control/src/object_learning.rs` | **唯一允许的改动**：`identified_by` 改为调用 `ObjectMap::declares_user_identity`，免得两处各写一份定义。不改别的 |
| `docs/01-request-flow.md` | 1.2 第二段（会话何时建立）、1.4 第 2 步、1.7 的“绑定”（不再限于入口）和“不绑定” |
| `docs/02-jev.md` | 2.5 里关于未认可凭证额度的一句 |
| `docs/04-deployment-testing.md` | 4.3 场景表：新增 F1 到 F4（排在 F5 之前），改 C8 的预期（C8 只在文档的表里，靶场脚本没有这个场景，不用为它加） |
| `docs/07-console-architecture.md` | 7.4.3 的 trace 字段表加 `unrecognized_credential`；7.4.6（批次 4 已改写）补一句“也不建立会话” |
| `schemas/decision-record.schema.json` | trace 加 `unrecognized_credential`（`python3 scripts/validate_library.py` 会校验示例） |
| `CHANGELOG.md` | `Unreleased` 顶部加一条中文记录，写明对正常用户的影响（见第 6 节） |
| `tests/security-lab/idor_origin.py`、`scripts/test_idor_lab.py`、`tests/security-lab/README.md` | 场景 F1 到 F4 |
| `tests/security-lab/effectiveness/regressions.py` | `p0-3-fake-cookie-metrics`、`p0-3-fake-cookie-export` 由 `known_gap` 翻成 `must`（第 7 节第 10 条） |

`engine.rs` 里的 `judge` 和 `observe` 已经带 `#[allow(clippy::too_many_lines)]`。不要新增 `#[allow]`；函数变长时拆出私有函数。

## 4. 测试

### 4.1 单元测试（`engine.rs` 的 `mod tests`，假 Jev）

新增，名字可以调整，断言不能少：

| 测试 | 断言 |
|---|---|
| `an_unrecognized_credential_is_refused_off_an_entry` | 拦截模式，`made-up` 访问 `GET /metrics`、`GET /api/admin/export`、`GET /users/alice`、带未见值的 `GET /api/patients/8`：都是 `NoSession`、`forward == false`、`refuse_status == 401`、`fake.calls() == 0`、`store.len() == 0`、`record.session` 为空、`record.trace.unrecognized_credential` 为真 |
| `an_unrecognized_credential_on_an_entry_is_judged_as_its_address` | `made-up` 访问入口：`record.context == Some(Address)`，带未见值时 Jev 额度记在地址上（沿用 `a_credential_without_a_session_spends_the_budget_of_its_address` 的做法，路径换成入口） |
| `an_origin_2xx_off_an_entry_recognizes_nothing` | 对 `made-up` 调 `observe`，路径 `/metrics`，状态 200：`store.len()` 不变 |
| `a_would_block_response_recognizes_nothing` | `would_block: true` 的 2xx 响应，分别在无身份站点的入口上、在用户身份站点上带用户声明、以及带 `issued_credential`：三种情况 `store.len()` 都不变，请求上的凭证和下发的凭证都没有会话 |
| `a_would_block_entry_response_claims_no_held_login` | 先让一个 JSON 登录响应被暂存，再让带着登录下发的那个凭证、`would_block: true` 的入口 2xx 经过 `observe`：没有会话建立，暂存的登录还在；之后同一个凭证的下一个请求在判定阶段绑定成功，`trace.session.login_request_id` 指向那次登录，登录响应的值已见 |
| `values_sent_before_recognition_are_not_learned_from_an_echo` | 观察模式，未认可的凭证在非入口发出未见值 X（本应拦截）；之后凭证被认可，三种方式各一遍（S4 入口 2xx、S3 身份声明、判定阶段登录绑定）；认可它的那个响应或其后的响应回显 X：X 没有被学成已见 |
| `an_unrecognized_entry_request_notes_what_it_sent_in_the_address_context` | 用户身份站点，未认可的凭证在入口发出值 X，响应 2xx 没有声明用户并回显 X：地址上下文没有把 X 学成已见（R8、R9） |
| `an_entry_2xx_recognizes_a_credential_on_a_site_without_user_identity` | 无身份站点，入口 200：会话建立，之后非入口的无值请求 `FastAllow` |
| `an_entry_2xx_does_not_recognize_on_a_user_identity_site` | 用户身份站点，`/login` 200 且响应里没有用户：不建会话，之后 `GET /metrics` 仍 401 |
| `an_identity_response_recognizes_the_credential` | 用户身份站点，身份入口 200 且声明了用户：会话建立并带身份标签；之后的请求按会话判定 |
| `an_echoed_user_does_not_recognize` | 用户身份站点，请求自己发出的值被身份位置原样返回：不认可 |
| `a_login_binds_on_the_first_request_wherever_it_lands` | JSON 登录后第一个请求落在非入口：绑定成功，`trace.session.login_request_id` 指向登录，登录响应的值已见 |
| `a_recognized_session_is_judged_as_before` | 已认可的会话上，快速放行、Jev 放行并缓存、Jev 拒绝三种路径的结果与现在相同 |
| `the_first_request_of_a_new_session_notes_what_it_sent` | S4 建立会话的那个响应回显了请求里的未见值：这个值没有被学成已见 |

需要调整的现有测试：

- `confirm` 辅助函数现在用非入口的 `/api/ping` 建会话，按 R6 不再成立，改成入口路径。
- `a_credential_the_origin_has_not_answered_starts_no_session`、`a_credential_without_a_session_spends_the_budget_of_its_address`：按新规则改写，保留它们原来要证明的事（假凭证不占会话槽、用地址额度）。
- PR #213 加的测试（被拒绝的凭证不建会话、暂存的上限和带入）：它们证明的事本 PR 之后仍然成立，断言不改；只有“非入口 2xx 建会话”作为前提的步骤换成入口。测试名以届时 `main` 为准，上面两条如果已被 #213 改名或改写，按现名处理。
- 断言“凭证第一次出现在非入口时不绑定登录”的测试：按 R1 反过来。
- 其他直接拿一个没被认可的凭证去判定非入口请求的测试：在请求之前加一步认可（`confirm`），**原有断言保持不变**。不要删除或 `#[ignore]` 任何测试。PR 描述里列出改了哪些测试、各自为什么改。

`crates/xshield-edge/tests/scenarios.rs`、`crates/xshield-judge/tests/live_jev.rs` 里的站点没有身份位置，会话都是先由入口的 2xx 建立的，预期不用改；如果有失败，按同样的原则处理。`live_jev` 不要运行。

### 4.2 靶场（`scripts/test_idor_lab.py`）

| 编号 | 场景 | 预期 |
|---|---|---|
| F1 | `plain.lab`，Cookie `SID=made-up`，`GET /api/patients/7001`（非入口）和一个没有请求值的非入口路径 | 401；判定记录 `decision_path == "no_session"`、`trace.unrecognized_credential == true`；源站没有收到请求；假 Jev 没有被调用 |
| F2 | `identity.lab`，`SID=made-up` 先 `GET /login`（入口，源站答 2xx），再访问非入口 | 第二个请求仍是 401 |
| F3 | `identity.lab`，绕过网关直接向源站登录拿到 `SID`（模拟网关重启后的老会话），经网关先访问非入口，再访问 `GET /api/home`，再访问患者列表里的一个患者 | 第一个请求 401；`/api/home` 放行；之后的请求按会话正常判定（列表里的患者快速放行） |
| F4 | `token.lab`（JSON 凭证站点，G1 用的那个）：`POST /api/token-login` 登录，带令牌的第一个请求落在非入口 | 绑定成功：放行，`trace.session.login_request_id` 指向登录，没有 `login_unbound` |

F1 到 F4 这四个编号是 PR 215 特意留出来的（它的场景从 F5 开始）。F2 需要源站的 `GET /login` 对任何人答 2xx；`idor_origin.py` 里没有的话加一个返回登录页的分支，只在靶场里用。F4 选哪个非入口路径以 `token.lab` 的入口表为准（`ENTRIES` 加 `/api/token-login`），选一个登录响应或入口都没有给过值也能放行的请求，或者断言绑定而不是放行。

G2（没发过的长令牌访问入口）按 R2、R4 仍应记 `login_unmatched`，但 `record.session` 变空、`record.context` 变成 `address`；它现有的三条断言预计不用改，改了要在 PR 里说明。C9（同一地址 11 个会话）和 W4a 到 W4g、F5 到 F13 的会话都由登录下发建立，预期不变。

全量靶场必须通过。现有场景的预期只允许因为本次行为变化而改，改了哪条在 PR 描述里说明。

## 5. 检查（AGENTS.md 的“质量”一节）

改动涉及 Rust、判定路径和 `xshield-core`，提交前全部执行并在 PR 描述里逐条写结果：

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `python3 scripts/test_idor_lab.py`
- 在 `fuzz/` 下：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`
- 改了 `object_learning.rs`，所以还要 `scripts/test_postgres.sh`（先 `pg_isready`，数据库没起来就先启动；确实跑不了要写明未执行）

没有执行的步骤写“未执行”和原因，不要写成通过。不要为了变绿去跳过测试、加 `#[allow]`、放宽 clippy、改工作流。

## 6. CHANGELOG 和文档要写清的影响

- 带着源站没认过的凭证访问非入口路径，现在是 401，此前会被放行或交给 Jev。
- 网关重启或会话闲置回收之后，在线用户的凭证变成未认可，要先访问一次入口才恢复：没有用户身份位置的站点，任何入口的 2xx 都行；有用户身份位置的站点，要靠身份接口的响应，所以身份接口应当登记为入口。
- JSON 凭证站点登录后的第一个请求不再必须落在入口上。
- 观察模式下本应拦截的请求，其响应不再建立会话（不学值的部分由批次 4 的记录说明）；观察期的“本应拦截”数量因此会比以前多，更接近拦截模式下的实际情况。
- 已知未解决：JSON 接口刷新令牌的站点，新令牌是未认可的（评审稿 P1-1），另行处理。

## 7. 验收标准

评审时逐条核对，缺一条不通过：

1. 第 1 节的表在新代码上重跑，“带 `SID=made-up`”一列全部是 401、0 次 Jev、网关里没有新会话。
2. 4.1 列出的每个新测试都在，断言与表里一致；4.2 的 F1 到 F4 在靶场里通过，PR 里有它们在 `main` 上的红阶段结果（F1、F2 在 `main` 上应当失败）。
3. 没有测试被删除、忽略或削弱；改动过的现有测试在 PR 描述里逐个说明。
4. `Prompt` 的 id 没变；没带凭证的请求和已认可会话的判定记录，除新字段外与改动前逐字段相同（用一条已有测试的记录对比即可）。
5. 生产路径没有新增 `unwrap`、`expect`、`panic`；没有新增 `#[allow]`、依赖、环境变量、配置项。
6. 凭证原文没有进入日志、trace 或发给 Jev 的内容。
7. docs 和 CHANGELOG 与实现一致；`docs/01` 1.7 不再说“只有入口请求会开始会话并参与绑定”。
8. 第 5 节的检查全部执行并写明结果，CI 全绿。
9. PR 标题 `fix(judge): …`（英文 Conventional Commits），描述按 `templates/pull-request.md` 的五个标题，开头带项目要求的两行归属。
10. 有效性回归用例（2026-11-13 补，防护有效性方案第 13 节第 7 条：意外通过算失败）：本 PR 对应 `p0-3-fake-cookie-*`（编造凭证访问 `/metrics`、`/api/admin/export`，预期拦）。第 1 层不需要任何站点配置，两种对象表配置上都应当通过。`tests/security-lab/effectiveness/regressions.py` 已在 `main` 上，`p0-3-fake-cookie-metrics` 和 `p0-3-fake-cookie-export` 现在是 `known_gap`（预期 `no_session`）：本 PR 把这两条翻成 `must`。在同一台机器上先后跑改动前（`main`）和改动后的 `python3 scripts/measure_effectiveness.py`（快速模式，有 PostgreSQL 时含学习段），把 P1、P2、P4、P7 和失败项的前后对比写进 PR 描述。P2（误拦率）或 P4 变差、或者除这两条之外有用例变了结果，要逐条说明原因；已知的意外通过项不属于本 PR，不动它们的状态。

## 8. 依赖和顺序

协调者在 2026-11-13 定的顺序，已和“修复大请求绕过与限额降级”线程的规划者对过：

- **16:55Z 的状态**：下面“必须先合入”的四项和批次 11、PR #213 都已在 `main`（`d9cf90a`），本 PR 可以开工。批次 11 已合入，所以每条建会话的路径都必须传来源地址，R2 的地址额度用它的地址分组。还在路上、会和本 PR 碰同一批文件的：WAF 批次 3（PR 227，`values.rs`）、T4c（PR 230，`values.rs` 和 `function_view`）、T4b（`function_view` 的键匹配，未开）、WAF 批次 5（未开）。它们都不改 `judge` 开头和 `observe` 的建会话逻辑；谁后合谁 rebase，`mod tests` 末尾的文本冲突两边都留。
- **必须先合入**（都已合入）：WAF 批次 1（限额超出回 429）、PR 196（重复 JSON 键与跨站点上下文）、WAF 批次 2（重写 `ask_jev` 为分批，`admit` 仍是每请求调一次）、WAF 批次 4（P1-5 学习部分，R5 建在它上面）。批次 4 不动 PR 193 在 `observe` 开头建会话的那一段，那一段留给本 PR 的 R5 和 R6；批次 4 的测试 3 由本 PR 把断言改成“新凭证没有会话”。
- **可以并行**：WAF 批次 3。它改 `values.rs`，删掉 `REQUEST_VALUES_MAX` 的上报链路（edge 的 `status.rs`、control 的 `system.rs`、控制台），并在 `engine.rs` 的 `mod tests` 里加回归测试，但不碰 `judge` 开头、`plan`、`admit`。两边都往 `mod tests` 末尾加测试，后合的一方 rebase 时会有文本冲突，保留两边即可。
- **谁先过验收谁先合**：WAF 批次 5（`sent` 收窄）。它除了 `observe` 还改 `plan_values`、`Judgement` 和 `Observation` 的字段、`proxy.rs` 的 `RequestContext`，并删除 `SessionContext` 里 `sent` 相关的成员。它若先合，R7 里的 `note_sent(observation.sent)` 按届时的写法改（规则不变：会话在这次响应里才建立时，这次请求发出的值也要算发出过）；本 PR 若先合，批次 5 负责 rebase。
- **谁先过验收谁先合**：WAF 批次 11（规划 11a 节：会话记下建立它的来源地址，表满时只淘汰会话最多的地址名下的，同一地址所有会话合计的 Jev 上限）。它改所有建会话入口的签名（`start_session`、`start_from_login`、`observe` 的 `seeded` 和 `issued`）和 `budget_key`，与本 PR 改的是同一批函数。它先合入时，本 PR 的每条建会话路径（S1、S3、S4、判定阶段的登录绑定）都按它的要求传入来源地址，R2 里“额度记在地址上”用它的地址分组；本 PR 先合入时由它 rebase。两者不重复：本 PR 之后仍然谁都能走的两条路径（无身份站点的入口 2xx、匿名下发的凭证）正是批次 11 要限制损害的对象。
- PR #213 已合入（`6e5b55f`）。它加的暂存 `PendingSent` 本 PR 保留（R9）。
- WAF 各批次都不依赖 `SessionContext::unconfirmed` 和 `Turn::unconfirmed`，也不会改它们，本 PR 可以放心删除。动手前确认 #213 之后它们还在、还是那个用途；不在了就以“未认可的凭证不走空会话那条路”这个结果为准。
- 开工前 `git fetch origin main` 并在最新 `main` 上开分支；动手前再看一遍 `judge`、`plan`、`admit`、`observe` 的现状，本规划里的函数名以届时的代码为准，行为规格（第 2 节）不变。
- 不依赖 T2 到 T5。合入后在观察模式的站点上看 `trace.unrecognized_credential` 为真的记录有多少、集中在哪些路径，这是切拦截前的依据。
- 不在本 PR 内：凭证轮换后上下文归零（P1-1），设计另见 `credential-rotation.md`（撰写中）。
