# 实现规划 C1：源站换发的凭证沿用原会话（别名、响应头换发、四条边界）

- 设计依据：[credential-rotation.md](credential-rotation.md) 第 3.1 节、第 3.2 节的 R1、第 4 节、第 8 节。用户在 2026-11-13 确认了第 10 节（沿用，按四条边界断开）。
- 写于 `main` `c1a5c7f`。**开工的前提是 T1（功能级越权第 1 层，[function-level-authz-plan-layer1.md](function-level-authz-plan-layer1.md)）和 WAF 批次 5（`sent` 收窄，[waf-p0-fix-plan.md](../plans/waf-p0-fix-plan.md) 第 6 节）都已合入 `main`**。本规划按“这两个 PR 合入之后的代码”写：未认可的凭证没有会话（T1），`SessionContext::sent`、`inherit_sent`、`note_request_sent` 已删除（批次 5）。开工前 `git fetch origin main`，先读一遍 `judge`、`plan`、`admit`、`observe` 和 `context.rs` 的现状；函数名以届时的代码为准，第 2 节的行为规格不变。两个前提有一个没合入就不要开工。
- 范围：`xshield-judge`（`context.rs`、`engine.rs`）、`xshield-core`（两个 trace 字段）、`xshield-edge`（把一个布尔值从判定带到响应观察）、`schemas/`、控制台的 `api/types.ts`（只加类型）、docs、靶场、CHANGELOG。**不改** `xshield-control`、`xshield-postgres`、`migrations/`、`.github/`、`deny.toml`、`Cargo.lock`、控制台页面。
- 验收人：“设计功能级越权防护”线程（Fable）。PR 开出后由它评审。
- 不在本 PR：响应 JSON 里的令牌（R2）、不带凭证的刷新请求（R3）、S5 续期。那是 C2、C3。

## 1. 要解决的问题

评审探针 `probe_e8_rotation`（`docs/design-records/answers/waf-strategy-review-probes.rs.txt` 第 117 行）在 `main` 上的结果：会话 `alice` 看过患者列表后 `GET /api/patients/7` 是 `fast_allow`；源站在一个普通响应里把 Cookie 换成 `alice2`；带 `alice2` 的同一个请求交给 Jev 并被拒。原因是会话键由凭证算出（`Judge::session_key`），凭证一变就是另一个上下文。

每个响应都重发会话 Cookie 的框架（Laravel、开了滑动过期的 ASP.NET）因此每个请求都像新会话的第一个请求。

## 2. 规格

### 2.1 用词和数据结构

- **上下文**：`SessionContext`，网关为一个会话记的全部东西。**上下文编号**：建立这个上下文的那个凭证的会话键（`session_key(site, credential)` 的值），和现在 `ContextStore.sessions` 的键相同。
- **别名**：指向一个已有上下文的另一个凭证的会话键。
- `ContextStore` 加一张别名表：别名的会话键指向上下文编号。每个上下文记自己的别名列表（按加入先后），每条带一个“用过没有”的标记。
- 每个上下文最多 `ALIASES_MAX = 16` 个别名（代码常量）。加第 17 个时去掉最旧的那个，被去掉的凭证此后是未认可的凭证。建立上下文的那个凭证不占名额，上下文活着它就一直有效。
- `ContextStore::len()` 仍然数上下文，`SESSIONS_MAX`、`IDLE_MAX_MS` 都按上下文算。带任何一个别名的请求都算这个上下文的活动（更新 `last_ms`）。
- 上下文被移除时（闲置过期被替换、容量满时被挤掉、`retain` 清理、2.4 的 B1 作废），它的别名一并从别名表里删掉。别名表里指向已不存在或已过期上下文的条目，在被查到时删掉。别名表的条目数因此不超过 16 乘以上下文数。

### 2.2 凭证先换成上下文编号

`judge()` 和 `observe()` 拿到请求凭证的会话键之后，先查别名表：命中且目标上下文活着，就用目标的上下文编号；否则用凭证自己的会话键。之后所有取会话的地方（`plan`、`admit`、`remember_allow`、`is_administrator`、`observe` 里学习和身份声明的那个会话、`record.session` 的标签）都用这个上下文编号。

结果：

- 带别名的请求，判定记录的 `session` 标签与换发前相同，已见值、放行缓存、经过的入口、近期访问、身份（含管理员角色）都是同一份。
- “已认可”（T1 的用词）的含义变成：凭证换成上下文编号之后，这个上下文活着。
- 换编号在 T1 的登录绑定（`start_from_login`）之前做：别名已经有上下文，不再去认领暂存的登录。

### 2.3 R1：什么时候加别名

在 `observe()` 里判断。记 X 为请求上的凭证，Y 为响应下发的凭证（`issued_credential`，非空）。下面的条件**全部**满足时，Y 成为 X 所在上下文 C 的别名：

1. X 已认可，上下文是 C。
2. 响应状态是 2xx 或 3xx，`would_block` 为假，路径不在 `bypass` 里。
3. Y 与 X 不同，Y 至少 `LOGIN_CREDENTIAL_CHARS`（16）个字符。
4. Y 的会话键在网关里没有主：既不是某个活上下文的编号，也不是某个活上下文的别名。（Y 已经是 C 的别名或就是 C 的编号时，什么都不用做。）
5. 2.4 的边界一条都没碰到。

加了别名之后：

- 这个响应只学进 C 一次（值、身份声明、近期访问、入口都记在 C 上），不再为 Y 另建会话。
- `trace.response.issued_session` **不写**（没有签发新会话）。控制台的时间线和请求详情因此不会在每次换发时显示“签发会话”。
- 3xx 的响应照现在的规则不学值，只加别名。

条件不满足时，Y 的处理与届时的 `main` 完全相同（Y 没有会话就为它开一个新会话并学这个响应，`issued_session` 写新会话的标签）。条件 3 里“短于 16 个字符”的情况不写 `fresh`：源站用 `deleted`、`guest` 这类固定值清 Cookie 时，它不是换发。

### 2.4 边界：哪些换发不沿用

按下面的顺序判断，记第一个碰到的原因。

**B1 身份变了**（先于 R1 判断，没有换发时也适用）。条件：站点声明了用户身份位置（T1 加的 `ObjectMap::declares_user_identity()`）；X 已认可，C 的身份里已经有用户；这个 2xx、非 `would_block` 的响应在身份位置上声明了一个用户（用与 `declare_identity` 相同的取值和回显过滤），并且与 C 的用户不同。只看用户，机构和角色的变化照旧就地更新。

碰到 B1 时：C 整个作废，连同它的全部别名（2.1 的移除）。之后这个响应按“请求带着未认可的凭证”走 T1 的认可规则：身份声明认可 X（S3），为它开一个新上下文，从这个响应学起；响应同时下发了 Y 的，按 T1 的 S1 处理。`trace.response.fresh` 写 `identity`。

**B2 主体不同**。X 和 Y（都先经 `credential_token` 去掉 `Authorization` 的方案名）都是 JWT 并且都有 `sub`，而 `sub` 不同；或者 `sub` 相同、两边都有 `iss` 而 `iss` 不同。`fresh` 写 `subject`。

- JWT 的判断：不超过 8 KiB，恰好两个点分成三段，每段非空且只含 `A-Z a-z 0-9 - _`；第二段按 base64url（无填充）解码后是一个 JSON 对象。`sub` 取字符串或数字（数字按十进制文本比较），`iss` 取字符串。
- 不验签名，不读 `exp`。任何一边不是 JWT 或没有 `sub`，B2 不适用（不算碰到边界）。
- base64url 解码自己写一个小函数，不加依赖。解码结果只在这一次比较里用，不存、不记日志。

**B3 密码登录**。得到 Y 的那个请求带着口令字段：请求值里有一个值，它的键名或位置（`RequestValue::key`、`at`）转小写后含 `password`、`passwd` 或 `pwd`。请求值没有读全（`ExtractedRequest::truncated`）时无法判断，按带着口令字段处理。`fresh` 写 `login`。

**B4 退出**。请求的逻辑路径最后一个非空段，去掉第一个 `.` 及其后的部分、去掉 `-` 和 `_`、转小写之后，等于 `logout`、`signout`、`logoff` 或 `signoff`。`fresh` 写 `logout`。

**共享的凭证**。Y 的会话键已经是**另一个**活上下文 D 的别名（条件 4 不满足的一种）：同一个值被源站发给了两个会话，它不是某一个会话私有的凭证。把 Y 从 D 的别名里摘掉，为 Y 开一个新上下文并学这个响应（与没有会话的 Y 在 `main` 上的处理相同）。`fresh` 写 `shared`。Y 是另一个活上下文的**编号**时不动它（与 `main` 相同），不写 `fresh`。

B2、B3、B4 碰到时，Y 的处理与届时的 `main` 相同（新会话，从空开始，学这个响应），X 和 C 不受影响。

三个名字列表（B3 的三个词、B4 的四个词、16 个字符）都是代码常量，不做成配置。

### 2.5 Jev 额度

一个上下文一份额度。上下文第一次得到别名时，把当时请求凭证的额度键（现在 `budget_key` 给活会话算出的那个值）记进上下文；此后这个上下文的请求不论带哪个凭证，额度都记在这个键上。没有别名的上下文不记，额度键的算法与现在逐字节相同（同一个凭证在各站点共用额度这一点不变）。

### 2.6 trace 字段

| 字段 | 位置 | 值 | 什么时候写 |
|---|---|---|---|
| `trace.session.continued` | `xshield-core` 的 `TraceSession`，`Option`，为空时不写出 | `issued` | 一个别名第一次被请求带来的那条判定记录。每个别名只写一次；建立上下文的凭证从不写 |
| `trace.response.fresh` | `ObservationSummary`，`Option`，为空时不写出 | `identity`、`subject`、`login`、`logout`、`shared` | 2.4 里碰到边界的那个响应 |

两个都是 `snake_case` 的枚举。C2 会给 `continued` 加 `announced`，本 PR 只有 `issued`。“第一次被带来”的标记在 2.2 换上下文编号时取（取到就置为用过）；并发的两个请求只有一个拿到。

### 2.7 口令字段的传递

B3 要在 `observe()` 里知道请求有没有口令字段，而 `observe()` 看不到请求体。做法与 `sent`、`echo` 相同：`Judgement` 加一个布尔字段（建议名 `password`，文档注释写明含义和“值没读全时为真”），`judge()` 在提取请求值之后算出；`xshield-edge` 的 `RequestContext` 多存一个布尔值；`Observation` 加同名字段。不转发的请求没有响应，值无所谓。

## 3. 不变的行为（验收时逐条核对）

- 源站不换发凭证的会话：判定路径、发给 Jev 的内容、缓存、额度、学习、判定记录，除 B1 之外与改动前逐字段相同。B1 只在声明了用户身份位置的站点上、同一个凭证的身份响应换了用户时发生。
- 没带凭证的请求、未认可的凭证（T1 的规则）、`bypass`：不变。请求没带凭证或凭证未认可时，响应下发的凭证按现在的规则处理，不产生别名，也不写 `fresh`。
- 登录表单答 302 加 `Set-Cookie`（请求不带凭证）：不变，`issued_session` 照常写。
- 4xx、5xx 的响应下发凭证：不变（现在就不为它建会话）。
- `would_block` 的响应：不加别名，不作废上下文，不写 `fresh`。
- `Prompt` 的 id、`state` 的内容：不变。别名、凭证原文、JWT 的内容都不进 `state`、日志和判定记录。
- 现有测试里下发的凭证都短于 16 个字符（`fresh`、`renewed`、探针里的 `alice2`），按 2.3 条件 3 不成为别名，所以它们的断言不用改。如果有现有测试因为本 PR 失败，**STOP** 并告诉验收人是哪一个、为什么，不要改断言去凑。

## 4. 改动位置

| 文件 | 改什么 |
|---|---|
| `crates/xshield-judge/src/context.rs` | 别名表和每个上下文的别名列表；凭证键换上下文编号（带“第一次使用”的标记）；加别名（含 16 个上限）；摘别名；作废上下文；`session()` 里过期替换、容量淘汰、`retain` 三处同步清别名；上下文的额度键 |
| `crates/xshield-judge/src/engine.rs` | `judge()`、`observe()` 开头换上下文编号；`budget_key` 读上下文记的额度键；`observe()` 里 B1（放在 T1 的认可判断之前）、R1 和 B2 到 B4、共享凭证；`Judgement::password`、`Observation::password`；`TraceSession.continued`、`summary.fresh`；`issued_session` 在加别名时不写 |
| `crates/xshield-judge/src/`（新的小模块或放在 `context.rs`） | JWT 主体的读取和 base64url 解码，纯函数 |
| `crates/xshield-core/src/context/trace.rs` | `TraceSession.continued`、`ObservationSummary.fresh` 和两个枚举 |
| `crates/xshield-edge/src/proxy.rs` | `RequestContext` 存 `password`，`observe` 时传给 `Observation` |
| `schemas/decision-record.schema.json`、`web/console/src/api/types.ts` | 加两个可选字段。控制台页面不改 |
| `tests/security-lab/idor_origin.py`、`scripts/test_idor_lab.py`、`tests/security-lab/README.md` | 5.4 的源站接口和场景 K1 到 K5 |
| docs、`CHANGELOG.md` | 第 8 节 |

生产路径不加 `unwrap`、`expect`、`panic`；不加 `#[allow]`（`judge`、`observe` 变长时拆私有函数）；不加依赖、配置项、环境变量。

## 5. 测试

名字可以调整，断言不能少。别名用例里的凭证都用 16 个字符以上的合成值；JWT 在测试里现拼（先写 JSON 再 base64url 编码），源码里不要出现 `eyJ` 开头的字面量，免得 `scripts/check_secrets.py` 报。

### 5.1 `context.rs`

| 测试 | 断言 |
|---|---|
| `an_alias_resolves_to_its_context` | 加别名后，别名键换出来的是原上下文编号；没加过的键换出来是它自己 |
| `the_seventeenth_alias_pushes_out_the_first` | 加 17 个别名：第 1 个不再换到这个上下文，后 16 个和建立上下文的键仍然有效；别名表里这个上下文的条目是 16 条 |
| `an_idle_context_takes_its_aliases_with_it` | 上下文闲置超过 `IDLE_MAX_MS`：别名不再换到它，查过之后别名表里没有这条；经别名的访问会刷新 `last_ms`，上下文不过期 |
| `eviction_at_capacity_removes_the_aliases` | 容量满时被挤掉的上下文，它的别名同时消失 |
| `forgetting_a_context_removes_every_alias` | 作废上下文后，编号和全部别名都没有会话，`len()` 少 1 |
| `the_first_use_of_an_alias_is_reported_once` | 同一个别名第一次换编号时标记为真，第二次为假；建立上下文的键始终为假 |

JWT 读取的纯函数另加测试：主体相同、主体不同、数字 `sub`、`iss` 不同、只有一边是 JWT、段数不对、非法字符、第二段不是 JSON 对象、超过 8 KiB。

### 5.2 `engine.rs`（假 Jev）

| 测试 | 断言 |
|---|---|
| `a_reissued_credential_continues_the_session` | 把 `probe_e8_rotation` 改成断言：换发前 `fast_allow`；带旧凭证的普通 200 响应下发新凭证；带新凭证的同一请求仍是 `fast_allow`，`fake.calls() == 0`，两条记录的 `record.session` 相同，`session_count() == 1` |
| `the_old_credential_still_reaches_the_session` | 换发后带旧凭证的请求仍是 `fast_allow`，同一个 `session` 标签 |
| `continued_is_written_once_for_a_new_alias` | 带新凭证的第一条记录 `trace.session.continued == Some(Issued)`，第二条没有；带旧凭证的记录从不带 |
| `a_reissue_does_not_write_an_issued_session` | 加别名的那个响应摘要里 `issued_session` 为空、`fresh` 为空 |
| `a_redirect_that_reissues_continues_too` | 302 加下发：加别名，不学值 |
| `a_short_reissued_value_starts_its_own_session` | 下发 `deleted`：`session_count() == 2`，新会话没有已见值，`fresh` 为空，`issued_session` 是新标签 |
| `a_reissue_after_a_password_request_starts_over` | 请求体 JSON 带 `password`、表单带 `passwd`、查询带 `pwd` 三种：`fresh == Some(Login)`，新凭证的会话没有旧上下文的已见值，旧凭证的上下文不变 |
| `a_reissue_after_an_unread_request_starts_over` | 请求值没读全（`truncated`）：同上，`fresh == Some(Login)` |
| `a_reissue_on_a_logout_path_starts_over` | `/logout`、`/api/auth/sign-out`、`/Account/LogOff`、`/users/sign_out`、`/logout.php`：`fresh == Some(Logout)`；`/api/blogout`、`/api/logouts/7`：照常加别名 |
| `a_reissued_token_for_another_subject_starts_over` | 新旧都是 JWT、`sub` 不同：`fresh == Some(Subject)`；`sub` 相同：加别名；`sub` 相同 `iss` 不同：`Subject`；旧凭证不是 JWT：加别名 |
| `another_user_under_the_same_credential_starts_over` | 用户身份站点，会话已声明用户甲并学过值；同一凭证的身份响应声明用户乙：`fresh == Some(Identity)`，之后会话的身份是乙，甲时学的值不再 `fast_allow`，`session_count()` 仍是 1 |
| `an_identity_change_drops_the_aliases_too` | 上下文有一个别名时发生 B1：别名此后是未认可的凭证（非入口 401） |
| `the_same_user_again_changes_nothing` | 身份响应再次声明同一个用户、只换了机构、声明的值是请求自己发出的回显、身份位置上有多个不同的值：都不触发 B1，上下文原样 |
| `a_value_issued_to_two_sessions_belongs_to_neither` | Y 已是上下文一的别名，上下文二的响应又下发 Y：`fresh == Some(Shared)`；之后带 Y 的请求看不到上下文一的值；上下文一的原凭证不受影响 |
| `a_credential_with_its_own_session_is_not_taken_over` | Y 已有自己的会话，别的会话的响应下发 Y：Y 的会话还在，没有别名，`fresh` 为空 |
| `an_unrecognized_credential_gains_no_alias` | 请求凭证未认可、或请求没带凭证，响应下发 Y：与 `main` 相同，Y 是自己的新会话 |
| `a_would_block_response_reissues_nothing` | `would_block` 的响应下发 Y：没有别名，Y 没有会话（T1 的 R5），C 不变 |
| `aliases_share_one_call_budget` | 站点 `advanced.session_calls_per_minute` 设小值：先用原凭证、再用别名各发要问 Jev 的请求，合计到上限后下一个是 429 `JEV_CALL_LIMIT` |
| `an_alias_reuses_a_cached_allow` | 原凭证的请求经 Jev 放行并缓存；别名发同一个请求是 `cached_allow` |
| `an_administrator_stays_one_after_a_reissue` | 管理员会话换发后，别名上的请求仍按管理员判（沿用管理档已有测试的写法，比如管理档来源的值仍然核验） |
| `a_reissue_does_not_launder_an_echo` | 请求以引用发出一个没见过的值并被转发，响应换发凭证并回显这个值：值没有被学进上下文，带别名再访问它不是 `fast_allow` |

### 5.3 `xshield-edge`

`crates/xshield-edge/tests/scenarios.rs` 加一个端到端场景：源站在普通响应里用 `Set-Cookie` 换会话 Cookie，之后带新 Cookie 访问换发前见过的对象是 `fast_allow`，`session` 标签不变；同一个源站上，带着 Cookie 再提交含 `password` 的登录并得到新 Cookie，新 Cookie 的会话从空开始（证明 `password` 从判定传到了响应观察）。

### 5.4 靶场

`tests/security-lab/idor_origin.py` 加三个只在靶场用的接口，注释写明用途：

- `POST /api/session/rotate`：已登录。发一个新的 `SID`（`secrets.token_urlsafe(18)`），新旧两个都有效，角色一并带上，答 200 `{"rotated": true}`。
- `POST /logout`：发一个不对应任何账号的新 `SID`（同样长度），答 200 `{"ok": true}`。
- `POST /api/session/switch`：已登录，请求体 `{"to": "<另一个医生>"}`，不带口令；把**当前这个** `SID` 改绑到那个医生，答 200，不换 Cookie。

场景（`scripts/test_idor_lab.py`，同步 `tests/security-lab/README.md` 和 docs/04 4.3）：

| 编号 | 站点 | 做什么 | 预期 |
|---|---|---|---|
| K1 | plain | 医生甲登录、看列表、打开自己的患者；`POST /api/session/rotate`；带新 Cookie 打开同一个患者，再打开一次 | 换发后第一次是 `fast_allow`，没有新增 Jev 调用，`session` 标签与换发前相同，`trace.session.continued` 是 `issued`；第二次没有 `continued`。换发那条记录的 `trace.response.issued_session` 为空，没有 `fresh` |
| K2 | plain | 接 K1，带旧 Cookie 打开同一个患者 | `fast_allow`，同一个 `session` 标签 |
| K3 | plain | 医生甲已登录；带着甲的 Cookie `POST /login`，账号口令是医生乙的；带得到的新 Cookie 打开甲的患者 | 登录那条记录 `trace.response.fresh` 是 `login`，`issued_session` 是另一个标签；打开甲的患者不是 `fast_allow`，结果与“乙全新登录后访问甲的患者”在 `main` 上的结果相同 |
| K4 | plain | 医生甲已登录；`POST /logout`；带得到的 Cookie 打开甲的患者 | 退出那条记录 `fresh` 是 `logout`，`issued_session` 是另一个标签；之后的请求不是 `fast_allow`，`session` 标签与甲的不同，`trace.session.known_values` 是 0 |
| K5 | identity | 医生甲登录、`GET /api/home`、看列表；`POST /api/session/switch` 换成乙；`GET /api/home`；打开甲的患者 | 第二次 `/api/home` 的记录 `fresh` 是 `identity`；之后 `trace.session.identity.user` 是乙的标签；打开甲的患者不是 `fast_allow` |

K3 到 K5 里“不是 `fast_allow`”之后的具体判定路径，以假 Jev 现有规则的实际结果为准，写进场景断言；不要为了场景去改假 Jev。已有场景的预期一条都不改。

## 6. 有效性回归用例

防护有效性方案规定意外通过算失败，修复 PR 合并时把对应用例从 `known_gap` 翻成 `must`。本 PR 对应 `p1-1-rotation`（浏览列表，刷新凭证，再打开同一患者，预期放）。clinic 源站的 `POST /api/session/refresh` 用 `Set-Cookie` 换发，正是 R1，两种对象表配置上都应当通过。

- `tests/security-lab/effectiveness/regressions.py` 已在 `main` 上：把 `p1-1-rotation` 改成 `must`，跑 `python3 scripts/measure_effectiveness.py`，把退出码和这个用例的判定路径写进 PR 描述。如果它没有通过，**STOP** 并带请求 ID 告诉验收人。
- 还不在 `main` 上：PR 描述的“发布与回滚”里写明“有效性批次 4 需把 `p1-1-rotation` 直接登记为 `must`”，合并后告诉验收人。

## 7. 检查（AGENTS.md 的“质量”一节）

改动涉及判定路径、`xshield-core` 和控制台的一个类型文件，全部执行并在 PR 描述里逐条写结果，没执行的写明原因：

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `python3 scripts/test_idor_lab.py`（全量）
- `fuzz/` 下 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`
- `web/console/` 下 `npm ci`、`npm run lint`、`npm test`、`npm run build`、`npm run test:e2e`
- 不运行 `live_jev`。`scripts/test_postgres.sh` 和 `cargo deny` 不需要（没有相关改动）。

另做一次变异检查并写进 PR 描述：临时去掉 2.4 的 B3 判断，`a_reissue_after_a_password_request_starts_over` 和 K3 应当失败；临时让 2.2 不查别名表，`a_reissued_credential_continues_the_session` 和 K1 应当失败。恢复后全部通过。

## 8. 文档和 CHANGELOG

- `docs/01-request-flow.md` 1.2：第一段的“凭证变了就是新会话”改成本规划的规则：源站在答复一个会话时换发的凭证是同一个会话的另一把钥匙；四条边界和共享凭证各一句；每个会话最多 16 个别名、旧凭证在被挤掉前继续有效；网关重启后别名随上下文丢失。写明已知局限（第 11 节）。身份一段补“用户变了则上下文从头开始”。
- `docs/02-jev.md` 2.5：额度一句补“换发得到的凭证与原凭证共用一份额度”。
- `docs/04-deployment-testing.md` 4.3：场景 K1 到 K5。
- `docs/07-console-architecture.md` 7.4.3：trace 字段表加 `trace.session.continued`、`trace.response.fresh`；`issued_session` 的说明改成“只在响应为一个凭证开了新会话时写”；示例 JSON 如果列了全部字段则同步。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录，写清三件事：换发凭证的站点上会话不再清零；声明了用户身份位置的站点上，同一个凭证换了用户会让上下文从头开始（这是对不换发凭证的站点唯一的行为变化）；判定记录多了两个可选字段、换发时不再写 `issued_session`。
- 同步设计稿 [credential-rotation.md](credential-rotation.md) 之外的文档里与新规则矛盾的句子：`grep -rn "凭证变了" docs` 的每一处都要看过。

## 9. 验收标准

1. 第 5 节的测试都存在并通过；第 7 节的检查都执行并写明结果，CI 全绿。
2. 第 3 节“不变的行为”逐条成立。没有测试被删除、忽略或削弱；改动过的现有测试在 PR 描述里逐个说明原因。
3. `probe_e8_rotation` 的场景成为回归测试，并且在未改动的 `main` 上失败（把失败输出贴进 PR 描述）。
4. 别名只从源站的响应里产生：没有任何路径让请求里的值变成别名（看代码，并由 `an_unrecognized_credential_gains_no_alias` 覆盖）。
5. 别名表有上限：上下文移除的每条路径都清别名（看代码，5.1 的四个测试覆盖）。
6. 凭证原文、JWT 的解码结果不进日志、trace、`state`；`Prompt` 的 id 没变。
7. 生产路径没有新增 `unwrap`、`expect`、`panic`；没有新增 `#[allow]`、依赖、配置项、环境变量；`git diff --stat` 里没有 `migrations/`、`.github/`、`deny.toml`、`Cargo.lock`。
8. 第 6 节的有效性用例按合并时 `main` 的状态处理完。
9. docs 和 CHANGELOG 与实现一致；`grep -rn "凭证变了" docs` 留下的句子都与新规则相符。
10. PR 标题 `fix(judge): …`（英文 Conventional Commits），描述按 `templates/pull-request.md` 的五个标题，结尾带项目要求的归属行。

## 10. 依赖和顺序

- **必须先合入**：T1（本规划用它的“已认可”、`declares_user_identity()`、S1 和 S3）；WAF 批次 5（它删除 `sent` 的继承，本规划不再处理“新会话继承发出过的值”）。C0（PR 203，长令牌登录绑定）已通过验收，也应当先合入，免得两边同时改 `observe` 里登录暂存的那一段。
- **可以并行，后合并的一方 rebase**：T4（改 `judge()` 里算管理员和缓存键的地方、`plan()` 的快速放行条件；本 PR 改它们前面的“凭证换上下文编号”）；WAF 批次 6、8、9（批次 8、9 也给 `RequestFacts`、`RequestContext` 加字段，保留两边）；T5a、T5b（不碰判定）。
- `Observation` 加字段会让其他分支里新写的 `Observation { … }` 字面量编译不过，后合并的一方补上 `password: false`。
- **WAF 批次 11**（`plans/waf-p0-fix-plan.md` 11a 节，2026-11-13 补）：它让会话记下建立它的来源地址，并改 `budget_key` 和所有建会话入口的签名。它先合入时，别名不建新会话，所以沿用原上下文已记下的来源地址，换发不改这个记录；本规划里“额度的键存在上下文里”按它届时的 `budget_key` 写，地址总上限照它的规则过。四种边界断开后新建的会话按它的要求传入这次响应的来源地址。PR #213 的暂存 `PendingSent` 由批次 5 删除，本规划以批次 5 已合入为前提，不处理它。
- 本 PR 合入后才能做 C2（响应 JSON 里的令牌、请求体里的刷新令牌、S5）。C2 的规划由验收线程在本 PR 定型后写。

## 11. 已知局限（写进 docs/01 1.2，不在本 PR 解决）

- 退出路径名字不标准、又在退出时换发长 Cookie 的站点：退出后的匿名会话沿用上一位的上下文，直到下一次带口令的登录（B3）或身份响应（B1）。
- 没有声明用户身份位置、又用单点登录（回调里没有口令字段）的站点：同一个浏览器里下一位登录后沿用上一位的上下文。这类站点应当声明用户身份位置。
- 换发的值短于 16 个字符的站点不沿用，和现在一样。
- 请求值没读全的请求得到新凭证时不沿用（B3 的保守处理）。
- 一个值第一次被发给某个会话时无法知道它是不是共享的；第二个会话得到同一个值时才分开。
- 不验 JWT 签名，不读 `exp`。
- 网关重启后别名和上下文一起丢失，用户从入口重新进入。
- 新令牌只出现在响应 JSON 里、或刷新请求不带旧凭证的站点，本 PR 不解决（C2、C3）。
