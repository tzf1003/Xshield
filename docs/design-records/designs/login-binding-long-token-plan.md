# 实现规划 C0：登录响应里的长令牌绑定不上会话（JSON 登录绑定的缺陷修复）

- 性质：缺陷修复，优先级高。docs/01 1.7 的“JSON 登录绑定”已经上线，但对 JWT 这类长令牌从未生效。
- 设计依据：docs/01 1.7 的现有规则，本规划不改规则，只让它对长令牌成立。它也是 [credential-rotation.md](credential-rotation.md)（P1-1）里 R2 的前置，但不依赖那份设计稿是否确认。
- 基线：`main` `0acae80`。开工前先 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-judge`（`values.rs`、`engine.rs`、`context.rs`）、docs/01、docs/07、靶场、CHANGELOG。**不改** `xshield-core`、`xshield-edge`、`xshield-control`、`web/console`、`migrations/`、`.github/`、`deny.toml`。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。

## 1. 问题和根因

现象：线上的 juice 站点，登录后会话的判定记录里没有 `trace.session.login_request_id`，登录响应里的值（购物篮编号等）不在会话的已见值里，绑定原因是 `login_unmatched`。

根因，三处连起来：

1. `crates/xshield-judge/src/values.rs` 的 `add_at` 丢弃超过 `VALUE_MAX_CHARS`（128）个字符的标量。这条限制本身是对的：那么长的值不是对象引用。但 JWT 一般 200 到 1000 多个字符，所以登录响应里的令牌根本不在提取出来的值里。
2. `engine.rs` 的 `observe` 暂存登录响应时，凭证候选只从这些值里取（不少于 16 个字符的）。令牌不在，候选里就没有它；如果响应里没有别的 16 字符以上的值，这份登录甚至不会被暂存。
3. `context.rs` 的 `HeldLogins::claim` 按“凭证的键控哈希等于某个候选的哈希”匹配，永远匹配不上。

测试缺口：现有测试用的令牌只有 34 个字符（`engine.rs` 里的 `LOGIN_TOKEN`）和 21 个字符（`context.rs`），没有一条用真实长度的 JWT 走真实的提取路径。

## 2. 修法

给响应提取加一条**凭证候选**通道：超过 128 个字符的标量不进已见值（不变），但可以作为登录绑定的候选，只留键控哈希。不调大 `VALUE_MAX_CHARS`。

### 2.1 提取（`values.rs`）

`ResponseFacts` 加一个字段：

```rust
/// 太长、不能当对象引用，但形状像凭证的字符串标量。只用于登录绑定，从不进入已见值。
pub credentials: Vec<ResponseValue>,
```

`walk_response` 遇到 JSON 字符串时：

- 不超过 `VALUE_MAX_CHARS` 个字符：和现在完全一样，进 `values`。
- 超过 `VALUE_MAX_CHARS` 且字节长度不超过新常量 `CREDENTIAL_MAX_BYTES = 8 * 1024`，并且满足下面的形状：进 `credentials`（字段名和位置的取法与 `values` 相同）。
- 其余：和现在一样丢弃。

形状（全部满足）：

- 每个字节都是可见 ASCII（0x21 到 0x7E），没有空白和控制字符。长的说明文字、HTML 片段因此被排除。
- 不以 `http://`、`https://`、`data:` 开头（忽略大小写）。

一个响应最多 `CREDENTIAL_CANDIDATES_MAX = 16` 个，按文档顺序取前 16 个。数字、HTML 响应不产生候选。`extract_response`（只返回 `values` 的那个函数）和 `values` 的内容与现在逐字节相同。

### 2.2 暂存（`engine.rs` 的 `observe`，`context.rs` 的 `HeldLogin`）

- `read_body` 把 `facts.credentials` 一并返回。
- `HeldLogin` 加 `credentials: Vec<Digest16>`：长候选的键控哈希，用和值相同的域（`self.key.mac("value", …)`），因为绑定时凭证的哈希就是这么算的。
- 暂存登录响应时，对每个长候选算哈希；这次请求自己发出过的（`observation.sent` 里有同一个哈希）不要，和短值的回声规则相同。
- “有候选才暂存”的条件改成：短值里有候选，**或者**长候选非空。
- `summary.pending_values` 是暂存的短值个数加长候选个数。
- `carries`（`context.rs`）：短值候选对上，或者 `credentials` 里有这个哈希，都算这份登录带着这个凭证。
- `take_login` 不变。长候选不在 `values` 里，所以不会被记成已见值；没有被用作凭证的长候选（比如刷新令牌）在绑定后随暂存一起丢弃。
- 暂存总量的上限（`HELD_VALUES_MAX`）把长候选也数进去：一份登录的分量是 `values.len() + credentials.len()`，`hold`、`forget_oldest`、`claim` 里加减的都用这个数。

候选的原文只在 `observe` 这一次调用里存在，不进日志、trace，也不发给 Jev。

### 2.3 不变的行为

- 已见值、对象引用、`VALUE_MAX_CHARS`、响应指纹和结构（`shape`）都不变。
- 16 到 128 个字符的令牌照旧走短值那条路。
- 绑定的时机、歧义、过期、`login_unbound` 的三个原因都不变。
- 发给 Jev 的 `state` 和提示词版本号不变。

## 3. 测试

**先写回归测试，在没改代码的 `main` 上跑一次确认它失败，把失败输出贴进 PR 描述，然后再修。** 下面用的长令牌在测试里现造：头部 `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9`，加两段由循环生成的 base64url 字符，总长不少于 700 个字符。不要把任何真实令牌写进仓库。

### 3.1 `values.rs`

| 测试 | 断言 |
|---|---|
| `a_long_token_is_a_credential_candidate_and_not_a_value` | `{"authentication":{"token":"<700 多字符>","bid":6}}`：`values` 只有 `bid`；`credentials` 有一条，字段名和位置与同处的短值取法一致，值是原文 |
| `the_value_limit_decides_between_a_value_and_a_candidate` | 恰好 128 个字符的串在 `values`、不在 `credentials`；129 个字符的在 `credentials`、不在 `values` |
| `a_long_text_or_a_url_is_no_candidate` | 带空格的长文字、带中文的长文字、`https://…` 开头的长链接、`data:` 开头的长串：`credentials` 为空 |
| `a_scalar_past_the_credential_limit_is_dropped` | 8193 字节的串：两边都没有 |
| `a_response_yields_at_most_sixteen_candidates` | 20 个长串：`credentials` 是前 16 个 |
| `html_yields_no_candidates` | HTML 响应里的长属性值：`credentials` 为空 |

### 3.2 `engine.rs`（接在现有 JSON 登录测试之后，走 `observe` 到 `judge` 的真实路径）

| 测试 | 断言 |
|---|---|
| `a_json_login_with_a_long_token_binds_its_session` | 照 `a_json_login_gives_the_session_its_credential_starts_the_values_it_returned` 写，令牌换成 700 多字符：`pending_values == Some(2)`；入口请求的 `login_request_id` 是那次登录，`login_unbound` 为空；`GET /rest/basket/6` 快速放行；`GET /rest/basket/7` 交 Jev |
| `a_long_token_is_never_a_seen_value` | 上一条绑定之后，会话的 `trace.session.known_values` 是 1（只有篮子编号） |
| `a_long_token_beside_the_credential_is_held_but_not_learned` | 响应里有两个长令牌（访问令牌和刷新令牌）加篮子编号：`pending_values == Some(3)`；用访问令牌绑定成功；`known_values` 是 1 |
| `a_login_whose_only_candidate_is_long_is_still_held` | 响应里除了长令牌没有任何 16 字符以上的值（篮子编号是个位数）：照样暂存、照样绑定。没有这条，只带令牌和短编号的登录响应连暂存都不会发生 |
| `a_long_token_the_request_sent_is_not_held` | 照 `a_login_that_echoes_what_it_was_sent_holds_only_what_it_issued` 写：登录请求自己带了一个长串，响应把它原样返回：它不是候选；拿它当凭证，`login_unbound` 是 `login_unmatched` |
| `a_bearer_scheme_is_removed_before_a_long_token_is_matched` | 凭证在 `Authorization` 头的站点，请求带 `Bearer <长令牌>`：绑定成功 |
| `two_held_logins_issuing_one_long_credential_take_nothing` | 两份未过期的暂存带同一个长令牌：`login_ambiguous` |

### 3.3 `context.rs`

| 测试 | 断言 |
|---|---|
| `long_candidates_count_toward_the_held_total` | 暂存的总量把长候选数进去：超出 `HELD_VALUES_MAX` 时淘汰最旧的一份，被认领或淘汰后总量减回去 |

### 3.4 靶场

靶场现在只有 Cookie 凭证的站点，JSON 登录没有端到端场景，这个缺陷因此漏过。加一个：

- 靶场源站（`tests/security-lab/idor_origin.py`）加 `POST /api/token-login`：请求体和现有登录相同，返回 200 的 JSON，形如 `{"authentication":{"token":"<700 多字符的令牌>","doctor":"DR-A"}}`；令牌由源站现造并记住。源站在读 `SID` Cookie 的地方同样接受 `Authorization: Bearer <令牌>`。
- `scripts/test_idor_lab.py` 加一个站点 `token.lab`：凭证是 `Authorization` 请求头，入口在现有的基础上加 `/api/token-login`。
- 场景 **G1**：经网关 `POST /api/token-login` 登录；带 `Authorization: Bearer <令牌>` 访问入口 `GET /api/patients`，放行；判定记录的 `trace.session.login_request_id` 是登录那次请求的 ID，没有 `login_unbound`。再访问登录响应没给过、列表里也没有的病人，交 Jev 被拦（与 A2 相同的预期）。
- 场景 **G2**：带一个源站没发过的 700 字符令牌访问入口，判定记录的 `login_unbound` 是 `login_unmatched`。

靶场改动只加不改：现有场景的预期一条都不动。

## 4. 检查（AGENTS.md 的“质量”一节）

改动涉及 Rust 和判定路径，提交前全部执行并在 PR 描述里逐条写结果：

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`（测试里的长令牌是现造的，不应触发；如果触发，改造法，不要往 `ALLOW` 里加）
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `python3 scripts/test_idor_lab.py`（全部场景，不只是新加的）

没有执行的步骤写“未执行”和原因，不要写成通过。不要为了变绿去跳过测试、加 `#[allow]`、放宽 clippy、改工作流。

## 5. 文档和 CHANGELOG

- `docs/01-request-flow.md` 1.7 的“暂存”一条：写明凭证候选有两类，16 到 128 个字符的标量（同时也是会话的值），和超过 128 个字符、不超过 8 KiB、全是可见 ASCII 的字符串（只作候选，不进已见值，绑定后丢弃）。
- `docs/07-console-architecture.md` 里 `response.pending_values` 的说明：数的是暂存的值加长候选。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录，说清影响：此前 JSON 登录返回的令牌超过 128 个字符（JWT 基本都是）时，登录绑定不生效，会话拿不到登录响应里的值，判定记录写 `login_unmatched`；现在生效。受影响站点的表现是登录后直接访问登录响应里给的对象不再需要问 Jev。

## 6. 验收标准

评审时逐条核对，缺一条不通过：

1. PR 描述里有回归测试在未修改的 `main` 上失败的输出，和修改后通过的输出。
2. 第 3 节列出的测试都在，断言与表里一致；靶场 G1、G2 通过，原有场景全部通过且预期没改。
3. `VALUE_MAX_CHARS` 没变；不含长标量的响应，`extract_response_facts` 的 `values` 和 `shape`、判定记录、发给 Jev 的内容都与改动前逐字相同；`Prompt` 的 id 没变。
4. 长候选从不成为已见值：绑定后 `known_values` 不因它增加，带着它当请求值的请求不会因它被核验。
5. 候选的原文不出现在日志、trace、判定记录、发给 Jev 的内容里；暂存里只有键控哈希。
6. 回声规则对长候选成立（3.2 的第五条）。
7. 暂存的三个上限仍然成立，长候选计入总量。
8. 生产路径没有新增 `unwrap`、`expect`、`panic`；没有新增 `#[allow]`、依赖、环境变量、配置项、表。
9. 没有测试被删除、忽略或削弱。
10. docs 和 CHANGELOG 与实现一致。
11. 第 4 节的检查全部执行并写明结果，CI 全绿。
12. PR 标题 `fix(judge): …`（英文 Conventional Commits），描述按 `templates/pull-request.md` 的五个标题，并带上项目要求的归属行。提交信息、PR、代码注释里不出现模型名，也不出现任何真实令牌或密钥。

## 7. 依赖和顺序

- 不依赖任何其他改动，现在就在最新 `main` 上做。它是缺陷修复，不必等“修复大请求绕过与限额降级”的批次，也不必等功能级越权的 T1。
- 它改 `engine.rs` 的 `observe` 里暂存登录的那一小段和 `read_body`。WAF 的批次 4、5 和 T1 也会动 `observe`，本 PR 先合，后面的各自 rebase；改动小，冲突是文本层面的。
- 合入并部署后，在 juice 站点上验证：登录后的入口请求，判定记录有 `trace.session.login_request_id`，没有 `login_unmatched`。这一步由部署线程做。
