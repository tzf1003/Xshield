# WAF 判定修复：实现规划与验收标准

- 日期：2026-11-13
- 基线：`main` `4e5361a`；文中的行号按这个提交写，只作定位参考，以函数名为准
- **2026-11-13 09:20 UTC 补充**：`main` 已到 `e3587a4`，其中 PR 193（`ad1a8e6`）改了会话的建立方式：源站没有应答过的凭证不建会话，这类请求按空视图判定，Jev 调用计入**客户端地址**的限额（默认 30 次每分钟）。写测试时，需要“已有会话”的场景先调 `mod tests` 里的 `confirm(&judge, &site, "凭证")`。PR 193 引入的 `SessionContext::unconfirmed`、`Turn::unconfirmed` 和 `observe` 开头建会话的那一段由“设计功能级越权防护”线程后续处理，本规划的批次不要改它们。
- 依据：[waf-strategy-review.md](../answers/waf-strategy-review.md)（P0-1、P0-2、P1-2、P1-5、P1-9、P2-1、P2-2、P2-3），探针在 [waf-strategy-review-probes.rs.txt](../answers/waf-strategy-review-probes.rs.txt)
- 分工：每个批次由一个实现线程（Haiku）完成并开 PR；规划和验收由“修复大请求绕过与限额降级”线程负责。**验收通过才合并**，实现线程不自行合并。
- 规划阶段没有改过代码，没有补丁可接手。

编号以评审文档为准：**P2-2 是置信度门槛，P2-3 是请求头**。

- **2026-11-13 09:41 UTC 补充**：“修复长令牌登录绑定失效”线程（改 `engine.rs` 的 `observe` 里暂存登录的一小段和 `read_body`）优先合入，批次 4、5 要 rebase 在它之上再提交验收。

- **2026-11-13 11:05 UTC 补充（用户已确认，原话“按建议就行”）**：放开 413 后送判上限为 1 MiB、每个请求最多 16 批；16 批的上限同样用于 48 KiB 以内的请求（规格见 3.4，随批次 2 实现）；置信度门槛的数据从 home-windows 的 `decision_log` 取。批次 1 已合并（PR #199，`402ed2c`）。
- **有效性验证的规则**（protection-effectiveness-plan.md 第 13 节第 7 条）：意外通过算失败。修复 PR 合并时，仓库里对应的回归用例要从 `known_gap` 翻成 `must`；有效性批次 4 合并之前用例还不在仓库，这之前合并的修复由有效性批次 4 直接登记为 `must`。

## 0. 所有批次共同的要求

1. 从最新 `origin/main` 开分支，开工前读 `AGENTS.md`、README、docs/00–03；批次里点到的 docs/07 章节按节读，不整篇读。
2. 只做本批次规格里写的事。发现规格之外的问题写进 PR 描述的“未做”，不顺手改。规格里写了“STOP”的地方，停下来在 PR 或线程里问验收方。
3. 测试只用假 Jev：单元测试用 `engine.rs` 里的 `FakeJev`，靶场用 `tests/security-lab/fake_jev.py`。不跑 `live_jev`。
4. 提交前按 AGENTS.md 的表跑检查，PR 描述里逐条写实际跑了什么、结果如何；没跑的写“未执行”和原因。判定路径的批次都要跑：
   - `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
   - `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
   - `python3 scripts/test_idor_lab.py`（全量，不只 `--only`）
   - 改了 `xshield-core` 的再跑 `fuzz/` 下三条；改了 `xshield-control`、`xshield-postgres` 的再跑 `scripts/test_postgres.sh`（本机 PostgreSQL 16 的启动方式见项目记忆 `local-test-environment`）；改了 `web/console/` 的跑该目录五条。
5. 不为变绿做的事见 AGENTS.md 最后一节：不加 `#[allow]`、不跳过或删除失败的测试、不改 CI。已有测试的断言只有在本批次规格改变了那条行为时才能改，并在 PR 里列出改了哪几条、为什么。
6. 生产路径不用 `unwrap`、`expect`、`panic`、下标越界可能的切片。新增依赖在 PR 里写原因和许可证，并跑 `cargo deny --locked check`。
7. 每个 PR：英文 Conventional Commits 标题；`CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录；按 `templates/pull-request.md` 的五个标题写描述；同步本批次列出的 docs 章节，行为与文档不一致算缺陷。
8. 改了 `state.rs` 里两段指令的批次（2、6、8），指令版本号会变：更新 `the_prompt_id_is_fixed_and_follows_the_questions` 里的固定值，并 `grep -rn jq_e290fa8a62172221` 把 docs/07 里引用旧号的示例一并更新。同时把 `tests/security-lab/fake_jev.py` 和 docs/02 §2.2 的 state 示例对齐。
9. 冲突热点：`CHANGELOG.md` 顶部、`state.rs` 的两段指令和指令版本号、`engine.rs` 的 `mod tests` 末尾。后合并的批次负责 rebase。

## 1. 批次与顺序

| 批次 | 内容 | 主要文件 | 依赖 | 可并行 | 状态 |
|---|---|---|---|---|---|
| 1 | P0-2：调用限额超出始终拒绝，回 429 | `engine.rs`、`proxy.rs`、靶场 C5、控制台文案 | 无 | 先单独做，改动小 | **已合并**（PR #199） |
| 2 | P0-1（上）+ P1-9：state 分批并行、长值分片、16 批预算（3.4） | `state.rs`、`engine.rs` 的 `ask_jev`、`xshield-core` 的 `JevRecord` | 1 | 与 4 并行 | **已合并**（PR #209，`b48c711`）。合并后的真实模型探测量到一个缺陷（分批请求的路径里带对象编号时后面的批次被判拒），补丁 PR #228 **已合并**（`188c66f`，规格 3.5，真实模型复测通过）。控制台的显示补丁 PR #229 **已合并**（`a330348`，2026-11-13） |
| 3 | P0-1（下）：请求值读全（不截 200、multipart、`text/plain` JSON、未知类型整段送判） | `values.rs`、`status.rs`、`system.rs`、靶场 | 2 合并后 | 与 4 并行 | **已合并**（PR #227，`dfbc131`，2026-11-13 19:11 UTC）。合并前在最终头上跑过全套检查、11 组对抗用例和有效性流水线（退出码 0，`p0-1-pad-200`、`p0-1-multipart`、`p0-1-long-value`、`p1-9-big-form` 都是 `must`），真实模型探测 18 次调用通过。留给批次 6 的后续：字段名的源站改写（第 7 节末尾）。留给批次 9 的后续：请求值总字节数上限（第 10 节末尾）。 |
| 4 | P1-5 学习部分：观察模式下本应拦截请求的响应不学 | `engine.rs` 的 `observe`、控制台就绪检查 | 1 | 与 2、3 并行 | **已合并**（PR #208，`f4e59ad`），`p1-5-observe-learns-would-block` 已是 `must` |
| 5 | P1-2：`sent` 收窄（做法一加二） | `context.rs`、`engine.rs` 的 `observe` 和 `plan_values` | 3、4 | 与 6、7 并行 | 可开工 |
| 6 | P2-1：批量赋值的值进判定 | `values.rs`、`state.rs` 指令 | 3 | 与 5、7 并行 | 可开工 |
| 7 | P2-2：置信度门槛 | `state.rs` 的 `conclude`、`engine.rs`、控制台失败码 | 2 | 与 5、6 并行 | 用户 2026-11-13 12:44 UTC 选定 0.60，实现线程已开。**15:45 UTC 带标注的真实站点数据显示 0.60 有代价没有收益（见第 8 节），验收方建议暂缓本批，协调者正在请用户重新决定；决定前不合并** |
| 8 | P2-3：请求头和非会话 Cookie 进攻击判定 | `values.rs`、`engine.rs`、`proxy.rs`、`state.rs` 指令 | 6 | 与 5、7 并行 | 可开工 |
| 9 | 放开 413：缓冲 1 MiB、文件流式转发（16 批预算已在批次 2） | `proxy.rs`、`values.rs`、`engine.rs` | 3、8 | 单独做 | 数值已确认；设计说明 [waf-batch9-design.md](waf-batch9-design.md) 已验收通过。Pingora 的重放缓冲写死 64 KiB，要到 1 MiB 需要 vendor 一份改两行常量的 pingora-core，**用户已选定 vendor 这一做法**（2026-11-13 12:44 UTC）；代码等 3、8 合并 |
| 10 | 按路由平时的正文大小决定超预算是否放行 | 学习任务、`engine.rs` | 9 | 单独做 | **等观察数据和用户确认阈值** |
| 11 | 伪造凭证的会话：淘汰只挤自己地址的，Jev 额度加地址总上限（11a） | `context.rs` 的 `ContextStore::session`、`engine.rs` 的限额检查 | PR #213 合并后 | 与 3 并行；与 5 都改 `context.rs`，后合的 rebase | **已合并**（PR #218，`8af2b5f`）；对应的有效性用例由有效性线程登记 |

合并顺序：1 → 2 → 3 →（4 可在 1 之后任意时刻）→ 5、6、7 → 8 → 9 → 10。批次 11 独立于这条链，PR #213 合并后任意时刻可做。同一波里并行的批次改的是不同函数，先过验收的先合，后一个 rebase。

不在本规划内：P0-3 和 P1-8（在“设计功能级越权防护”线程）、P1-1、P1-3、P1-4、P1-6、P1-7、P2-4、P2-5、P2-6、P2-8（维持现状）。

## 2. 批次 1：调用限额超出始终拒绝，回 429（P0-2）

**现状**：`admit()` 返回 `Err("JEV_CALL_LIMIT")` 和 `build_state` 返回 `StateTooLarge` 都走 `unjudged()` → `Verdict::Unjudged` → `apply_policy` 按 `on_jev_unavailable` 处理，`allow` 的站点会转发（探针 `probe_e6_budget_burn`、`probe_e9_big_form`）。

**行为规格**

| 情况 | `on_jev_unavailable: allow` | `deny` | 观察模式 |
|---|---|---|---|
| 调用限额超出（`JEV_CALL_LIMIT`） | 拒绝，429 | 拒绝，429 | 转发，记“本应拦截” |
| state 过大（`JEV_STATE_TOO_LARGE`） | 拒绝，403 | 拒绝，403 | 转发，记“本应拦截” |
| 服务故障（超时、传输、HTTP 错误、响应无效、`JEV_UNKNOWN`、未配置） | 转发，`unjudged`（不变） | 拒绝，403（不变） | 不变 |

- `decision_path` 仍是 `jev_unavailable`，`jev.failure` 仍是原来的码，不新增 `DecisionPath`。
- 429 的记录里 `trace.refused` 写 `rate_limited`；网关回的 JSON `error` 也是 `rate_limited`。401 和 403 不变。不加 `Retry-After`。

**改动点**

- `crates/xshield-judge/src/engine.rs`
  - `Verdict` 加一个变体表示“限额超出”；`admit()` 失败时 `ask_jev` 返回它，`row.failure` 照写。`StateTooLarge` 改为返回 `Verdict::Unsafe(DecisionPath::JevUnavailable)`，`row.failure` 照写。
  - `apply_policy`：新变体 → `refuse(DecisionPath::JevUnavailable, 429)`，不读 `on_jev_unavailable`。
  - `judge()` 里 `record.trace.refused` 的三分支：401 `unauthenticated`、429 `rate_limited`、其余 `forbidden`。
  - 更新 `Judgement::refuse_status`、`DecisionPath::JevUnavailable`、`Outcome::Blocked`（在 `xshield-core/src/context/log.rs`）的文档注释。
- `crates/xshield-edge/src/proxy.rs:468`：`error` 文本同样三分支。
- `crates/xshield-control/src/preview.rs`、`insights.rs`：检查“切换 `on_jev_unavailable` 的影响预览”有没有把 `JEV_CALL_LIMIT`、`JEV_STATE_TOO_LARGE` 的记录算成会随切换改变的行；有就排除。没有这类逻辑就在 PR 里写明核对过。
- `scripts/test_idor_lab.py` 的 C5：期望 429，标题改为“超出部分拒绝并回 429”；`tests/security-lab/README.md` 的 C5 行同步。
- 控制台：`grep -rn "JEV_CALL_LIMIT\|JEV_STATE_TOO_LARGE\|unauthenticated" web/console/src`，把说“按 `on_jev_unavailable` 处理”的文案改对（`lib/explain.ts`、`features/request-detail/detail-model.ts:762` 附近、`JevInspector.tsx`、`RelatedRail.tsx`），`refused` 的取值表加 `rate_limited`。`schemas/decision-record.schema.json` 的 `refused` 和状态码说明同步。
- 文档：docs/01 §1.4 第 7 步、docs/02 §2.5、docs/03 里 `on_jev_unavailable` 的说明、docs/06（6.6.4 失败码表和第 437 行附近的失败卡片说明）、docs/07 §7.4.1（拒绝状态码和 `refused` 取值）与 7.5 的失败码表。

**必须的测试**（`engine.rs` 的 `mod tests`，名字可调整）

1. `a_spent_call_limit_is_refused_with_429_whatever_the_site_allows`：照 `probe_e6_budget_burn` 写。站点 `enforce` + `on_jev_unavailable: allow`，先 `confirm` 让凭证有会话，同一会话 60 次调用后第 61 个请求：`forward == false`、`refuse_status == 429`、`outcome == Blocked`、`decision_path == JevUnavailable`、`jev.failure == Some("JEV_CALL_LIMIT")`、`trace.refused == Some("rate_limited")`、`fake.calls() == 60`。
2. 同一场景在观察模式：`forward == true`、`outcome == WouldBlock`。
3. `on_jev_unavailable: allow` 下服务故障（`fake.fail(JevFailure::Timeout)` 之类）仍是 `Unjudged` 并转发。已有同类测试就指出是哪条。
4. `allow` 站点上 state 过大的请求（照 `probe_e9_big_form`）：`forward == false`、`refuse_status == 403`、`failure == Some("JEV_STATE_TOO_LARGE")`、`fake.calls() == 0`。批次 2 会把这条改成分批放行。
5. 已有断言 `JEV_CALL_LIMIT` 的三处测试（`engine.rs` 约 2976、3528、3549 行）按新行为更新。
6. 没有会话的凭证（不调 `confirm`）耗尽的是地址限额：第 31 个需要判定的请求得到 429，行为同上。
7. `crates/xshield-edge/tests/scenarios.rs` 里加或改一条：限额超出时客户端收到 429 和 `{"error":"rate_limited",…}`。

**验收标准**：上面 7 条存在且通过；靶场全量通过且 C5 为 429；`grep -rn "on_jev_unavailable" docs web/console/src` 里不再有把限额超出说成受它控制的句子。

## 3. 批次 2：state 分批并行、长值分片（P0-1 上半 + P1-9）

**目标**：发给 Jev 的内容不再截断任何请求值，不再因为 state 过大而拒绝。本批只改“已提取的值怎样送判”，不改提取（提取在批次 3）。

### 3.1 `state.rs`

- 常量：`VALUE_PART_CHARS = 512`、`VALUE_PART_OVERLAP = 64`。
- `StateValue` 加 `part: Option<(u16, u16)>`（第几片、共几片，从 1 起）。渲染时只有 `Some` 才输出 `"part":"2/5"`。
- **分片**：值超过 512 个字符时切成若干片，每片最多 512 字符，相邻两片重叠 64 字符，按字符边界切（中文、表情不能切坏）。去掉各片的重叠部分后拼起来必须等于原值。每片复制原值的 `at`、`key`、`object`，`seen_as` 为空，`verified` 为 false。
  - 先判断是不是秘密，再分片：字段名或位置命中 `is_secret_name`，或整个值包含会话凭证的，**不分片**，照旧整个渲染成 `<redacted>`。把这段判断从 `render_value` 里提出来共用。
- **不再截断值**：删掉 `render_value` 的 `cap` 参数和 `...[truncated]`。
- **去重**：`at` 和 `value` 都相同的值只送一次。
- `at` 渲染时超过 256 字符的截到 256 并加 `...`（位置名不是判定内容；超长键名在批次 3 会作为值单独送判）。`seen_as` 每条超过 256 字符的同样截断。
- **裁剪级别**仍是 0–4，含义改为：

  | 级别 | 最近访问 | 每值来源 | 其他 |
  |---|---|---|---|
  | 0 | 10 | 3 | |
  | 1 | 3 | 3 | |
  | 2 | 0 | 3 | |
  | 3 | 0 | 1 | |
  | 4 | 0 | 0 | `entries_passed` 置空，`path` 截到 256 字符；只在一个值独占一批仍放不下时用 |

- 新函数 `build_states(input) -> Result<Vec<(String, u8)>, JudgeError>`：
  1. 去重、分片。
  2. 全部值放一份，按级别 0–3 依次试，放得下就只返回这一份。**值不多的请求必须和现在逐字节相同**，`GOLDEN_STATE` 测试不许改。
  3. 放不下就分批：按级别 3 的参数，按原顺序贪心装，每批序列化后不超过 `STATE_BYTES_MAX`。可以先按每个值渲染后的长度估算，但每批最后要实际序列化（含 `scrubbed`）核对一次，超了就把这一批对半再拆。只剩一个值还超，用级别 4。
  4. 每批的 `entry`、`session`、`method`、`path`、`truncated` 相同，只有 `values` 不同。
  5. `StateTooLarge` 保留为防御性错误，按上面的规则不应再出现；出现时沿用批次 1 的处理（拒绝，403）。
- 两段指令各加一句（英文，写进常量；措辞可微调，意思不能少）：
  - `ACCESS_INSTRUCTIONS`：大请求会分成几份文档，本份只列一部分值，只判列出的值；带 `part` 的值是一段长文本的一片，不选择任何对象。
  - `ATTACK_INSTRUCTIONS`：带 `part n/m` 的值是长值的一片，相邻片有少量重叠；逐片检查，载荷在片的边缘开始或结束也算存在。

### 3.2 `engine.rs` 的 `ask_jev`

- `admit()` 每个请求只调一次：**调用限额按请求计一次，不按批计**。
- `build_states` 返回一份时，流程和记录与现在完全相同。
- 返回多份时并行调用，同时在途最多 `JEV_PARALLEL_MAX = 8`。实现用 `futures-util` 的 `buffer_unordered`（已在 `Cargo.lock` 里，许可证 MIT OR Apache-2.0；作为 `xshield-judge` 的直接依赖加入时在 PR 里写明，并跑 `cargo deny --locked check`）。不要 `tokio::spawn`（`self` 不是 `'static`）。
- **合并规则**，与完成顺序无关：
  1. 有任何一批结论是 Deny → 拒绝（`JevDeny`）。出现 Deny 后不再等其余调用。
  2. 否则有任何一批调用失败或响应无效 → 不可判定，失败码取批次序号最小的那个。
  3. 否则有任何一批 Unknown → `JEV_UNKNOWN`。
  4. 全部 Allow → 放行（`JevAllow`），放行缓存的条件和现在相同。
- **记录**（`JevRecord`，在 `xshield-core/src/context/log.rs`）：加两个字段 `batches: Option<u16>`（总批数）和 `batch: Option<u16>`（记录展示的是第几批，从 1 起），只有多批时才有值，`None` 时不序列化。其余字段写“定结论的那一批”：
  - 按上面规则 1–3 定结论的，取对应的那一批（多批同类取序号最小的）。
  - 全部 Allow 时取把握最小的一批：`min(P(ALLOW), P(BENIGN))` 最小，相同取序号最小。这样 `jev_confidence` 反映整个请求里最弱的一环。
  - `millis` 是全部调用的墙上时间；`request_bytes` 是已发出各批之和；`usage` 把各批 `usage` 顶层的数值字段按名相加，非数值字段取展示的那一批。
- 控制台 `web/console/src/api/types.ts` 加这两个字段，`JevInspector.tsx` 在多批时显示“第 k 批，共 N 批”；`lib/align.ts` 加级别 4 的说明；`schemas/decision-record.schema.json` 同步。失败码 `JEV_STATE_TOO_LARGE` 保留，文案改为“已不应出现”之类的准确说法。

### 3.3 必须的测试

`state.rs`：

1. 2000 字符的值分片：每片不超过 512 字符，相邻重叠 64，去重叠拼接等于原值，带 `"part":"1/5"` 这样的标记，输出里没有 `[truncated]`。再用含中文和表情的长值测一次。
2. 字段名是秘密的长值、包含凭证的长值：都只出现一个 `<redacted>`，不分片。
3. 把原来的 `requests_that_cannot_fit_fail_instead_of_dropping_values` 改成：200 个 120 字符的值 → 至少两批，每批不超过 `STATE_BYTES_MAX`，各批的 `(at, value)` 合起来恰好等于输入，每个只出现一次。
4. `GOLDEN_STATE` 不变并通过。
5. 一个值独占一批的极端情况：512 个控制字符的值，加上很长的 `at`、`seen_as`、16 条很长的入口路径、很长的 `path` → 成功，不返回错误。
6. 相同 `at` 和 `value` 的重复值只出现一次。

`engine.rs`（给 `FakeJev` 加两样东西：按 state 内容决定回答，例如“state 含某个标记就 DENY 或失败”；记录同时在途的最大调用数，`ask` 里要有一个 `await` 点）：

7. 照 `probe_e9_big_form`（120 个字段、约 9.5 KB）：`enforce` 下 `forward == true`、`JevAllow`、`fake.calls() >= 2`、`record.jev.batches == Some(调用次数)`。批次 1 的第 4 条测试改成这个结果。
8. 限额按请求计一次：`session_calls_per_minute` 为 1 的站点，上面这个大请求通过；同一会话紧接着的下一个需要判定的请求得到 429。
9. 照 `probe_e4` 里的长值：`comment=` 后 600 个 `A` 再接 `' OR 1=1--`。发出的 state 里至少有一份含 `OR 1=1`；假 Jev 设成见到 `OR 1=1` 就判 ATTACK 时，请求被拒（`JevDeny`）。
10. 多批里只有一批判 Deny → 拒绝，`record.jev.state` 是判 Deny 的那一批，`record.jev.batch` 指向它。
11. 多批里一批超时、其余 Allow → `jev_unavailable` + `JEV_TIMEOUT`，`allow` 站点转发、`deny` 站点 403。一批超时同时另一批 Deny → 拒绝。
12. 并行：多批请求里同时在途的最大调用数大于 1 且不超过 8。
13. 多批放行后同一请求再来一次 → `cached_allow`，不再调用。
14. 最坏情况计数：48 KiB 的 JSON 数组、元素是各不相同的短数字，判定能完成；测试里断言批数并把实际批数写进 PR 描述（批次 9 的 16 批预算要用这个数）。

**文档**：docs/02 §2.2（`part`、分批）、§2.4（不再截断，上限含义）、§2.5（限额按请求计、并行上限 8）；docs/01 §1.4 第 6、7 步；docs/07 §7.5.1（两个新字段、多批时各字段含义）、§7.5.3（级别表）、失败码表里 `JEV_STATE_TOO_LARGE` 一行；docs/06 对应文案。

**验收标准**：14 条测试存在并通过；`GOLDEN_STATE` 未改；`grep -n "truncated\]" crates/xshield-judge/src/state.rs` 无结果；靶场全量通过；单批请求的 `JevRecord` 序列化结果与改动前相同（没有多出字段）。

### 3.4 验收后补充（2026-11-13，PR #209 第一轮验收的结论，随批次 2 一起改）

验收时用对抗用例量到三个问题，都要在批次 2 里解决。

**(a) 每个请求最多 16 批（`JEV_BATCHES_MAX = 16`）。** 200 个值的上限挡不住批数：一个值可以任意长（URL 不受 48 KiB 正文上限约束），一个 300 KB 的查询值在 `83d61eb` 上是 31 次调用，而限额只计一次。用户已确认 16 批的上限用于所有请求。规则：

1. 只在需要分批时排序，稳定排序，三类依次排：① 没核验的非输入值（`kind` 不是 `input` 且 `verified == false`，含这类值的片段）；② 其余不分片的值；③ 其余片段。每类内部保持原顺序。
2. 按这个顺序装批，只发前 16 批。没装进去的值和片段个数记为 `left_out`。
3. 第 ① 类在 16 批内装不完 → `StateTooLarge`，不调用，403（越权判定不允许不完整）。
4. `left_out > 0` 时照常按合并规则定结论。全部 Allow 则放行，但不写放行缓存，`JevRecord` 加 `left_out: Option<u32>`（`None` 不序列化）。控制台 Jev 面板显示“攻击判定不完整：有 N 个值或片段没有送判”，`schemas/decision-record.schema.json`、docs/02 §2.4 和 §2.5、docs/07 §7.5.1、docs/06 同步。docs/02 写明这条残留边界：把内容藏在 16 批（约 128 KiB 文本）之后可以避开攻击判定，批次 10 会按路由平时的大小再收一层。
5. 观察模式和拦截模式相同。

**(b) 空壳太大时各批用级别 4。** 每批都带完整的 `path` 和 `entries_passed`，这两样客户端能撑大（长路径；`/share/*` 这类入口的实际路径）。7400 字符的路径加 150 个短查询值在 `83d61eb` 上是 32 次调用，路径再长一点就是每批一个值。规则：级别 3 的空壳（不含值的 state）超过 `STATE_BYTES_MAX / 2` 时，所有批都按级别 4 装（`entries_passed` 置空、`path` 截到 256、不列来源）。路径各段本来就作为值送判，截 `path` 不丢内容。

**(c) 片段不能一律“不选择对象”，同一个值的各片 `kind` 要一致。** 现在的指令写“带 part 的值不选择任何对象”，把 `/api/patients/7` 写成 `/api/patients/000…07`（600 个字符，不少源站会按数字 7 处理）就拿到了这条豁免，改动前这样的值是 `kind: reference`、从未见过、会被判拒。另外 `kind` 是按片段文本算的，`/api/patients/aaa…a7` 的第一片是 `route`、第二片是 `reference`。规则：

- 片段的 `kind` 取整个值的 `kind`（`StateValue` 带上它，`render_value` 优先用）。
- `ACCESS_INSTRUCTIONS` 那一句改成这个意思：带 `part` 的值是一个长值的一片，按它的位置和 `kind` 像短值一样判；长的自由文本不选择对象，但处在选择对象的位置上的长值（路径里的编号、编号类字段）是一个从未展示过的对象引用。指令版本号随之再变一次。

**补充的测试**（在 3.3 的 14 条之外）：

15. 查询里一个约 300 KB 的长文本值，后面跟一个短参数 `tail=' OR 1=1--`：调用次数恰好 16；短参数在发出的某一份 state 里；假 Jev 见到 `OR 1=1` 判 ATTACK 时请求被拒。
16. 同一个请求不带注入：转发，`jev_allow`，`batches == Some(16)`，`left_out` 大于 0；同一请求再来一次仍然调用（没有走缓存）。
17. 路径里一段约 200 KB 的数字（引用类片段超过 16 批）：403，0 次调用，`JEV_STATE_TOO_LARGE`。
18. 7400 字符的路径加 150 个短查询值：批数不超过 4，`left_out` 为空。
19. `/api/patients/` 后接 600 个 `a` 再接 `7`：各片的 `kind` 都是 `reference`。再加一个靶场场景（可选但建议）：把别人的患者编号垫到 600 个字符访问，拦截模式下 403、`jev_deny`。
20. 单批请求的 `JevRecord` 没有 `left_out` 字段（并进现有的 `a_single_call_record_has_no_batch_fields`）。

3.3 第 14 条（48 KiB 短数字的最坏批数）在 200 个值的上限还在时量不出来，保留现在的测试，注释和 PR 描述里“最坏 2 批”的说法改掉：最坏是 16 批。批次 3 放开值数上限后，用同一条测试断言 16 次调用和 `left_out`。

其他：`state.rs` 里被改过的 `level` 测试（值长 150 改 120、`level < 5` 改 `< 4`）要在 PR 描述里列出并说明原因；`futures-util` 按工作区其他依赖的写法声明。

### 3.5 合并后补丁：分批时路径值每一批都带（2026-11-13，真实模型探测的结论）

**量到的事实**（main `b48c711`，提示词 `jq_d5df87392a92b44d`，模型 `jev-1.13.0`；全文在 [../designs/waf-batch2-live-probe-result.md](../designs/waf-batch2-live-probe-result.md)）：`POST /api/patients/7005/notes`，会话见过病人 7005，正文是 24 个 420 字符的字段加一个 1,500 字符的字段，全是正常文字，分 2 批。第 1 批 ALLOW 0.98，第 2 批 DENY 0.86，请求被拦。三条带编号路径的用例第 2 批都是 DENY（0.86、0.92、0.91）；同样形状、路径里没有编号的 `POST /api/feedback` 两批都 ALLOW 0.99。原因：每批的 `request.path` 相同，都带着 `7005`，但已核验的路径值 `{"at":"path[2]","value":"7005","verified":true}` 只在第 1 批里，批次用的级别 3 又没有 `recent`，模型在第 2 批找不到这个编号展示过的证据。把这一个路径值补进第 2 批再问，答 ALLOW 0.96、0.99。

影响：正文需要两批以上、路由里带对象编号的正常请求在拦截模式下被拦。这正是批次 2 要放行的那类请求；其中值的个数不多的那部分（比如上面这 25 个长字段）在批次 2 之前是把值截短后装进一份 state 放行的，对这部分请求是变差。假 Jev 只看列出的值，靶场和有效性流水线都量不出来；验收时我只做了假模型上的对抗用例，没有要求先做真实模型探测就合并，这是验收的疏漏。

**规格**（只改 `state.rs` 的分批路径；指令文字不改，提示词版本号不变）

1. **路径值**指 `at` 以 `path[` 开头、没有 `part` 的值（整段不超过 512 字符的路径段）。请求需要分批时，路径值和 `function` 一样算请求自身的空壳：每一批的 `request.values` 开头都是全部路径值，按原顺序，按该批的裁剪级别照常渲染（`verified`、`seen_as`、`object`、`attempt` 都照常）。其余的值按 3.4 (a) 的三类顺序装在它们后面。
2. 空壳的大小把路径值算进去：`batch_trim` 的“超过 `STATE_BYTES_MAX / 2` 用级别 4”和 `pack` 的起始大小都用带路径值的空壳。
3. 计数：路径值只算一次。`left_out` 只数没送出的非路径值和片段；3.4 (a) 第 3 条的“第 ① 类装不完”只数不在空壳里的第 ① 类值。
4. 超过 512 字符的路径段照旧切片，片段不进空壳，照旧按第 ① 类排在最前（片段永远是没核验的，带它的那一批本来就该判拒）。
5. 带上路径值之后级别 4 的空壳仍超过 `STATE_BYTES_MAX / 2`（路径各段加起来有几千个字符）时，路径值不进空壳，按合并时的做法排序装批。这是病态路径，行为与 `b48c711` 相同，写进 docs/02 的残留边界。
6. 一份 state 装得下的请求完全不变：`GOLDEN_STATE` 不改，级别 0 到 3 的整份路径不动。

**假 Jev 跟着真实模型改**（`tests/security-lab/fake_jev.py`，理想模式和普通模式都生效）：`request.path` 里有一段全是 ASCII 数字，而 `request.values` 里没有 `at` 以 `path[` 开头、`value` 等于这一段的条目时，`access` 答 DENY。文件头的说明里写明这条来自上面的实测。这样靶场和有效性流水线以后能量出同类问题。加这条之后先不改 `state.rs` 跑一遍靶场全量和有效性流水线，把因此新失败的场景列进 PR 描述；修好 `state.rs` 后它们必须全部恢复。**如果有场景在修好之后仍因这条规则失败（比如固定路由段里的数字没有作为值送出），停下来把场景名和 state 原文发给验收方，不要放宽规则，也不要改场景。**

**必须的测试**

1. 状态层：`/api/patients/7005/notes`（四个路径值，`7005` 已核验并带一条来源）加 24 个 420 字符的字段和一个 1,500 字符的字段：批数不少于 2；每一批的 `request.values` 开头依次是四个路径值，`path[2]` 那条带 `verified: true`；每个非路径值和片段在所有批里恰好出现一次；`left_out == 0`。
2. 状态层：同上但 `7005` 没核验：每一批都带它，且没有 `verified` 键。
3. 状态层：路径值不重复计数。`/api/patients/7005/notes` 加一个约 300 KB 的查询值：恰好 16 批，`left_out` 等于没送出的片段数（自己算出来断言相等），路径值不计入。
4. 状态层：路径里一段 600 字符的值：它的片段在所有批里各出现一次，不重复。3.4 的第 17、18、19 条原样通过，断言不改。
5. 状态层：12 段各 500 字符的路径加足够分批的查询值：不报错，每个路径值恰好出现在一批里（第 5 条规格的回退）。
6. 引擎层：会话先见过病人 7005，再发第 1 条那样的请求；测试里的假模型在一批的 `request.values` 没有已核验的 `path[2]` 时答 DENY。断言转发、`jev_allow`、`batches` 不少于 2。这条测试在不改 `state.rs` 时必须失败，PR 描述里贴失败输出。
7. 引擎层：同一请求换成没见过的病人 7006：拒绝，`jev_deny`。
8. `fake_jev.py` 新规则的单元测试（`tests/security-lab/` 下现有的假 Jev 测试文件里）：路径带数字段且值里有它 → 按原规则；值里没有 → DENY；路径没有数字段 → 不受影响。
9. 靶场两个场景：对自己病人的备注路由发需要两批以上的正常长表单 → 转发，判定记录 `jev_allow`、`batches` 不少于 2；对别人病人发同样的表单 → 403、`jev_deny`。
10. 有效性回归用例 `p1-9-big-form-on-object`（`tests/security-lab/effectiveness/regressions.py`，`must`，预期 `allow`，站点 `clinic-truth`）：登录，列出病人，对列表里自己的病人 `POST /api/patients/{id}/notes`，正文大到分两批以上（PR 描述里贴这条的判定记录，`batches` 不少于 2）。跑 `python3 scripts/measure_effectiveness.py`：`must` 通过率 100%，意外通过只有已知的三条（`p0-1-multipart`、`p0-1-long-value`、`p1-9-big-form`，由有效性批次 8 翻，本 PR 不动它们）。

**文档**：docs/02 §2.4（各批共用的内容加上路径值；第 5 条的残留边界进 §2.5）、docs/07 §7.5.3 如有对应描述一并改、CHANGELOG 一条。提示词版本表不动。

**不在本 PR**：`live_jev` 用例。合并后由功能级越权线程（持有密钥）用它的探测代码重跑 P10 到 P14，验收方看结果。

**验收标准**：10 条测试存在并通过；第 6 条和第 9 条的第一个场景在 `b48c711` 的 `state.rs` 上失败（验收方自己做这次回退检查）；现有测试的断言没有改动（有改动逐条列出原因）；靶场全量、有效性流水线按上面的口径通过；合并后的真实模型重跑 P10 放行、P11、P12、P14 仍拦。

## 4. 批次 3：请求值读全（P0-1 下半）

依赖批次 2 已合并（否则值变多只会多出 state 过大的拒绝）。

### 4.1 `values.rs` 的 `extract_request`

- 删除 200 个值的上限：`push` 不再看 `REQUEST_VALUES_MAX`。常量连同它的整条上报链路一起删：`xshield-edge/src/status.rs:237`、`xshield-control/src/system.rs:140,277`、`web/console/src/api/types.ts:977`、`features/system/ParamsPanel.tsx:88`、`tests/fixtures/system.json:197`、docs/07 第 215 行和第 780 行附近的示例。
- 删除 `BODY_PARSE_MAX`（网关已经限制了正文大小；`xshield-core/src/context/route.rs` 里同名常量是另一回事，不动）。
- JSON 深度超过 `JSON_DEPTH_MAX` 时不再丢弃：把那棵子树序列化成文本，作为一个值放在当前位置（批次 2 会给它分片）。不再因此置 `truncated`。
- 键名超过 64 个字符时，和带语法的键名一样作为 `#name` 值送判（改 `push_unusual_key` 的条件）。
- 按正文类型分派：

  | 类型 | 处理 |
  |---|---|
  | `application/x-www-form-urlencoded` | 不变 |
  | JSON（`is_json_media`） | 解析成功按 JSON；失败按“整段” |
  | `multipart/form-data` | 见 4.2；解析不出任何部分按“整段” |
  | 其他类型，或没有 `Content-Type` | 去掉首尾空白后以 `{` 或 `[` 开头且能解析成 JSON 的，按 JSON；否则按“整段” |

- **整段**：正文按 UTF-8（有损）解码后作为**一个**值放在 `body`，没有键，不再只取前 2048 字节；`truncated = true`。
- 本批之后，`engine.rs` 的 `token_digests` 只剩整段正文的请求会用到（值超过 200 个、正文过大这两种情况不再存在）。它按词取摘要、漏掉含 `/`、`=`、`:` 的值的问题由批次 5 修，本批不动它。
- `ExtractedRequest::truncated` 的含义改为“正文不是结构化数据，整段作为文本判定”，更新注释、`schemas/decision-record.schema.json` 里 `values_truncated` 的说明和 docs/07 第 224 行。`engine.rs` 里依赖它的逻辑不动：整段的请求不快速放行、不用放行缓存、响应里出现请求的任何词都不学（`token_digests`）。

- **16 批预算**：批次 2 已经实现（3.4）。本批放开值数上限后，48 KiB 以内的正文第一次能超过 16 批（约两千个以上的短值）。本批不改预算的规则，只加测试：48 KiB 各不相同的短数字 → 恰好 16 次调用、转发、`left_out` 大于 0、不进缓存；一万个惰性之外的短参数最后跟一个没见过的 `patient_id=8` → 引用排在前面，仍被送判并判拒；两千五百个各不相同的没见过的编号类参数 → 403、0 次调用、`JEV_STATE_TOO_LARGE`。

### 4.2 multipart 解析（自己写，不加依赖）

- 边界取自 `Content-Type` 的 `boundary` 参数（参数名不分大小写，值可以带引号）。没有边界 → 按整段。
- 用 `--边界` 切分。第一段之前的内容忽略；遇到 `--边界--` 结束。每一部分：头部到第一个空行为止（`\r\n\r\n` 或 `\n\n` 都接受），其余是内容，去掉结尾的一个换行。
- 从 `Content-Disposition` 取 `name`、`filename`、`filename*`（值可以带引号，引号里可以有分号）。
- 有 `filename` 或 `filename*` 参数（值为空也算）的是文件部分：只把文件名作为值放在 `body.<name>#filename`，**不带键**（带键会被当成对象引用），内容不提取。
- 其余是文本部分：内容有损解码后和表单字段一样处理，位置 `body.<name>`，键是 `name`，键名同样过 `push_unusual_key`。这一部分自己的 `Content-Type` 是 JSON 且能解析时，按 JSON 展开到 `body.<name>` 之下。
- 没有 `name` 的部分：位置 `body`，没有键。找不到头部结束位置的部分：整块作为文本值放在 `body`。宁可多判，不可漏判。
- 生产路径不许 panic：所有切片用 `get`，按字节查找，不假设 UTF-8。

### 4.3 必须的测试

`values.rs`：

1. 5000 个查询参数全部提取（替换原来断言 200 个上限的测试）。
2. multipart：两个文本字段加一个文件部分 → 文本字段的位置、键、值正确；文件部分只有 `body.avatar#filename`，文件内容里的标记不出现在任何值里。
3. multipart 变体：带引号的边界、只用 `\n` 换行、`filename*=UTF-8''…`、没有 `name` 的部分、某一部分的 `Content-Type: application/json`、缺边界、内容里没有任何边界 → 都不 panic，结果符合 4.2。
4. `text/plain` 里的 JSON 对象按 JSON 提取（`body.patient_id`），`truncated == false`。
5. `text/xml` 正文：一个值，位置 `body`，包含正文全部内容（用 5000 字节的正文，断言结尾的标记在值里），`truncated == true`。
6. `Content-Type: application/json` 但正文不是合法 JSON → 整段。
7. 20 层嵌套的 JSON：最深处的标记字符串出现在某个值里。
8. 100 个字符的键名作为 `#name` 值出现。

`engine.rs`（探针转成回归测试）：

9. `probe_e3_padding` 两个场景：200 个惰性参数之后的 `patient_id=8` 和注入串都在发出的 state 里，`patient_id` 的 `kind` 是 `reference`；假 Jev 设成“见到没展示过的引用就 DENY”或“见到 `OR 1=1` 就 ATTACK”时请求被拒。
10. `probe_e4` 的 multipart 场景：state 里有 `body.patient_id` 值 `8` 和 `OR 1=1`，`request.truncated` 为 false。
11. `probe_e4` 的 `text/plain` JSON 场景：`body.patient_id` 值 `8` 作为引用送判。
12. 300 个值全部是会话已见过的同类对象编号的请求 → `fast_allow`，0 次调用（大请求不因为大而调用模型）。

靶场（`scripts/test_idor_lab.py` 加场景，`tests/security-lab/README.md` 加行；用靶场已有的接口，需要时给 `tests/security-lab/` 的源站加最小的接口）：

13. 垫 200 个惰性参数后引用别人的对象 → 403、`jev_deny`。
14. 用 multipart 提交、字段里引用别人的对象 → 403、`jev_deny`。
15. 600 字符填充之后带注入串的长值 → 403、`jev_deny`。
16. 120 个字段的正常表单 → 源站的成功状态码、`jev_allow`。

**文档**：docs/01 §1.3（提取规则、整段的含义、multipart、文件部分只判文件名）、docs/02 §2.4、docs/07 §7.4.2 的 `values[]` 和 `values_truncated` 两行与系统参数示例、docs/06 里 `values_truncated` 的提示文案。在 docs/01 §1.3 写明一条已知边界：带文件名的 multipart 部分内容不判。

**验收标准**：16 条测试存在并通过；`grep -rn "REQUEST_VALUES_MAX\|request_values_max" crates web/console/src web/console/tests docs` 无结果；`cargo test -p xshield-judge` 里一个 48 KiB、约一万个参数的请求能在测试超时内判完（加一条这样的测试，不断言耗时，只要求完成）。

### 4.4 真实模型探测后的补充（2026-11-13，PR #227 头 `48a209e`，结果在 [../designs/waf-batch3-live-probe-result.md](../designs/waf-batch3-live-probe-result.md)）

探测里五种目标请求有四种两遍都符合预期。两件事要处理：

**(a) 合并顺序。** 120 个字段的表单在带编号的路径上两遍都被拦，是 3.5 的分批缺陷，不是本批引入的，但本批让分批的请求变多。所以 3.5 的补丁先合，本批随后合入 main 再合并；合入后请探测线程在带编号的路径上重跑 V4。

**(b) 两种请求体源站按字段读、网关按一段文字读，随本批改掉。** 网关读得比源站粗，字段里的编号就不是引用，越权判定只能靠模型从一段文字里读出来；把编号埋在 512 个字符之后，它落在一个 `input` 长值的后一片里，指令又说长的自由文本不选择对象。Rack 会把这两种都解析成字段。

1. **所有带 `boundary` 的 `multipart/*`**（`mixed`、`related` 等，不只 `form-data`）都按 4.2 读。没有 `name` 的部分照 4.2 放在 `body`、没有键；这一部分自己的类型是 JSON 且能解析时照 4.2 展开。
2. **没有 `Content-Type`、又不是 JSON 的正文，形状是表单时按表单读**，`truncated = false`。“形状是表单”的判据写死：去掉首尾空白后非空，不含任何空白字符和控制字符，不含 `;`，按 `&` 切开后每一段都含 `=`。（`;` 是 16:17 UTC 实现线程提出后加的：有的框架把 `;` 也当分隔符，含 `;` 的正文整段判定，与改动前相同。）不满足的照旧整段。只对没有 `Content-Type` 的正文这样做；`text/plain` 等其他类型不变（常见框架不会把它们解析成字段）。

补充的测试：

17. `multipart/mixed` 和 `multipart/related` 各一例，字段同第 2 条：`body.patient_id` 是带键的值，`truncated == false`，边界和头部文字不出现在任何值里。
18. 没有 `Content-Type` 的 `patient_id=8&note=routine`：`body.patient_id` 值 `8`、键 `patient_id`，`truncated == false`。
19. 没有 `Content-Type` 的非表单正文各一例（含空格的一句话；`a=1&b`；只有换行分隔的两行）：整段，`truncated == true`。
20. 引擎层：没有 `Content-Type`，正文是 `note=<600 个字符>&patient_id=8`，会话没见过 8：state 里有 `body.patient_id`，`kind` 是 `reference`；假 Jev 设成“见到没展示过的引用就 DENY”时请求被拒。再加一例 `multipart/mixed` 同样的字段。
21. 靶场一个场景：不带 `Content-Type` 提交表单、字段里引用别人的对象 → 403、`jev_deny`。

docs/01 §1.3 的类型表同步，并在已知边界里加一条：网关只按 `&` 切分查询和表单，源站如果把 `;` 也当分隔符，`;` 后面的字段在网关里是前一个值的一部分，照常送攻击判定，但其中的编号不作为引用核验。这条边界在本批之前就存在，本批不解决。这两条改了 state 里值的形状，合并前按第 13 节第 8 条请探测线程重跑 V6、V7 和它们的良性对照（自己的编号：放行，且不再每次都问模型）。

**(c) 验收读 PR #227（`bfaef70`）时找到的解析差异，随本批改掉。** 原则不变：源站可能读成字段的内容，网关也要读成字段；拿不准时两种读法都送判。4.2 里“`filename` 值为空也算文件部分”是我写错的，方向反了。

3. **文件部分只认非空的文件名。** `filename` 和 `filename*` 都为空（或没有）的部分是文本部分，内容照常送判。原因：Go 的 `mime/multipart` 把文件名为空的部分当普通字段，按原规格它的内容不判，字段里的编号和注入都能藏进去。
4. **一个部分有多个不同的 `name`**（参数重复，或有多个 `Content-Disposition` 头）时，内容在每个名字下各送一次（位置、键各用各的）。原因：解析器有的取第一个，有的取最后一个。
5. **文本部分带 `Content-Transfer-Encoding: base64` 或 `quoted-printable`**（不分大小写）时，原文照常送判，解码成功且与原文不同时，解码后的内容在同一位置、同一键下再送一次。解码器自己写，不加依赖，按字节处理，不许 panic；base64 按 Python 非严格解码的读法解（16:45 UTC 修订，原来写的“遇到第一个 `=` 停”不对）：丢掉字母表以外的所有字符（含空白）；`=` 只有在补齐一组时才结束数据，即这一组已有 3 个符号，或已有 2 个符号且这是上一个符号之后的第二个 `=`，结束之后的内容不读；其余位置的 `=` 丢掉、继续解；数据在一组中间结束时，解出已经完整的字节（比 Python 宽，Python 此时报错）；一个字节都解不出才算失败。例子：`J=yBPUiAxPTEtLQ==` 解出 `' OR 1=1--`（第 2 个字符处的 `=` 不结束数据），`OA==eA` 解出 `8`。（16:35 UTC 实现线程指出 Python 的 `b64decode` 默认丢弃非法字符，Django 用的就是它，所以严格解码会漏掉 `JyBPUi'AxPTEtLQ==` 这种写法。）原因：Django 对字段做 base64 解码，Go 对部分做 quoted-printable 解码，网关只看原文的话 `JyBPUiAxPTEtLQ==` 在源站就是 `' OR 1=1--`。
6. **任何类型的正文，去掉首尾空白后以 `{` 或 `[` 开头且能解析成 JSON 的，都按 JSON 读**，包括 `application/x-www-form-urlencoded` 和读不出部分的 `multipart/*`。原因：有的源站不看类型一律按 JSON 解析，`text/plain` 堵上之后同样的正文换个类型又成了一个键名或一段文字。**16:45 UTC 修订：JSON 读法不优先，两种都读。** 原来写的“真正的表单不会整体是合法 JSON，所以优先于按表单读”是错的：`{"a=":"&patient_id=8&b="}` 既是合法 JSON，按 `&` 切开又是三个字段，按表单读的源站得到 `patient_id=8`，网关只按 JSON 读时它是一段文字的一部分，不是引用，比 main 还退了一步。改为：类型是 `application/x-www-form-urlencoded` 的正文照常按表单读，同时能解析成 JSON 的，JSON 读出的值也加进去；没有类型的正文能解析成 JSON 的按 JSON 读，同时满足第 2 条表单形状的再按表单读一遍。两种读法都成立时 `truncated = false`。其他类型（`text/plain` 等）和读不出部分的 `multipart/*` 只有 JSON 一种读法，不变。

   **17:00 UTC 二次修订（没有类型的正文），以这一段为准，第 2 条的“形状是表单才按表单读”随之放宽。** 功能级验收线程在靶场上实测了上面的回归（[../designs/waf-batch3-json-precedence-finding.md](../designs/waf-batch3-json-precedence-finding.md)，Z4：表单类型、体 `{"a":"&note=x&patient_id=PT-7004&b="}`，`bfaef70` 拦截，`a05cc85` 放行到源站）。同时发现第 2 条的判据太严，起不到防护作用：Rack 对没有类型的 POST 一律按表单读，值里加一个空格（`note=a b&patient_id=8`）或者 JSON 里加一个空格，网关就不按表单读了。没有类型的正文改为“每种说得通的读法都读”：
   - 能解析成 JSON（去掉首尾空白后以 `{` 或 `[` 开头）：读 JSON 的值。
   - 含有 `=`：按表单读（只按 `&` 切）。满足第 2 条严格判据（下称“严格表单形状”）时所有字段都读，与现在相同；不满足时只保留名字像字段名的字段：名字去掉首尾空白后非空，且只含字母、数字和 `_ - . [ ] % +`，用去掉空白后的名字作键和位置。这个过滤是为了不把 XML 属性、JSON 字符串里的 `=`（base64 补位、URL 查询串）读成一堆带“user”“token”字样的假引用。
   - 既不是 JSON 也不是严格表单形状：整段再作为一个文本值放在 `body`，`truncated = true`（与现在相同）。
   
   类型是 `application/x-www-form-urlencoded` 的：照常按表单读（所有字段，不过滤），能解析成 JSON 的再加 JSON 的值。`text/plain` 等其他类型不变。

   **17:20 UTC 验收 `e6fed2f` 后的三处补充**（探针 9 组里 8 组通过，其余实现与规格一致）：
   - 没有类型的正文能解析成 JSON 时，表单读法一律用“只保留像字段名的名字”那一种，即使它也满足严格表单形状。否则紧凑的 JSON（`{"user":"bob","sig":"abc=="}` 没有空白，整体是一个含 `=` 的段）会多出一个键为 `{"user":"bob","sig":"abc` 的假引用，正常客户端多问模型甚至被拦。表单类型的正文不变（main 上本来就这样读）。
   - 第 4 条的名字数上限（`PART_NAMES_MAX = 4`）要留，防止“名字数 × 内容”放大；但超过时不能退成没有名字的一段文本：`name="a"; …; name="patient_id"` 写 5 个名字，Django 取最后一个得到 `patient_id=8`，网关里 `8` 成了 `body` 下的 `input`。改为：超过 4 个不同名字时，只看第一个和最后一个 `Content-Disposition` 头，各取 `parameters` 给出的第一个 `name` 和最后三个 `name`（最后三个覆盖最后一个写出的和至多两个还原出的），去重后至多 8 个，内容在这些名字下各读一次，同时 `truncated = true`。解析器只会取第一个或最后一个头、第一个或最后一个参数，中间的不用读。
   - quoted-printable 的软换行：`=` 后面跟若干空格或制表符再跟换行，也算软换行（Go 先去掉行尾空白再判断）。

7. **参数的 RFC 2231 写法统一还原**（16:55 UTC 加）。`parameters` 除了原样的参数，还给出还原后的普通参数：`x*=charset'lang'百分号编码` 还原成 `x`；`x*0=`、`x*1=`、`x*2*=` 这样的续写按序号拼起来还原成 `x`（带 `*` 结尾的段做百分号解码，第一段去掉 `charset'lang'` 前缀）。`boundary`、`name`、`filename` 都走这一处，`filename_star` 的特例并进来。还原出的 `name` 与普通的 `name` 不同时按第 4 条各读一次。原因：Go 的 `mime.ParseMediaType` 两种写法都还原，Django 还原 `name*`；按 a05cc85，`name*=UTF-8''patient_id` 的部分在网关里没有名字，内容 `8` 是 `body` 下的一个 `input`，不是引用；`boundary*0=` 的正文整段不拆。
8. **部分头部的折行先拼接再读**（16:55 UTC 加）。以空格或制表符开头的头部行并进上一行（中间留一个空格）。原因：Go 的 `textproto` 会拼接，`Content-Disposition: form-data;` 换行后 ` name="patient_id"` 在 Go 里有名字，在网关里没有。PR 描述把它列为已知边界 6，改成修掉，docs/01 §1.3 的已知边界删掉这一条。

补充的测试：

22. `name="patient_id"; filename=""` 的部分，内容 `8`：`body.patient_id` 值 `8`、带键；`truncated == false`。`filename="a.png"` 的对照仍只有文件名。
23. `name="note"; name="patient_id"` 和两个 `Content-Disposition` 头各一例：`body.note` 和 `body.patient_id` 都有值 `8`，各带自己的键。
24. base64 的字段（`JyBPUiAxPTEtLQ==`）：值里既有原文也有 `' OR 1=1--`；quoted-printable 的字段（`=27 OR 1=3D1--`）同理；夹了非法字符的 base64（`JyBPUi'AxPTEtLQ==`）同样解出 `' OR 1=1--`；`J=yBPUiAxPTEtLQ==` 同样解出；`OA==eA` 解出 `8`；没有补齐的 `JyBPUiAxPTEtLQ` 同样解出；什么都解不出的（`'''`）只有原文；带换行的 base64 能解。引擎层一例：base64 的注入串，假 Jev 见到 `OR 1=1` 判 ATTACK 时请求被拒。
25. `Content-Type: application/x-www-form-urlencoded`，正文 `{"patient_id":8}`：`body.patient_id` 值 `8`，`truncated == false`；普通表单 `a=1&b=2` 不受影响；`multipart/form-data; boundary=b`，正文是 JSON（没有任何部分）：按 JSON。
26. `Content-Type: application/x-www-form-urlencoded`，正文 `{"a=":"&patient_id=8&b="}`：有 `body.patient_id` 值 `8`、键 `patient_id`，也有 JSON 读出的那个值，`truncated == false`；没有 `Content-Type` 的同一正文结果相同。引擎层一例：会话没见过 8，假 Jev 设成“见到没展示过的引用就 DENY”时请求被拒。第 25 条里表单类型的 `{"patient_id":8}` 现在两种读法的值都有，断言 `body.patient_id` 值 `8` 仍成立。
26a. 没有 `Content-Type` 的正文各一例：`note=a b&patient_id=8`（`body.patient_id` 值 `8` 带键，另有整段文本，`truncated == true`）；`{"a": "&patient_id=8&b="}`（JSON 里有空格：`body.patient_id` 值 `8` 带键，另有 JSON 的值，`truncated == false`）；`x& patient_id=8`（键是去掉空白的 `patient_id`）；`<user id="5">t</user>`（只有整段文本，没有带键的值）；`{"token":"abc=="}`（只有 JSON 的值）。第 19 条里的 `a=1&b` 现在还多一个 `body.a`，整段文本和 `truncated == true` 不变。靶场加一个场景钉住表单类型的回归：医生 A 的会话，`POST /api/notes`，表单类型，体 `{"a":"&note=x&patient_id=PT-7004&b="}`，期望 403、`jev_deny`、不到源站（场景原文在上面链接的文档里，编号用下一个没占用的 B 号）。
27. `Content-Disposition: form-data; name*=UTF-8''patient_id`，内容 `8`：`body.patient_id` 值 `8`、键 `patient_id`。`name*0="patient"; name*1="_id"` 同样。`name="note"; name*=UTF-8''patient_id`：两个名字下都有。`Content-Type: multipart/form-data; boundary*0=a; boundary*1=b`，正文用 `--ab` 分隔：按部分读出字段。文件名的既有测试（`filename*`）不变。
28. 头部折行：`Content-Disposition: form-data;\r\n name="patient_id"`，内容 `8`：`body.patient_id` 值 `8`、带键；折行里的 `filename="a.png"` 使它成为文件部分；折行的 `Content-Transfer-Encoding` 也读到。引擎层一例（27 或 28 任选其一的写法）：会话没见过 8，假 Jev 见到没展示过的引用就 DENY 时请求被拒。

docs/01 §1.3 同步，并把仍然存在的差异写进已知边界：`boundary` 参数重复时只认第一个，认不出部分就整段判定；部分里再嵌套 multipart 时内层整段作为文本判定。

有效性用例：本批在同一个 PR 里把 `p0-1-pad-200` 翻成 `must`。`p0-1-multipart`、`p0-1-long-value`、`p1-9-big-form` 由有效性批次 8 翻，`p0-1-big-upload`、`p0-1-big-json` 属于批次 9，本批都不动。

## 5. 批次 4：观察模式下本应拦截请求的响应不学（P1-5 学习部分）

**现状**：`Judge::observe` 不看 `observation.would_block`，只把它写进 `summary.after_would_block`。docs/07 §7.4.6 记录了这个问题。

**行为规格**：`observation.would_block == true` 时，这个响应对上下文不产生任何影响，和拦截模式下请求根本没到源站一样：

- 不学值（会话和地址两种上下文都不学），不暂存登录响应，不声明身份，不记入口通过，不进最近访问，不算属性越权告警，不上报结构。
- 仍然执行 `note_request_sent`（请求发出的值照旧记下）。
- 响应摘要：`observed = Skipped`、`skip = Some(Skip::WouldBlock)`（`xshield-core/src/context/trace.rs` 的 `Skip` 加这个变体，序列化为 `would_block`）、`after_would_block = true`、`new_values = 0`。`issued_session` 照常填。
- bypass 路径和非 2xx 的判断顺序不变，`would_block` 的检查放在它们之后、读正文之前。

P1-5 的 413 部分不在本批，由批次 9 处理。PR 193 在 `observe` 开头为入口上被源站应答的凭证建会话的那一段，本批不动；“本应拦截的响应不建会话”由“设计功能级越权防护”线程的第 1 层补上，届时它会把下面测试 3 的断言改成“新凭证没有会话”。

**改动点**

- `engine.rs` 的 `observe`。
- `Skip::WouldBlock` 的下游：`web/console/src/lib/vocab.ts` 和 `api/types.ts` 的跳过原因、`schemas/decision-record.schema.json`、docs/06 第 368 行附近、docs/07 §7.4.3。
- 控制台文案：`detail-model.ts:563`“本应拦截请求的响应也进入了上下文”改为没有进入；`sessions/TimelineList.tsx:157` 的“本应拦截学习”标签改为“本应拦截，未学习”。
- 就绪检查里“由本应拦截请求学到的值被后续请求引用 N 次”这一项不再有意义，整条删掉：`web/console/src/features/sites/Readiness.tsx:81` 附近、`api/types.ts` 的 `after_would_block_refs`、`xshield-control/src/insights.rs:364,1424,1434`、`xshield-postgres/src/decision_stats.rs:984` 的查询和它的测试、对应夹具、docs/07 第 852 行附近。
- docs/07 §7.4.6 改写为已定的行为；docs/00 §0.5 和 docs/01 §1.4 第 8 步补一句。

**必须的测试**

1. 观察模式站点：一个本应拦截的请求，它的 2xx 响应带 `would_block: true` 交给 `observe` → `new_values == 0`、`skip == Some(Skip::WouldBlock)`；随后引用该响应里某个编号的请求不是 `fast_allow`。
2. 对照：同一响应 `would_block: false` 时照常学，随后的请求 `fast_allow`。
3. 本应拦截的登录请求，响应下发了凭证：不暂存登录，新凭证的会话没有任何已见值，`entry_passed == false`。
4. 本应拦截且没有凭证的入口请求：地址上下文不学。
5. `xshield-edge/tests/scenarios.rs` 加一条观察模式的端到端场景：本应拦截请求的响应没被学。
6. 控制台和 control、postgres 的测试随删除项更新并通过（跑 `scripts/test_postgres.sh` 和控制台五条）。

**验收标准**：6 条通过；`grep -rn "after_would_block_refs" crates web` 无结果；docs/07 §7.4.6 与代码一致。

### 5.1 验收后补充（2026-11-13，PR #208 第一轮）

- 控制台要区分新旧记录（规格原来的文案改法有疏漏）：判定日志保留 7 天，升级前的记录是 `after_would_block = true` 且 `observed = json`、`new_values > 0`，它们的响应当时进了上下文。`learningAttention` 在 `after_would_block` 且 `observed !== "skipped"` 时写“本应拦截请求的响应也进入了上下文（旧版本的记录）”，其余写“没有进入上下文”；时间线标签按 `learned > 0` 分“本应拦截学习”和“本应拦截，未学习”。两种各有数据和断言。
- 测试 3 的“不暂存登录”要有一条 JSON 凭证站点的测试（正文带令牌、没有 `Set-Cookie`）。验收方的三条探针在 [waf-batch4-acceptance-probes.rs.txt](waf-batch4-acceptance-probes.rs.txt)。

## 6. 批次 5：`sent` 收窄，做法一加二（P1-2）

依赖批次 3、4 已合并。

**现状**：请求里没核验的值的摘要经 `Judgement::sent` → `Observation::sent` → `note_request_sent` 永久记进 `SessionContext::sent`，之后任何响应都不学（`context.rs` 的 `learn`）。探针 `probe_e15_search_by_id_then_open`。

**行为规格**

- **做法一**：排除只对“带这个值的那次请求的响应”生效，不再记进会话。之后别的请求的响应展示同一个值，照常学。
- **做法二**：在当次响应里，请求以**输入**发出的值（`value_kind` 为 `input`：查询、表单、JSON 里非引用键下的值），如果响应把它放在**类似标识的字段**里，算源站展示，学。请求以**引用**发出的值（路径段，以及 `value_kind` 为 `reference` 或 `route` 的值）在当次响应里的回显仍然不学。
  - “类似标识的字段”只认 JSON 响应：字段名最后一段满足 `is_id_like`，或站点声明过它是标识（`kind::declares`）。**HTML 响应里的 `link` 和 `value` 不算**：搜索页的分页链接会把搜索词原样放进 `href`，那是回显不是展示。
  - 正文不是结构化数据的请求（`truncated`）不适用做法二，当次响应里出现请求的任何词都不学，和现在一样。
  - 档位机制的 `echo` 不变。

**改动点**

- `engine.rs`：`plan_values` 把没核验的值分成两组摘要，`Judgement` 相应加一个字段（例如 `typed`：以输入发出的值）；`sent` 只留以引用发出的值和整段请求的词。`Observation` 加同名字段，`xshield-edge/src/proxy.rs` 的 `RequestContext` 多存、多传一份。
- `observe`：学习之前先从这次响应的值里去掉 `sent` 命中的；`typed` 命中的只有在“类似标识的字段”里才保留。登录响应暂存、身份声明、地址上下文都用过滤后的值。
- `context.rs`：`SessionContext::sent`、`sent_overflow`、`note_sent`、`note`、`stop_learning`、`SentRecord`、`sent_record`、`inherit_sent`、`SENT_MAX`，以及 `learn` 和 `declare_identity` 里对 `self.sent` 的检查全部删除；`engine.rs` 的 `note_request_sent`、`stop_learning` 一并删除。PR #213（伪造凭证不建会话，2026-11-13）加的暂存也在这里删：`PendingSent`、`PendingRecord`、`PENDING_MAX`、`PENDING_VALUES_MAX`、`ContextStore::pending`、`ContextStore::note_sent`、`ContextStore::stop_learning`、`SessionContext::sent_len`，以及 `ContextStore::session` 里带入暂存的那一段和 docs/01 §1.2 讲暂存的段落。删除后“凭证没有会话时被拒请求的值”不再记录，这与做法一一致。
- 整段请求的词超过 5000 个时（原来的 `SENT_MAX` 分支），改成“这次响应什么都不学”：`Judgement` 和 `Observation` 各加一个布尔字段传递。
- **按词回声的缺口（2026-11-13 10:15 UTC 补充，设计线程验收时在 `main` 上复现）**：`token_digests` 按 `[A-Za-z0-9-_.@+]` 之外的字符分词，含 `/`、`=`、`:` 的值（base64 编号、`user:42` 这类复合编号）整体的摘要不在 `sent` 里，源站回显时被当成新值学进上下文，也会作为登录候选暂存。批次 3 之后只有整段正文的请求还走 `token_digests`，本批把它补上：过滤响应的值时，“`sent` 命中”定义为**整个值的摘要在 `sent` 里，或者把这个值按 `token_digests` 同一套规则分词后至少有一个词且每个词的摘要都在 `sent` 里**。分词函数提成一个，两处共用。这条规则对学习、登录暂存、身份声明、地址上下文同样生效。
- **STOP**：如果发现 `sent` 还有本规格没提到的用途（除了上面列的），先问验收方再删。

**必须的测试**

1. `probe_e15` 改成回归测试并断言：搜 `q=20261113001`，JSON 响应 `{"results":[{"id":"20261113001"}]}` → `new_values >= 1`，随后 `GET /api/orders/20261113001` 为 `fast_allow`。
2. 做法一：请求以引用发出没见过的值（路径里的编号，观察模式或 Jev 放行后转发），当次响应回显 → 不学；之后**另一个请求**的响应在 `id` 字段展示它 → 学，再访问为 `fast_allow`。
3. 引用回显不洗白：`GET /api/patients/8` 的响应里有 `{"id":"8"}` → 不学，再次请求仍然交 Jev。（已有同类测试就保留并指出。）
4. 输入放在非标识字段里回显（`{"query":"20261113001"}`、`{"note":…}`）→ 不学。
5. HTML 响应把搜索词放进 `href` 的查询串 → 不学。
6. 响应下发新凭证时，新会话不学当次请求以引用发出的值的回显（替换原来 `inherit_sent` 的测试）。
7. 整段请求（`text/xml`）的响应里出现请求里的词 → 不学；词超过 5000 个 → 这次响应什么都不学，但下一次响应照常学（原来是整个会话停止学习）。
8. 按词回声：整段请求（`text/xml`）的正文里有 `aaaaaaaaaa/bbbbbbbbbb==` 和 `user:42`，JSON 响应在 `id`、`token` 字段里回显它们 → 都不学，也不作为登录候选暂存；响应里另一个请求没发过的值照常学。响应值 `user:43`（`43` 不在请求里）照常学。
9. `context.rs` 里依赖已删除项的测试删掉或改写，PR 里列出。
10. 靶场加一个场景：搜编号再打开结果 → 放行；并确认现有的回显类场景（README 里找“回显”）结果不变。

**文档**：docs/01 §1.2（什么算已见、`sent` 的新范围）、docs/07 §7.4.7、CHANGELOG。docs/01 §1.2 里写明接受的风险：源站搜索不按权限过滤时，搜到的编号可以读；值先被存进源站、之后在标识字段里展示时会被学。

**验收标准**：10 条通过；`grep -n "sent_overflow\|inherit_sent\|SENT_MAX" crates -r` 无结果；靶场全量通过。

## 7. 批次 6：批量赋值的值进判定（P2-1）

依赖批次 3 已合并。

**现状**：JSON 的布尔值不提取；小写单词在非标识键下是惰性值。`{"role":"admin","isAdmin":true}` 是 `fast_allow`、0 次调用（探针 `probe_e2_mass_assignment`）。

**行为规格**

- JSON 布尔值提取为 `"true"`、`"false"`（`walk_request` 的 `Value::Bool`）。`null` 仍不提取。普通键下它们是小写单词，仍是惰性值，不影响快速放行。
- **权限类键**下的值不算惰性：把键名用 `xshield_core::kind::kind_words` 拆成词，任何一个词是 `role`、`roles`、`admin`、`administrator`、`superuser`、`staff`、`permission`、`permissions`、`privilege`、`privileges`、`scope`、`scopes` 之一，就算权限类键。如果 `kind_words` 拆不出 `isAdmin`、`is_admin` 里的 `admin`，在 `values.rs` 里自己按驼峰和下划线拆，**不要改 `kind_words`**（对象表在用）。
- `value_kind` 对权限类键返回新的种类 `privilege`。
- `ACCESS_INSTRUCTIONS` 加一句：`kind` 为 `privilege` 的值授予角色、权限或管理员标记；注册、修改自己资料这类请求里出现它，给自己或新账号提升权限的，答 DENY；管理员在管理别的账号时设置角色不算。措辞可调。指令版本号随之更新。
- `tests/security-lab/fake_jev.py`：`kind` 为 `privilege` 且值是 `admin`、`true`、`root`、`superuser` 之一时 access 答 DENY。

**必须的测试**

1. `values.rs`：`{"role":"admin","isAdmin":true,"deleted":null,"done":true}` → `role`、`isAdmin` 两个值非惰性，`done` 惰性，`deleted` 不出现。
2. `values.rs`：`payroll`、`controller`、`stroller` 这类只是包含 `role` 字母的键不算权限类键；`userRole`、`is_admin`、`user_permissions`、`scope` 算。
3. `engine.rs`：照 `probe_e2`，`PATCH /api/profile` 带 `{"role":"admin","isAdmin":true}` → 不是 `fast_allow`，调用 1 次，state 里两个值的 `kind` 是 `privilege`。
4. `engine.rs`：`{"completed":true,"title":"x"}` 这类普通布尔值的请求，判定路径和调用次数与改动前相同。
5. 靶场加场景：注册或改资料时带 `role=admin` → 403、`jev_deny`；`tests/security-lab/README.md` 加行。

**文档**：docs/01 §1.3 和 §1.5、docs/02 §2.2（`kind` 的取值）、docs/04 里把批量赋值写成“不在范围内”的句子改掉。PR 描述里写明：真实模型是否按这句指令判拒没有验证，需要用户提供密钥跑 `live_jev` 才能确认。

**验收标准**：5 条通过；靶场全量通过。

**并入本批的一条（2026-11-13 18:45 UTC，批次 3 验收时记下）：字段名的源站改写。** PHP 解析查询串和表单时会改字段名：去掉开头的空白，把空格、`.` 和没有配对的 `[` 换成 `_`。所以 `patient.id=8`、`patient%20id=8`、`patient[id=8` 在 PHP 源站都是 `patient_id=8`，网关里的位置却是另一个名字，对不上对象表的位置（档位收紧因此不生效）。批次 3 只补了“名字两端有空白时再按去掉空白的名字读一次”。本批改字段名相关逻辑时一并处理：`pairs` 里名字按 PHP 规则改写后与原名不同的，在改写后的名字下再读一次（值不变），查询串和表单都适用；加值级测试和一条靶场场景。`loose_pairs`（没有类型、不是严格表单的正文）现在先判断、去空白再做百分号解码，`%20patient_id=8` 只读成 ` patient_id`；本批让它和 `pairs` 共用同一条名字规则（解码后再去空白、再改写）。批次 3 的实现线程把现成的补丁和两条测试存在 `designs/waf-batch6-field-name-readings.patch`，从它开始。

## 8. 批次 7：置信度门槛（P2-2）

仓库和项目文件里没有可用的概率分布数据（`waf-batch10` 报告里没有概率，`waf-audit` 只提到个别值 0.53、0.55），分布要从部署环境的 `decision_log` 取。请用户或有数据库访问的线程在控制库上跑：

```sql
SELECT width_bucket(jev_confidence, 0.3, 1.0, 14) AS bucket,
       min(jev_confidence) AS low, max(jev_confidence) AS high,
       count(*) FILTER (WHERE decision_path = 'jev_allow') AS allows,
       count(*) FILTER (WHERE decision_path = 'jev_deny') AS denies
FROM decision_log
WHERE jev IS NOT NULL AND jev_confidence IS NOT NULL
GROUP BY 1 ORDER BY 1;
```

`jev_confidence` 的算法在 `xshield-postgres/src/decision_log_store.rs:783`，开工时先读它，确认它是不是下面规格里用的那个量；不是的话把查询改成直接从 `jev->'access'`、`jev->'attack'` 取。

**数据和数值（2026-11-13）**：home-windows 的分布在 [jev-confidence-distribution.txt](jev-confidence-distribution.txt)，`jev_confidence` 就是下面规格用的量（两个问题最高项概率的较小值）。`jev_allow` 共 357 条，没有低于 0.5 的；分布没有明显的断点，0.85 以上才集中（283 条）。各门槛会让多少条现在的放行变成“不可判定”：

| T | 受影响的放行 | 占 357 条 |
|---|---|---|
| 0.60 | 19 | 5.3% |
| 0.70 | 38 | 10.6% |
| 0.80 | 57 | 16.0% |
| 0.85 | 74 | 20.7% |

验收方的建议是 **T = 0.60**：数据里没有标注哪些低把握放行是错的，分布也给不出天然的切点，所以先只去掉接近平手的放行（最高项不到 0.6，意味着其余两项合计超过 0.4）；每提高 0.05 约多拒 2 到 3 个百分点的放行，默认 `on_jev_unavailable = deny` 下这些都是 403。样本来自 home-windows 的测试流量，不代表生产；有效性验证跑出带标注的结果后再按误拦和漏拦调整。已向用户发决定卡，回复前按 0.60 规划。

真实模型的一条佐证（2026-11-13，功能级越权线程的真实回归，`designs/function-level-authz-live-regression-result.md`）：商店的开放重定向 `GET /redirect?to=https://example.org/x` 三遍都答 `attack` 为 BENIGN 0.53 到 0.56（ATTACK 0.41 到 0.45），现在被放行；门槛 0.60 会把它变成不可判定，按 `on_jev_unavailable` 处理。批次 7 的测试里加一条与它同形的用例（BENIGN 0.55、ATTACK 0.43 → 不可判定）。

第二条佐证（2026-11-13，`b48c711` 上的探测，[../designs/waf-batch2-live-probe-result.md](../designs/waf-batch2-live-probe-result.md) 第 4 条）：批次 2 的指令合入后，只靠路径的攻击探测的 ATTACK 概率比旧提示词低约 0.1（`/.git/config` 0.55 变 0.42，`/backup.sql` 0.52 变 0.42，`/h2-console` 0.34 变 0.24，开放重定向 0.43 变 0.37），只量了一遍。这几条目前都由 `access` 判拒，结论没变；但 `attack` 这一问上它们现在是 BENIGN 0.58 上下，门槛 0.60 正好卡在这附近。批次 7 的测试里再加一条：`access` 答 DENY、`attack` 答 BENIGN 0.58 的请求仍然是拒绝（拒绝不设门槛，不能因为另一问低把握变成不可判定）。

**带标注的真实站点数据（2026-11-13 15:45 UTC，`/mnt/project-files/acceptance/batch6/real-site-rerun-b48c711.md`“置信度门槛扫描”）**：home-windows 上 Juice Shop 站点一个窗口的 353 次模型放行、219 次模型拒绝，套件里 100 个良性请求、220 个攻击请求。

- 门槛 0.60 让 19 次放行（5.4%）变成不可判定，其中套件良性请求 7 个；30 个漏拦一个也拦不下（它们的放行把握在 0.63 到 0.91）。`on_jev_unavailable: deny` 的站点上误拦率从 7.0% 升到 14.0%。
- 要拦下第一个漏拦要 0.65（拦 2 个，代价 10 个良性），拦下批量赋值那 10 个要 0.75（代价 16 个良性）。这 30 个漏拦都是注册接口的探针，模型是有把握地答了放行，靠门槛分不开；其中批量赋值由批次 6 从 state 内容上解决。
- 拒绝一侧：7 个误拦里 5 个的拒绝把握在 0.50 到 0.60，80 个拦对的请求都在 0.70 以上。

验收方据此改了建议：**暂缓批次 7**。当初建议 0.60 时写明“有效性验证跑出带标注的结果后再按误拦和漏拦调整”，现在标注数据说这个门槛在这个站点上只增加误拦。只有一个站点、一种套件，不能说门槛永远没用，所以 P2-2 保留为未解决，等更多站点的标注数据再定。这是用户选过的数值，是否暂缓由用户决定，协调者在问；决定前批次 7 不合并。备选：保持 0.60（接受误拦上升，换来“接近平手不放行”）；降到 0.55（10 次放行受影响，3 个良性，同样拦不下漏拦）。

拒绝一侧的现象只记录不动手：把低把握的拒绝改成不可判定，在 `deny` 站点上结果不变，在 `allow` 站点上是放宽防护，只凭一个站点的 7 个样本不提这个改动。

**行为规格**（`T = 0.60`，写成代码常量 `ALLOW_CONFIDENCE_MIN`，不做成配置）

- 放行要求 `P(ALLOW) >= T` 且 `P(BENIGN) >= T`。
- 口径（有效性方案按门槛扫描时用同一个）：比较的量是判定记录里 `jev.access.ALLOW` 和 `jev.attack.BENIGN` 两个概率的较小值，放行时它等于库里的 `decision_log.jev_confidence` 列；**恰好等于 `T` 算放行**（`>=`）。字段名不新增、不改名。
- 最高项是 ALLOW 和 BENIGN 但有一个低于 `T` → 不可判定，失败码用新的 `JEV_LOW_CONFIDENCE`，按 `on_jev_unavailable` 处理。
- 拒绝不设门槛：最高项是 DENY 或 ATTACK 就拒，和现在一样。
- 多批请求（批次 2）逐批套用这条规则。

**改动点**：`state.rs` 的 `conclude` 和 `Conclusion` 的使用处、`engine.rs` 的 `ask_jev`；新失败码的下游：`web/console/src/api/types.ts`、`lib/vocab.ts`、`lib/explain.ts`、`lib/filter-dsl.ts`、`schemas/decision-record.schema.json`、docs/06 的失败码表、docs/07 的失败码表；docs/02 §2.3。就绪检查里加一项“低把握放行 N 次”是否要做，开工前问验收方。

**必须的测试**：门槛两侧各一例（恰好等于 `T` 放行）；只有一个问题低于门槛；DENY 0.4 仍然拒；多批里一批低于门槛；`allow` 和 `deny` 站点各一例；`verdicts_follow_the_most_probable_options` 按新规则更新。

## 9. 批次 8：请求头和非会话 Cookie 进攻击判定（P2-3）

依赖批次 6 已合并（两批都改指令和 `plan_values`）。

**行为规格**

- 网关把请求头的名和值交给判定：`RequestFacts` 加 `headers: &[(String, String)]`（名小写）。判定记录里仍然只存头的名字，不变。
- 只有**含特殊字符**的头值和 Cookie 值才成为请求值。特殊字符：`'`、`"`、`<`、`>`、反引号、`$`、`{`、`}`、`|`、`\`、控制字符（制表符除外）、连续的 `..`。原值和百分号解码后的值任何一个含有就算。
- 不看的头：会话凭证所在的头或 Cookie、`authorization`、`proxy-authorization`、`cookie`（按单个 Cookie 处理）、名字命中 `is_secret_name` 的头和 Cookie、`sec-` 开头的头、`if-none-match`、`if-match`、`if-range`、`content-type`。
- 位置写 `header.<名>` 和 `cookie.<名>`，`value_kind` 返回 `header`，没有键，永远不算已核验，长值照批次 2 分片。
- 为了不让一个稳定的头值（例如带引号的 Cookie）让该会话的每个请求都去调用模型：请求被 Jev 放行后，把这次送判的每个头值按“头名加值”的摘要记进会话的放行缓存（复用 `cache_allow`，时长同放行缓存）；之后同一会话再带同样的头值，命中缓存就不再作为请求值。判拒不缓存。
- 请求的放行缓存键要包含送判的头值。
- `ATTACK_INSTRUCTIONS` 加一句：`header.*` 和 `cookie.*` 位置的值是请求头和 Cookie，同样检查。`ACCESS_INSTRUCTIONS` 加一句：`kind` 为 `header` 的值不选择对象。指令版本号更新。

**必须的测试**

1. 普通浏览器请求头（真实的 Chrome `User-Agent`、`Accept`、`Accept-Language`、`Referer`、`sec-ch-ua`、`If-None-Match: W/"abc"`）→ 没有任何头值成为请求值，原本 `fast_allow` 的请求仍然 `fast_allow`。
2. `User-Agent: ${jndi:ldap://x/a}`、`X-Forwarded-For: 1' OR '1'='1`、`Referer` 里有 `%27`、Cookie `theme=<script>` → 各自成为请求值并送判，假 Jev 判 ATTACK 时拒绝。
3. 会话凭证的头和 Cookie、`Authorization`、名字含 `token` 的头：值不出现在任何 state 和 trace 里。
4. 头值放行后同一会话带同样的头值再发别的请求 → 不因这个头再调用；换一个值 → 再判。
5. 头值判拒后重发 → 仍然送判。
6. `xshield-edge` 的场景测试：头里带注入的请求端到端被拒。靶场加一个场景。

**文档**：docs/01 §1.3、docs/02 §2.2 和 §2.6（外发数据多了哪些）、docs/07 §7.4.2；写明边界：不含上述特殊字符的头值不判。

## 10. 批次 9：放开 413

数值已由用户确认（2026-11-13：1 MiB、16 批）。方案在评审文档 P0-1 节第 6–10 点，它取代 P1-5 的 413 部分和 P2-7。16 批预算、排序和“攻击判定不完整”的标记已经在批次 2 实现（3.4），本批直接沿用，不另做一套。代码等批次 3、8 合并后开工，下面的设计说明可以提前写。

开工的第一步不是写代码，而是交一份设计说明给验收方（写在线程里即可），回答：

1. Pingora 现在的重放缓冲上限是多少、能不能调；`request_filter` 里读完 1 MiB 正文后怎样把它交给上游。如果不能在 `request_filter` 里读，在 `request_body_filter` 里攒够再判是否可行，判拒时上游已经收到请求头会有什么后果。
2. 分块传输的请求怎样缓冲到上限。
3. 超过 1 MiB 的正文怎样边转发边不判，multipart 的文件部分怎样流式转发。

规格要点（数值确认后细化）：正文不超过 1 MiB 的全部提取，引用全部核验；JSON 里内嵌的 base64 长串不送判，只记长度；需要送判的文本每个请求最多 16 批，短值和引用优先，超出部分照常转发并在判定记录里标“攻击判定不完整”；超过 1 MiB 的正文只判路径和查询，记录里标明；multipart 超过 1 MiB 时判前 1 MiB 里完整的文本字段和文件名；观察模式和拦截模式行为一致，都不再有因为大小而来的 413。

**批次 3 留给本批的一条（2026-11-13 17:25 UTC）：** 批次 3 之后同一段内容可能被读几遍（一个部分至多 8 个名字，原文加 base64、quoted-printable 解码各一遍；表单类型或没有类型的正文按 JSON 和表单各读一遍）。正文上限是 48 KiB 时最坏约 1 MiB 的请求值，可以接受；上限放到 1 MiB 后最坏是二十几 MiB。本批的规格里要给“请求值总字节数”加上限（建议正文大小的 4 倍），超过时多出来的读法不再展开，请求 `truncated = true`，并加一条测试。

## 11. 批次 10：按路由平时的正文大小决定超预算是否放行

用户已同意方向：学习每条路由平时的正文大小，平时就大的路由超预算时放行（批次 9 的行为），平时很小的路由突然来了超大请求不放行。学习数据不足的路由按“平时就大”对待，不因此拒绝。

等批次 9 合并并有一段观察数据之后再细化。阈值（多大算超出、需要多少样本）用观察数据提出，给用户确认后才开工。

## 11a. 批次 11：伪造凭证的会话只能挤掉自己地址的会话，只能花自己地址的额度

2026-11-13 验收 PR #213 时发现，协调者要求并入本规划。依赖 PR #213 已合并。

**现状（在 #213 的头 90f97d7 上实测，`main` 相同）**

- 网关把“源站对带这个凭证的请求答了 2xx”当作源站认了凭证（`observe` 里 `seeded` 那一支和 `start_session`）。公开页面对任何凭证都回 2xx：伪造凭证 `GET /login`（入口，`fast_allow`，不调用 Jev）得到 200 后 `session_count` 加 1；200 个伪造凭证得到 200 个会话，Jev 调用 0 次；不带值的非入口页面（`GET /about`）同样。
- 读代码可知的同类路径（没有单独实测）：响应下发凭证（`issued`）也建会话。给匿名访客发会话 Cookie 的源站（PHP、Java 容器的默认行为），不带 Cookie 的请求每次都得到一个新会话。
- 后果一：会话表上限 2 万（`SESSIONS_MAX`），满了淘汰全表最久没活动的。2 万个请求之后，比这轮请求更早活动的真实会话全部被淘汰，已见值丢失，真实用户的请求改走 Jev 或被拦。
- 后果二：每个会话各有每分钟 60 次的 Jev 额度，一个地址可以拿到任意多份。批次 1 定下的“限额超出一律 429”因此拦不住消耗模型额度；限额表（`LIMITER_MAX` 5 万个窗口）也能被填满，填满后新的键一律拒绝。
- 不构成越权放行：伪造的凭证源站不认，这些会话只学得到公开页面的值。

**与功能级越权第 1 层（T1，`designs/function-level-authz-plan-layer1.md`）的关系**：T1 会收紧建会话的条件（非入口路径的 2xx 不再建会话，用户身份站点要看到身份声明），但它之后仍然留下两条谁都能走的路径：非用户身份站点上入口的 2xx，以及匿名下发的凭证。本批限制的正是这两条路径能造成的损害，两者不重复。T1 和本批改同一批建会话的函数，后合的 rebase；本批的测试不要依赖“非入口 2xx 建会话”这一条现状（测试 8 用入口 `GET /login`）。

**为什么不能直接收紧建会话的条件**：网关分不出一个 2xx 是不是因为凭证才给的；网关重启后真实用户的会话也是靠 2xx 重新建立的；登录响应下发的凭证在匿名发 Cookie 的源站上同样可以随便拿。所以本批不去判断会话真假，只限制一个来源地址能造成的损害。

**行为规格**

(a) **来源地址分组**。新增一个函数，把客户端地址变成分组键：IPv4 用完整地址；IPv6 取前 64 位（一个 /64 通常是一个用户或一个站点，攻击者手里有整个 /64）；IPv4 映射的 IPv6 地址按 IPv4；解析不了或为空的原样作为一组。下面两条都用这个分组。没有凭证的请求现有的每地址 30 次额度（`budget_key` 的 `address` 分支）也改用它。**地址上下文的键（`address_key`）不改**，注册流程的上下文仍按完整地址。

(b) **会话记下是哪个地址建的**。`SessionContext` 记录建立它的那个请求或响应的来源地址分组键（键控哈希，不存地址原文）。所有建会话的入口都要传入：`observe` 的 `seeded`、`issued`、`start_session`，判定阶段的 `start_from_login`，以及地址上下文（它的来源就是自己）。会话之后从别的地址来请求不改这个记录。

(c) **表满时的淘汰**。`ContextStore::session` 在表满、且清掉过期会话之后仍然满时：按 (b) 的记录把会话分组，找出会话数最多的那个地址，淘汰它名下最久没活动的会话。会话数并列时，取名下有全表最久没活动会话的那个地址。一趟扫描完成（现在的实现本来就整表扫一遍找最旧的，量级不变）。
  - 效果：单个地址造出再多会话，表满后挤掉的只是自己名下的。真实会话只有在它的地址名下会话数不少于攻击者最大的那个地址时才会被淘汰。
  - 所有客户端来自同一个对端地址时（网关前面还有一层代理），退化成现在的行为（全表最久没活动的）。

(d) **地址总上限**。有会话的请求调用 Jev 时，除了会话自己的窗口（`session_calls`，默认每分钟 60），再过一个“这个来源地址的所有会话合计”的窗口，上限是 `session_calls` 的 10 倍（常量 `ADDRESS_SESSIONS_FACTOR = 10`，默认即每分钟 600；不加配置项）。键与没有会话的请求的地址窗口分开（例如 `mac("address-sessions", 分组键)`），两种额度互不占用。
  - 两个窗口都没满才放行并各记一次；任一个满了就回 429、`JEV_CALL_LIMIT`，**两个窗口都不记数**（`Limiter` 需要先看后记）。这样一个刷满自己额度的会话不会吃掉同地址其他会话的总额度。
  - 先看地址窗口：被地址上限拒绝的调用不为会话新建窗口，限额表不会因此增长。
  - 判定记录、失败码、控制台都不变（429、`rate_limited`、`JEV_CALL_LIMIT`）。不加字段区分是哪个上限。
  - 10 这个倍数用户已在决定卡上确认（2026-11-13 14:23 UTC：加，单会话额度的 10 倍，固定值，不做成配置项）。

**改动点**

- `context.rs`：`SessionContext` 加来源字段；`ContextStore::session` 的满表分支按 (c)；建会话的函数签名带上来源。
- `engine.rs`：分组函数；`budget_key`；限额检查那一段（现在是 `inner.limiter.allow(limit_key, limit, …)`）按 (d)；`Limiter` 加“两个键都未满才记数”的方法。
- **STOP**：如果建会话的入口比 (b) 列的多，或者发现还有别处依赖“淘汰的是全表最久没活动的”，先问验收方。

**必须的测试**

1. 存储层：一个地址建 19,000 个会话，另外 1,000 个地址各建 1 个且活动时间更早；该地址再建 5,000 个 → 那 1,000 个会话全部还在，`len()` 等于 `SESSIONS_MAX`。
2. 存储层：两个地址各 10,000 个会话，第三个地址 50 个；任一大地址继续建 → 第三个地址的 50 个都在。
3. 存储层：所有会话来自同一个地址 → 淘汰的是最久没活动的（现有的最久没活动测试保留并指出）。
4. 判定层：`session_calls_per_minute` 设为 2（总上限 20）。同一地址 11 个已建立的会话，前 10 个各调用 2 次都放行，第 11 个会话的调用回 429、`JEV_CALL_LIMIT`，Jev 没有多被调用；另一个地址的会话不受影响；过了一分钟恢复。
5. 判定层：一个会话在自己的额度满后继续请求被拒，这些被拒的请求不占地址总额度（同地址其余 9 个会话仍能各调用 2 次）。
6. 判定层：没有会话的请求的每地址额度与会话的地址总上限互不占用。
7. 分组函数：同一 /64 的两个 IPv6 地址同组，不同 /64 不同组；IPv4 映射地址与对应 IPv4 同组；空地址和乱写的地址不 panic。
8. 判定层回归：伪造凭证从一个地址经 `GET /login` 得到 200 建会话（现状保留，本批不改这一点），断言这些会话的来源是该地址（通过第 4 条的总上限体现即可）。
9. 靶场：如果站点配置能设 `advanced.session_calls_per_minute`（C5 的做法），加一个场景验证地址总上限；做不了就在 PR 里说明原因。

**文档**

- docs/01 §1.2：会话表满时的淘汰规则；把“随手编造的凭证不能……”那句写成实际成立的范围：公开页面的 2xx 和匿名下发的凭证仍会建会话，但一个地址造出的会话表满后只挤掉自己名下的，合计额度不超过总上限；拥有很多地址的攻击者仍能做到，写明是残留边界。
- docs/02 §2.5：地址总上限和倍数、IPv6 按 /64、两个地址窗口互不占用；写明网关取的是连接的对端地址，前面有代理时所有客户端同属一个地址，地址额度和总上限就成了全站合计（边缘侧目前没有 `XSHIELD_CONTROL_TRUSTED_PROXIES` 那样的设置，本批不加）。
- CHANGELOG 一条。

**验收标准**：9 条通过；验收方重跑探针：2 万多个伪造凭证从一个地址经公开页面建会话之后，此前由另一个地址建立的会话仍在。

## 12. 等用户确认的事项

| 事项 | 影响批次 | 状态 |
|---|---|---|
| 置信度门槛的数值 | 7 | 用户 2026-11-13 12:44 UTC 选定 0.60。15:45 UTC 的真实站点标注数据显示它在该站点只增加误拦，验收方建议暂缓批次 7，协调者在请用户重新决定 |
| 1 MiB 缓冲上限、每请求最多 16 批、超出部分转发并标记 | 9 | **已确认**（2026-11-13） |
| 16 批预算用于 48 KiB 以内的请求 | 2、3 | **已确认**（2026-11-13），规格在 3.4 |
| 路由正文大小的阈值和样本数 | 10 | 等观察数据 |
| 批次 9 读正文的做法 | 9 | **已确认** vendor 一份 pingora-core 改重放缓冲常量（2026-11-13 12:44 UTC，设计线程的决定卡），落地要求见 waf-batch9-design.md 1.5 和 6 |
| 同一来源地址所有会话合计的 Jev 调用上限（建议单会话额度的 10 倍） | 11 | **已确认**（2026-11-13 14:23 UTC，决定卡）：加，10 倍，固定值 |

## 13. 验收方对每个 PR 做的事

1. 对照本文件逐条核对行为规格和“必须的测试”，缺一条不通过。
2. 自己拉分支重跑 AGENTS.md 表里对应的检查，不采信 PR 描述里的结果。
3. 读完整 diff：有没有规格外的改动、`#[allow]`、被改弱的旧断言、生产路径上的 `unwrap`、凭证或口令字段进入 state 或日志的新路径。
4. 对绕过类批次（1、2、3、6、8）自己写对抗用例试一遍，不只跑 PR 自带的测试。
5. 文档、CHANGELOG、指令版本号、靶场 README 是否同步。
6. CI 全绿后合并；不通过时在 PR 里写明具体哪条、怎么改。
7. 合并前在合并后的头上跑一遍有效性流水线（`python3 scripts/measure_effectiveness.py`）。这个修复对应的 `known_gap` 回归用例（`tests/security-lab/effectiveness/regressions.py`）必须在同一个 PR 里翻成 `must`；`must` 通过率 100%；意外通过只允许是别的 PR 已知留下的（`b48c711` 上是 `p0-1-multipart`、`p0-1-long-value`、`p1-9-big-form`，由有效性批次 8 补翻）。仓库里没有对应用例的修复（如批次 11），合并时告诉协调者由有效性线程登记。
8. 改了发给 Jev 的 state 形状或指令文字的批次（2、3、6、7、8），合并前先请持有密钥的线程用真实模型探测一遍，结果看过再合并。假 Jev 只看列出的值，量不出模型对 state 其余部分的反应（3.5 的缺陷就是这样漏过去的）。
