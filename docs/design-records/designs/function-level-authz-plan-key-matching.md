# 实现规划 T4b：功能键的 `{id}` 不再盖住路由词，管理员会话不判未知功能

- 状态：**用户两项都已选定（2026-11-13 15:33Z、15:34Z）：A 部分“`{id}` 只认带数字的段”和 B 部分“管理员会话不判未知功能”一起做，一个 PR。** PR 219（T6）合入 main 后开工。
- 范围：`crates/xshield-core/src/path_template.rs`、`crates/xshield-core/src/context/objects.rs`、`crates/xshield-core/src/context/learning.rs`、`crates/xshield-judge/src/engine.rs`（只 B）、`crates/xshield-judge/tests/live_jev.rs`、`crates/xshield-control/src/object_functions.rs` 的测试、`schemas/site-config.schema.json` 的说明文字、靶场一到两个场景、`tests/security-lab/effectiveness/regressions.py` 一条用例、docs、CHANGELOG。
- **不改**：判定指令和提示词（提示词版本号必须不变，有测试钉住）、`fake_jev.py` 的判断规则、`migrations/`、`.github/`、`deny.toml`，不加依赖，不加配置项。
- 验收人：功能级越权线程。规格里写了 **STOP** 的地方，停下来在 PR 或线程里问验收人。
- 依赖：T4（`1230f04`）、T5a（`47224d8`）已在 main。T6（PR 219）先合入；它没合入时本 PR 等它。

## 1. 要解决的问题

T6 的真实回归发现两件事。

**A。** 功能表里的 `GET /api/patients/{id}` 现在覆盖 `GET /api/patients/export-all`：`{id}` 覆盖请求的任意非空段。于是 `export-all` 被当成已知功能，快速放行，不问 Jev。而学习把纯字母的段当成各自的功能（少于 50 个不同取值时不合并），T5a 的候选列表又因为“已知”把它藏起来。管理员看不到它，网关也不拦它。

**B。** 被认作管理员的会话请求功能表里没有的管理接口（`GET /api/admin/reports`），带着 `{"known":false}` 去问 Jev，真实模型三遍都答 DENY（0.99 以上）。管理员用到没进表的管理接口就被拦。

## 2. A 部分的规格

### 2.1 两个占位符

功能键的模板有两个占位符：

- `{id}`：一个**值**。覆盖请求的一个段，条件是这个段去掉第一个 `;` 及之后的部分后非空，并且**不是纯路由词**。
- `{name}`（新增）：**任意**一个段。覆盖请求的一个段，条件是这个段去掉 `;` 部分后非空。

**纯路由词**的定义（新增函数，放在 `path_template.rs`，公开，供下面三处共用）：1 到 `FUNCTION_SEGMENT_MAX`（32）字节，每个字节都是 ASCII 字母或 `.`、`_`、`~`、`-`。也就是说，带数字的、超过 32 字节的、含其他字节的（保留下来的百分号转义、`@`、`:`、花括号）都不是纯路由词，都算值。

```rust
/// Whether `segment` reads as a route word and nothing else: 1 to 32 bytes, each an ASCII letter,
/// `.`, `_`, `~` or `-`. A function's `{id}` does not cover such a segment (docs/07 section 7.9.18).
#[must_use]
pub fn is_plain_word(segment: &str) -> bool
```

一个例外：请求段恰好是 `{name}` 时，`{id}` 不覆盖它，只有 `{name}` 覆盖。原因是 T5a 用 `knows_function(方法, 候选键的模板)` 判断候选是否已知，候选键 `GET /users/{name}` 不能被表里的 `GET /users/{id}` 当成已知。请求段恰好是 `{id}` 时，两个占位符都覆盖它（判定用的模板里，纯数字和 UUID 的段已经写成 `{id}`）。

效果对照（表里只有 `GET /api/patients/{id}`）：

| 请求 | 现在 | 改后 |
|---|---|---|
| `/api/patients/7005`、`/api/patients/PT-7004`、UUID | 已知 | 已知 |
| `/api/patients/export-all` | 已知 | 未知 |
| `/api/patients/export-all;1`（矩阵参数里带数字） | 已知 | 未知（先去掉 `;` 部分再判断） |
| `/api/patients/;x`（去掉后为空） | 已知 | 未知 |
| `/api/patients/alice` | 已知 | 未知。站点的编号是纯字母名字时，条目要写成 `GET /api/patients/{name}` |

### 2.2 `objects.rs`

- `covers(declared, request)` 按 2.1 改。它是功能查找和“位置所在路由算已知”共用的，两处一起收紧：位置键 `GET /api/patients/{id} path[2]` 也不再让 `export-all` 算已知。
- 排名多一项：字面段数多的优先；一样多时 **`{id}` 段多的优先**（`{id}` 比 `{name}` 窄）；再是管理档且高可靠的优先；再是书写靠前的。`covers` 的返回值带上 `{id}` 段数即可。
- `valid_function_key`：含花括号的段只能是 `{id}` 或 `{name}`。其余检查不变。
- `template_covers` 和 `request_key`（公共访问站点上给请求值找位置的那一套）**不改**：那是给值找位置，slug 编号仍要被 `{id}` 的位置管到。改了它的测试失败时 **STOP**。
- `function_of`、`admin_only`、`knows_function` 的签名不变。管理档条目也按新规则覆盖：`PUT /api/users/{id}`（管理档）不再把 `PUT /api/users/me` 当成越权尝试。这是有意的，写进文档。

### 2.3 `learning.rs`

`merge_functions` 现在把两类轻的子段都合并成 `{id}`。改为：

- 带数字的轻子段（不是纯路由词的）达到 `MERGE_IDS_MIN`（10）个：合并成 `{id}`，不变。
- 纯路由词的轻子段达到 `MERGE_WORDS_MIN`（50）个：合并成 **`{name}`**。
- 分组用 2.1 的 `is_plain_word`，不要再各写一份“有没有数字”的判断。
- 计子段时跳过的占位符由 `{id}` 一个变成 `{id}`、`{name}` 两个。
- 同一层可以同时出现 `{id}` 和 `{name}` 两个兄弟，它们在下一层是两个不同的前缀，各自成组。

阈值、`named_under`、结果与输入顺序无关这几条都不变。库里已有的、由纯字母合并出来的 `{id}` 提议，下一轮学习会按现有规则撤回并以 `{name}` 重新提出，不写迁移。

### 2.4 其余跟着变的地方

- `object_functions.rs`（T5a）：代码不用改，`knows()` 走的是 `knows_function`。它的测试里凡是靠 `{id}` 盖住纯字母段的断言，按新规则改期望，并加一条：表里有 `GET /api/patients/{id}`、窗口里有 `GET /api/patients/export-all` 时，后者出现在 `candidates` 里且 `sensitive` 为真。
- `schemas/site-config.schema.json`：功能键的说明里“`{id}` 是唯一的占位符”改为两个占位符及其含义。`pattern` 不变。
- 控制台：`web/console` 里没有功能键的语法检查（服务端检查）。搜一遍 `web/console/src` 里解释 `{id}` 含义的界面文字，有涉及功能键的就补上 `{name}`；T5b 的功能视图已合入时，在它的说明文字里补一句，没合入就不动。除此之外不改控制台。
- `live_jev.rs`（T6 的表）：`GET /api/patients/export-all` 去掉 `.known().known_gap()`，回到 `Must`、期望 `Unknown`，注释删掉。`KnownGap` 的个数断言减一，docs/04 4.4 那句里的数字同步。**不要运行 `--ignored`**。

### 2.5 靶场和有效性回归

- 靶场加场景 F14：基线站点（开关为真、功能表里有 `GET /api/patients/{id}` 或对象表里有这条路由上的位置）的医生请求 `GET /api/patients/export-all`。期望：交 Jev，`function.known` 为 `false`，拦截。`fake_jev.py` 对未知功能的现有规则不认 `export` 这个词时 **STOP**，不要改它的规则。
  - **17:10Z 验收人的决定：** STOP 触发了（`OPS_WORDS` 里没有任何导出类的词）。批准在本 PR 里给 `OPS_WORDS` 加 `export-all` 这一个词，不加 `export`：指令写的是“批量导出”，真实模型对 `GET /api/patients/{id}/export-pdf` 放行，而假 Jev 按子串匹配，加 `export` 会比真实模型严。`test_fake_jev.py` 加一条（`export-all` 答 DENY，`export-pdf` 答 ALLOW），加词后跑全量靶场和有效性流水线并写明别的场景有没有变。真实模型拦不拦 `export-all` 由验收时的真实调用确认。
- `regressions.py` 加一条 `p0-3-function-route-word`，来源 `P0-3`，`must`，`block`，原因 `access`，站点 `SITE_TRUTH`：医生登录后 `GET /api/patients/export-all`。PR 描述里写明这条在 main 上的决定路径（应为快速放行）和改后的决定路径。`clinic-truth` 的功能表不满足前提时 **STOP**。

## 3. B 部分的规格

`engine.rs` 的 `function_view`：会话是管理员（`admin` 为真）时，`unknown` 为假。其余不变：

- 管理员会话请求未知的功能，不带 `function`，照常按值判定（没有值的请求快速放行）。
- 管理员会话命中管理档条目：与现在相同，`trace.function` 有 `tier`，没有 `attempt`。
- 尝试越权（非管理员命中管理档条目）不受影响，“尝试越权，同时未知”那一行也不受影响。
- 方法覆盖：管理员会话不再因为传输方法不在基线里而带 `{"known":false}`。
- 放行缓存的键已含管理员标志，不用改。

`live_jev.rs`：`emr-role` 上的两条 `adminA` 用例由 `Observe` 改为 `Must`、期望放行、期望 `function` 为空（`.known()`）。`Status::Observe` 和 `observe()` 不再有人用，删掉，连同两个测试里对它的分支和个数断言。

靶场加场景 F15：有角色身份位置且开关为真的站点上，管理员登录、访问首页后 `GET /metrics`。期望：不带 `function`，不因未知功能被拦。靶场里没有同时具备这两项的站点，而加一个要动的不只是一份站点配置时 **STOP**。

## 4. 测试

名字可调整，覆盖面不能少。

`path_template.rs`：

- `a_plain_word_is_letters_and_marks_only`：`export-all`、`users`、`a.b_c~d` 为真；空串、`7005`、`PT-7004`、`a1`、33 字节的字母串、`a%2Fb`、`a@b`、`{id}`、`{name}` 为假。

`objects.rs`：

- `an_id_segment_does_not_cover_a_route_word`：2.1 表里的五行。
- `an_id_segment_ignores_digits_in_matrix_parameters`：`export-all;1`、`export-all;v=2` 未知。
- `a_name_segment_covers_any_segment`：`GET /users/{name}` 覆盖 `alice`、`7005`、`PT-7004`、`{id}`，不覆盖 `;x`。
- `an_id_entry_does_not_know_a_name_key`：表里 `GET /users/{id}`，`knows_function("GET", "/users/{name}")` 为假；表里 `GET /users/{name}`，`knows_function("GET", "/users/{id}")` 为真。
- `the_narrower_placeholder_wins`：`GET /a/{id}`（开放）和 `GET /a/{name}`（管理档、高）并存，请求 `/a/123` 取前者，请求 `/a/alice` 取后者；两种书写顺序都测。
- `an_administrator_function_with_an_id_does_not_claim_a_route_word`：`PUT /api/users/{id}` 管理档，`admin_only("PUT", "/api/users/me")` 为假，`admin_only("PUT", "/api/users/7005")` 为真。
- `a_position_does_not_make_a_route_word_known`：只有位置 `GET /api/patients/{id} path[2]`，`knows_function("GET", "/api/patients/export-all")` 为假，`/api/patients/7005` 为真。
- `a_function_key_takes_both_placeholders`：`GET /users/{name}` 合法，`GET /users/{userId}`、`GET /users/{NAME}` 被拒。
- 现有的 `request_key`、`template_covers` 测试一条不改。

`learning.rs`：

- `fifty_word_children_merge_into_a_name`：50 个纯字母的轻子段合并成 `{name}`；49 个不合并。
- `ten_digit_children_merge_into_an_id`：现有断言保留。
- `words_and_ids_at_one_level_merge_apart`：同一层 10 个带数字的和 50 个纯字母的，各自合并，结果里两种键都有；一个重的纯字母子段保持原样。
- `a_route_word_among_ids_stays_a_function`：`PT-…` 十个加一个 `export-all`，后者保持 `GET /api/patients/export-all`。
- 结果与输入顺序无关的现有测试扩到含 `{name}` 的输入。

`engine.rs`：

- A：`a_route_word_under_an_id_function_is_asked_as_unknown`：表里 `GET /api/patients/{id}`、开关为真，医生请求 `/api/patients/export-all`，Jev 被调用，`state.request.function` 为 `{"known":false}`；同一个会话请求见过的 `/api/patients/7005` 仍快速放行。
- B：`an_administrator_session_is_not_asked_about_an_unknown_function`：管理员会话请求表里没有的 `GET /api/admin/reports`，不调用 Jev，`trace.function` 为空；普通会话同一个请求仍带 `{"known":false}`。`an_administrator_override_to_an_unlisted_method_is_not_unknown`：管理员带方法覆盖的那条现有测试按新行为改期望。
- 提示词版本号的现有断言不动，必须仍然通过。

`live_jev.rs`：`function_cases_reach_jev_as_intended` 在改后的用例表上通过。

## 5. 文档

- docs/07 7.9.18：格式一节的第 5 条改为两个占位符；“段的比较”按 2.1 重写，带上 2.1 的对照表；`function_of` 的排名加上 `{id}` 段数；写明管理档条目同样按新规则覆盖，并给出 `PUT /api/users/me` 的例子；“已接受的限制”里与此相关的条目同步。B：“未知功能”一条加上“会话不是管理员”，表格里“管理员会话命中管理档条目”那一行的 `function` 列改为“没有”，限制里“未知与否只看传输方法”那条去掉管理员的部分。
- docs/07 7.9.19：路径段合并的说明改为两类各自的占位符。7.9.20：`candidates` 的说明里补一句，纯字母的段不被 `{id}` 条目算作已知。
- docs/01 1.4、docs/02 2.2、docs/03 3.2：有描述 `{id}` 覆盖范围或管理员与未知功能的句子就同步，没有就不动。
- docs/04：4.3 加 F14（和 F15），4.4 的 `KnownGap` 数字。4.5.5 是当时的实测记录，**不改**；验收人跑完真实模型后给一句补记，由实现线程加在 4.5.5 末尾。
- CHANGELOG 的 `Unreleased` 顶部加一条中文记录：功能表的 `{id}` 不再覆盖纯字母的路由词，新增 `{name}`；（B）管理员会话不再因未知功能被问。写明对已有功能表的影响：编号是纯字母名字的接口要把条目改成 `{name}`，否则打开开关后这些请求会去问 Jev。
- PR 描述按 `templates/pull-request.md` 的五个标题写，写明真实调用没有运行、由验收人运行。提交标题用英文 Conventional Commits，例如 `fix(judge): keep a route word out of a function's id segment`。

## 6. 检查

改了 `xshield-core` 和判定路径，AGENTS.md 表里的这几组都要跑：三个 python 检查；`cargo fmt`、`clippy`、全工作区测试和文档测试；`python3 scripts/test_idor_lab.py`；`scripts/test_postgres.sh`（`xshield-control` 的测试改了）；`fuzz/` 下的 fmt、clippy、test。控制台有改动时再跑控制台那一组。缺环境的步骤在 PR 里写明没有执行。不加 `#[allow]`，生产路径不用 `unwrap`、`expect`。

## 7. 验收

1. 第 4 节的测试都在并通过；第 6 节的检查通过，CI 全绿。
2. 验收人做变异：把 `covers` 里 `{id}` 的“不是纯路由词”条件去掉，`an_id_segment_does_not_cover_a_route_word`、engine 的 A 测试和 `function_cases_reach_jev_as_intended` 必须失败；把矩阵参数的剥离去掉，`an_id_segment_ignores_digits_in_matrix_parameters` 必须失败；（B）把 `!admin` 去掉，engine 的 B 测试必须失败。
3. 提示词版本号不变。
4. `request_key`、`template_covers` 的测试没有被改。
5. 有效性回归：`p0-3-function-route-word` 登记为 `must`，PR 里有它在 main 上和改后的决定路径。
6. **真实调用由验收人执行**：密钥只经环境变量传入。跑一遍 `live_function_table`（约 73 次调用，开跑前先告诉用户这个数），`GET /api/patients/export-all` 必须被拦，其余 `Must` 与 4.5.5 的记录一致。`export-all` 接近平局时由验收人决定它的状态。
7. 文档与行为一致，CHANGELOG 有记录。

## 8. 与在途改动的关系

- WAF 批次 7（置信度门槛）会改变接近平局的用例的结论，与本改动无关，各自验收。
- T5b（控制台功能视图）只显示键，不解析占位符。谁后合入，谁在功能视图的说明文字里补 `{name}`。
- T1、C1 不碰这几处。
- T4c（PR 230，`_method` 兜底）也改 `engine.rs` 的 `function_view`（管理档条目的查找），B 部分改的是同一个函数里未知功能的判断。两处不重叠，谁后合入谁 rebase。靶场编号：T4b 用 F14、F15，T4c 用 F16 到 F21。
- 2026-11-13 17:05Z：PR 219 已合入（`c42a52b`），本规划可以开工，基线是这个提交。合入后提示词版本是 `jq_d5df87392a92b44d`，docs/04 4.5.5 末尾有这个版本上的复跑记录（一遍 74 次调用），第 7 节第 6 条的“与 4.5.5 的记录一致”以它为准。
