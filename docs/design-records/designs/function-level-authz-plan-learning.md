# 实现规划 T2：功能证据、路径段合并和管理档提议

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 5.1、6.1、8、9 节。用户在 2026-11-13 确认了第 15 节的全部问题（只分管理员；功能表的变更全部由管理员确认）。
- 基线：`main` `0acae80`。开工前先 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-core`（`path_template.rs`、`context/learning.rs`）、`xshield-postgres`（一个新模块、两处小改）、`xshield-control`（`object_learning.rs`）、`migrations/0011`、docs、CHANGELOG。**不改** `xshield-judge`、`xshield-edge`、`context/objects.rs`、`web/console`、`schemas/`、`.github/`、`deny.toml`。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。
- 这一步**不改变任何判定，也不改站点配置**。学习任务多记一类证据，多产生一类提议；提议要等 T5 的接口和页面才看得到、确认得了。

## 1. 要解决的问题

学习任务现在只统计“位置”（接口里的某个值）。功能级越权需要按“功能”（方法加路由模板）统计：

- 哪些功能在正常流量里被走过，有多少个单位走过。这是第 3 层的基线候选。
- 哪些功能只有管理员走过。这是第 2 层的管理档提议。

单位沿用现有的定义：站点声明了用户身份位置（`identified_by` 为真）时按用户，否则按会话。

## 2. 规格

### 2.1 功能键

功能键是 `方法 模板`，例如 `GET /api/patients/{id}`。它必须满足 T3 定的校验规则，将来才能原样确认进 `objects.functions`。

在 `xshield-core/src/path_template.rs` 加：

```rust
/// 学习时一个请求算作哪个功能的模板；这条路径不能算作功能时为 None。
pub fn function_template(path: &str) -> Option<String>;
```

规则，按顺序：

1. `canonical_path(path)`，没有规范拼写则 `None`。
2. 逐段处理：先去掉第一个 `;` 及之后的部分，去掉后为空则整个返回 `None`。
3. 段是纯数字或 UUID（现有的 `is_variable_segment`）：写成 `{id}`。
4. 段长于 32 字节，或含有 `[A-Za-z0-9._~-]` 之外的字节（包括保留下来的百分号转义、`@`、`:`、`{`、`}`）：写成 `{id}`。这类段是令牌、邮箱、编码过的文字，不是路由词，也不应该原样进证据表。
5. 其余段原样保留，不改大小写。
6. 拼回 `/` 开头的模板；根路径是 `/`。

在 `xshield-core/src/context/learning.rs` 加：

```rust
/// 一条判定记录的功能键。
pub fn function_key(method: &str, path: &str) -> Option<String>;
```

- 方法必须是 3 到 7 个大写 ASCII 字母，否则 `None`。`HEAD` 记作 `GET`。`OPTIONS` 返回 `None`（预检不算功能）。
- 模板用 `function_template(path)`。
- 整个键超过 `KEY_MAX`（256 字节）时 `None`。

`path` 用**逻辑路径**（`decision_log` 的 `COALESCE(logical_path, path)`），这样按请求头或请求体取接口名的站点，每个接口名是一个功能。

### 2.2 从判定记录读出事实

`DecisionFacts` 加三个字段，`object_learning_store::read_batch` 的查询和 `facts_of` 相应补上：

| 字段 | 来源 |
|---|---|
| `method: String` | `decision_log.method` |
| `path: String` | `COALESCE(logical_path, path)` |
| `client: String` | `decision_log.client` |

所有构造 `DecisionFacts` 的地方（`learning.rs` 的两个测试辅助函数和 `facts_of`）补上这三个字段。现有的 `observe`、`observe_tiers` 不读它们，行为不变。

新增：

```rust
pub enum FunctionFact {
    /// 一个普通单位走过这个功能。
    Used { function: String, unit: String, day: u64 },
    /// 一个没有身份的访问者走过：用户身份站点上还没声明用户的会话，或者没有会话的客户端地址。
    Anonymous { function: String, unit: String, day: u64 },
    /// 一个管理员单位走过。
    Admin { function: String, unit: String, day: u64 },
    /// 一个普通单位在这个功能上被拒绝。
    Refused { function: String, unit: String, day: u64 },
}

/// 一条判定记录的功能事实：零条、一条，或者管理员在入口上走过时的两条。
pub fn observe_functions(record: &DecisionFacts, identified: bool) -> Vec<FunctionFact>;
```

规则：

- `record.trace.bypass` 有值：`None`。
- `function_key(&record.method, &record.path)` 为 `None`：`None`。
- **走过**：`outcome == Allowed`，判定路径是 `FastAllow`、`CachedAllow`、`JevAllow` 之一，状态码在 200 到 399 之间。注意这里含 3xx，和现有的 `answered_and_allowed`（只认 2xx）不同：表单提交后跳转是正常的“走过”。不要改 `answered_and_allowed`，另写一个函数。
- **被拒绝**：判定路径是 `JevDeny`，或状态码是 401、403（与 `observe_tiers` 的判断相同）。
- `on_entry` = `record.trace.entry.is_some()`；`admin` = 现有的 `is_admin(record)`；`primary` = 现有的 `unit_of(record, identified)`。

| 情况 | 事实 |
|---|---|
| 走过，不在入口上，`admin` 为真，有 `primary` | `Admin { unit: primary }` |
| 走过，在入口上，`admin` 为真，有 `primary` | `Used { unit: primary }` 和 `Admin { unit: primary }` 两条 |
| 走过，有 `primary`，以上都不适用 | `Used { unit: primary }` |
| 走过，没有 `primary`，`record.session` 非空 | `Anonymous { unit: "s:" + session }` |
| 走过，没有 `primary`，没有会话，`record.client` 非空 | `Anonymous { unit: "a:" + client }` |
| 被拒绝，不在入口上，`admin` 为假，有 `primary` | `Refused { unit: primary }` |
| 其他 | `None` |

几条理由，写进文档注释：

- 入口上的请求一律按普通单位记，管理员也一样，所以入口永远不会被提议成管理档（设计稿 5.1“入口不提议”）。
- 管理员在入口上走过时多记一条 `Admin`（2026-11-13 验收 PR 204 第二轮时补）：`Used` 那条让入口的普通单位数不为零，入口照旧不会被提议；`Admin` 那条让这个单位在全站普通单位数里被去掉（见 2.3），否则只登录、没碰别的功能的管理员会被数成普通用户的旁证。不为此新增类型，迁移 0011 不变。
- 没有身份的访问者单独一类：登录页、登录提交这些功能只有它们在走，基线需要它们；但它们不能证明“有足够多的普通用户在活动”。
- 用户身份站点上，会话还没声明用户时走过管理功能，记成没有身份的访问者，也就是“有非管理员走过”。这是有意保守：判定那边同样会把这种请求当作非管理员，管理员登录后头几个请求就会碰到的功能，不该被提议成管理档。

### 2.3 存储

迁移 `migrations/0011_function_evidence.sql`：把 `object_response_evidence_kind_check` 换成允许多四个取值的约束（先 `DROP CONSTRAINT` 再 `ADD CONSTRAINT`），并更新表和列的注释。不建新表，不回填，不动其他约束。

| `kind` | `slot` 列 | `unit` 列 |
|---|---|---|
| `function` | 功能键 | 普通单位 |
| `function_anon` | 功能键 | `s:会话标签` 或 `a:客户端地址` |
| `function_admin` | 功能键 | 管理员单位 |
| `function_refused` | 功能键 | 普通单位 |

每个站点、类型、功能、单位、UTC 日一行，`fingerprints` 为空，`complete` 用默认值。行数不会超过同期的判定记录数，所以不另设上限。

新模块 `crates/xshield-postgres/src/object_function_store.rs`（在 `lib.rs` 登记），照 `object_tier_store.rs` 的写法：

```rust
/// 写入一批功能事实。同批先去重；ON CONFLICT DO NOTHING；带站点代际保护。
pub async fn record_function_facts(pool, site, generation, facts: &[FunctionFact]) -> Result<(), LearningStoreError>;

/// 窗口内的功能键和各自走过的单位数（function、function_anon、function_admin 三类合起来的不同单位数），
/// 按单位数从多到少、再按键排序，最多 limit 条；第二个返回值说明是否还有更多。
pub async fn function_keys(pool, site, oldest_day, limit) -> Result<(Vec<FunctionUse>, bool), LearningStoreError>;

/// 按合并映射（原键到合并后的键）汇总窗口内的证据，键是合并后的功能键。一条 SQL 完成：
/// 把映射用 unnest($keys::text[], $merged::text[]) 连上证据表，按合并后的键和类型
/// 取 count(DISTINCT unit)、count(DISTINCT day)、max(day)。
pub async fn function_evidence(pool, site, oldest_day, mapping: &BTreeMap<String, String>) -> Result<BTreeMap<String, FunctionEvidence>, LearningStoreError>;

/// 窗口内全站走过任意功能的普通单位数：kind = 'function' 的不同单位，
/// 去掉窗口内同时有 function_admin 行的单位。
pub async fn site_ordinary_units(pool, site, oldest_day) -> Result<u32, LearningStoreError>;
```

`site_ordinary_units` 为什么要去掉管理员单位（2026-11-13 验收 PR 204 时补）：管理员在入口上的请求按 2.2 记成 `function`，如果照数，一个只有管理员在用的站点（五个管理员各登录一次）也能凑够“有普通用户在活动”的旁证，所有非入口功能都会被提议成管理档。旁证必须来自从没以管理员身份出现过的单位。

不需要新的清理函数：现有的 `prune_tier_evidence` 按天删除这张表的所有类型，`forget_site` 按站点删除。各加一条测试钉住新类型也被清掉。

`object_tier_store::load_tier_evidence` 的三条查询都写明了 `kind`，新类型不会混进去；加一条测试钉住（写入功能事实后，响应位置的读数不变）。

### 2.4 路径段合并

路径里的标识不是数字也不是 UUID 时（`/products/PT-7004`、`/u/alice`、带哈希的静态文件），每个取值是一个不同的键，永远攒不够单位。合并把这样的段归成 `{id}`。它是纯函数，放在 `context/learning.rs`：

```rust
pub struct FunctionUse { pub key: String, pub units: u32 }

/// 兄弟段里，含数字的轻量取值达到这个数就合并。
pub const MERGE_IDS_MIN: usize = 10;
/// 兄弟段里，不含数字的轻量取值达到这个数才合并。
pub const MERGE_WORDS_MIN: usize = 50;
/// 一次学习最多分析这么多个功能键。
pub const FUNCTION_KEYS_MAX: usize = 20_000;

/// 每个键归到哪个键下统计。没被合并的键映射到自己。
pub fn merge_functions(
    uses: &[FunctionUse],
    thresholds: Thresholds,
    named_under: &[String],
) -> BTreeMap<String, String>;
```

算法：

1. 把每个键拆成方法和段的列表。
2. **受保护的键**：`named_under` 是站点 `routes` 里每条规则路径的主干（`route.path().stem()`，去掉结尾的 `/`）。一个键的开头几段与某条主干的段逐字相同时，这个键原样保留，不参与下面任何一步（既不被合并，也不算作别人的兄弟）。理由：路由规则路径之下的段是接口名，每个名字是一个不同的功能，合并会把没人用过的接口名也变成已知。
3. 从第 0 段起逐段往后处理。处理第 `p` 段时，把长度大于 `p` 的键按“方法加前 `p` 段（用已经替换过的结果）”分组。
4. 组内，第 `p` 段的每个不同取值是一个孩子，`{id}` 除外。孩子的分量是组内带这个取值的键里 `units` 的最大值。分量小于 `thresholds.sessions` 的是轻量孩子。
5. 轻量孩子分两类：含 ASCII 数字的，和不含的。含数字的达到 `MERGE_IDS_MIN` 个时，把它们的第 `p` 段都换成 `{id}`；不含数字的达到 `MERGE_WORDS_MIN` 个时同样处理。两类各算各的。
6. 分量达到阈值的孩子不动：它自己就是一个站得住的功能（`/u/settings`、`/products/featured`）。
7. 处理完所有段，把每个键拼回去，得到映射。

为什么不含数字的门槛高得多：`/api/users`、`/api/orders` 这样的路由词不含数字，一个小站点的二三十个接口可能都还没攒够单位，按 10 个就合并会得到 `GET /api/{id}`，把 `/api/metrics` 也变成已知。50 个互不相同、都很少人用的纯字母兄弟段，基本只会是用户名、标签这类数据。这两个数是代码常量，不做成配置。

合并的结果只用来汇总证据和生成提议，最后进不进功能表仍然由管理员确认；T5 的页面会标出一个候选是由多少个路径合并来的。

### 2.5 管理档的规则

纯函数，放在 `context/learning.rs`：

```rust
pub struct FunctionEvidence {
    /// 走过的非管理员单位数：function 与 function_anon 两类的不同单位数之和。
    pub ordinary_units: u32,
    /// 走过的管理员单位数。
    pub admin_units: u32,
    /// 管理员走过的不同天数。
    pub admin_days: u32,
    /// 被拒绝的普通单位数。
    pub refused_units: u32,
    /// 任何一类证据的最后一天。
    pub last_day: u64,
}

/// 这个功能该不该提议成管理档，以及可靠性。None 表示不提议。
pub fn judge_function(
    evidence: &FunctionEvidence,
    site_ordinary_units: u32,
    identified: bool,
    thresholds: Thresholds,
) -> Option<Reliability>;
```

- 必须 `admin_units >= 1` 且 `ordinary_units == 0`。
- 旁证 `support = max(refused_units, site_ordinary_units)`，必须 `>= thresholds.sessions`。它说明“普通用户没走过”不是因为没有普通用户。
- `strong = support >= 2 * thresholds.sessions && admin_days >= 2`。
- 可靠性用现有的 `grade(strong, identified)`：有用户身份时 `strong` 为 `high`、否则 `medium`；没有用户身份的站点各降一档，降到 `low` 就不提议。

所以没有声明用户身份位置的站点最多得到 `medium` 的提议，确认后判定也不会按它收紧。这和位置档位的规矩相同，写进文档。

### 2.6 学习任务（`object_learning.rs`）

`learn_site` 的批次循环里，和 `tiers` 并排收集功能事实，在游标前进之前写入：

```rust
functions.extend(observe_functions(facts, identified));
…
function_store::record_function_facts(pool, site, generation, &functions).await?;
```

在 `judge_tiers` 之后调用新函数 `judge_functions(pool, site, generation, oldest_day, now_millis)`：

1. 照 `judge_tiers` 的开头取当前配置，代际不一致就返回。
2. `function_keys(…, FUNCTION_KEYS_MAX)` 取键；`named_under` 取自当前配置的 `routes`；`merge_functions` 得到映射。
   `function_keys` 报告还有更多键（超过 `FUNCTION_KEYS_MAX`）时，这一轮不判断功能：不写提议，也不撤回已有的提议，照 `judge_tiers` 跳过时的写法留一行日志后返回（2026-11-13 验收 PR 204 时补）。理由：被截掉的键不在合并映射里，合并后的键会缺掉它们的证据，可能把普通用户在用的功能提议成管理档；没有判断也不等于证据没了，所以不撤回。
3. `function_evidence(…, &mapping)` 和 `site_ordinary_units(…)`。
4. 对每个合并后的功能调用 `judge_function`。有结果的，用现有的 `tier_judgements::put` 写一条提议：`slot` 是功能键，`tier` 是 `Tier::Admin`，`reliability` 是结果，`units` 是 `admin_units`，`seen_values` 和 `agreement_per_mille` 为 0，`last_day` 取证据的。
5. 没有结果的功能，以及这一轮没出现的功能，它们没被驳回的提议要撤回：新增 `tier_judgements::retain_functions(pool, site, generation, &judged_keys)`，删除本站点“键是功能键、不在列表里、没被驳回”的行。被驳回的行留着，规则不会再提同一条。

提议复用 `object_tier_judgements`，不建新表。功能键恰好有一个空格，位置键恰好有两个，两类行靠这个区分：

- 现有的 `tier_judgements::retain` 会删掉“不在声明位置列表里”的所有行，必须改成只删位置键的行（SQL 加条件 `slot LIKE '% % %'`），否则每轮学习都会把功能提议清掉。
- `retain_functions` 的条件相反：`slot NOT LIKE '% % %'`。
- `tier_judgements::proposals` 会把功能提议也读出来。现有的调用方 `object_map.rs` 的 `judgement_bodies` 用 `declared_class_of` 过滤，功能键不是声明的位置，会被滤掉；加一条测试钉住（库里有一条功能提议时，`GET /api/sites/{name}/objects` 的 `judgements` 里没有它）。

本 PR 不读 `objects.functions`（T3 还没合入）。“配置里已经带着同样档位的功能不再提议”这一步由 T5 的列表接口过滤，和位置提议在 `judgement_bodies` 里的做法一样。

学习关闭（`auto_learn` 为假）的站点不记证据、不出提议，和现在一样。

## 3. 测试

### 3.1 `path_template.rs`

| 测试 | 断言 |
|---|---|
| `a_function_template_replaces_numbers_and_uuids` | `/api/patients/8` 得 `/api/patients/{id}`；带 UUID 的段同样；`/` 得 `/` |
| `a_function_template_drops_matrix_parameters` | `/api/admin;x=1/users` 得 `/api/admin/users`；`/api/users/7;v=2` 得 `/api/users/{id}`；`/api/;x/users` 得 `None` |
| `a_long_or_unusual_segment_is_an_id` | 33 字节的段、`a@b.com`、`%E4%BD%A0`、`{id}`、`a:b` 各得 `{id}` |
| `a_word_segment_is_kept_as_it_is` | `/api/Users/PT-7004/v2.list` 原样返回 |
| `a_path_without_a_canonical_spelling_has_no_function` | 相对路径、带 `?` 的、带控制字符的、转义不完整的，各得 `None` |

### 3.2 `learning.rs`（新开 `mod function_tests`）

| 测试 | 断言 |
|---|---|
| `a_function_key_is_the_method_and_the_template` | `("DELETE", "/api/patients/8")` 得 `DELETE /api/patients/{id}`；`HEAD` 得 `GET …`；`OPTIONS`、`get`、`PROPFINDX1`、8 个字母的方法各得 `None`；超过 256 字节得 `None` |
| `an_ordinary_units_2xx_or_3xx_is_a_use` | 200 和 302 各得 `Used`；500、404 得 `None`；`would_block` 加 200 得 `None`；`blocked` 得 `None` |
| `an_admin_off_an_entry_is_an_admin_use_and_on_an_entry_an_ordinary_one` | 管理员、非入口只得 `Admin`；`trace.entry` 有值时得 `Used` 和 `Admin` 两条 |
| `a_session_without_a_user_on_a_site_with_users_is_anonymous` | `identified` 为真、会话没声明用户：`Anonymous`，单位是 `s:` 加会话标签，即使它的角色是 `admin` |
| `a_request_without_a_session_counts_its_client_address` | 没有会话、有客户端地址：`Anonymous`，单位是 `a:` 加地址；两者都空得 `None` |
| `a_refusal_counts_for_an_ordinary_unit_off_an_entry` | 403、401、`JevDeny` 各得 `Refused`；管理员、入口上、没有 `primary` 的各得 `None` |
| `a_bypassed_request_is_no_function_fact` | `trace.bypass` 有值得 `None` |
| `ten_light_siblings_with_digits_become_an_id` | 12 个 `GET /products/PT-70xx`（各 1 个单位）加 `GET /products/featured`（30 个单位）：前 12 个映射到 `GET /products/{id}`，`featured` 映射到自己。只有 9 个时全部映射到自己 |
| `words_merge_only_from_fifty_light_siblings` | 25 个各 1 个单位的 `GET /api/<字母词>` 全部映射到自己；60 个 `GET /u/<字母名>` 加 30 个单位的 `GET /u/settings`：60 个映射到 `GET /u/{id}`，`settings` 不动 |
| `a_heavy_sibling_is_left_alone` | 12 个轻量的 `PT-…` 加一个达到阈值的 `GET /products/PT-1`：轻量的合并，`PT-1` 不动 |
| `segments_merge_level_by_level` | 60 个用户、每人两篇 `GET /u/<名>/posts/<带数字的标题>`：全部映射到 `GET /u/{id}/posts/{id}` |
| `siblings_join_an_id_that_is_already_there` | `GET /orders/{id}` 加 12 个轻量的 `GET /orders/ORD-…`：都映射到 `GET /orders/{id}` |
| `methods_do_not_merge_with_each_other` | 6 个 `GET /x/A1…` 加 6 个 `POST /x/B1…`：都不合并 |
| `functions_under_a_named_route_are_never_merged` | `named_under = ["/rpc"]`，12 个轻量的 `POST /rpc/v2.users.<…>`：全部映射到自己；同一批键在 `named_under` 为空时会合并 |
| `merging_is_stable` | 对合并结果再合并一次，映射不变；输入顺序打乱，结果相同 |
| `a_function_only_admins_use_is_proposed_when_ordinary_users_are_around` | 管理员 1 个单位 2 天、普通 0、被拒绝 0、全站普通单位 10、有身份、阈值 5：`high`。全站普通单位 5：`medium`。全站普通单位 4：`None` |
| `refusals_count_as_much_as_bystanders` | 被拒绝 10、全站普通单位 0：`high` |
| `one_ordinary_use_stops_the_proposal` | `ordinary_units` 为 1（无论来自普通单位还是没有身份的访问者）：`None` |
| `one_day_of_admin_use_is_not_high` | 管理员只在一天里用过：`medium` |
| `without_identities_a_function_is_never_high` | `identified` 为假：最强的证据得 `medium`，较弱的得 `None` |

### 3.3 `xshield-postgres`（需要数据库）

`object_function_store.rs` 的测试模块，照 `object_tier_store.rs` 的辅助函数写：

- 写入同一事实两次只有一行；代际不对的写入被丢弃。
- `function_keys` 的单位数是三类“走过”的不同单位数，同一个单位在两类里只算一次；`limit` 生效并报告还有更多；`function_refused` 的行不产生键。
- `function_evidence` 按映射汇总：两个键映射到同一个合并键时，同一个单位只算一次；`admin_days` 是不同天数；窗口之外的行不算。
- `site_ordinary_units` 只数 `function` 类，并且不数窗口内同时有 `function_admin` 行的单位。
- `prune_tier_evidence` 删掉窗口外的功能行；`forget_site` 删掉站点的功能行。
- `load_tier_evidence` 的结果不受功能行影响。
- `object_tier_judgement_store`：`retain` 不再删除功能键的行；`retain_functions` 删除不在列表里、没被驳回的功能行，保留被驳回的，也不碰位置键的行。
- 迁移：`crates/xshield-control/tests/migrations.rs` 通过；旧类型的行照常写入；不认识的类型仍被约束拒绝。

### 3.4 `xshield-control`（`object_learning.rs` 新开 `mod function_pass_tests`，需要数据库）

照 `tier_pass_tests` 的写法往 `decision_log` 里放合成的记录，跑一轮学习：

| 测试 | 断言 |
|---|---|
| `a_function_only_admins_use_is_proposed_as_admin` | 声明了用户和角色身份的站点；1 个管理员在两天里走过 `GET /api/admin/search`，10 个普通用户走过别的功能：库里有 `GET /api/admin/search` 的管理档提议，`high` |
| `a_function_an_ordinary_user_uses_is_not_proposed` | 同上，但有一个普通用户也走过它：没有提议 |
| `an_entry_is_never_proposed` | 只有管理员走过的功能在入口上（记录的 `trace.entry` 有值）：没有提议 |
| `slug_paths_are_judged_as_one_function` | 管理员走过 12 个不同的 `POST /admin/users/<带数字的名字>/ban`：只有一条提议，键是 `POST /admin/users/{id}/ban` |
| `a_function_proposal_is_withdrawn_when_its_evidence_ages_out` | 证据过了窗口后再跑一轮：提议没了 |
| `a_dismissed_function_proposal_stays_dismissed` | 驳回后再跑一轮：不重新提议，行还在 |
| `tier_proposals_of_positions_survive_the_function_pass_and_the_other_way_round` | 同一站点既有位置的档位提议又有功能提议，跑两轮后两类都在 |
| `a_site_with_learning_off_keeps_no_function_evidence` | `auto_learn` 为假：证据表里没有功能行 |
| `function_proposals_are_not_listed_as_position_judgements` | 2.6 里说的那条（可以放在 `object_map.rs` 的测试模块里） |
| `a_site_with_more_function_keys_than_one_pass_reads_is_not_judged` | 键数超过上限时（测试里把上限当参数传小）：不出新提议，已有的未驳回提议还在 |
| `administrators_on_entries_are_no_ordinary_bystanders` | 6 个管理员，1 个走过非入口功能 F，其余 5 个只登录（入口），没有普通用户：F 没有提议，入口也没有提议 |

## 4. 检查（AGENTS.md 的“质量”一节）

改动涉及 Rust、`xshield-core`、`xshield-postgres`、`xshield-control`、`migrations/`，提交前全部执行并在 PR 描述里逐条写结果：

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `scripts/test_postgres.sh`。这一步对本 PR 是必须的：大部分新测试只在有数据库时才运行。先 `pg_isready`，数据库没起来就先启动（项目记忆里有本地启动 PostgreSQL 16 的办法）。跑不了就不要开 PR，先说明卡在哪里。
- 在 `fuzz/` 下：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`
- 没改判定路径，`scripts/test_idor_lab.py` 不强制。

没有执行的步骤写“未执行”和原因，不要写成通过。不要为了变绿去跳过测试、加 `#[allow]`、放宽 clippy、改工作流。

## 5. 文档和 CHANGELOG

- `docs/07-console-architecture.md` 在 7.9.17 之后加小节 **7.9.19 功能的学习证据与管理档提议**（7.9.18 留给 T3，两边各加各的，不要改对方的编号）：功能键的规则、四类证据和单位、路径段合并的规则和两个门槛及理由、管理档提议的规则和可靠性、提议存在哪里。7.9.16 里说 `object_response_evidence` 有哪几类行的那一段补上新的四类。
- `docs/07` 第 7.8 节数据库部分补迁移 0011。第 7.11 节安全与隐私补一句：功能证据按单位记，没有会话的入口请求用客户端地址作单位，保留 7 天；路径里过长或带特殊字符的段不进证据表。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录：学习任务开始按功能记录证据，并提议只有管理员走过的功能为管理档；本次不改变判定，提议在后续版本的控制台里确认。
- 设计稿在 `docs/design-records/designs/`（2026-11-27 从项目共享文件夹导入的快照），由验收线程更新。

## 6. 验收标准

评审时逐条核对，缺一条不通过：

1. 没有任何判定变化：`xshield-judge`、`xshield-edge` 没有改动；站点配置没有新字段；学习任务不写新的配置版本。
2. 第 3 节列出的测试都在，断言与表里一致，并且在有数据库的环境里实际运行过（PR 描述里贴出 `scripts/test_postgres.sh` 的结果）。
3. 现有的位置学习不受影响：`observe`、`observe_tiers`、`judge_tier`、`answered_and_allowed` 的行为没变；现有测试除了给 `DecisionFacts` 补字段之外没有改断言。
4. 功能键符合 2.1：只含 `[A-Za-z0-9._~-]` 和 `{id}` 的段，不含 `;`，方法不是 `HEAD`、`OPTIONS`。证据表里不出现长于 32 字节的路径段、邮箱或百分号转义的文字。
5. 合并规则与 2.4 一致：两个门槛、分量达到阈值的孩子不动、路由规则路径之下不合并、结果与输入顺序无关。
6. 管理档规则与 2.5 一致：有一个非管理员走过就不提议；入口不提议；没有用户身份的站点得不到 `high`。
7. 位置的档位提议和功能提议互不清除；被驳回的功能提议不再出现；功能提议不出现在现有的 `judgements` 列表里。
8. 迁移只改一个约束，可重复部署（`_sqlx_migrations` 正常记录），旧行不变。
9. 生产路径没有新增 `unwrap`、`expect`、`panic`；没有新增 `#[allow]`、依赖、环境变量、表、配置项。
10. 没有测试被删除、忽略或削弱。
11. docs 和 CHANGELOG 与实现一致。
12. 第 4 节的检查全部执行并写明结果，CI 全绿。
13. PR 标题 `feat(control): …`（英文 Conventional Commits），描述按 `templates/pull-request.md` 的五个标题，并带上项目要求的归属行。提交信息、PR、代码注释里不出现模型名。

## 7. 依赖和顺序

- 不依赖 T1、T3，也不依赖“修复大请求绕过与限额降级”的任何批次，可以马上开工。那边的批次不改 `context/learning.rs`、`object_learning.rs` 和学习相关的存储。
- 与 T3（见 [function-level-authz-plan-table.md](function-level-authz-plan-table.md)）改的文件不重叠。T3 会在 `object_learning.rs` 的测试模块里加一条测试，后合的一方 rebase 时两边都保留。docs/07 的小节编号已经分好（T3 用 7.9.18，本 PR 用 7.9.19）。
- T1 合入后，带未认可凭证的请求不再有会话，也就不会作为单位出现在功能证据里。本 PR 不需要为此做任何事。
- T5（确认接口与功能表页）要等本 PR 和 T3 都合入。
