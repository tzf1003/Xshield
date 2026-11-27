# 实现规划 T5a：功能表的候选、确认和驳回接口（控制面）

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 5.1、6.1、8.2、8.3、10 节。用户在 2026-11-13 的决定：功能表的变更**全部由管理员确认**，不自动加入。
- 前置：T2（PR 204，功能证据和管理档提议，docs/07 7.9.19）和 T3（功能表的格式和查找，docs/07 7.9.18）都合入 `main`。T2 没合入前不要开工。开工前 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-control`（新文件 `object_functions.rs`，`lib.rs` 的路由，`object_learning.rs` 里抽一个共用函数，`contract.rs`）、`xshield-postgres`（两个只读查询）、`web/console/tests/fixtures/`（一个契约样例文件）、docs、CHANGELOG。**不改** `xshield-core`、`xshield-judge`、`xshield-edge`、`migrations/`、`.github/`、`deny.toml`，不做控制台页面（页面是后续的 T5b），不加依赖、表、环境变量。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。
- 这一步**不改变任何判定**。它只让管理员能看到学习结果并把它写进站点配置；配置里的功能表什么时候影响判定，由“判定使用功能表”的改动决定。
- 规格里写了 **STOP** 的地方，停下来在 PR 或线程里问验收人。

## 1. 要解决的问题

学习任务已经在按功能记证据，并把“只有管理员走过的功能”写成提议（`object_tier_judgements` 里功能键的行）。但这些东西只在库里：没有接口能列出学到了哪些功能，没有接口能把它们写进 `objects.functions`，提议也没法确认或驳回。本 PR 补上这三个接口，供控制台的功能表页使用。

## 2. 规格

三个接口都在 `/api/sites/{name}/objects/functions` 之下，登录检查与其余 `/api` 相同。处理函数放新文件 `crates/xshield-control/src/object_functions.rs`（`object_map.rs` 已经四千多行，不要再往里加）。

### 2.1 共用：一个站点窗口内的功能证据

`object_learning.rs` 的 `judge_functions` 里“读键、合并、读证据、读全站普通单位数”这一段，抽成一个函数，学习任务和列表接口都调它，保证两边看到的合并结果相同：

```rust
pub(crate) struct FunctionWindow {
    /// 合并后的功能键到证据。
    pub evidence: BTreeMap<String, FunctionEvidence>,
    /// 全站普通单位数（site_ordinary_units）。
    pub ordinary_units: u32,
}

/// None 表示功能键超过 keys_max，这一轮不能合并。
pub(crate) async fn function_window(
    pool: &PgPool, record: &SiteRecord, oldest_day: u64, keys_max: usize,
) -> Result<Option<FunctionWindow>, store::LearningStoreError>
```

抽取之后 `judge_functions` 的行为不变：它已有的测试一条都不许改，全部通过。

### 2.2 `GET /api/sites/{name}/objects/functions`

返回（字段名即 JSON 键，`snake_case`）：

```json
{
  "status": "ok",
  "window_days": 7,
  "threshold_units": 5,
  "identified": true,
  "ordinary_units": 37,
  "admin_units": 2,
  "functions": [
    {"key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high",
     "ordinary_units": 0, "admin_units": 2, "refused_units": 3, "last_seen": "2026-11-12", "on_entry": false}
  ],
  "candidates": [
    {"key": "GET /api/reports/{id}", "ordinary_units": 12, "admin_units": 1, "refused_units": 0,
     "last_seen": "2026-11-13", "requests_24h": 340, "suggested": true, "sensitive": false, "on_entry": false}
  ],
  "proposals": [
    {"key": "DELETE /api/users/{id}", "tier": "admin", "reliability": "medium",
     "admin_units": 2, "refused_units": 1, "last_seen": "2026-11-13", "in_table": true}
  ],
  "unlearned": {
    "requests": 57, "unkeyed_requests": 2, "complete": true,
    "top": [{"key": "GET /metrics", "requests": 40, "sample": "req_…"}]
  }
}
```

- `status`：
  - `ok`。
  - `over_limit`：功能键超过 `FUNCTION_KEYS_MAX`（`function_window` 返回 `None`）。这时 `candidates` 为空，`functions` 各行的证据数字为 0、`last_seen` 为 `null`，`proposals` 照库里的列出（它们是之前某一轮的结果），`unlearned` 照常计算。
  - `learning_off`：站点 `objects.learning.auto_learn` 为假。内容照实际能读到的给。两者同时成立时给 `learning_off`。
- `window_days`：`WINDOW_DAYS`。`threshold_units`：`objects.learning.thresholds.sessions`。`identified`：站点是否声明了用户身份位置（`identified_by`）。`ordinary_units`：全站普通单位数。`admin_units`：窗口内有 `function_admin` 行的不同单位数（新查询 `site_admin_units`，见 2.5）。控制台用后两个数说明提议的依据，并在 `admin_units` 为 0 时提示“没有会话被认作管理员”。
- `functions`：配置里 `objects.functions` 的每一条，按配置里的顺序。证据按**键逐字相等**从窗口里取，取不到就是 0 和 `null`。`last_seen` 的格式照 `object_map.rs` 的 `last_seen()`。`tier`、`reliability` 没有时省略。`on_entry`：键的模板匹配站点的某条入口模式（`spec.matching_entry(模板)`）。
- `candidates`：窗口里有证据的合并后功能键中，配置**不认识**的那些（`!map.knows_function(方法, 模板)`）。对象表在同一路由上声明过位置的功能已经算已知，不列。
  - `suggested`：`ordinary_units + admin_units >= threshold_units`。控制台默认只勾选它们。
  - `sensitive`：模板转小写后含有下面任一词：`admin`、`manage`、`audit`、`metrics`、`actuator`、`server-status`、`debug`、`swagger`、`console`、`phpinfo`、`internal`、`config`、`backup`、`ftp`、`export`。写成本文件里的常量，注释说明它与判定指令里列的运维词对应，用来提醒管理员别把这类路径顺手勾进基线。
  - `requests_24h`：最近 24 小时里这个功能键上以 `fast_allow` 或 `cached_allow` 放行的请求数（见下面的流量统计）。
  - 排序：`ordinary_units + admin_units` 从少到多，相同按键。少的排前面，是为了让管理员先看到可疑的。
  - 超过 256 字节（`KEY_MAX`）的键不列。
- `proposals`：`object_tier_judgements` 里功能键的提议（键里恰好一个空格），去掉配置里已经有“同一个键、`tier: admin`、同样 `reliability`”条目的。`admin_units` 取提议行的 `units`；`refused_units` 取窗口证据里同键的值，取不到（包括 `over_limit`）为 `null`；`in_table` 表示配置里有逐字相同的键。按键排序。
- `unlearned`：最近 24 小时里以 `fast_allow` 或 `cached_allow` 放行、功能键既不被配置认识、也不在 `candidates` 里的请求。这些是源站没有成功应答过的路径（404、被拒绝），所以学习没有把它们记成“走过”；打开“未知功能交 Jev”之后它们会去 Jev。`requests` 是总数，`top` 是按请求数最多的 50 个键，各带一个示例请求 ID。算不出功能键的路径（`function_key` 返回 `None`）计入 `unkeyed_requests`，不进 `top`。`complete` 为假表示分组超过了一次读取的上限，数字是下限。

**流量统计**：`xshield-postgres` 的 `decision_stats.rs` 加一个查询（照 `path_groups` 写）：

```rust
/// 窗口内以 fast_allow 或 cached_allow 放行的请求，按方法和逻辑路径分组，最多 GROUP_LIMIT 组。
pub async fn function_traffic(pool: &PgPool, scope: &Scope)
    -> Result<(Vec<FunctionTraffic>, bool), sqlx::Error>   // method, path, count, sample; complete
```

`path` 取 `COALESCE(logical_path, path)`。窗口是最近 24 小时，起点不早于站点的创建时间（判定日志比站点活得久，同名的旧站点的行不能算进来，照 `slot_impact` 的 `Scope` 写法）。控制面拿到分组后用 `function_key(方法, 路径)` 得到键再按键相加。这里的键没有经过学习的路径段合并，所以 `/products/PT-7004` 这类路径在 `candidates` 里是合并后的 `{id}`，在流量里是原样：统计 `requests_24h` 时，把流量的键用 `function_window` 同一次合并得到的映射换成合并后的键再比；映射里没有的键原样使用。为此 `FunctionWindow` 可以把映射一并带出来。

错误：未知站点 404 `SITE_NOT_FOUND`；查询失败 500。

### 2.3 `POST /api/sites/{name}/objects/functions/changes`

把管理员在功能表页上的一批操作写成站点配置的**一个**新版本。请求体（`deny_unknown_fields`，四个列表都可省略）：

```json
{
  "add": ["GET /api/reports/{id}", "POST /api/reports"],
  "admin": [{"key": "DELETE /api/users/{id}", "reliability": "medium"}],
  "open": ["POST /api/admin/export"],
  "remove": ["GET /api/old"]
}
```

| 列表 | 含义 | 对配置做什么 | 不满足时 |
|---|---|---|---|
| `add` | 把功能加入功能表（已知功能，不带档位） | 配置里没有逐字相同的键时追加 `{key, source}`；`source` 在这个键是当前窗口的候选时为 `rule`，否则为 `admin`。已有相同的键时不动 | 键不合法由下面的整体校验报出 |
| `admin` | 确认一条管理档提议 | 键必须有一条提议，且提议的 `reliability` 与请求体里的相同。把逐字相同的条目设为 `tier: admin` 加这个 `reliability`、`source: rule`；没有这个条目就追加 | 没有提议：404 `JUDGEMENT_NOT_FOUND`；可靠性对不上：409 `JUDGEMENT_CHANGED`；键的模板落在入口上：409 `FUNCTION_ON_ENTRY`。都带 `field`（如 `admin[0]`） |
| `open` | 取消一个功能的管理档 | 逐字相同的条目去掉 `tier` 和 `reliability`，`source` 改为 `admin`，条目保留为已知功能 | 没有这个条目或它不带档位：409 `FUNCTION_CHANGED`，带 `field` |
| `remove` | 从功能表删除 | 删掉逐字相同的条目 | 没有这个条目：409 `FUNCTION_CHANGED`，带 `field` |

- 四个列表都为空、同一个键出现两次（跨列表也算）、总条数超过 `FUNCTIONS_MAX`：400 `INVALID_BODY`。
- 应用顺序：`remove`、`open`、`admin`、`add`。在 `ObjectMapDto` 上改 `functions`，再 `ObjectMap::try_from` 整体校验；校验失败用现有的 `From<ConfigError> for ApiError` 报出（非法的键会得到 `objects.functions[n]` 的位置和 `key_invalid`）。不要给 `xshield-core` 加新的方法。
- 把“请求体加当前配置加候选集合加提议集合，得到新的对象表或一个错误”写成一个**纯函数**，处理函数只负责读库、调它、写库。
- 写入用 `site_spec_store::write`，带读到记录时的版本，`Change::Update`，备注为一句中文，写明各类操作的条数，例如“管理员确认了功能表的变更：新增 12，管理档 1，取消管理档 0，删除 0”。站点已不存在 404 `SITE_NOT_FOUND`；版本已变 409 `VERSION_CONFLICT`（带 `current_version`）。照 `write_judgement` 写。
- 配置写成功之后，对 `admin` 里的每一条调 `tier_judgements::clear_confirmed(pool, 站点, 键, Tier::Admin, reliability)`。
- 新配置与旧配置相同（比如 `add` 的键都已存在）时不写新版本，仍然做上一条的清理，返回 204。
- 成功返回 204。
- `open` 之后学习任务下一轮可能再次提议同一个功能（证据没变）。这是预期的：它只是提议，管理员可以用 2.4 驳回。写进文档。

### 2.4 `POST /api/sites/{name}/objects/functions/proposals/dismiss`

请求体 `{"key": "DELETE /api/users/{id}"}`。键必须是功能键的形状（恰好一个空格），否则 400 `INVALID_BODY`：这个接口不能用来驳回位置的档位提议。调 `tier_judgements::dismiss(pool, 站点, 站点创建时间, 键, 现在)`；有提议被驳回返回 204，没有返回 404 `JUDGEMENT_NOT_FOUND`。驳回之后规则在证据达到另一个结论之前不再提议（现有行为）。

### 2.5 `xshield-postgres` 的两个只读查询

- `decision_stats::function_traffic`（2.2）。
- `object_function_store::site_admin_units(pool, site, oldest_day) -> u32`：窗口内 `kind = 'function_admin'` 的不同单位数。

不改表，不加迁移。

### 2.6 契约样例

`web/console/tests/fixtures/functions.json`：一份 2.2 的响应，`functions`、`candidates`、`proposals`、`unlearned.top` 各至少两行，覆盖带档位和不带档位、`suggested` 真和假、`sensitive` 真和假、`refused_units` 为 `null`。`crates/xshield-control/src/contract.rs` 照其他样例加一条：读成 Rust 的响应类型再写回，JSON 相同。控制台的类型和页面不在本 PR。

## 3. 测试

名字可以调整，每条要有。

### 3.1 纯函数（`object_functions.rs` 的 `mod tests`）

| 测试 | 断言 |
|---|---|
| `adding_a_candidate_writes_a_rule_entry_and_any_other_key_an_admin_one` | 候选里的键 `source` 为 `rule`；不在候选里的合法键为 `admin`；已存在的键不重复、不改动 |
| `confirming_a_proposal_sets_the_admin_tier_on_the_entry_or_adds_it` | 已有条目被设上 `tier`、`reliability`、`source: rule`；没有条目时追加 |
| `a_proposal_that_changed_or_is_gone_is_not_confirmed` | 没有提议得 `JUDGEMENT_NOT_FOUND`；可靠性不同得 `JUDGEMENT_CHANGED`；`field` 指向 `admin[n]` |
| `an_admin_tier_is_not_confirmed_on_an_entry` | 模板匹配入口模式：`FUNCTION_ON_ENTRY` |
| `opening_a_function_keeps_it_known_without_a_tier` | `tier`、`reliability` 没了，条目还在，`source` 为 `admin`；条目不存在或不带档位得 `FUNCTION_CHANGED` |
| `removing_a_function_deletes_the_entry` | 条目没了，其余条目和顺序不变；不存在得 `FUNCTION_CHANGED` |
| `an_empty_or_repeating_change_is_refused` | 四个列表都空、同一个键出现两次（同列表内、跨列表）：`INVALID_BODY` |
| `an_invalid_key_is_refused_by_the_map` | `add` 一个 `get /x` 或 `GET /a/{userId}`：得到对象表校验的错误，位置在 `objects.functions[n]` |
| `the_other_parts_of_the_map_are_untouched` | 变更前后 `classes`、`slots`、`learning` 相等 |
| `candidates_leave_out_what_the_map_knows` | 功能表里的键、被 `{id}` 条目覆盖的键、对象表在同一路由上有位置的键，都不在候选里 |
| `a_candidate_is_suggested_at_the_threshold_and_flagged_when_sensitive` | 单位数等于阈值为 `suggested`，少一个不是；`GET /api/admin/users`、`GET /metrics` 为 `sensitive`，`GET /api/patients` 不是；排序从少到多 |
| `proposals_already_in_the_table_are_left_out` | 配置有同键、admin、同可靠性的条目：不列；可靠性不同：列出且 `in_table` 为真 |
| `traffic_outside_the_table_and_the_candidates_is_unlearned` | 流量分组里：已知功能不计；候选的键计入它的 `requests_24h`（经合并映射）；其余进 `unlearned`；算不出键的进 `unkeyed_requests`；`top` 最多 50 个且按请求数排 |

### 3.2 数据库测试（照 `object_map.rs` 的 `mod live_tests` 和 `object_learning.rs` 的 `function_pass_tests` 写，`scripts/test_postgres.sh` 会跑到）

| 测试 | 断言 |
|---|---|
| `the_functions_list_shows_the_table_the_candidates_and_the_proposals` | 造一个站点和几天的功能证据，跑一轮学习：列表里三部分与预期一致，`ordinary_units`、`admin_units` 正确 |
| `a_site_over_the_key_limit_lists_no_candidates` | `function_window` 用很小的 `keys_max`：`status` 为 `over_limit`，`candidates` 为空，库里已有的提议仍列出 |
| `a_site_with_learning_off_says_so` | `auto_learn: false`：`status` 为 `learning_off` |
| `confirming_changes_writes_one_version_and_clears_the_proposal` | 一次请求里 `add` 两条、`admin` 一条：站点版本只加 1，备注含条数，配置里有这三条；提议被清掉，再列时 `proposals` 里没有它 |
| `a_change_that_changes_nothing_writes_no_version` | `add` 的键都已存在：204，版本不变 |
| `a_stale_version_is_a_conflict` | 读记录之后配置被另一次保存改动：409 `VERSION_CONFLICT` 带 `current_version`。现有测试里没有可照的构造方式时，把“写入时带的是读到的版本”放在处理函数的一个小函数里单独测，并在 PR 里说明 |
| `dismissing_a_function_proposal_keeps_it_dismissed` | 驳回后列表里没有它；再跑一轮学习（证据不变）仍没有；对位置键调用得 `INVALID_BODY`；没有提议得 `JUDGEMENT_NOT_FOUND` |
| `site_admin_units_counts_distinct_administrators` 和 `function_traffic_groups_fast_and_cached_allows_by_logical_path` | 两个新查询各一条：前者不数其他类型的行和窗口外的行；后者只数这两种判定路径，带接口名的请求按逻辑路径分组，窗口外不计 |
| `the_function_pass_still_judges_as_before` | 不新增测试：`function_pass_tests` 现有各条不改且通过，说明 2.1 的抽取没有改变行为 |

### 3.3 契约

`contract.rs` 的新测试（2.6）通过。

## 4. 检查（AGENTS.md 的“质量”一节）

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `scripts/test_postgres.sh`（本机 PostgreSQL 16 的启动方式见项目记忆 `local-test-environment`；数据库测试在没有设置数据库地址时会直接返回，PR 里要写明它们是真的跑过）
- `web/console/` 下的五条（新增了 `tests/fixtures/` 里的文件）
- 没有改 `xshield-core`、判定路径和依赖，`fuzz/`、靶场、`cargo deny` 可以不跑，在 PR 里写明。

生产路径不用 `unwrap`、`expect`、`panic`。不加 `#[allow]`，不跳过或删除失败的测试，不改 CI。已有测试的断言不改。

## 5. 文档和 CHANGELOG

- docs/07 7.9.2 的端点表加三行。
- docs/07 新增一节（接在 7.9.19 之后）：三个接口的请求、响应、错误码，各字段的含义和算法（候选怎么筛、`suggested` 和 `sensitive`、`unlearned` 是什么、为什么少的排前面、`open` 之后提议可能再出现）。
- docs/07 7.9.19 末尾“实现状态”那句改为：接口已有，页面是后续工作。
- docs/07 7.9.1 的错误码清单加 `FUNCTION_CHANGED`、`FUNCTION_ON_ENTRY`。
- 文档里不写线程代号。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录，写明只有接口、没有页面、不改判定。
- PR 描述按 `templates/pull-request.md` 的五个标题写。提交标题用英文 Conventional Commits，例如 `feat(control): list, confirm and dismiss learned functions`。提交信息、PR、代码注释里不写模型名。

## 6. 验收标准

1. 第 3 节的测试都存在并通过；第 4 节的检查都跑过并通过，数据库测试确实执行了。
2. `git diff main --stat` 里没有 `crates/xshield-core`、`crates/xshield-judge`、`crates/xshield-edge`、`migrations/`、`.github/`、`deny.toml`、`Cargo.lock`。
3. `function_pass_tests` 和 `object_map.rs` 的测试没有被改动的断言。
4. 一次 `changes` 请求最多写一个配置版本；写配置失败时不清理任何提议。
5. `GET …/objects` 的 `judgements` 仍然只有位置提议。
6. 三个接口未登录时返回 401（路由挂在登录检查之内）。
7. 响应里没有单位的原文（用户标签、会话标签、客户端地址）：只有计数。

## 7. 依赖和顺序

- **依赖**：T2 和 T3 合入。不依赖“判定使用功能表”（T4），可以与它并行。
- **冲突热点**：`CHANGELOG.md` 顶部；`lib.rs` 的 `object_routes`；`object_learning.rs` 的 `judge_functions`（如果 T2 的后续修正还在动它）；docs/07 的 7.9.2 和 7.9.19 之后。后合并的一方 rebase。
- **之后**：T5b（控制台的功能表页、“未知功能交 Jev”的开关、就绪检查里的 `trace.function` 计数、请求详情里的功能显示）依赖本 PR 和 T4，规划另写。

## 8. 本 PR 不做的

- 控制台的任何页面、类型和请求函数。
- “未知功能交 Jev”开关的读写（开关由 T4 加进配置；界面在 T5b）。
- 候选的驳回状态：没有地方存“这个候选我不要”，候选不勾选即可。有需求再加。
- 按请求回放的影响预估：管理档提议的影响由证据里的单位数说明（提议的前提就是窗口内没有普通单位走过它）；开关的影响由 `requests_24h` 和 `unlearned` 说明。
