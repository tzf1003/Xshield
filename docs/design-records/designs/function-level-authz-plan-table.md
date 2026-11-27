# 实现规划 T3：功能表的配置格式、校验和查找（`objects.functions`）

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 5.2、5.3、6.1 节。用户在 2026-11-13 确认了第 15 节的全部问题（只分管理员；功能表的变更全部由管理员确认）。
- 基线：`main` `0acae80`。开工前先 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-core`（`context/objects.rs`）、`xshield-control`（只有 `tightening.rs` 的一处构造）、`schemas/`、`examples/`、`web/console`（只做“读得进、存得回、看得到差异”，不做页面）、docs、CHANGELOG。**不改** `xshield-judge`、`xshield-edge`、`xshield-postgres`、`migrations/`、`.github/`、`deny.toml`。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。
- 这一步**不改变任何判定**。网关读入并校验功能表，但判定还不用它；用它的是 T4（第 2、3 层的判定）。CHANGELOG 要把这一点写明。

## 1. 要解决的问题

对象表的条目是“位置”（某个接口里的某个值），必须带类别。没有地方能记“这个接口本身只给管理员用”或“这个接口是本站的正常功能”。本 PR 在 `objects` 下加一个列表 `functions`，定下它的格式、校验和查找规则，并保证控制台保存配置时不把它丢掉。

现在的控制台会丢：`web/console/src/lib/objects-validate.ts` 的 `parseObjects` 遇到 `learning`、`classes`、`slots` 之外的键直接报错，`web/console/src/lib/yaml.ts` 的 `orderObjects` 和 `features/sites/spec-model.ts` 的三方合并也只带这三个键。不处理的话，手写了功能表的站点在控制台里打不开配置，或者一保存就没了。

## 2. 规格

### 2.1 配置格式

```json
"objects": {
  "functions": [
    { "key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high" },
    { "key": "GET /api/patients/{id}", "source": "admin" }
  ]
}
```

| 字段 | 必填 | 取值 |
|---|---|---|
| `key` | 是 | `方法 路由模板`，中间一个空格。规则见 2.2 |
| `source` | 是 | `admin`、`rule`、`agent`，与位置条目相同（复用 `SlotSource`） |
| `tier` | 否 | 只接受 `admin`。省略表示这个功能对所有会话开放，条目只表示“已知功能” |
| `reliability` | 否 | `low`、`medium`、`high`（复用 `Reliability`）。只能和 `tier` 一起出现。省略按 `low` 算 |

和设计稿 5.2 相比少了 `paused`：功能条目目前没有自动暂停，手工想停用管理档时删掉 `tier` 即可，条目仍是已知功能。等真有自动暂停的需求再加。请把设计稿 5.2 里“`paused` 沿用”那半句同步删掉。

`functions` 省略或为空时，序列化结果里不出现这个键（`#[serde(default, skip_serializing_if = "Vec::is_empty")]`），所以现有站点的配置逐字不变。最多 `FUNCTIONS_MAX = 2048` 条，与 `SLOTS_MAX` 相同。

**本 PR 不加** `objects.learning` 里的第 3 层开关。开关和它的行为一起在 T4 加，免得出现一个打开了却没有效果的配置项。

### 2.2 键的校验（`valid_function_key`）

键必须是判定能产生的拼写，否则条目永远匹配不上而没人发现。全部满足才接受，否则拒绝，原因 `KeyInvalid`：

1. 恰好两段，用一个空格分开；整个键不超过 `KEY_MAX`（256 字节）。
2. 方法：3 到 7 个大写 ASCII 字母，且不是 `HEAD`、`OPTIONS`（这两个方法在查找时另有规则，见 2.3，写成条目永远匹配不上）。
3. 模板以 `/` 开头，不含 `?`、`#`、控制字符，并且 `canonical_path(template) == Some(template)`（与位置键相同）。
4. `position_template(template) == template`：纯数字或 UUID 的段必须写成 `{id}`。
5. 含 `{` 或 `}` 的段只能恰好是 `{id}`。写成 `{userId}` 的拒绝，免得管理员以为它是占位符。
6. 段里不含 `;`（查找时请求段会去掉 `;` 之后的部分，带 `;` 的字面段永远匹配不上）。

其他校验：

| 情况 | 位置 | 原因 |
|---|---|---|
| 超过 2048 条 | `objects.functions` | `TooMany`（复用） |
| 键不合规则 | `objects.functions[n]` | `KeyInvalid`（复用） |
| 两条的键在忽略模板字母大小写后相同 | `objects.functions[n]`（后一条） | `DuplicateKey`（复用） |
| `tier` 不是 `admin` | `objects.functions[n]` | 新增 `FunctionTierUnsupported`，代码 `function_tier_unsupported` |
| 有 `reliability` 没有 `tier` | `objects.functions[n]` | `ReliabilityWithoutJudgement`（复用） |
| 条目里有不认识的字段 | `objects` | 现有的“段解析失败”路径（`deny_unknown_fields`） |

`ObjectsPlace` 新增 `Functions` 和 `Function(usize)`，`field()` 分别给出 `objects.functions` 和 `objects.functions[n]`。新增的原因只有 `FunctionTierUnsupported` 一个。

### 2.3 查找（`ObjectMap` 的新方法，纯函数，T4 和控制面都用）

调用方传入方法和请求的路由模板（`position_template(逻辑路径)`，也就是 `xshield-judge` 里 `route_template` 的结果）。

```rust
/// 功能表里管这个请求的条目；没有则 None。
pub fn function_of(&self, method: &str, template: &str) -> Option<&ObjectFunction>;
/// 条目确认它只给管理员：tier 为 admin 且 reliability 为 high。
pub fn admin_only(&self, method: &str, template: &str) -> bool;
/// 本站是否知道这个功能：功能表有条目管它，或者对象表里有位置声明在这个接口上。
pub fn knows_function(&self, method: &str, template: &str) -> bool;
/// 全部条目，按书写顺序。
pub fn functions(&self) -> &[ObjectFunction];
```

**段的比较**（功能专用，不要改现有的 `template_covers`，位置条目的行为不变）：

- 条目模板和请求模板按 `/` 分段，段数必须相同。
- 条目的 `{id}` 段覆盖请求的任意一个非空段。
- 其他段：请求段先去掉第一个 `;` 及之后的部分，再与条目段做忽略 ASCII 大小写的比较。去掉之后为空的段不匹配任何字面段。
- 记下逐字相等（或忽略大小写相等）的段数，叫字面段数。

忽略大小写和去掉 `;` 参数是有意的：源站如果不分大小写（IIS、部分框架）或会剥掉 `;` 参数（Java 系），`/API/Admin/export`、`/api/admin;x/export` 到的是同一个管理功能，条目必须照样管住；源站如果区分，这些拼写本来就是 404，多管一下没有代价。

**`function_of` 的规则**：

1. 方法是 `OPTIONS`：返回 `None`（预检请求不带凭证，不参与管理档）。
2. 方法是 `HEAD`：按 `GET` 查。
3. 在方法相同的条目里找出所有覆盖请求模板的，按下面的顺序取第一名：字面段数多的优先；一样多时，`tier` 为 `admin` 且 `reliability` 为 `high` 的优先（取更严的）；再一样时，书写顺序靠前的优先。

**`admin_only`**：`function_of` 的结果 `tier == Some(Tier::Admin)` 且 `reliability == Some(Reliability::High)`。可靠性不是 `high` 的条目不收紧，这和位置条目的规矩相同。

**`knows_function`**：

1. `function_of` 有结果，为真。
2. 对象表的任意一条位置（`slots`，暂停与否都算，因为接口确实存在）满足：键的方法与请求方法相同（`HEAD` 按 `GET`），键的模板按上面的段比较覆盖请求模板，为真。位置键形如 `GET /api/patients [].id`，取前两段。
3. 方法是 `OPTIONS`：任意方法下满足 1 或 2 即为真（预检对应的真实方法是已知功能，预检就是已知的）。
4. 否则为假。

**性能**：T4 会在每个请求上调用它们，条目最多 2048 条加 2048 条位置。校验时建一次索引（按方法和段数分组即可），查找只看同组的条目，不要每次扫全表、每次重新切分全部键。

### 2.4 `ObjectMap` 的其他改动

- `ObjectMapDto` 加 `functions: Vec<ObjectFunction>`；`ObjectMap` 加同名字段和上面的索引；`TryFrom`、`From<ObjectMap> for ObjectMapDto` 带上它。
- `ObjectMap::is_empty()` 把“没有功能条目”算进去。
- 现有的 `with_paused`、`with_entry`、`with_accepts_public`、`with_tier` 不动功能表（它们本来就是就地改，保持即可，加测试钉住）。
- `crates/xshield-control/src/tightening.rs` 的 `apply` 用字面量重建 `ObjectMapDto`（约第 210 行），必须带上 `functions: map.functions().to_vec()`，否则自动收紧写新版本时会把功能表清空。同文件测试里的字面量（约第 278 行）补 `functions: Vec::new()`。改完后全仓库搜一遍 `ObjectMapDto {`，确认没有第三处。
- 本 PR 不加往功能表里写条目的方法（`with_function…`）。写入由确认接口做，在 T5。

### 2.5 契约和样例

- `schemas/site-config.schema.json` 的 `$defs.objects.properties` 加 `functions`：数组，`maxItems` 2048；条目 `additionalProperties: false`，`required: ["key", "source"]`；`key` 用 `pattern` 表达“大写方法、空格、以 `/` 开头”；`tier` 的 `enum` 只有 `"admin"`；`if` 有 `reliability` `then` 必须有 `tier`。描述用中文，指向 docs/07 的 7.9.18。
- `examples/site-emr.yaml` 现在没有 `objects` 段。给它加一个只含 `functions` 的 `objects` 段，两条：一条管理档（`POST /api/admin/export`，`rule`，`admin`，`high`），一条已知功能（`GET /api/patients/{id}`，`admin`）。这样 `scripts/validate_library.py`（契约）和 `crates/xshield-core/tests/v4_samples.rs`（解析）会同时校验到新字段。加之前确认靶场和其他测试没有逐字比对这个样例；有的话一并更新。

### 2.6 控制台（只做不丢、不拒、差异可见）

| 文件 | 改动 |
|---|---|
| `web/console/src/api/types.ts` | 新增 `ObjectFunctionEntry { key; source; tier?: "admin"; reliability? }`；`ObjectsSpec` 加 `functions?: ObjectFunctionEntry[]` |
| `web/console/src/lib/objects-validate.ts` | `parseObjects` 接受 `functions`（逐条解析，形状错误给出第几条）；`checkObjects` 加条数上限、键的形状（方法大写、两段、以 `/` 开头、长度）、重复键、`tier` 只能是 `admin`、`reliability` 必须带 `tier`；`objectChanges` 列出功能条目的新增、删除、档位或可靠性变化，文案照位置条目的写法，放进 `vocab.ts` |
| `web/console/src/lib/yaml.ts` | `orderObjects` 原样带上 `functions`，条目内字段顺序固定为 `key`、`source`、`tier`、`reliability` |
| `web/console/src/features/sites/spec-model.ts` | 三方合并用 `mergeList(…, (item) => item.key)` 合并 `functions`，并放进合并结果的 `objects`；`objects` 是否为空的判断把它算进去 |
| `web/console/src/features/sites/objects/objects-model.ts` | `withObjectLists` 现在用展开保留其他键，确认 `functions` 不会被它删掉，加测试钉住 |

控制台的细校验（规范拼写、`{id}`）以网关为准，控制台不重复实现，网关拒绝时照现有方式显示 `objects.functions[n]` 和原因。给 `function_tier_unsupported` 配一句中文说明，放在现有原因文案的同一处。

不做页面、不做表单。功能表页、基线确认、提议在 T5。

## 3. 测试

### 3.1 `xshield-core`（`objects.rs` 里新开一个 `mod function_tests`）

| 测试 | 断言 |
|---|---|
| `functions_are_read_and_written_and_absent_when_empty` | 带两条功能的段解析后 `functions()` 有两条；再序列化与原文等价；没有功能的 `ObjectMap` 序列化结果里没有 `functions` 键 |
| `a_function_key_is_a_method_and_a_canonical_template` | 逐个拒绝并给出 `KeyInvalid`：三段的键、小写方法、`HEAD /x`、`OPTIONS /x`、不以 `/` 开头、带 `?`、`/a//b`、`/a/b/`、`/api/users/7`、`/api/users/{userId}`、`/api/a;x/b`、超过 256 字节 |
| `a_function_tier_is_admin_only` | `tier: "self"`、`"org"`、`"public"` 各被拒绝，原因 `FunctionTierUnsupported` |
| `a_function_reliability_needs_a_tier` | 只有 `reliability` 的条目被拒绝，原因 `ReliabilityWithoutJudgement` |
| `function_keys_repeat_when_they_differ_only_by_case` | `GET /api/Users` 和 `GET /api/users` 同时出现被拒绝，原因 `DuplicateKey`，位置是后一条 |
| `more_functions_than_the_limit_are_refused` | 2049 条被拒绝，位置 `objects.functions`，原因 `TooMany` |
| `an_exact_function_is_found` | `function_of("POST", "/api/admin/export")` 返回那一条 |
| `an_id_segment_covers_any_segment` | 条目 `GET /api/patients/{id}`：`/api/patients/{id}`、`/api/patients/PT-7004`、`/api/patients/7;x=1` 都找到；`/api/patients` 和 `/api/patients/7/notes` 找不到 |
| `the_most_literal_function_wins_and_then_the_stricter` | 条目 `GET /api/reports/{id}`（无档位）和 `GET /api/reports/monthly`（管理档、高）：`/api/reports/monthly` 得到管理档那条，`/api/reports/weekly` 得到无档位那条。条目 `GET /a/{id}/c`（无档位）和 `GET /a/b/{id}`（管理档、高）：`/a/b/c` 得到管理档那条 |
| `a_function_is_found_whatever_the_case_and_matrix_parameters` | 条目 `DELETE /api/admin/users/{id}`（管理档、高）：`/API/Admin/Users/{id}`、`/api/admin;x=1/users/{id}` 的 `admin_only` 为真 |
| `head_is_looked_up_as_get_and_options_as_any_method` | 条目只有 `GET /api/a`（管理档、高）和 `POST /api/b`：`admin_only("HEAD", "/api/a")` 为真；`function_of("OPTIONS", "/api/a")` 为 `None`；`knows_function("OPTIONS", "/api/b")` 为真；`knows_function("OPTIONS", "/api/c")` 为假；`knows_function("GET", "/api/b")` 为假 |
| `only_a_high_admin_tier_is_admin_only` | 管理档 `medium`、管理档无可靠性、无档位，`admin_only` 都为假 |
| `a_declared_position_makes_its_function_known` | 位置 `GET /api/patients [].id` 和暂停的位置 `DELETE /api/patients/{id} path[2]`，功能表为空：`knows_function("GET", "/api/patients")`、`knows_function("DELETE", "/api/patients/PT-7")` 为真；`knows_function("POST", "/api/patients")` 为假 |
| `editing_positions_keeps_the_functions` | 带功能表的 `ObjectMap` 经过 `with_paused`、`with_entry`、`with_tier`、`with_accepts_public` 之后 `functions()` 不变 |

### 3.2 `xshield-core` 的配置层和样例

- `context/config.rs` 的测试里加一条：站点配置带 `objects.functions` 时解析成功；条目带未知字段时报 `objects` 段错误。
- `tests/v4_samples.rs` 通过（样例里的两条功能被解析出来，加断言）。
- `fuzz/` 的 `site_config` 目标不需要改，但要按第 4 节跑它的检查。

### 3.3 `xshield-control`

- `tightening.rs`：`a_split_keeps_the_function_table`，带功能表的 `ObjectMap` 经过 `apply` 之后功能表不变。
- 现有的确认判断、自动暂停、自动收紧的测试不改断言就通过。挑 `object_learning.rs` 里一条会写新配置版本的测试（如 `a_suspended_declared_position_is_paused_by_one_new_version`），在它旁边加一条带功能表的同类测试，断言新版本里功能表还在。这条测试需要数据库。

### 3.4 控制台（`web/console/tests/`，vitest）

- `objects-validate.test.ts`：`parseObjects` 接受带 `functions` 的段并原样返回；条目形状错误时报第几条；`checkObjects` 对重复键、超上限、`tier` 不是 `admin`、只有 `reliability` 各给出一条消息；`objectChanges` 对新增、删除、加上管理档各给出一行。
- YAML 和 JSON 往返：带功能表的配置经过 `specToYaml` 再解析，功能表不变；没有功能表的配置输出与改动前逐字相同。
- 三方合并：我方加了一条功能、对方加了另一条，合并结果两条都在；我方没动、对方删了一条，合并结果是删掉的。
- `diff-summary.test.ts` 或同类测试里补一条功能表变化的摘要。

## 4. 检查（AGENTS.md 的“质量”一节）

改动涉及 Rust、`xshield-core`、`xshield-control`、`web/console`，提交前全部执行并在 PR 描述里逐条写结果：

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- 在 `fuzz/` 下：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`
- `scripts/test_postgres.sh`（改了 `xshield-control`；先 `pg_isready`，数据库没起来就先启动；确实跑不了要写明未执行）
- 在 `web/console/` 下：`npm ci`、`npm run lint`、`npm test`、`npm run build`、`npm run test:e2e`
- 没改判定路径，`scripts/test_idor_lab.py` 不强制，但样例文件变了，跑一遍确认没受影响更稳妥。

没有执行的步骤写“未执行”和原因，不要写成通过。不要为了变绿去跳过测试、加 `#[allow]`、放宽 clippy 或 biome、改工作流。

## 5. 文档和 CHANGELOG

- `docs/03-admin-config-audit.md` 的站点配置表，`objects` 一行补上 `functions` 的字段说明。
- `docs/07-console-architecture.md` 在 7.9.17 之后加小节 **7.9.18 功能表**（T2 用 7.9.19，两边各加各的，不要改对方的编号），写 2.1 到 2.3 的规则：格式、键的校验、查找顺序、忽略大小写和 `;` 参数的理由、`HEAD` 和 `OPTIONS` 的处理、位置条目让接口自动算已知。写明判定在后续改动里启用。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录：新增站点配置 `objects.functions`（功能表）；本次只有格式、校验和保存，网关还不按它判定；控制台保存、导入导出、三方合并都会保留它。
- 设计稿 [function-level-authz.md](function-level-authz.md) 在 `docs/design-records/designs/`（2026-11-27 从项目共享文件夹导入的快照），由验收线程自己更新，实现线程不用管。

## 6. 验收标准

评审时逐条核对，缺一条不通过：

1. 没有 `objects.functions` 的站点：配置的序列化结果、控制台导出的 YAML 和 JSON、判定结果都与改动前逐字相同。`xshield-judge`、`xshield-edge` 没有任何改动。
2. 第 3 节列出的测试都在，断言与表里一致。
3. 带功能表的配置在这些路径上都不丢条目：控制台打开再保存、YAML 导入导出、三方合并、确认一个位置的判断、自动暂停、自动收紧。每条路径有测试。
4. 2.2 的每条拒绝规则都有测试；拒绝时 API 返回的 `field` 是 `objects.functions` 或 `objects.functions[n]`，不回显配置里的值。
5. 2.3 的查找规则与表里一致，尤其是：字面段多的优先、同分取更严的、忽略大小写、去掉 `;` 参数、`HEAD` 按 `GET`、`OPTIONS` 不参与管理档。位置条目的查找（`request_key`、`template_covers`）没有被改动。
6. 查找不扫全表（看实现）。
7. 生产路径没有新增 `unwrap`、`expect`、`panic`；没有新增 `#[allow]`、依赖、环境变量、表；新增的配置只有 `objects.functions` 一项。
8. 没有测试被删除、忽略或削弱；改动过的现有测试在 PR 描述里逐个说明。
9. docs、契约、样例、CHANGELOG 与实现一致。
10. 第 4 节的检查全部执行并写明结果，CI 全绿。
11. PR 标题 `feat(core): …`（英文 Conventional Commits），描述按 `templates/pull-request.md` 的五个标题，并带上项目要求的归属行。提交信息、PR、代码注释里不出现模型名。

## 7. 依赖和顺序

- 不依赖 T1、T2，也不依赖“修复大请求绕过与限额降级”的任何批次，可以马上开工。
- 与 T2（功能证据与学习规则，见 [function-level-authz-plan-learning.md](function-level-authz-plan-learning.md)）改的文件不重叠：T2 改 `context/learning.rs`、`xshield-postgres`、`object_learning.rs`，本 PR 改 `context/objects.rs`、`tightening.rs`、契约和控制台。3.3 里加在 `object_learning.rs` 测试模块里的那一条测试，如果和 T2 冲突，后合的一方 rebase 时两边都保留。
- T4（判定）和 T5（确认接口与功能表页）都要等本 PR 合入。
