# 实现规划 T4：判定使用功能表（功能级越权第 2、3 层）

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 5.3、6.2、6.3、10、16 节。功能表的格式和查找函数已由 T3 合入（`main` `1b16938`，docs/07 7.9.18）。
- 基线：`main` `1b16938`。开工前先 `git fetch origin main`，以最新 `main` 为准。
- 范围：`xshield-core`（`context/objects.rs`、`context/trace.rs`）、`xshield-judge`（`engine.rs`、`state.rs`、`slots.rs`）、`xshield-edge`（`proxy.rs` 的两处 `RequestFacts`）、`xshield-control`（只有 `tightening.rs` 的一处构造）、`schemas/`、`examples/`、`tests/security-lab/`、`scripts/test_idor_lab.py`、`scripts/validate_library.py`、`web/console`（只做“读得进、存得回、看得到差异”，不做页面）、docs、CHANGELOG。**不改** `xshield-postgres`、`migrations/`、`.github/`、`deny.toml`，不加依赖、环境变量、表、`DecisionPath` 的取值、Jev 的问题数量。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。
- 这一步**改判定**，但只影响配置了的站点：功能表里有可靠性为 `high` 的管理档条目，或打开了下面的开关。其他站点的判定、`state` 的数据、判定记录都与现在逐字节相同。指令文字对所有站点都会变（提示词版本号变）。
- 测试只用假 Jev。不跑 `live_jev`（真实模型的回归是 T6）。
- 规格里写了 **STOP** 的地方，停下来在 PR 或线程里问验收人，不要自己选一个做法。

## 1. 要解决的问题

现在一个请求只要每个值都核验过（或者根本没有值），网关就快速放行，不看它调的是什么接口。于是：

- 普通用户调 `POST /api/admin/export`（没有值）或拿自己的编号调 `PUT /api/admin/users/{id}/role`，快速放行。源站如果只是在界面上不显示按钮，就被越权了。
- 任何会话访问 `GET /metrics`、`GET /actuator/env`，快速放行。

本 PR 让判定读功能表：

- **第 2 层**：功能表里确认为管理档（`tier: admin`、`reliability: high`）的功能，非管理员会话来调就是**尝试越权**，交 Jev 并要求答 DENY。
- **第 3 层**：站点打开开关后，功能表之外的功能不再免检，交 Jev，由模型按路径判断它是不是管理、运维、调试一类。

## 2. 规格

### 2.1 开关 `objects.ask_unknown_functions`

```yaml
objects:
  functions:
    - key: GET /api/patients
      source: admin
  ask_unknown_functions: true
```

- 布尔，默认 `false`。为 `false` 时不写出这个键（`#[serde(default, skip_serializing_if = "is_false")]`，`objects.rs` 里已有 `is_false`），现有站点的配置逐字不变。
- 放在 `objects` 下，与 `functions` 并列，不放进 `objects.learning`：它是判定的设置，不是学习的设置；而且控制台的学习设置表单要求 `learning` 里每个键都在。设计稿 6.2 原来写的是“`objects.learning` 里的一个布尔项”，我会同步改掉。
- **功能表为空时不允许打开**：`functions` 为空而开关为真，拒绝。位置新增 `ObjectsPlace::AskUnknownFunctions`（`field()` 给出 `objects.ask_unknown_functions`），原因新增 `ObjectsReason::AskWithoutFunctions`（码 `ask_without_functions`）。
- `ObjectMapDto` 和 `ObjectMap` 各加这个字段；`From<ObjectMap> for ObjectMapDto` 带上；`is_empty()` 把它算进去。
- `ObjectMap` 新增两个方法：
  - `asks_unknown_functions() -> bool`：开关的值。
  - `guards_functions() -> bool`：开关为真，或功能表里至少有一条 `tier: admin` 且 `reliability: high` 的条目。这个值在建表时算一次存起来（`#[serde(skip)]`），不要每个请求扫一遍功能表。
- `crates/xshield-control/src/tightening.rs` 的 `apply` 手工构造 `ObjectMapDto`（约 210 行），要带上开关，否则自动收紧一次开关就丢了。

### 2.2 请求的功能

只有 `tuning.objects.guards_functions()` 为真时才算下面这些；为假时一个字节都不多算，请求的处理与现在完全相同。

**路径**用逻辑路径 `turn.resolved.logical_path()`，与位置键、学习任务的功能键一致。

**候选模板**（新函数，放 `xshield-judge/src/slots.rs`，纯函数）：

```rust
/// 一个请求在功能表里查找时用的模板：第一条是 route_template(path)。
/// 路径的规范拼写里还留着 %2F 或 %5C 时，把它们换成 `/` 后再取一次模板，与第一条不同就作为第二条。
pub fn function_templates(path: &str) -> Vec<String>
```

- `canonical_path` 会把转义的十六进制转成大写，所以只需要找 `%2F` 和 `%5C`。`canonical_path(path)` 为 `None` 时只有第一条。
- 第二条的理由：有的源站或它前面的代理会先解码 `%2F` 再路由，`/api/admin%2Fexport` 到的是 `/api/admin/export`。不查第二条，管理档条目就能被这样绕开。`/api/x/..%2Fadmin/export` 换完再规范化得 `/api/admin/export`，同样要查到。
- 双重编码（`%252F`）不处理，写进文档的局限里。

**候选方法**：

- 传输方法 `M0` = `request.method` 转成 ASCII 大写。`function_of` 只按原样匹配，而条目的方法都是大写；有的源站不分方法大小写，所以先转大写再查。
- 方法覆盖：下面每个值去掉首尾空白、转大写后，是 3 到 7 个 ASCII 字母的才算，去重，去掉与 `M0` 相同的。
  - `RequestFacts` 新增字段 `method_overrides: &'a [String]`：请求头 `x-http-method-override`、`x-http-method`、`x-method-override` 的全部取值（同一个头出现多次的每个值都要），原样。网关在 `proxy.rs` 构造 `RequestFacts` 的两处填它；`crates/xshield-judge/tests/live_jev.rs` 和 `engine.rs` 测试里的构造处填空切片。
  - 已提取的请求值里 `at` 恰好是 `query._method` 或 `body._method` 的值。
- 覆盖不看传输方法是不是 `POST`：只有覆盖后的方法落在管理档条目上才有影响，正常请求不会这样，所以放宽没有代价。

**第 2 层的命中条目**：按顺序试 `(M0, 每个模板)`，然后 `(每个覆盖方法, 每个模板)`，第一个 `objects.admin_only(方法, 模板)` 为真的就是命中，记下 `objects.function_of(方法, 模板)` 的 `key`。都不为真就是没有命中。`HEAD` 按 `GET`、`OPTIONS` 不参与，这两条 `function_of` 已经处理了，不要在外面再做一遍。

**尝试越权** = 有命中条目，且会话不是管理员（`judge()` 里已有的 `admin`，没有会话、凭证未被认可、地址上下文都不是管理员）。

**未知功能** = `objects.asks_unknown_functions()` 为真，且 `!is_templatable(path) || !objects.knows_function(M0, 第一条模板)`。未知与否只看传输方法和第一条模板：基线是按真实流量的方法和路径学来的，覆盖方法和解码后的模板不在基线里。

这些结果在 `judge()` 里算好（紧接着 `admin` 之后），放进 `Turn` 的一个新字段（比如 `function: Option<FunctionView>`，结构自定），`plan`、`ask_jev`、`remember_allow` 从 `Turn` 读，不要各算一遍。

### 2.3 去向

| 情况 | 快速放行 | 读放行缓存 | 写放行缓存 | `state.request.function` | `trace.function` |
|---|---|---|---|---|---|
| 尝试越权 | 不 | 不 | 不 | `{"tier":"admin","attempt":"over_privilege"}` | 有 |
| 未知功能（不是尝试越权） | 不 | 可以 | 可以 | `{"known":false}` | 有 |
| 尝试越权同时未知（`POST` 未知，覆盖方法命中管理档） | 不 | 不 | 不 | `{"tier":"admin","attempt":"over_privilege","known":false}` | 有 |
| 管理员会话命中管理档条目 | 与现在相同 | 与现在相同 | 与现在相同 | 没有 | 有（没有 `attempt`） |
| 其他 | 与现在相同 | 与现在相同 | 与现在相同 | 没有 | 没有 |

- `plan()` 的快速放行条件加上“不是尝试越权、不是未知功能”；读缓存的条件加上“不是尝试越权”；`remember_allow` 遇到尝试越权直接返回（模型没照指令答 DENY 时，这个放行也不能被缓存）。
- 尝试越权**即使请求里的值全部核验过**也不快速放行。值照常进 `state`（带 `verified: true`）。
- 未知功能被 Jev 放行后可以走缓存，否则一个不在基线里的轮询接口会把会话的调用额度用完。缓存键已经包含对象表的摘要和管理员标志，改表或换开关会让旧缓存失效，不用改键。
- Jev 判拒绝、超时、答 UNKNOWN、限额用完，全部按现有规则（`apply_policy`），不加新的分支。`on_jev_unavailable: allow` 的站点在 Jev 不可用时会转发尝试越权的请求，这与值的尝试越权一致，写进文档。
- 没有凭证且不在入口上的请求仍在最前面得到 `no_session`（401），不调 Jev，不写 `trace.function`。绕过路径（`bypass`）仍最先返回，功能表管不到它。
- 网关不自己拒绝尝试越权，交 Jev 并要求 DENY，沿用 11-03 定下的做法。

### 2.4 `state` 和指令

`StateInput` 加 `function: Option<StateFunction>`（`pub struct StateFunction { pub admin_attempt: bool, pub unknown: bool }`，名字可调）。两个都为假时 `engine` 传 `None`。`render` 在 `request` 里只在 `Some` 时写 `function`：`admin_attempt` 为真写 `"tier":"admin"` 和 `"attempt":"over_privilege"`，`unknown` 为真写 `"known":false`。`None` 时 `request` 里没有这个键，`GOLDEN_STATE` 测试不许改。

`state` 里**不放功能键**，只放上面三个字段。路径已经在 `request.path` 里。

如果开工时 WAF 批次 2（state 分批）已经合入：`function` 属于每批都相同的部分，和 `method`、`path` 一样每批都带，任何裁剪级别都不丢。

`ACCESS_INSTRUCTIONS` 插入下面这一段，位置在 `" Answer DENY if any object-selecting value was never shown to this session"` 这句**之前**（前面有一个空格，照抄）：

```
 state.request.function is present only on a site that keeps a table of its functions; a function is the method and the path with ids replaced. function.known false means the table does not list this method and path. Most such requests are ordinary: a new page, a new API, a static file. Answer DENY for function.known false only when the path or interface name itself shows a privileged or operational function that an application page for ordinary users would not call: administration (admin, manage, staff roles, audit), operations and monitoring (metrics, actuator, server-status, health internals), debugging and developer tooling (debug, swagger, console, phpinfo), internal or configuration endpoints, backups, directory or file listings (ftp), bulk export or bulk delete of a whole collection. Otherwise function.known false changes nothing: judge the values as above. function.attempt over_privilege means an administrator confirmed this function as administrators-only and this session is not an administrator session: answer DENY.
```

`access` 问题 DENY 选项的含义（`Prompt::new` 里的第二条）改成：

```
Some object the request selects was never shown to this session as that kind of object, or the request reaches a privileged or operational function.
```

**这两段文字一个词都不要改。** 它们是 11-13 用真实模型试过三版之后留下的（设计稿第 16 节，原文在 `function-level-authz-probe/jev_probe.py` 的 `draft3`）。第一版把“未知”说重了，模型把 12 个普通新接口拒了 10 个。觉得措辞有问题就 **STOP**。

指令变了，提示词版本号对所有站点都会变：更新 `the_prompt_id_is_fixed_and_follows_the_questions` 里的固定值，`grep -rn jq_e290fa8a62172221` 把 docs/07 7.5.5 的版本表补一行。别的批次先合入改过指令的话，以合并后实际算出的值为准。

### 2.5 `trace.function`

`xshield-core/src/context/trace.rs` 新增：

```rust
pub struct TraceFunction {
    /// 请求的功能键：大写的传输方法、一个空格、第一条模板。
    pub key: String,
    /// 命中的管理档条目的键（可能与 key 不同：{id} 覆盖、方法覆盖、解码后的模板）。
    pub entry: Option<String>,
    /// 命中条目的档位，目前只有 "admin"。
    pub tier: Option<String>,
    /// 尝试越权时为 over_privilege（复用 Attempt）。
    pub attempt: Option<Attempt>,
    /// 只在未知功能时出现，值为 false。
    pub known: Option<bool>,
}
```

- `Trace` 加 `function: Option<TraceFunction>`，`#[serde(default, skip_serializing_if = "Option::is_none")]`；`TraceFunction` 里的 `Option` 字段同样省略。旧记录照常读入。
- 只在 2.3 表里写“有”的三种情况写它，并且只在请求走到 `plan` 里取值那一步之后（`no_session` 和绕过的请求没有）。
- `key` 用**脱敏后的路径**取模板：与 `state.request.path` 同一个 `redacted_path(...)` 的结果。路径里带着会话凭证时，凭证不能进 `trace.function`。`key` 超过 256 字节时按字符边界截到 256。
- `Trace::fit` 不动它（它很小）。
- `schemas/decision-record.schema.json` 的 `trace` 是 `additionalProperties: false`，要加 `function`。控制台 `web/console/src/api/types.ts` 的 trace 类型加这个可选字段，本 PR 不做显示。

### 2.6 契约、样例、控制台

- `schemas/site-config.schema.json`：`objects` 加 `ask_unknown_functions`（布尔），并用 `if`/`then` 表达“为真时 `functions` 至少一条”。`functions` 的说明去掉“本版只读入和保存，网关还不按它判定”。
- `examples/site-emr.yaml`：注释里同一句话改掉。样例里**不要**打开开关（样例的功能表不是完整基线）。
- `scripts/validate_library.py`：加一个被接受的用例（有功能表且开关为真），加两个被拒绝的用例（开关为真但没有功能表；开关不是布尔）。
- 控制台只做不丢、不拒、差异可见，照 T3 对 `functions` 的做法：
  - `web/console/src/api/types.ts` 的 `ObjectsSpec` 加 `ask_unknown_functions?: boolean`。
  - `lib/objects-validate.ts`：`parseObjects` 接受这个键（只接受布尔）；`checkObjects` 在开关为真而功能表为空时给出一条本地错误；保存对话框的变更摘要加一行（打开或关闭“功能表之外的功能交 Jev 判定”）；网关拒绝 `objects.ask_unknown_functions` / `ask_without_functions` 时给出中文说明。
  - `lib/yaml.ts` 的 `orderObjects`：只在为真时写出，位置在 `functions` 之后。
  - `features/sites/spec-model.ts` 的三方合并：按标量合并（我改了用我的，否则用最新的）。
  - 开关的界面（开关控件、打开前的影响预估）不在本 PR，属于 T5。在那之前开关通过 YAML 导入或 API 设置。

### 2.7 假 Jev 和靶场

`tests/security-lab/fake_jev.py` 的 `judge()` 加两条，没有 `request.function` 时结果与现在相同：

- `request.function.attempt == "over_privilege"`：`access` 答 DENY。
- `request.function.known is False` 且路径（转小写）里含有运维词：答 DENY。词表写成模块常量并注明它是指令那一段的缩影：`admin`、`metrics`、`actuator`、`server-status`、`debug`、`swagger`、`console`、`phpinfo`、`ftp`、`backup`、`internal`。
- `known` 为 false 但路径普通：不因此 DENY，照原规则判值。

靶场源站 `idor_origin.py` 加一个接口：`POST /api/admin/export`，**不检查角色**（注释写明这是故意的漏洞：界面上只有管理员看得到按钮，接口本身谁都能调），答 200 和 `{"exported": 患者数}`。

`scripts/test_idor_lab.py` 新增三个站点，不改已有站点：

| 站点 | 模式 | 对象表 |
|---|---|---|
| `functions.lab` | 拦截 | `ADMIN_OBJECTS` 加 `functions`：`POST /api/admin/export`（admin，high）、`DELETE /api/patients/{id}`（admin，high）、`GET /api/admin/search`（admin，medium）。开关关 |
| `baseline.lab` | 拦截 | `ADMIN_OBJECTS` 加 `functions`（都不带档位）：`POST /login`、`GET /api/home`、`GET /api/patients`、`POST /api/patients`、`GET /api/patients/{id}`、`GET /api/search`。开关开 |
| `fobserve.lab` | 观察 | `functions.lab` 的功能表加 `baseline.lab` 的那几条，开关开 |

场景（编号接着 T1 的 F1–F4；F1–F4 不在本 PR）：

| 编号 | 站点 | 做什么 | 预期 |
|---|---|---|---|
| F5 | functions | 医生登录后 `POST /api/admin/export` | 403，`jev_deny`，`blocked`，源站没收到；Jev 收到的 `state.request.function` 是 `{"tier":"admin","attempt":"over_privilege"}`；记录的 `trace.function.attempt` 是 `over_privilege` |
| F5b | functions | 医生新建一个患者，再对它 `POST /api/patients/{新编号}`，带请求头 `X-HTTP-Method-Override: DELETE` | 403，`jev_deny`；`trace.function.key` 是 `POST /api/patients/{id}`，`entry` 是 `DELETE /api/patients/{id}` |
| F6 | functions | 管理员 `admin_root` 登录、访问 `GET /api/home`（声明角色）后 `POST /api/admin/export` | 200，`fast_allow`，源站收到；没有新增 Jev 调用；`trace.function` 有 `tier`、没有 `attempt` |
| F7 | functions | 医生新建一个患者（编号在响应里见过），再 `DELETE /api/patients/{新编号}` | 403，`jev_deny`，源站没收到；`state` 里这个值 `verified: true`，同时带 `function.attempt` |
| F8 | functions | 医生 `GET /api/admin/search?q=x`（条目可靠性 medium） | 与没有条目时相同：Jev 收到的 `state` 没有 `function`，网关放行，源站自己答 403 |
| F9 | baseline | 医生 `GET /metrics` | 403，`jev_deny`，源站没收到；`state.request.function` 是 `{"known":false}` |
| F10 | baseline | 医生 `GET /api/comments`（不带查询串，没有请求值）两次 | 第一次 `jev_allow`，`state` 带 `{"known":false}`，源站收到；第二次 `cached_allow`，没有新增 Jev 调用 |
| F11 | baseline | 不带凭证 `DELETE /api/patients`（入口路径，基线里没有这个方法） | 交 Jev：`state.entry.matched` 为真且带 `{"known":false}`；假 Jev 放行，源站答 401 |
| F12 | admin（已有站点，没有功能表） | 医生 `POST /api/admin/export`、`GET /metrics` | 都是 `fast_allow`（前一个源站答 200，后一个源站答 404），没有新增 Jev 调用，记录里没有 `trace.function`。这是与 F5、F9 的对照 |
| F13 | fobserve | 医生 `POST /api/admin/export`；医生 `GET /metrics` | 两个都转发（源站收到），`would_block`，判定路径 `jev_deny` |

F6、F12 和单元测试里写“`fast_allow`”“与现在相同”的地方，以未改动的 `main` 上同一个请求的实际判定路径为准：开工时先在 `main` 上跑一遍记下来。如果 `main` 上不是 `fast_allow`，**STOP** 并告诉验收人，不要改预期去凑。

已有场景（A、B、C、W）的预期一条都不改。`tests/security-lab/README.md` 和 docs/04 4.3 的场景表同步。`lab.send` 如果还不能带自定义请求头，给它加一个 `headers` 参数（`labkit.exchange` 已经支持）。

## 3. 不变的行为（验收时逐条核对）

- 没有管理档 `high` 条目、也没开开关的站点：判定路径、`state` 字节、判定记录字节、Jev 调用次数都不变。
- 管理档条目可靠性不是 `high`：不收紧，`guards_functions()` 不因它为真。
- 管理员会话访问管理功能：按正常逻辑判。角色不是放行理由，管理员请求里没见过的值照样交 Jev。
- 值的尝试越权（位置的 `accepts_public`）逻辑不动；`plan_values` 里的 `unplaceable` 不动。
- `observe`（响应学习）不动。
- `DecisionPath`、`Outcome`、拒绝状态码的取值不变。

## 4. 测试

名字可以调整，每条要有。`engine.rs` 的测试照 `admin_site()` 那一组（约 5047 行起）写，假 Jev 用 `FakeJev`。

### 4.1 `xshield-core`

`objects.rs` 的 `mod function_tests`：

| 测试 | 断言 |
|---|---|
| `the_unknown_function_switch_round_trips_and_is_left_out_when_off` | 为真时序列化有这个键，读回相等；为假或省略时序列化结果里没有这个键 |
| `the_switch_without_functions_is_refused` | `functions` 为空而开关为真：`ObjectsPlace::AskUnknownFunctions`、`ask_without_functions`，`field()` 是 `objects.ask_unknown_functions` |
| `a_map_guards_functions_only_with_a_sure_admin_entry_or_the_switch` | 空表：假；只有不带档位的条目：假；admin + medium：假；admin + high：真；不带档位的条目加开关：真 |
| `with_entry_and_the_judgement_setters_keep_the_switch` | `with_entry`、`with_tier`、`with_accepts_public`、`with_paused` 之后开关和 `guards_functions()` 不变 |

`trace.rs`：没有 `function` 的旧 trace JSON 能读入且再序列化不多出键；带 `function` 的往返相等；`TraceFunction` 里为 `None` 的字段不写出。

### 4.2 `xshield-judge` 的 `slots.rs`

`function_templates`：`/api/patients/8` 得一条 `/api/patients/{id}`；`/api/admin%2Fexport`、`/api/admin%2fexport`、`/api/admin%5Cexport` 的第二条是 `/api/admin/export`；`/api/x/..%2Fadmin/export` 的第二条是 `/api/admin/export`；没有规范拼写的路径（如 `/api/%zz`）只有一条。

### 4.3 `xshield-judge` 的 `state.rs`

- `function` 的三种渲染（只尝试越权、只未知、两者都有）的 `request.function` 与 2.3 的表逐字相同；`None` 时 `request` 没有这个键。
- `GOLDEN_STATE` 不改并通过。
- `the_prompt_id_is_fixed_and_follows_the_questions` 更新为新值。
- `the_function_paragraph_keeps_its_tested_wording`：`ACCESS_INSTRUCTIONS` 含有 `Most such requests are ordinary: a new page, a new API, a static file.` 和 `Otherwise function.known false changes nothing: judge the values as above.`，并且这一段在 `Answer DENY if any object-selecting value was never shown` 之前。目的是以后有人改措辞时测试会提醒他这段话是对着真实模型调过的。

### 4.4 `xshield-judge` 的 `engine.rs`

第 2 层（站点：`admin_site()` 的对象表加功能表，开关关）：

| 测试 | 场景和断言 |
|---|---|
| `a_non_administrator_on_an_admin_function_is_sent_to_jev_as_an_attempt` | 医生会话（没有角色）`POST /api/admin/export`，没有值，假 Jev 答 DENY：不转发，403，`JevDeny`，`fake.calls() == 1`；`state.request.function` 是尝试越权那一种；`trace.function` 的 `key`、`entry` 都是 `POST /api/admin/export`，`tier` 是 `admin`，`attempt` 是 `OverPrivilege` |
| `an_attempt_on_an_admin_function_is_never_fast_allowed_with_verified_values` | 条目 `DELETE /api/patients/{id}`；医生在非公共响应里见过 8，再 `DELETE /api/patients/8`：交 Jev；`state` 里值 `verified: true` 且带 `function.attempt` |
| `an_attempt_on_an_admin_function_neither_reads_nor_writes_the_allow_cache` | 假 Jev 答 ALLOW：第一次 `JevAllow`；同样的请求再来一次仍然调 Jev（`fake.calls() == 2`），不是 `CachedAllow` |
| `an_administrator_uses_an_admin_function_as_before` | 管理员会话 `POST /api/admin/export`：`FastAllow`，`fake.calls() == 0`；`trace.function` 有 `tier`，`attempt` 为 `None`。再发一个带未见值的管理功能请求：交 Jev，`state` 里没有 `function` |
| `an_admin_function_of_medium_reliability_tightens_nothing` | 条目可靠性 medium：医生的请求 `FastAllow`，没有 `trace.function` |
| `a_method_override_header_is_judged_by_the_stricter_method` | 医生 `POST /api/patients/8`，`method_overrides` 为 `["delete"]`（小写）：尝试越权；`trace.function.key` 是 `POST /api/patients/{id}`，`entry` 是 `DELETE /api/patients/{id}`。三个头名在网关侧的读取由 4.5 测 |
| `a_method_field_in_the_form_or_the_query_is_judged_by_the_stricter_method` | 表单体 `_method=DELETE`，以及查询串 `?_method=DELETE`：都是尝试越权 |
| `an_override_that_is_no_method_is_ignored` | 覆盖值为 `DELETE FROM`、空串、`X`、`TOOLONGMETHOD`：不是尝试越权，结果与没有覆盖时相同 |
| `a_lower_case_transport_method_is_looked_up_in_upper_case` | `request.method` 为 `delete`：尝试越权 |
| `an_encoded_slash_is_looked_up_as_a_slash_too` | 医生 `POST /api/admin%2Fexport`、`POST /api/x/..%2Fadmin/export`：尝试越权，`entry` 是 `POST /api/admin/export` |
| `a_head_on_an_admin_get_function_is_an_attempt_and_options_is_not` | 条目 `GET /api/admin/search`（high）：医生 `HEAD` 是尝试越权；带凭证的 `OPTIONS` 不是 |
| `observe_mode_forwards_an_attempt_as_would_block` | 观察模式站点，假 Jev 答 DENY：转发，`WouldBlock` |
| `an_attempt_follows_the_site_policy_when_jev_is_down` | 假 Jev 超时：`on_jev_unavailable: deny` 的站点 403；`allow` 的站点转发、`Unjudged` |
| `a_request_without_a_session_off_an_entry_is_still_no_session` | 不带凭证访问管理功能（非入口）：`NoSession`，401，`fake.calls() == 0`，没有 `trace.function` |
| `a_bypassed_path_is_not_guarded_by_the_function_table` | 管理功能的路径同时在 `bypass` 里：`Bypass`，没有 `trace.function` |
| `the_credential_in_a_path_never_reaches_the_function_trace` | 路径的一段就是会话凭证：`trace.function.key` 里是 `<redacted>`，整个记录序列化后不含凭证 |

第 3 层（站点：功能表列出几个不带档位的功能，开关开）：

| 测试 | 场景和断言 |
|---|---|
| `an_unknown_function_is_sent_to_jev_when_the_site_asks` | 会话 `GET /metrics`，没有值，假 Jev 答 DENY：不转发，`JevDeny`；`state.request.function` 是 `{"known":false}`；`trace.function` 的 `key` 是 `GET /metrics`、`known` 是 `Some(false)`、没有 `entry` |
| `an_unknown_function_jev_allows_is_served_from_the_cache_next_time` | 假 Jev 答 ALLOW：第一次 `JevAllow`，第二次 `CachedAllow`，`fake.calls() == 1` |
| `a_known_function_is_judged_as_before` | 功能表里有的功能，以及功能表里没有、但对象表在同一路由上声明了位置的功能：`FastAllow`，没有 `trace.function` |
| `a_site_that_does_not_ask_leaves_unknown_functions_alone` | 功能表有一条管理档 high 条目、开关关：`GET /metrics` 是 `FastAllow`，没有 `trace.function` |
| `a_path_without_a_canonical_spelling_is_an_unknown_function` | 开关开，路径 `/api/patients/%zz`：交 Jev，带 `{"known":false}` |
| `an_entry_request_without_a_credential_on_an_unlearned_method_is_asked` | 不带凭证，入口路径，基线里没有的方法：交 Jev，`state.entry.matched` 为真且带 `{"known":false}` |
| `an_override_onto_an_admin_function_from_an_unknown_one_carries_both` | 开关开；功能表有 `DELETE /api/patients/{id}`（admin，high），没有 `POST /api/patients/{id}`，对象表在这条路由上也没有 `POST` 的位置。医生 `POST /api/patients/8` 带覆盖 `DELETE`：`state.request.function` 的 `tier`、`attempt`、`known` 三个字段都有；假 Jev 答 ALLOW 后同样的请求再来一次仍调 Jev |

不变性：

| 测试 | 断言 |
|---|---|
| `a_site_without_guarded_functions_builds_the_same_state_and_record` | 同一组请求分别在 `admin_site()` 和“`admin_site()` 加几条不带档位的功能、开关关”的站点上跑：`record.jev.state` 相同，记录序列化后除站点名外相同，都没有 `function` |

### 4.5 `xshield-edge`

`crates/xshield-edge/tests/scenarios.rs` 加一条：站点有管理档 high 的 `DELETE` 条目，非管理员会话发 `POST`，分别带 `X-HTTP-Method-Override: DELETE`、`X-HTTP-Method: DELETE`、`X-Method-Override: DELETE`，以及同一个头出现两次（第一个值 `GET`，第二个值 `DELETE`）：客户端都收到 403，源站没有收到请求。

### 4.6 `xshield-control`

T3 在 `tightening.rs` 里加过“自动收紧后功能表不丢”的测试（约 448 行）。在同一条里加断言或再加一条：收紧之后 `asks_unknown_functions()` 仍为真。

### 4.7 假 Jev、靶场、契约、控制台

- `tests/security-lab/test_fake_jev.py`：`function.attempt` 得 DENY；`known: false` 加 `/metrics` 得 DENY；`known: false` 加 `/api/comments` 得 ALLOW；没有 `function` 的 `/api/admin/search` 仍是原来的结果。
- 靶场 F5–F13 全部通过，已有场景全部通过且预期未改。
- `scripts/validate_library.py` 的三个用例（2.6）。
- 控制台 vitest（照 T3 为 `functions` 写的用例各补一条）：`parseObjects` 读入布尔、拒绝非布尔；`checkObjects` 在空功能表上报错；`orderObjects` 为假时不写、为真时写在 `functions` 之后；三方合并；变更摘要；网关拒绝的中文说明。

## 5. 检查（AGENTS.md 的“质量”一节）

全部要跑，PR 描述里逐条写实际结果；没跑的写“未执行”和原因。

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `python3 scripts/test_idor_lab.py`（全量，不只 `--only`）
- `fuzz/` 下 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`（改了 `xshield-core`）
- `scripts/test_postgres.sh`（改了 `xshield-control`；本机 PostgreSQL 16 的启动方式见项目记忆 `local-test-environment`）
- `web/console/` 下 `npm ci`、`npm run lint`、`npm test`、`npm run build`、`npm run test:e2e`
- 没有改依赖，`cargo deny` 可以不跑，在 PR 里写明。

生产路径不用 `unwrap`、`expect`、`panic`、可能越界的下标。不加 `#[allow]`，不跳过或删除失败的测试，不改 CI。已有测试的断言只有提示词版本号那一处允许改。

## 6. 文档和 CHANGELOG

行为与文档不一致算缺陷。文档里不写线程代号（T4、T5 这类），写“后续改动”。

- docs/00 0.3、0.6：补一句功能级的规则和它的前提（角色身份位置；第 3 层靠模型）。
- docs/01 1.4：第 4 步加功能的尝试越权和未知功能；第 5 步写明尝试越权不查不写缓存、未知功能可以缓存。
- docs/02 2.2：`state.request.function` 的三个字段和出现条件，给一个示例；指令新增的一段说了什么。2.5：未知功能会增加调用量，放行后走缓存。
- docs/03 3.2：`objects` 一行加 `ask_unknown_functions`，删掉“本版只读入、校验和保存，网关的判定还不使用它”。
- docs/04 4.3：F5–F13。
- docs/07：7.4.3 加 `trace.function`；7.4.7 或 7.9.18 新增“功能表在判定中的使用”（2.2、2.3 的规则，方法覆盖、转义斜杠、大小写、`HEAD`/`OPTIONS`、绕过路径不受管）；7.5.5 版本表加一行；7.9.18 开头“本版只读入”那句改掉，并写开关的校验。
- docs/06：有提到功能表“尚未用于判定”的地方同步（`grep -rn "还不\|尚未" docs/06-console-ui.md` 核对）。
- 文档要写清的局限：见第 9 节。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录，写明：哪些站点受影响（有管理档 high 条目的，或打开开关的）；提示词版本号对所有站点变化；`on_jev_unavailable: allow` 时尝试越权在 Jev 不可用期间会被转发；建议先在观察模式看 `trace.function`。
- PR 描述按 `templates/pull-request.md` 的五个标题写。提交标题用英文 Conventional Commits，例如 `feat(judge): judge requests by the function table`。提交信息、PR、代码注释里不写模型名。

## 7. 验收标准

1. 第 4 节的测试都存在并通过；第 5 节的检查都跑过并通过。
2. 第 3 节“不变的行为”逐条成立；`GOLDEN_STATE` 未改；靶场已有场景的预期未改。
3. `git diff main -- crates/xshield-judge/src/state.rs` 里指令的新增部分与 2.4 的两段**逐字相同**。
4. 尝试越权的请求在任何情况下都不是 `fast_allow` 或 `cached_allow`（测试覆盖：没有值、值全部核验、Jev 曾放行过）。
5. `guards_functions()` 为假的站点上，`judge()` 不调用 `function_templates`，也不为方法覆盖多做任何查找（看代码）。
6. 会话凭证不出现在 `trace.function` 和 `state` 里（测试覆盖）。
7. `grep -rn "只读入\|还不按它判定\|还不使用它" docs schemas examples web/console/src` 没有结果。
8. 控制台打开一个开关为真的站点配置再保存，开关还在；YAML 导出再导入相等。
9. `git diff --stat` 里没有 `migrations/`、`.github/`、`deny.toml`、`Cargo.lock`。
10. 第 10 节的有效性回归用例按合并时 `main` 的状态处理完：`regressions.py` 已在 `main` 上时用例已翻成 `must` 且流水线退出 0；不在时 PR 描述里有第 10.3 节要求的那一段。

## 8. 依赖和顺序

- **依赖**：只依赖 T3，已合入。现在就可以开工。
- **可以并行**：T1（第 1 层）、T2（PR 204）、T5、WAF 修复的各批次。
- **冲突热点**（后合并的一方 rebase，不是谁等谁）：
  - `CHANGELOG.md` 顶部：每个 PR 都有。
  - `state.rs` 的 `ACCESS_INSTRUCTIONS` 和提示词版本号：WAF 批次 2、6、8 也改。合并后版本号以实际计算值为准。
  - `state.rs` 的 `StateInput`、`render` 和 `engine.rs` 的 `ask_jev`：WAF 批次 2 把一份 `state` 改成多批。谁后合并谁保证 `function` 每批都带。
  - `engine.rs` 的 `judge()`、`plan()`：T1 改最前面的 `no_session` 判断，本 PR 改快速放行和缓存的条件，位置不同。
  - `proxy.rs` 的两处 `RequestFacts`：WAF 批次 8 也加字段。批次 8 把请求头的值放进请求值之后，`method_overrides` 字段保留不动。
  - `scripts/test_idor_lab.py` 的 `site_specs` 和场景表：T1 加 F1–F4。
  - docs/07 7.9.18 附近：T2 加 7.9.19。
- WAF 批次 3（multipart 解析）合入后，multipart 表单里的 `_method` 会自动被 `body._method` 覆盖到，不用另外处理。
- 本 PR 合入后：T5 的开关界面、就绪检查里的 `trace.function` 计数、请求详情里的功能显示才能做；T6（真实 Jev 回归）才能跑。

## 9. 已知局限（写进文档，不在本 PR 解决）

- 第 2 层只在声明了角色身份位置、且角色标签是 `admin` 的站点上有意义。没有任何会话被认作管理员的站点上，管理档条目会把真管理员也拦住。
- 管理员会话在身份响应到达之前（刚登录、网关重启后）调管理功能会被拦。
- 管理档条目落在入口上（比如把 `POST /login` 标成管理档）会拦住所有没有管理员身份的登录。控制台在后续改动里提示。
- `bypass` 里的路径不受功能表管。
- 未知与否只看传输方法；方法覆盖只在覆盖后的方法命中管理档条目时起作用。
- 双重编码的斜杠（`%252F`）不解码查找。
- 第 3 层的判断质量取决于模型。名字普通的管理接口（如 `GET /api/Users`）模型认不出来，那要靠第 2 层的条目。
- `on_jev_unavailable: allow` 的站点在 Jev 不可用期间会转发尝试越权和未知功能的请求，与值的尝试越权一致。

## 10. 有效性回归用例（2026-11-13 补，协调者转达的规则）

防护有效性方案（`docs/design-records/plans/protection-effectiveness-plan.md` 第 4.5 节和第 13 节第 7 条）规定：意外通过算失败，修复 PR 合并时要把对应的回归用例从 `known_gap` 翻成 `must`。本 PR 对应的用例是 `p0-3-function-level`（普通医生的真实会话访问 `GET /api/admin/export`、`GET /metrics`，预期拦）。`p0-3-fake-cookie-*` 属于 T1，不归本 PR。

### 10.1 这个用例只在带功能表的站点上能通过

本 PR 对没有功能表的站点一个字节都不改（第 3 节），所以 `clinic-none` 上这两个请求合并后照旧不被网关拦，这是设计：功能表要管理员确认才生效。用例翻成 `must` 只对 `clinic-truth` 成立，前提是 `tests/security-lab/clinic_origin.py` 的 `site_spec("truth")` 带上功能表和开关：

- `objects.functions`：源站经判定的每个接口各一条（`source: admin`），**故意不列** `GET /metrics`。`GET /api/admin/search` 和 `GET /api/admin/export` 两条带 `tier: admin`、`reliability: high`，其余不带档位。接口清单以 `clinic_origin.py` 的 `_dispatch` 为准，写成真值常量（比如 `FUNCTIONS`），不要手抄进 `site_spec`。
- `objects.ask_unknown_functions: true`。
- `site_spec("none")` 不变。

两个请求在 `clinic-truth` 上的预期（理想模型，即加了 2.7 两条规则的 `FakeJev`）：

| 请求 | 靠哪一层 | 判定记录 |
|---|---|---|
| 医生 `GET /api/admin/export` | 第 2 层。这条路由上有已声明的响应位置，所以它不算未知功能，必须靠管理档条目 | `blocked`，`jev_deny`，`trace.function.attempt` 为 `over_privilege` |
| 医生 `GET /metrics` | 第 3 层。功能表里没有它，路由上也没有已声明的位置 | `blocked`，`jev_deny`，`trace.function.known` 为 `false` |

`clinic-none` 上这个用例应当像 `idor_public_source` 在 `none` 上那样单独报成“需要功能表”，不计入 `must` 的失败。怎么报由有效性方案的验收线程（“规划防护有效性快速验证”）定，本 PR 不改评分器的口径。

### 10.2 会连带变化的良性流量

`tests/security-lab/clinic_traffic.py` 第 198 行附近，普通医生的旅程里有一步 `GET /api/admin/search?q=…`，预期源站答 403（给管理档学习提供“被拒绝”的证据）。`clinic-truth` 带上管理档条目之后，这一步在拦截模式下由网关拦（403 来自网关，源站收不到）。这是第 2 层该拦的请求，不是误拦：防护段如果重放这一步，它的预期要标成“拦”，不要算进误拦数（S2）。训练段用的站点配置不带功能表时不受影响；如果训练段也用带功能表的配置，这一步在观察模式下会记 `would_block`，管理档学习的“被拒绝”证据还算不算要实跑确认，结果写进 PR 描述。

管理员旅程先 `GET /api/home` 再调管理功能（第 238 到 242 行），身份在管理功能之前已经声明，不受影响。如果实跑里管理员被拦，**STOP** 并带上请求 ID 告诉验收人，不要调旅程顺序去凑。

### 10.3 按合并时 `main` 的状态分两种做法

- **`tests/security-lab/effectiveness/regressions.py` 已经在 `main` 上**（有效性批次 4 先合）：本 PR 负责 10.1 的 `site_spec("truth")` 改动、10.2 的预期，把 `p0-3-function-level` 在 `truth` 上的 `status` 改成 `must`，并跑 `python3 scripts/measure_effectiveness.py`，结果（退出码、这个用例两个请求的判定路径、S2）写进 PR 描述。用例或评分器要为“按配置分开”改结构时，先和有效性方案的验收线程对一下再改。
- **还不在 `main` 上**（本 PR 先合）：本 PR 不碰 `clinic_origin.py` 和 `clinic_traffic.py`（没有流水线可以验证）。PR 描述的“发布与回滚”里写明：“有效性批次 4 需按 `function-level-authz-plan-judge.md` 第 10.1、10.2 节给 `clinic-truth` 加功能表和开关，并把 `p0-3-function-level` 直接登记为 `must`”。合并后告诉验收人，由验收人转给协调者。

两种情况都不要为了让用例变绿去改 `FakeJev` 的词表或用例的请求。

