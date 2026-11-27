# 实现规划 T5b：控制台的功能视图、未知功能开关、就绪检查和请求详情

- 设计依据：[function-level-authz.md](function-level-authz.md) 第 5.1、6.1、6.2、8.2、8.3、10 节。用户在 2026-11-13 的决定：功能表的变更**全部由管理员确认**；先只分管理员。
- 前置：T4（PR 215，判定使用功能表，`trace.function`）和 T5a（功能候选、确认、驳回三个接口）**都合入 `main`**。任何一个没合入都不要开工。开工前 `git fetch origin main`，以最新 `main` 为准：接口字段以 `main` 上的 `web/console/tests/fixtures/functions.json` 和 docs/07 里 T5a 写的那一节为准，`trace.function` 以 docs/07 7.4 的字段表为准。它们与本规划的字段名有出入时照它们写，并在 PR 里说明。
- 范围：`web/console/`（页面、类型、请求函数、测试）、`xshield-control`（就绪检查加一个字段）、`xshield-postgres`（一个只读查询）、docs/06、docs/07、CHANGELOG。**不改** `xshield-core`、`xshield-judge`、`xshield-edge`、`migrations/`、`.github/`、`deny.toml`，不加依赖、表、环境变量、配置项。
- 验收人：功能级越权线程（Fable）。PR 开出后由它评审。
- 这一步**不改变任何判定**，也不加新的接口：它让管理员在控制台里看到学习结果、确认功能表、打开开关，并在就绪检查和请求详情里看到功能表起了什么作用。
- 规格里写了 **STOP** 的地方，停下来在 PR 或线程里问验收人。

## 1. 要解决的问题

功能表已经参与判定，三个接口也有了，但管理员只能手写 YAML：看不到学到了哪些功能，没法一次确认基线，没法确认或驳回管理档提议，打开“未知功能交 Jev”之前不知道会影响多少请求，请求被功能表拦下后详情页也不说原因。本 PR 把这些补到控制台里。

## 2. 规格

### 2.1 类型、请求函数和查询

`web/console/src/api/types.ts` 加（字段照 `functions.json`）：

```ts
export type FunctionsStatus = "ok" | "over_limit" | "learning_off";
export interface FunctionRow { key: string; source: ObjectSource; tier?: "admin"; reliability?: ObjectReliability;
  ordinary_units: number; admin_units: number; refused_units: number; last_seen: string | null; on_entry: boolean }
export interface FunctionCandidate { key: string; ordinary_units: number; admin_units: number; refused_units: number;
  last_seen: string | null; requests_24h: number; suggested: boolean; sensitive: boolean; on_entry: boolean }
export interface FunctionProposal { key: string; tier: "admin"; reliability: ObjectReliability;
  admin_units: number; refused_units: number | null; last_seen: string | null; in_table: boolean }
export interface UnlearnedTraffic { requests: number; unkeyed_requests: number; complete: boolean;
  top: Array<{ key: string; requests: number; sample: string }> }
export interface SiteFunctions { status: FunctionsStatus; window_days: number; threshold_units: number;
  identified: boolean; ordinary_units: number; admin_units: number;
  functions: FunctionRow[]; candidates: FunctionCandidate[]; proposals: FunctionProposal[]; unlearned: UnlearnedTraffic }
export interface FunctionChanges { add?: string[]; admin?: Array<{ key: string; reliability: ObjectReliability }>;
  open?: string[]; remove?: string[] }
```

`Readiness` 加 `functions: { attempts: number; unknown: number | null } | null`（2.6）。trace 类型上的 `function` 字段 T4 已加；没有就照 docs/07 7.4 补上：`{ key: string; entry?: string; tier?: "admin"; attempt?: "over_privilege"; known?: false }`。

`tests/helpers/fixtures.ts` 把 `functions.json` 按 `SiteFunctions` 类型导出（这一步同时让类型检查盯住契约样例）。样例的 `candidates` 现在没有“达到门槛而且名字敏感”的行：加一行（例如 `GET /api/admin/reports`，`suggested: true`、`sensitive: true`），`contract.rs` 的往返测试会照样通过。`last_seen` 是当天零点的 RFC 3339 时间（如 `2026-11-12T00:00:00.000Z`），页面上只显示日期。

`api/client.ts` 加三个函数，`api/queries.ts` 加三个钩子，照 `useConfirmJudgement`、`useDismissJudgement` 写：

| 钩子 | 请求 | 查询键或失效 |
|---|---|---|
| `useSiteFunctions(name)` | `GET /api/sites/{name}/objects/functions` | 键 `["objects", name, "functions"]`。现有代码对 `["objects", name]` 的失效按前缀匹配，保存站点、确认位置提议之后它会一起刷新，不用另加失效 |
| `useChangeFunctions()` | `POST …/objects/functions/changes` | 成功后失效 `["objects", name]`、`["site", name]`、`["versions", name]`、`["sites"]`（它写了一个配置版本，照 `useConfirmJudgement` 失效的那几项） |
| `useDismissFunctionProposal()` | `POST …/objects/functions/proposals/dismiss`，体 `{key}` | 成功后失效 `["objects", name]` |

### 2.2 功能视图放在哪

对象表标签（`ObjectsTab`）的“视图”单选从两个变成三个：按类别、按位置、**功能**。URL 是 `view=functions`（`search-schema.ts` 的 `view` 允许值加 `"functions"`）。选中时，工具栏以下的内容换成新组件 `FunctionsView`（新文件 `src/features/sites/objects/FunctionsView.tsx`），计数标签、搜索框、位置抽屉、冷启动面板、位置的判断提议卡片都不显示。

- 对象表为空（现在显示冷启动面板）时，视图单选仍然显示，功能视图仍然能进：功能表不依赖位置。
- `ObjectsTab` 始终调 `useSiteFunctions`（一个轻请求），单选上的字是“功能”，有管理档提议时是“功能 N”（N 为 `proposals.length`）。这个请求失败不影响另外两个视图：单选上只写“功能”，错误只在功能视图里显示（用现有的错误块）。
- 不新增标签页，不改站点详情的标签计数。

纯逻辑放新文件 `src/features/sites/objects/functions-model.ts`，不含 React，不发请求；文案放 `lib/vocab.ts` 的一个新常量 `FUNCTION_VIEW`（`FUNCTION_TEXT` 已存在，是保存对话框用的，不要混在一起）。

### 2.3 功能视图的内容

从上到下五块。数字用 `fmtInt`，键用 `SafeText` 和现有的 `obj-code` 样式，表格用现有表格样式，不引入新的组件库用法。

**(1) 状态行。**

- 一句概况：`最近 {window_days} 天：普通单位 {ordinary_units}，管理员单位 {admin_units}。单位是{identified ? "用户" : "会话"}。`
- `status` 为 `over_limit`：警告 `功能键超过上限，学习这一轮没有判断：候选不可用，已有的提议是之前的结果。`
- `status` 为 `learning_off`：提示 `自动学习已关闭：下面是已有的证据，不会再更新。`
- `admin_units` 为 0，且功能表里有管理档条目或列表里有提议：警告 `最近 {window_days} 天没有任何会话被认作管理员。管理档功能对每个会话都算尝试越权，拦截模式下会拦住所有人。先检查对象表里身份位置的角色声明。`
- 固定的一行小字：`绕过规则下的路径不经判定，功能表管不到它们。`

**(2) 管理档提议**（`proposals` 为空时不显示这一块）。标题 `管理档提议 {N}`，说明 `学习发现只有管理员走过的功能。确认后非管理员会话请求它算尝试越权：交 Jev 判定并要求拒绝。`

每行：键；依据 `管理员单位 {admin_units} · 被源站拒绝的普通单位 {refused_units ?? "—"} · 可靠性 {高/中}`；`in_table` 为真时注 `已在功能表里`；一个勾选框“确认为管理档”；一个“驳回”按钮。

- 勾选进入待确认的变更（2.4 的 `admin`）。默认不勾。
- 可靠性为“中”的提议，行下加一句：`可靠性为中的管理档只记在功能表里，判定不按管理档处理。`（docs/07 7.9.18 的 `admin_only`：只有 `high` 收紧。）
- “驳回”立即调 `useDismissFunctionProposal`，成功后提示 `已驳回，同一提议不再出现，除非证据得出另一个结论。`，失败显示 `errorText(code)`。驳回不是配置变更，草稿有改动时也可以用。

**(3) 功能表**（`functions`）。标题 `功能表 {N}`；为空时写 `功能表还是空的。从下面的候选里确认要加入的功能。`

列：功能（键）、档位、来源、普通单位、管理员单位、被拒绝、最近、操作。

- 档位：没有 `tier` 写 `已知`；`admin` + `high` 写 `管理档 · 可靠性 高`；`admin` + 其他可靠性写 `管理档 · 可靠性 中（不收紧）` 或 `低（不收紧）`。
- 来源：`rule` 写“规则”，`admin` 写“管理员”，其余照现有 `ObjectSource` 的词。
- 行内标记（`tag` 样式加文字，不只靠颜色）：
  - 管理档条目且 `on_entry` 为真：`在入口上`，悬停说明 `入口上没有管理员身份的请求（包括登录）都算尝试越权。`
  - 键的模板落在站点 `bypass` 的某条模式下（`functions-model.ts` 里的 `underBypass(key, bypass)`，用 `lib/patterns.ts` 的 `parsePattern`、`matchesPattern` 匹配键里空格后面的部分）：`在绕过规则下`，悬停说明 `这个路径不经判定，条目不起作用。`
- 操作：管理档条目有“取消管理档”（进入 `open`），每行有“删除”（进入 `remove`）。两个都是切换：点一次标记，再点一次撤销，行上显示 `将取消管理档` 或 `将删除`。同一行标了“删除”就不能再标“取消管理档”。

**(4) 候选**（`candidates`）。标题 `候选 {N}`，说明 `学习在流量里见到、功能表还没有的功能。走过的单位少的排在前面。确认后它们成为已知功能。`

列：勾选框、功能、普通单位、管理员单位、被拒绝、最近、24 小时请求数（`requests_24h`）。

- **默认勾选**：`suggested && !sensitive`。达到门槛但名字敏感的（`/metrics`、`/actuator`、带 `admin` 的路径等）不默认勾，行上标 `名字敏感`，悬停说明 `这类路径常常不该对所有人开放。加入功能表之后它就是已知功能，未知功能判定不再管它。`
- 未达门槛的（`suggested` 为假）标 `不到 {threshold_units} 个单位`，不默认勾。
- `on_entry` 为真的标 `入口`（中性，不是警告）。
- 表头的勾选框全选或全不选当前列表；旁边一个文字按钮 `恢复默认勾选`。
- 默认勾选只在数据第一次到达时算一次；之后列表刷新（轮询、保存后失效）不覆盖管理员已经改过的勾选，只去掉已经不在列表里的键（`prunePending`）。
- `status` 为 `over_limit` 时这一块只显示状态行里的那句警告。

**(5) 未知功能交 Jev**（开关，2.5）和它下面的“没学到的流量”。

### 2.4 待确认的变更和确认

`functions-model.ts`：

```ts
export type Pending = { add: ReadonlySet<string>; admin: ReadonlySet<string>; open: ReadonlySet<string>; remove: ReadonlySet<string> };
export function defaultPending(data: SiteFunctions): Pending;            // add = suggested && !sensitive，其余为空
export function prunePending(pending: Pending, data: SiteFunctions): Pending;  // 去掉列表里已经没有的键
export function changesOf(pending: Pending, data: SiteFunctions): FunctionChanges | null;
```

`changesOf`：四个集合都空返回 `null`；否则只带非空的列表，各列表里键的顺序照 `data` 里对应列表的顺序；`admin` 的 `reliability` 取提议行的值。待确认的变更只存在组件状态里，不进 URL，不进站点草稿。

视图底部一个固定的操作条：`待确认：加入 {a} · 管理档 {m} · 取消管理档 {o} · 删除 {r}` 和按钮 **确认变更…**。

- 没有待确认的变更时按钮置灰。
- 站点草稿有未保存的改动时（`ObjectsTab` 里已有的 `drafted`）按钮置灰，说明用 `OBJECT_JUDGEMENT.panel.dirtyDraft` 那句：这个确认会写一个配置版本，与位置提议的确认同一条规矩。
- 点开是一个确认框（antd `Modal`，照 `JudgementPanel`），逐类列出将要做的事和后果：
  - `加入 {a} 个已知功能`，其中有名字敏感的，单独列出这些键并写 `下面 {k} 个功能的名字敏感，确认它们确实对所有登录用户开放`。
  - `确认 {m} 个管理档`：逐条列键和可靠性；有可靠性为中的，带 2.3 那句；有 `on_entry` 的候选或条目与之同键时带 `在入口上` 的警告；`admin_units` 为 0 时带状态行那句警告。
  - `取消 {o} 个管理档`：`这些功能之后对所有会话开放，学习可能再次提议。`
  - `删除 {r} 个功能`：站点开着未知功能判定时加 `删除后这些功能的请求会交 Jev 判定。`
  - 站点开着未知功能判定，而这批变更会把功能表删空（`functions-model.ts` 的 `emptiesTable(pending, data)`）：确认按钮置灰，写 `未知功能判定开着时功能表不能删空。先关掉开关。`（网关会用 `ask_without_functions` 拒绝，接口答 400 `SITE_CONFIG_OBJECTS_INVALID`。）
  - 末尾：`确认后站点保存一个新版本，判定开始使用它。`
- 确认调 `useChangeFunctions`，体为 `changesOf` 的结果。成功：关框，清空待确认的变更，提示 `已确认。站点保存了一个新版本。`，列表随失效刷新。
- 失败：关框，显示 `errorText(code)`；响应带 `field`（如 `admin[0]`）时把它换成对应的键写在后面。`JUDGEMENT_NOT_FOUND`、`JUDGEMENT_CHANGED`、`FUNCTION_CHANGED`、`VERSION_CONFLICT` 之后重新取列表并 `prunePending`，其余勾选保留，让管理员再确认一次。`lib/vocab.ts` 的错误码文案加 `FUNCTION_CHANGED`（“功能表已经变了，列表已刷新，请再确认一次”）和 `FUNCTION_ON_ENTRY`（“这个功能在入口上，不能确认为管理档”）；其余几个码已有文案的沿用。

不做手工输入键的入口：要加候选之外的功能，或手工写管理档，用配置标签的 YAML（T3 已经做了校验和保存对话框里的变更说明）。

### 2.5 “未知功能交 Jev”开关

功能视图的最后一块，标题 `未知功能交 Jev`，说明 `打开后，功能表里没有的功能不再快速放行，交 Jev 判定；Jev 被告知这个功能不在站点的已知功能里。`

- 一个开关，状态取**草稿**（`working.objects?.ask_unknown_functions === true`）。切换时构造新的草稿（只改这一个键；关掉时删掉这个键），调 `onApply(spec, options)`，由现有的保存对话框保存（T4 已经让保存对话框写出这条变更）。不新增保存路径。
- 草稿的功能表为空时开关置灰，说明 `功能表为空时不能打开。先确认候选。`（网关会用 `ask_without_functions` 拒绝这样的配置。）
- 有待确认的变更（2.4）时开关置灰，说明 `先确认或放弃上面的变更。`：两种写入不要叠在一起。
- 开关上方是**影响预估**，开和关时都显示，数字只来自列表接口（`functions-model.ts` 的 `askEstimate(data)`）：
  - `candidateRequests` = 全部候选的 `requests_24h` 之和，`candidateCount` = 候选数；
  - `unlearned` = `unlearned.requests`，`unkeyed` = `unlearned.unkeyed_requests`，`complete` = `unlearned.complete`。`unkeyed_requests` 不计入 `requests`（docs/07 7.9.20），所以 `total` = `candidateRequests + unlearned + unkeyed`。`unkeyed` 里含 `OPTIONS` 预检，其中路由已知的那些打开后并不会去 Jev，所以这一项是上限，文字里写“至多”。
  - 文字（关着时）：`最近 24 小时里现在被快速放行或缓存放行的请求中，有 {total} 个的功能不在功能表里，打开后它们改为交 Jev 判定：{candidateCount} 个候选功能上 {candidateRequests} 个，没学到的路径上 {unlearned} 个{，另有至多 {unkeyed} 个算不出功能键（预检或写法不规范的路径）}。`；`complete` 为假时在数字后加 `以上`，并注 `分组超过一次读取的上限，数字是下限`。
  - 文字（开着时）：`开关已打开。按现在的功能表，最近 24 小时里还有 {total} 个放行过的请求属于未知功能。`（缓存放行过的未知功能请求仍会计入，这是预期的。）
  - `total` 为 0：`最近 24 小时没有功能表之外的放行请求。`
  - 还有 `suggested && !sensitive` 的候选没加入功能表时加警告 `还有 {n} 个建议加入的候选没有确认，打开后它们的请求都会交 Jev。`
  - 站点是观察模式时加一句 `观察模式下这些请求照常转发，只记为本应拦截。`
- **没学到的流量**：`unlearned.top` 的表，列为功能键、请求数、示例（链接到请求详情，照别处的请求链接写法）。说明 `源站没有成功应答过的路径（404、被拒绝），所以学习没有记它们。` 为空时不显示表。

### 2.6 就绪检查

**控制面。** `ReadinessBody` 加一个字段：

```rust
/// The function table at work in the window (docs/07 section 7.9.18); `None` when the site's table guards nothing.
pub functions: Option<ReadinessFunctions>,

pub struct ReadinessFunctions {
    /// Requests by a session that is no administrator for an administrator's function.
    pub attempts: i64,
    /// Requests for a function the table does not list; `None` when the site does not ask about them.
    pub unknown: Option<i64>,
}
```

- `record.spec.objects().guards_functions()` 为假时 `functions` 为 `None`（序列化成 `null`，照 `jev_p95_ms`）；`asks_unknown_functions()` 为假时 `unknown` 为 `None`。
- `xshield-postgres` 的 `decision_stats.rs` 加一个查询，照 `attempt_requests` 写，一次读出两个数：

```rust
/// 窗口内 trace.function.attempt 为 over_privilege 的请求数，和 trace.function.known 为 false 的请求数。
pub async fn function_requests(pool: &PgPool, site: &str, since_millis: i64) -> Result<(i64, i64), sqlx::Error>
```

  SQL 用 `count(*) FILTER (WHERE d.trace -> 'function' ->> 'attempt' = 'over_privilege')` 和 `count(*) FILTER (WHERE d.trace -> 'function' ->> 'known' = 'false')`，条件同 `attempt_requests`（`d.site = $1 AND d.at_millis >= $2`）。不加索引，不加迁移。
- 站点不看功能表时不发这个查询。
- `web/console/tests/fixtures/insights.json` 的 `readiness` 加 `"functions": {"attempts": 1, "unknown": 4}`，`contract.rs` 现有的往返测试继续通过。其他带 `readiness` 的样例或模拟数据补 `"functions": null`。

**控制台。** `Readiness.tsx` 的 `readinessRows` 在“尝试越权”那一行之后加（`functions` 为 `null` 时一行都不加）：

| 条件 | 标记 | 文字 |
|---|---|---|
| `attempts > 0` | ▲ | `非管理员请求管理档功能 {n} 个：交 Jev 判定并要求拒绝，拦截模式下被拦` |
| `attempts == 0` | ✓ | `没有非管理员请求管理档功能` |
| `unknown` 不为 `null` 且 `> 0` | ▲ | `未知功能的请求 {n} 个：功能表里没有，已交 Jev 判定。属于正常功能的，在对象表的功能视图里加入` |
| `unknown == 0` | ✓ | `没有未知功能的请求` |

文案放 `FUNCTION_VIEW.readiness`。这两行不带“逐条查看”链接（请求列表没有按功能过滤的条件，本 PR 不加）。

### 2.7 请求详情

`trace.function` 存在时（T4 只在请求到达管理档条目或功能未知时写它）：

**判定过程**（`detail-model.ts` 的 `pipelineSteps`）在“会话”一步之后加一步 `{ id: "function", name: "功能" }`，`done: true`：

| `trace.function` | `reason` | `warn` |
|---|---|---|
| `attempt` 为 `over_privilege` | `管理档功能 {entry}：这个会话不是管理员，算尝试越权，交 Jev 并要求拒绝`；`key` 与 `entry` 不同时在前面加 `请求是 {key}，按 ` 并把冒号前改成 `{entry} 处理`（方法覆盖、编码斜杠的情况） | 真 |
| 有 `entry`，没有 `attempt` | `管理档功能 {entry}：管理员会话` | 假 |
| `known` 为 `false` | `{key} 不在功能表里，按未知功能交 Jev` | 真 |

两种同时出现（管理档尝试加未知，T4 规划里接受的那个边角）时两句都写，用“；”连接。这一步不是 `decisive`：定结论的仍然是 Jev 那一步。`trace.v === 0` 的旧记录和没有 `trace.function` 的记录不加这一步，现有步骤的顺序和文字一字不变。

**一句话解释**（`lib/explain.ts`）：`explainRecord` 里照 `unknownLine` 的做法加一个 `functionLine`，放在 `reason` 之前：

- 尝试越权：`请求的是管理档功能 {entry}，这个会话不是管理员。`
- 未知功能：`功能 {key} 不在功能表里。`
- 两者都有：两句都写。有 `entry` 没有 `attempt`（管理员会话）时不加。

判定路径是 `jev_deny`、Jev 的 access 最高为 DENY、并且请求里没有“见过但未核验”的值（`offendingValue` 为空）时，`reason` 现在会写成“请求的值 在这个会话里从未出现过”，对功能越权是错的：这种情况下有 `functionLine` 时 `reason` 改为 `Jev 判定越权（DENY {p}%）。`。有这样的值时 `reason` 不变。其他判定路径的 `reason` 不变。

`key`、`entry` 是脱敏后的路径，照别处用 `SafeText` 显示，超过 80 个字符截断（用现有的 `clip`）。不改请求列表，不加新的筛选条件。

## 3. 测试

名字可以调整，每条要有。

### 3.1 单元测试（`web/console/tests/*.test.ts`，`npm test`）

新文件 `functions-model.test.ts`：

| 测试 | 断言 |
|---|---|
| `the default selection takes suggested candidates that are not sensitive` | 用 `functions.json`：达到门槛且不敏感的在 `add` 里；达到门槛但敏感的不在；未达门槛的不在；`admin`、`open`、`remove` 为空 |
| `pruning drops the keys the list no longer has` | 四个集合各放一个已不在列表里的键和一个还在的：只留还在的 |
| `the body carries only the lists that hold something, in the list's order` | 四个都空得 `null`；只勾两个候选得 `{add: [...]}`，顺序同 `candidates`；`admin` 带提议行的 `reliability` |
| `the estimate adds the candidates and the unlearned traffic once` | `total`、`candidateRequests`、`candidateCount`、`unlearned`、`unkeyed`、`complete` 与手算一致；全为 0 时 `total` 为 0 |
| `a batch that empties the table is caught while the site asks about unknown functions` | 把表里的条目全部标为删除且不加入任何候选：`emptiesTable` 为真；留一条或同时加入一个候选：为假 |
| `a function under a bypass pattern is flagged` | `GET /static/app.js` 对 `["/static/*"]` 为真；`GET /api/x` 为假；没有 `bypass` 为假；键里没有空格为假且不抛错 |

改已有的测试文件，只加不改断言：

| 文件 | 新测试 | 断言 |
|---|---|---|
| `explain.test.ts` | `a function attempt is named before the reason` | `jev_deny` + DENY + `trace.function` 尝试越权、没有值：整句以 `请求的是管理档功能 POST /api/admin/export，这个会话不是管理员。Jev 判定越权（DENY` 开头，不含 `从未出现过` |
| `explain.test.ts` | `an unknown function is named before the reason` | `known: false` + `jev_allow`：以 `功能 GET /metrics 不在功能表里。` 开头，后面是原来的 `jev_allow` 句子 |
| `explain.test.ts` | `a record without a function reads as before` | 现有各条断言不动且通过 |
| 测 `pipelineSteps` 的文件（没有就新建 `detail-function.test.ts`） | `the function step follows the session step` | 三种 `trace.function` 各一条：步骤 id 顺序里 `function` 紧跟 `session`；`reason`、`warn` 如 2.7；没有 `trace.function` 时没有这一步 |
| 测 `readinessRows` 的文件（没有就新建 `readiness-functions.test.ts`） | `the function rows appear only for a site that guards functions` | `functions: null` 时行数与现在相同；`{attempts: 3, unknown: null}` 多一行 ▲；`{attempts: 0, unknown: 4}` 多两行，✓ 和 ▲ |

### 3.2 端到端（新文件 `web/console/tests/sites-functions.spec.ts`，`npm run test:e2e`）

`tests/helpers/mock-api.ts` 加三条路由：`GET …/objects/functions` 默认答一个空的列表（`status: "ok"`，各数组为空，数字为 0），这样现有的对象表用例不受影响；两个 `POST` 默认 204。本文件用 `overrides` 换成 `functions.json`，写法照 `sites-judgements.spec.ts`（`mockApi`、`callsTo`、`freezeClock`）。

| 测试 | 断言 |
|---|---|
| `the functions view lists the table, the candidates and the proposals` | 进 `/sites/emr?tab=objects&view=functions`：三块标题和各自的行数；单选上是“功能 2”（样例的提议数）；按类别视图的计数标签不在页面上 |
| `the suggested candidates are picked, the sensitive ones are not` | 勾选状态如默认规则；敏感的行有 `名字敏感` |
| `confirming posts one change with what was picked` | 默认勾选不动，再勾一条提议，确认：对 `changes` 只发了一次请求，请求体与预期逐字相等；成功提示出现；待确认的计数归零 |
| `a proposal is dismissed at once` | 点“驳回”：对 `dismiss` 发了 `{key}`，提示出现 |
| `a draft with changes of its own holds the confirmation back` | 先在配置标签改一项再回到功能视图：“确认变更…”置灰并带说明；“驳回”仍可用 |
| `a refused change says why and keeps the rest picked` | `changes` 答 409 `FUNCTION_CHANGED` 带 `field: "remove[0]"`：错误文字含对应的键；列表重新取了一次；其余勾选还在 |
| `the switch states its impact and goes through the save dialog` | 影响预估的数字与样例手算一致；打开开关后出现保存对话框，变更说明里有开关那一条；功能表为空的站点上开关置灰并有说明 |
| `the over-limit state shows no candidates` | `status: "over_limit"`：警告出现，候选一块没有表 |
| `the functions view has no accessibility violations` | 用 `tests/helpers/axe.ts` 跑一次（照其他页面的用例） |
| `sites-objects.spec.ts`、`sites-judgements.spec.ts` | 现有用例不改且通过 |

`detail.spec.ts` 加一条：一个带 `trace.function`（尝试越权）的请求详情，头部的一句话和判定过程里的“功能”一步都在。详情样例照现有的 `request-detail-*.json` 新建一个，值用合成的。

e2e 不加重试。`sites-judgements.spec.ts:49` 在本机偶尔超时（与本 PR 无关）：遇到时重跑确认，不要改它，在 PR 里照实写。

### 3.3 Rust

| 测试 | 位置 | 断言 |
|---|---|---|
| `function_requests_counts_attempts_and_unknown_functions` | `decision_stats.rs` 的数据库测试（照 `attempt_requests` 的那条写，`scripts/test_postgres.sh` 会跑到） | 造五行：一行尝试越权、一行未知、一行两者都有、一行只有管理员走管理档（有 `entry` 没有 `attempt`）、一行没有 `function`：得 `(2, 2)`；窗口外的行和别的站点的行不计 |
| `readiness_reports_functions_only_for_a_guarding_site` | `insights.rs` 的测试（纯函数能测就测纯函数：把“由配置和两个数得到 `Option<ReadinessFunctions>`”写成一个小函数） | 空表：`None`；有 admin + high 条目、开关关：`Some { attempts, unknown: None }`；开关开：`unknown` 为 `Some` |
| 契约 | `contract.rs` | `insights.json` 加了 `functions` 之后往返相同 |

## 4. 检查（AGENTS.md 的“质量”一节）

- `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py`
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`
- `scripts/test_postgres.sh`（本机 PostgreSQL 16 的启动方式见项目记忆 `local-test-environment`；PR 里写明数据库测试确实跑过）
- `web/console/` 下 `npm ci`、`npm run lint`、`npm test`、`npm run build`、`npm run test:e2e`
- 没有改 `xshield-core`、判定路径和依赖，`fuzz/`、靶场、`cargo deny` 可以不跑，在 PR 里写明。

生产路径不用 `unwrap`、`expect`、`panic`。不加 `#[allow]`，不放宽 biome 规则，不跳过或删除失败的测试，不给 e2e 加重试，不改 CI。已有测试的断言不改。

## 5. 文档和 CHANGELOG

- docs/06 6.4.10（对象表）加一小节“功能视图”：五块内容、默认勾选的规则（达到门槛且名字不敏感）、确认框写什么、开关和影响预估、哪些情况置灰。配一张与本节其他图同样画法的文字示意图。
- docs/06 6.4.4（请求详情）：一句话解释的表加两行（管理档尝试、未知功能），判定过程加“功能”一步。
- docs/06 里就绪检查的行清单（6.4.9 或 6.4.11，以现有写法所在处为准）加两行。
- docs/06 6.6.5 加两个错误码的文案；6.6.7 加词：功能、已知功能、管理档、候选、名字敏感、未知功能。
- docs/07 7.9.11：`readiness.functions` 的两个数、各自何时为 `null`。
- docs/07 7.10 的查询键表加 `['objects', name, 'functions']`。
- docs/07 7.9.19、7.9.20 里“页面是后续工作”的几句改为页面已有，指向 docs/06 6.4.10；7.9.20 里 `suggested` 的“控制台默认只勾选它们”如果还在，改为“控制台默认勾选 `suggested` 为真且 `sensitive` 为假的候选”。
- 文档里不写线程代号。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录：控制台对象表多了功能视图，可以确认功能表、确认或驳回管理档提议、打开未知功能判定并看到影响预估；就绪检查和请求详情显示功能表的作用；不改判定。
- PR 描述按 `templates/pull-request.md` 的五个标题写，带功能视图和请求详情的截图各一张（合成数据）。提交标题用英文 Conventional Commits，例如 `feat(console): confirm the function table and show it at work`。提交信息、PR、代码注释里不写模型名。

## 6. 验收标准

1. 第 3 节的测试都存在并通过；第 4 节的检查都跑过并通过，数据库测试和 e2e 确实执行了。
2. `git diff main --stat` 里没有 `crates/xshield-core`、`crates/xshield-judge`、`crates/xshield-edge`、`migrations/`、`.github/`、`deny.toml`、`Cargo.lock`、`web/console/package.json`、`web/console/package-lock.json`。
3. 没有功能表的站点：就绪检查的行、请求详情、对象表的另外两个视图与改动前相同（现有 e2e 和单元测试的断言一条不改）。
4. 功能表的每一次写入都经过管理员的一次明确确认：`changes` 只在确认框里点了确认之后发出，一次确认只发一个请求；开关只经保存对话框写入。页面加载、默认勾选、轮询都不发任何写请求。
5. 达到门槛但名字敏感的候选不默认勾选。
6. 草稿有未保存的改动时不能确认变更；有待确认的变更时不能切换开关。
7. 影响预估的数字只来自列表接口，文字写明是最近 24 小时、是放行过的请求。
8. 页面上没有单位的原文，只有计数；键和路径经 `SafeText` 显示。
9. 新增的状态和警告都有文字或形状，不只靠颜色（docs/06 6.8.2）；功能视图通过 axe 检查。
10. 有效性回归：本 PR 不改判定，没有对应用例，不动 `tests/security-lab/effectiveness/`。

## 7. 依赖和顺序

- **依赖**：T4 和 T5a 合入 `main`。
- **冲突热点**：`CHANGELOG.md` 顶部；`web/console/src/lib/vocab.ts`、`api/types.ts`、`api/queries.ts`；`ObjectsTab.tsx`；`insights.rs` 的 `ReadinessBody`；docs/06 6.4.10、docs/07 7.9.11。后合并的一方 rebase。
- **之后**：T6（真实 Jev 回归）与本 PR 互不依赖。

## 8. 本 PR 不做的

- 手工输入功能键、在页面上改管理档的可靠性：用 YAML。
- 请求列表按功能过滤、就绪检查两行的“逐条查看”链接。
- 站点详情标签上的提议计数、总览页的提醒。
- 按请求回放的影响预估（`POST /preview` 不变）：开关的影响用列表接口的两个数说明。
- 接入向导里的功能表步骤。
- 管理员会话是否豁免未知功能判定：这是判定的问题，留给真实 Jev 回归之后再定。
