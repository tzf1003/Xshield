# 02 Jev 判定

## 2.1 定位

v3 已经实现了 Jev 的接入（`xshield-worker` 的 `model_eval`，经 Vercel AI Gateway 调用 `typesafe-ai/jev`），但它只是一个**离线一次性命令行工具**：操作员准备一份已批准、已脱敏的 JSON 文件，跑一次评估，产出证据，结果不连接网关的放行路径。线上请求里看不到 Jev，原因就在这里。

v4 把 Jev 放进请求路径：网关在 [01.4](01-request-flow.md#14-判定步骤) 第 6 步同步调用 Jev，结果直接决定放行还是拦截。供应商接入沿用 v3 已验证的部分：固定 HTTPS 目标、拒绝重定向、密钥只从环境变量读取（默认 `AI_GATEWAY_API_KEY`；`XSHIELD_JEV_ROUTE=direct` 时使用 `XSHIELD_JEV_API_KEY` 直连 TypeSafe）、响应结构严格校验。实现在 `crates/xshield-judge`，该 crate 不依赖 v3 的 worker。

## 2.2 调用内容

一次调用发送 `state`（上下文）和两个 Choice 问题。`state` 由网关组装：

```json
{
  "entry": { "matched": false },
  "session": { "age_seconds": 640, "entries_passed": ["/login", "/api/home", "/api/patients"] },
  "recent": [
    { "method": "GET", "path": "/api/patients", "status": 200 },
    { "method": "GET", "path": "/api/patients/7", "status": 200 }
  ],
  "request": {
    "method": "GET",
    "path": "/api/patients/8",
    "values": [
      { "at": "path[2]", "kind": "reference", "value": "8", "seen_as": ["age @ GET /api/patients/7"] }
    ],
    "truncated": false
  }
}
```

`kind` 是 `reference`（像对象引用）、`route`（路径里的词）或 `input`（其他输入）；网关已用响应核验过同类对象的值多一个 `"verified": true`；`truncated` 表示请求体被摘要或截断。`seen_as` 为空表示这个值从未出现过。上例中 `8` 只以"年龄"出现过，从未作为患者 ID 出现，Jev 据此判断这是越权引用。

请求值不截断。超过 512 个字符的值切成若干片，每片最多 512 个字符，相邻两片重叠 64 个字符，按字符切（中文和表情不会切坏）。每一片是一个值，带 `"part": "2/5"`（第 2 片、共 5 片），不带 `seen_as` 和 `verified`。片的 `kind` 取整个值的 `kind`，不按片段自己的文本算：一个路径编号整段是引用，它的每一片都是引用，不会因为第一片恰好只含字母而变成 `route`。指令要求 Jev 逐片检查攻击内容；带 `part` 的值按它的位置和 `kind` 像短值一样判，长的自由文本不选择任何对象，但处在选择对象位置上的长值（路径里的编号、编号类字段）是一个从未展示过的对象引用。同一个 `at` 和 `value` 的重复值只送一次。

```json
{ "at": "body.note", "kind": "input", "value": "……（512 个字符，接着下一片）", "part": "1/3", "seen_as": [] }
```

`state` 放不进一份时（超过 8 KiB），请求值分成几批，每批一份 `state`，每份各自调用 Jev（[2.5](#25-延迟费用与限流)）。装批的顺序与上限见 [2.4](#24-输入上限与脱敏)：没核验的非输入值先装，其余不分片的值次之，片段最后，至多 16 批。各批的 `entry`、`session`、`method`、`path`、`truncated` 和 `function`（站点有功能表时）相同，只有 `values` 不同；分批时裁剪级别为 3（最近访问为 0，每值来源 1 条）。请求自身的空壳（不含值的 state，其中包括 `function`）超过 4 KiB 时，所有批改用级别 4：`entries_passed` 置空，`path` 截到 256 字符，不列来源。

站点配置了档位（[07.4.7](07-console-architecture.md#747-档位在判定中的使用)）时，`seen_as` 的每一项在括号里附上来源响应的档位和可靠性，如 `"id @ GET /api/search [patient] (tier public, reliability high)"`；请求值的位置配置了 `accepts_public` 时，值上带 `"public_access": {"accepts": false, "reliability": "high"}`。值被判为尝试越权时带 `"attempt": "over_privilege"`：这个值只由公共档响应展示过，而请求位置不接受公共来源。指令要求 Jev 对带 `attempt` 的值答 DENY，不论它在 `seen_as` 里出现过几次，因为公共搜索只证明源站展示过它，不证明本会话有权操作它。没有标档位的站点，`state` 的内容与之前相同。

站点有功能表并接管判定（[07.9.18](07-console-architecture.md#7918-功能表)）时，`state.request` 多一个 `function` 对象，描述请求的功能。它有两个字段，都可以单独出现，也可以同时出现：

- `"tier": "admin"` 与 `"attempt": "over_privilege"`：请求命中管理档条目，而会话不是管理员，即尝试越权。指令要求 Jev 对这次请求答 DENY，不论值如何。
- `"known": false`：站点开了 `ask_unknown_functions`，而功能表和对象表都不认得这个请求的功能。指令只在路径或接口名本身显示特权或运维功能时才要求 DENY；普通页面、普通接口照值判定，不因“未知”而拒绝。

请求没有触及这两类功能时，`request` 里没有 `function` 键，`state` 与之前相同。下面是医生会话请求 `POST /api/admin/export` 的例子（管理员的导出在这个站点上是管理功能）：

```json
"request": {
  "method": "POST",
  "path": "/api/admin/export",
  "function": {"tier": "admin", "attempt": "over_privilege"},
  "values": [],
  "truncated": false
}
```

指令新增一段，位置在“有对象引用值从未展示给本会话就答 DENY”那句之前，说明 `state.request.function` 的两种情况。`function.known` 为假时，只有路径或接口名本身显示管理、运维、调试、内部接口、备份、目录列表、批量导出或删除这类特权或运维功能，才答 DENY；路径普通的，照值判定，不因此拒绝。`function.attempt` 为 `over_privilege` 时答 DENY。`access` 问题 DENY 选项的说明也增加了“或请求触及特权或运维功能”，与这段指令对应。这段文字是对着真实模型调过的，逐字保留；改动它须重新用真实模型测试，并在 [07.5.5](07-console-architecture.md#755-指令版本表) 的版本表里登记新的指令 ID。

两个问题：

| 问题 | 选项 |
|---|---|
| `access`：这次请求要访问或操作的业务对象，是否都在本会话此前的正常访问中作为同类对象出现过？入口本身需要的输入不算指定对象。 | `ALLOW` / `DENY` / `UNKNOWN` |
| `attack`：请求值里是否含有注入、命令执行、路径穿越等攻击内容？ | `BENIGN` / `ATTACK` / `UNKNOWN` |

问题的完整说明文字固定在代码里，随版本发布，不做成站点配置。TypeSafe 契约中 `questions` 是具名映射，一次调用可以带两个问题；如果实测不支持，拆成两次并行调用，对网关其他部分没有影响。

## 2.3 结论规则

每个问题取概率最高的选项：

- `access=DENY` 或 `attack=ATTACK`：拦截。
- 任一问题最高项是 `UNKNOWN`：按 `on_jev_unavailable` 处理。
- 其余：放行。

完整概率写入判定日志。首版不设单独阈值；积累观察模式数据之后，如果需要再加一个全局阈值。

## 2.4 输入上限与脱敏

- 每次调用的 `state` 序列化后不超过 8 KiB（沿用 v3 的上限）。超出时先裁剪：减少 `recent` 条数，再减少每个值的 `seen_as` 条数（级别见 [07.5.3](07-console-architecture.md#753-裁剪级别)）。仍放不下的，请求值不截断，而是分成几批，每批一次调用，最多 16 批（[2.5](#25-延迟费用与限流)）。请求值和长值的片段都不因大小被拒绝。分批时先送没核验的非输入值（它们的片段也是，必须在 16 批内送完），再送其余整值，最后送其余片段；16 批之后没送出的值和片段数记在判定记录的 `left_out` 里，判定只依据送出的部分。只有分批后仍有单个值放不进 8 KiB，或没核验的非输入值在 16 批内装不完时才返回 403，不发出调用，不论 `on_jev_unavailable`；这两种情况都不会出现在正常请求里，判定记录的失败码是 `JEV_STATE_TOO_LARGE`。
- 字段名或位置包含 `password`、`passwd`、`pwd`、`secret`、`token`、`otp`、`credential`、`authorization`、`cvv` 的请求值，以及含会话凭证原文的值，不发送原文，只发送 `"<redacted>"` 和长度。站点可以在 `advanced.secret_fields` 追加词（例如身份证号、银行卡号的字段名），不能删除内置词；判定日志用同一规则脱敏。
- 会话凭证、`Cookie`、`Authorization` 等请求头不发送。
- 会话凭证取自 `Authorization` 头时，按去掉认证方案后的令牌比对（`Bearer abc` 比对 `abc`）：客户端在查询、请求体或路径里重复令牌时不会带 `Bearer`。路径中含凭证的一段在发给 Jev 的 `path`、`recent` 和判定日志的 `path`、`logical_path` 里写成 `<redacted>`；引用早先请求的文本（`seen_as`、判定记录里的位置）在发出和写入前再整体检查一遍。路径和整段文本里的这项检查只对不少于 8 字节的凭证做，更短的凭证在路径里就是普通单词或数字；请求值和查询参数不受这个长度限制。请求体无法检查（413）而被拒绝的请求，判定记录同样脱敏。

## 2.5 延迟、费用与限流

- 单次调用超时默认 2 秒，部署时可用 `XSHIELD_JEV_TIMEOUT_MS` 改默认值，站点可用 `advanced.jev_timeout_ms` 覆盖（[07.6](07-console-architecture.md#76-站点级判定参数advanced)）；超时按 `on_jev_unavailable` 处理。
- 配置来源：控制台保存的 Jev 配置（[03.3.1](03-admin-config-audit.md#331-模型配置在控制台保存)）优先，没有时读环境变量。两者都没有时网关照常启动，判定记为 `JEV_NOT_CONFIGURED`，不发出调用。
- 快速放行和放行缓存（[01.4](01-request-flow.md#14-判定步骤) 第 4、5 步）用来减少调用次数。
- 一个请求的 `state` 分成几批时，各批并行调用，同时在途最多 8 个（`JEV_PARALLEL_MAX`）。调用限额按请求计一次，不按批计：一个请求的几批调用只用一次额度。合并规则与各批完成的先后无关：任一批判拒，请求即拒绝，出现拒绝后不再等其余调用；否则任一批调用失败或答案无效，按 `on_jev_unavailable` 处理，失败码取批次序号最小的那一批；否则任一批结论是 UNKNOWN，按 UNKNOWN 处理；全部放行才放行，放行结论写进缓存的条件与一批时相同。判定记录展示定结论的那一批（[07.5.1](07-console-architecture.md#751-jevrecord-v2)）。出现拒绝后，还没开始的调用也不再发出。

批数最多 16（`JEV_BATCHES_MAX`）。超过 16 批时只发前 16 批，没送出的值和片段数记在 `left_out`。这时结论照常按上面的合并规则定：全部放行则放行，但这样的放行不写进放行缓存，同样的请求下次会再判一次。控制台的 Jev 面板显示“攻击判定不完整：有 N 个值或片段没有送判”。

这是一条残留的边界：把内容藏在 16 批（约 128 KiB 文本）之后，可以避开攻击判定。批次 10 会按路由平时的正文大小再收一层，把这个数字压下去。

- 功能表接管判定且开关为真时，功能表和对象表都没有的接口，每次请求都先交给 Jev，直到一次放行进入缓存；之后在缓存时长内同一会话的同一请求不再调用。它们与其他请求共用每个会话每分钟 60 次的上限。上线前先在观察模式下统计 `trace.function` 里 `known` 为假的次数，再决定是否调大 `advanced.session_calls_per_minute`。
- 每个会话每分钟最多 60 次 Jev 调用；没有会话的请求按来源 IP 每分钟最多 30 次，凭证还没有会话的请求（源站尚未认过这个凭证，见 [01](01-request-flow.md) 1.2）也算在来源 IP 上。超出的请求不发出调用，直接返回 429 拒绝，不论 `on_jev_unavailable` 如何设置，防止有人用大量不同请求消耗模型额度。两个上限站点可用 `advanced.session_calls_per_minute`、`advanced.address_calls_per_minute` 调整。额度按凭证和来源 IP 计，不按站点分开：同一个凭证在各站点的请求共用它的额度；学到的上下文则按站点分开（[01](01-request-flow.md) 1.2）。
- 这些数值是起点，需要用真实站点的观察模式数据校准。控制台在每个参数旁显示最近 24 小时的耗时、超时和触发上限的次数，并在观察模式下给出调整建议。

## 2.6 数据外发

请求值和已见值的来源说明会发到模型服务。首版默认经 Vercel AI Gateway 到 TypeSafe；已确定后期换成私有部署的模型，接口保持 TypeSafe 兼容（同样的 `state` 和 `questions`），切换时只改 `XSHIELD_JEV_ENDPOINT` 和密钥，网关的判定逻辑不变。在切到私有模型之前，处理受监管数据的站点上线前要确认外发路径合规。

## 2.7 不再保留的部分

v3 围绕离线评估建立的以下机制全部删除：人工批准外发的 `approval_ref` 流程、每次调用四件证据对象写入加密证据库、模型调用 journal 与崩溃恢复补记、基于证据重验的结果缓存、校准数据集、分区血缘审查、批量只读证据能力和校准报告。v4 只在判定日志里保存每次调用的输入、指令版本、原始输出、概率、耗时和失败码（[07.5](07-console-architecture.md#75-jev-调用上下文的保存)）。
