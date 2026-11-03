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

- `state` 序列化后不超过 8 KiB（沿用 v3 的上限）。超出时依次截断：先减少 `recent` 条数，再减少每个值的 `seen_as` 条数，最后截断过长的请求值并标注已截断。用到的裁剪级别写进判定日志（[07.5.3](07-console-architecture.md#753-裁剪级别)）。
- 字段名或位置包含 `password`、`passwd`、`pwd`、`secret`、`token`、`otp`、`credential`、`authorization`、`cvv` 的请求值，以及含会话凭证原文的值，不发送原文，只发送 `"<redacted>"` 和长度。站点可以在 `advanced.secret_fields` 追加词（例如身份证号、银行卡号的字段名），不能删除内置词；判定日志用同一规则脱敏。
- 会话凭证、`Cookie`、`Authorization` 等请求头不发送。

## 2.5 延迟、费用与限流

- 单次调用超时默认 2 秒，部署时可用 `XSHIELD_JEV_TIMEOUT_MS` 改默认值，站点可用 `advanced.jev_timeout_ms` 覆盖（[07.6](07-console-architecture.md#76-站点级判定参数advanced)）；超时按 `on_jev_unavailable` 处理。
- 配置来源：控制台保存的 Jev 配置（[03.3.1](03-admin-config-audit.md#331-模型配置在控制台保存)）优先，没有时读环境变量。两者都没有时网关照常启动，判定记为 `JEV_NOT_CONFIGURED`，不发出调用。
- 快速放行和放行缓存（[01.4](01-request-flow.md#14-判定步骤) 第 4、5 步）用来减少调用次数。
- 每个会话每分钟最多 60 次 Jev 调用；没有会话的请求按来源 IP 每分钟最多 30 次。超出的请求按 `on_jev_unavailable` 处理，防止有人用大量不同请求消耗模型额度。两个上限站点可用 `advanced.session_calls_per_minute`、`advanced.address_calls_per_minute` 调整。
- 这些数值是起点，需要用真实站点的观察模式数据校准。控制台在每个参数旁显示最近 24 小时的耗时、超时和触发上限的次数，并在观察模式下给出调整建议。

## 2.6 数据外发

请求值和已见值的来源说明会发到模型服务。首版默认经 Vercel AI Gateway 到 TypeSafe；已确定后期换成私有部署的模型，接口保持 TypeSafe 兼容（同样的 `state` 和 `questions`），切换时只改 `XSHIELD_JEV_ENDPOINT` 和密钥，网关的判定逻辑不变。在切到私有模型之前，处理受监管数据的站点上线前要确认外发路径合规。

## 2.7 不再保留的部分

v3 围绕离线评估建立的以下机制全部删除：人工批准外发的 `approval_ref` 流程、每次调用四件证据对象写入加密证据库、模型调用 journal 与崩溃恢复补记、基于证据重验的结果缓存、校准数据集、分区血缘审查、批量只读证据能力和校准报告。v4 只在判定日志里保存每次调用的输入、指令版本、原始输出、概率、耗时和失败码（[07.5](07-console-architecture.md#75-jev-调用上下文的保存)）。
