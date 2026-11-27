# WAF 批次 3（PR 227）真实模型探测的结果（2026-11-13）

在 PR 227 的头 `48a209e`（基于 main `b48c711`）上跑的。TypeSafe `jev-1.13.0` 直连端点，密钥只经环境变量传入。11 类请求各跑两遍，共 24 次模型调用，全部 HTTP 200，耗时 147 到 424 毫秒。探测用例在 `designs/function-level-authz-probe/live_values_probe.rs`（没有提交进仓库）。

会话是一个医生，源站给它展示过 PT-7001、PT-7002、PT-7003，没有展示过 PT-7004。站点没有对象表和功能表。

## 结论

1. 你们要确认的五种请求里，第 1、2、3、5 种两遍都符合预期，余量很大。
2. 第 4 种（120 个字段的中文表单）在不带编号的路径上两遍都放行。在带编号的路径上两遍都被拦，原因是 #209 的分批缺陷（后面的批次不带已核验的路径值），不是 PR 227 引入的。
3. 另外探了两种 PR 227 仍然当成一段文字读的请求体（没有 `Content-Type` 的表单、`multipart/mixed`）。模型两遍都拦住了别人的编号，但网关没有把里面的字段当引用核验，见第 3 节。

## 1. 各用例的结果

| 用例 | 请求 | 想要 | 两遍的结果 | Jev 收到的请求值 |
|---|---|---|---|---|
| V1 | `GET /api/appointments?pad0=x&…&pad199=x&patient_id=PT-7004` | 拦 | 拦，DENY 1.00、1.00 | `query.patient_id` reference `PT-7004`，没有见过。200 个 `pad` 是惰性值，不送 |
| V1c | 同上，`patient_id=PT-7001` | 放 | 快速放行，没有问模型 | |
| V2 | `multipart/form-data`，字段 `patient_id=PT-7004`、`note` | 拦 | 拦，DENY 1.00、1.00 | `body.patient_id` reference `PT-7004`，没有见过；`body.note` input |
| V2c | 同上，`patient_id=PT-7001` | 放 | 放，ALLOW 0.99、0.99 | `body.patient_id` reference `PT-7001`，已核验；`body.note` input |
| V3 | JSON 体 `text` 为 600 个字符的正常文字后接 `' OR 1=1 --` | 拦 | 拦，ATTACK 1.00、1.00（access 为 ALLOW 0.94、0.92） | `path[2]` reference `PT-7001` 已核验；`body.text` input 切成 `1/2`、`2/2` 两片，注入串在第二片末尾 |
| V3q | 查询里 200 个 `pad` 之后的 `q`，内容同上 | 拦 | 拦，ATTACK 1.00、1.00 | `path[2]` 已核验；`query.q` input 两片 |
| V4 | 120 个字段的中文表单，`POST /api/patients/PT-7001/survey` | 放 | **两遍都被拦**。第 1 批 ALLOW 0.97，第 2 批 DENY 0.67、0.65 | 第 1 批：`path[2]` reference `PT-7001` 已核验，加 73 个 `body.answer_N` input；第 2 批：47 个 `body.answer_N` input，**没有 `path[2]`** |
| V4b | 同一表单，`POST /api/surveys` | 放 | 放，两批都是 ALLOW 0.97 | 74 个和 46 个 `body.answer_N` input |
| V5 | `text/plain` 体 `{"patient_id":"PT-7004"}` | 拦 | 拦，DENY 1.00、1.00 | `body.patient_id` reference `PT-7004`，没有见过 |
| V6 | 没有 `Content-Type`，体 `patient_id=PT-7004&note=routine` | 只记录 | 拦，DENY 0.99、0.99 | `body` input，值是整段 `patient_id=PT-7004&note=routine`；`truncated` 为真 |
| V7 | `multipart/mixed`，字段同 V2 | 只记录 | 拦，DENY 0.99、0.99；ATTACK 0.38、0.32 | `body` input，值是整个 multipart 文本（边界和头部都在里面）；`truncated` 为真 |

attack 没有列出的用例，BENIGN 都不低于 0.95。

## 2. 第 4 种请求在带编号的路径上被拦

V4 和 V4b 的请求体完全相同，只有路径不同。V4 的第 2 批里 `request.path` 还是 `/api/patients/PT-7001/survey`，但 `values` 里没有 `path[2]` 这个已核验的值，模型看到一个带编号的路径而没有任何依据，答 DENY。这与 WAF 批次 2 探测里的 P10 到 P14 是同一个缺陷（结果在 `designs/waf-batch2-live-probe-result.md`），修复在“Fix later batches denied on ID routes”线程。

PR 227 没有引入它，但会让它更常见：去掉 200 个值的上限、请求体整段读之后，分批的请求变多了。建议分批缺陷的修复先合，或与 PR 227 同时合。修复合入后我会在带编号的路径上重跑 V4。

## 3. 仍然当成一段文字读的请求体

PR 227 之后，没有 `Content-Type` 的请求体（不是 JSON 时）和 `multipart/form-data` 之外的 multipart 类型，整段作为 `body` 的一个 input 值。Rack（Rails 用的）把没有类型的 POST 当表单解析，也解析 `multipart/mixed` 和 `multipart/related`，所以源站读到的是字段，网关读到的是一段文字。后果有三个：

- **引用不核验。** 字段里的对象编号不是 reference，是否越权全靠模型从文字里读出来。这次两遍都读出来了（DENY 0.99），但没有网关侧的保证。
- **自己的编号也要每次问模型。** 这类请求标了 `truncated`，不走快速放行和放行缓存。
- **`multipart/mixed` 的攻击概率偏高。** 正常内容的 V7 是 ATTACK 0.32 到 0.38，离误拦不远。边界和头部的文字被当成了内容。

建议 PR 227 把带 `boundary` 的 `multipart/*` 都按部分读（改动很小）。没有 `Content-Type` 的表单是否按表单读，由 WAF 这边的验收线程定。这类请求体里的 `_method` 字段由功能级越权的 T4c 兜底（`designs/function-level-authz-plan-method-field.md`）。

## 4. 探测没有覆盖的

- 超过 16 批、有遗漏（`left_out`）的请求。
- 文件上传部分（只读文件名）。
- 样本很小，只说明这组请求上的表现。

## 5. 新头上的复跑（PR 227 头 `f81a099`，基于 main `d9cf90a`，2026-11-13 17:24Z）

WAF 规划线程要求：带编号路径上的 V4，V6、V7 和各自的良性对照，再加这个头新增的三种读法。9 类请求各跑两遍，共 18 次模型调用，全部 HTTP 200，耗时 134 到 393 毫秒。会话和站点与前面相同。

| 用例 | 请求 | 想要 | 两遍的结果 | Jev 收到的请求值 |
|---|---|---|---|---|
| V4 | 120 个字段的中文表单，`POST /api/patients/PT-7001/survey` | 放 | **放**。两批都是 ALLOW 0.96 到 0.97 | 两批都带 `path[2]` reference `PT-7001` 已核验，另有 73 个和 47 个 `body.answer_N` input |
| V6 | 没有 `Content-Type`，体 `patient_id=PT-7004&note=routine` | 拦 | 拦，DENY 1.00、1.00 | `body.patient_id` reference `PT-7004`，没有见过；`truncated` 为假 |
| V6c | 同上，`patient_id=PT-7001` | 放 | 快速放行，没有问模型 | |
| V7 | `multipart/mixed`，字段 `patient_id=PT-7004`、`note` | 拦 | 拦，DENY 1.00、1.00；ATTACK 0.00 | `body.patient_id` reference `PT-7004`，没有见过；`body.note` input；`truncated` 为假 |
| V7c | 同上，`patient_id=PT-7001` | 放 | 放，ALLOW 0.99、0.99；ATTACK 0.00 | `body.patient_id` reference `PT-7001` 已核验；`body.note` input |
| W1 | 表单类型，体 `{"a":"&note=x&patient_id=PT-7004&b="}` | 拦 | 拦，DENY 1.00、1.00；ATTACK 0.80、0.80 | `body.patient_id` reference `PT-7004`，没有见过；`body.a` input（JSON 读法）；键名 `{"a":"` 作为 `#name` input；`body.b` input `"}` |
| W1c | 同上，`patient_id=PT-7001` | 放 | **拦**。access 是 ALLOW 0.97、0.96，拦在 attack：ATTACK 0.79、0.72 | `body.patient_id` reference `PT-7001` 已核验，其余同 W1 |
| W2 | `multipart/form-data` 的文本部分，`Content-Transfer-Encoding: base64`，解码后是 `' OR 1=1 --` | 拦 | 拦，ATTACK 0.99、0.99 | `path[2]` 已核验；`body.note` input 两个值：原文 `JyBPUiAxPTEgLS0=` 和解码后的 `' OR 1=1 --` |
| W2c | 同上，解码后是一句正常的话 | 放 | 放，ALLOW 0.99、1.00；ATTACK 0.02 | `body.note` 原文和解码后的文字各一个值 |

结论：

1. V4 在带编号的路径上通过了，#228 的修复（每一批都带路径值）在这个头上生效。
2. V6、V7 现在读成字段：别人的编号是没有见过的引用，DENY 1.00；自己的编号快速放行或 ALLOW 0.99。`multipart/mixed` 正常内容的 ATTACK 从上次的 0.32 到 0.38 降到 0.00。
3. W1 读到了表单字段，别人的编号被拦。**W1c 与预期不同**：access 认可了自己的编号（ALLOW 0.96 到 0.97），但 attack 两遍都答 ATTACK（0.72 到 0.79），请求被拦。模型把“合法 JSON 里藏着一段表单”这个包法本身看成攻击，W1 的 ATTACK 也是 0.80。我认为这不算误拦：正常客户端不会发这种形状的请求体。它不能当成良性对照用，是否接受由 WAF 规划线程定。
4. W2 的解码读法生效：模型看到了解码后的注入串，ATTACK 0.99；正常文字的对照 ATTACK 0.02。

日志、转发记录和空跑记录里没有密钥。探测用例在 `designs/function-level-authz-probe/live_values_probe2.rs`（接在 main 的 `live_jev.rs` 和 `live_values_probe.rs` 的辅助函数后面编译），没有提交进仓库。
