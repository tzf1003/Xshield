# T4c 实现规划：`_method` 字段藏在值上限之后或未解析的请求体里（2026-11-13）

来源：PR 215 合并后的代码审查（P1）。规划和验收在“设计功能级越权防护”线程，代码由实现线程写。主干冻结期间可以开草稿 PR，不合并。

**15:59Z 修订：** WAF 批次 3（PR 227，分支 `claude/project-thread-k5uduz`）去掉了 200 个值的上限和 64 KiB 的解析上限，并按部分读取 `multipart/form-data`，文本字段记在 `body.<字段名>`。它合入后第 1 节的三种情况都由它修掉，`override_methods` 不用改。所以本规划改为**叠在 PR 227 上**做第 2 节的内容：钉住这些情况的测试，加上“请求体被当成一段文字读”时的兜底。附录是 PR 227 不合入时的独立做法，只在协调员通知改用时才做。

**16:22Z 修订：** PR 227 的头更新为 `b6f4d0e`：带 `boundary` 的 `multipart/*` 都按部分读，没有类型且形状像表单（没有空白和控制字符、每个 `&` 分段都有 `=`）的请求体按字段读。第 2.1 节和第 3 节按新头改写，兜底保留。

## 1. 问题

docs/07 7.9.18 规定方法覆盖按更严的方法判定。请求头的覆盖由网关单独传入，没有问题。`_method` 字段的覆盖是 `override_methods`（`crates/xshield-judge/src/engine.rs`）从 `extracted.values` 里按 `at == "query._method" || at == "body._method"` 找的，下面三种情况找不到：

1. **值上限。** `push`（`values.rs`）在 `REQUEST_VALUES_MAX`（200）之后丢弃值。路径段、查询、请求体共用这 200 个名额。`_method` 排在第 200 个值之后就不在 `values` 里。JSON 对象的成员按键排序，`A001` 到 `A200` 这类键排在 `_method` 前面。
2. **multipart。** `extract_request` 只解析 `application/x-www-form-urlencoded` 和 JSON。`multipart/form-data` 的请求体整个不解析，`_method` 字段从来不在 `values` 里。带文件上传的表单正是用 multipart 提交 `_method` 的（Rails、Laravel、Symfony）。这一条比第 1 条更容易用到。
3. **超过 `BODY_PARSE_MAX`（64 KiB）的请求体。** 现在到不了：网关对超过 48 KiB（`REQUEST_BODY_MAX`）的请求体直接答 413。上限以后放大时会变成真问题，这次一并处理。

后果：非管理员会话发 `POST /api/users/5`，把 `_method=DELETE` 藏起来，判定按普通的 `POST` 走，`trace.function` 没有尝试标记，Jev 没被要求拒绝。Jev 答 ALLOW 就转发，源站认 `_method` 的话执行的是管理档的 `DELETE /api/users/{id}`。

## 2. 规格（叠在 PR 227 上）

分支从 `origin/claude/project-thread-k5uduz` 开出，PR 227 合入后 rebase 到 `main`。PR 描述写明依赖。

### 2.1 还剩什么没有读到

PR 227（头 `b6f4d0e`）之后，下面的请求体仍然被当成一段文字（`whole_body`，或 multipart 里没有字段名的部分），里面的 `_method` 不会成为 `body._method`，而 Rack 这类解析器照样拆成字段：

- 没有 `Content-Type`、形状不像表单的请求体：带原始空格的（`note=hello world&_method=DELETE`）、有空分段的（`a=1&&_method=DELETE`）、结尾带 `&` 的（`_method=DELETE&`）。
- 类型不是表单、JSON、multipart 的请求体（如 `text/plain`），源站宽松解析时。
- 边界或头部写法让本解析器读不出部分、而源站的解析器读得出的 multipart；字段名用 `name*=` 写的部分。

这些是解析差异，逐个补不完，所以用一条从严的兜底。

### 2.2 `values.rs`

`ExtractedRequest` 加一个字段：

```rust
/// The body, or a part of it, was read as one text and its bytes hold `_method`: the request may name a
/// method that was not read (docs/07 section 7.9.18).
pub method_field_unread: bool,
```

请求体整段按文字读（`whole_body`），或 multipart 有一个部分没有字段名而按文字读时：整个请求体的原始字节里含 `_method`、`%5Fmethod` 或 `%5fmethod`，就置真。读成了带名字的字段的请求体不扫描（`_method` 已经在 `values` 里）。

### 2.3 `engine.rs`

- `override_methods` 不改。
- `function_view`：传输方法和各覆盖方法都没有命中管理档条目，而 `extracted.method_field_unread` 为真时，再用功能表里出现过的每个方法（按功能表的顺序去重，去掉已经试过的）各试一遍每个模板，第一个命中的就是 `admin_entry`。管理员会话不受影响（`attempt` 仍为假）。
- `trace.function.key` 仍是传输方法的键，`entry` 是命中的条目。未知功能的判断不变。
- 不改 state 的结构，不改指令。**提示词版本号不能变。**
- 只改 `xshield-judge`。确实要在 `xshield-core` 加查询方法时，另跑 `fuzz/` 的三项检查。

### 2.4 已知的残留边界（写进 docs/07 7.9.18）

- ~~兜底只认 `_method` 的三种写法。表单体里把字母逐个百分号编码的键名在按文字读的请求体里找不到。~~ 已由 2.5 (a) 取消：先解码再找。
- 按文字读的请求体里只要出现 `_method` 这几个字，而同一路径在别的方法下有管理档条目，非管理员的这次请求会被当成尝试越权。这是有意从严。

### 2.5 首轮验收后的补充（2026-11-13，PR 230 头 `b03ba70`，PR 227 头 `a05cc85`）

首轮验收：`b03ba70` 的实现符合 2.1 到 2.4，本地全套检查通过，变异都被抓到，红阶段复核一致。下面两条在 rebase 到 PR 227 的新头时一起做。

**(a) 找 `_method` 之前先做一遍百分号解码。** 2.4 第一条残留边界取消：`note=hello world&%5Fm%65thod=DELETE`（没有类型，Rack 按表单读）在 `b03ba70` 上放行，绕过只要多编码一个字母，而文档里还写着这个例子。`names_method_field` 改为：请求体字节宽松地做一遍百分号解码（解不了的原样保留，`+` 不用处理），在结果里找 `_method`。三种写法的列表不再需要。只解码一遍，`%255Fmethod` 不算。docs/07 7.9.18 和 CHANGELOG 里“只认三种写法”的句子相应改掉。

**(b) 按 JSON 读、而类型不是 JSON 类型的请求体。** `a05cc85` 起，以 `{` 或 `[` 开头且能解析成 JSON 的请求体不论类型都按 JSON 读并提前返回，`method_field_unread` 不再计算。`{"a":"&_method=DELETE&b="}` 配表单类型，源站读到 `_method=DELETE`，网关读不到（现象和复现见 `designs/waf-batch3-json-precedence-finding.md`）。这个差异不只影响 `_method`，已经报给 WAF 验收线程，建议 PR 227 把 JSON 读法改成“加一种读法”。T4c 这边的规则与 PR 227 最后怎么改无关：

- 标记的条件是“请求体里有一段没有被读成源站也会读成的字段”：整段按文字读；multipart 有没有字段名的部分；按 JSON 读而类型不是 JSON 类型，且没有同时按字段读。满足其一，且解码后的字节里有 `_method`，置真。
- 类型是 JSON 类型（`is_json_media`）并且解析成功的不置真：源站按 JSON 读，顶层的 `_method` 已经在 `body._method`。
- PR 227 如果改成表单类型下两种读法都读，`body._method` 会由表单读法读到；没有类型又不像表单的会同时整段按文字读，已经落在原来的条件里。那样第三个条件可能不需要单独写，以下面的测试通过为准。

新增测试（在第 3 节的基础上）：

| 位置 | 断言 |
|---|---|
| `values.rs` | `note=hello world&%5Fm%65thod=DELETE`（没有类型）置真；`%255Fmethod` 为假 |
| `engine.rs` | 表单类型的 `{"a":"&_method=DELETE&b="}`、没有类型的 `{"a=":"&_method=DELETE&b="}` 和 `{"a": "x y&_method=DELETE&b="}`：有尝试标记，`entry` 为 `DELETE /api/users/{id}`；`application/json` 的 `{"note":"about _method"}`：没有 |
| 靶场 F20 | 普通会话 `POST /api/patients/{id}`，表单类型，体 `{"a":"&_method=DELETE&b="}`：403，`trace.function.attempt` 为 `over_privilege` |
| 靶场 F21 | 没有类型，体 `note=hello world&%5Fm%65thod=DELETE`：同上 |

红阶段补一行：F20、F21 在 `b03ba70` 与 `a05cc85` 合并后的树上失败（验收时已测到，场景当时叫 Z1、Z5）。变异补一条：去掉解码后 F21 和对应单测失败；(b) 如果写成了单独的条件，去掉它时对应的单测失败。

**16:45Z 更新（WAF 规划线程确认了 (b) 的根因并改了规格）。** PR 227 不会在 `a05cc85` 合并，下一个头会这样读：表单类型一律按字段读，再加 JSON 的值；没有类型的请求体，能解析就加 JSON 读法，含 `=` 就加表单读法，既不是 JSON 也不严格像表单时再加整段文本；`text/plain` 只保留 JSON 读法；另外会读 RFC 2231 的参数名（`name*=`）、拼接折行的头。对 T4c 的影响：

- 等这个新头出来再 rebase，不要 rebase 到 `a05cc85`。
- `note=hello world&_method=DELETE`、`a=1&&_method=DELETE`、`_method=DELETE&`（没有类型）会被读成字段，由读到的 `body._method` 判定，不再走兜底。F18 和 `an_unread_method_field_…` 里这几条照样要通过，但不再是兜底的证据。
- 兜底还管的情况要各留一条能被“去掉兜底”的变异打掉的测试：没有类型、含 `;` 的 `note=x;_method=DELETE`（表单读法把它并进 `note` 的值，同时整段按文字读）；`text/plain` 等类型里的 `_method`；multipart 里没有字段名的部分。靶场把其中第一条做成一个场景（可以改 F18 的请求体，或新增一条）。
- `name*=utf-8''_method` 新头读得到名字的话，`values.rs` 里它“置真”的断言改成“读成 `body._method`，不置真”，并在 `engine.rs` 断言它按 `DELETE` 判。
- 2.5 (a) 不变。2.5 的测试表不变：三条 JSON 形状的请求体在新头上应由表单读法读到，断言的是结果（有尝试标记、`entry` 正确），不管走哪条路。

### 2.6 后续批次 T4d（2026-11-13 19:35Z 定，PR 230 合入 main 之后另开一个小 PR，不并进 PR 230）

PR 230 按 2.1 到 2.5 验收通过（头 `45d3e51`，合入 main 后 `e8c80a2`），照原样合并。下面三条是验收之后发现的，同一个实现线程接着做，基线是合入 PR 230 之后的 `main`。只改 `crates/xshield-judge/src/values.rs`、`engine.rs`、靶场、docs/04、docs/07、CHANGELOG；提示词和 `state` 不变，不需要真实模型探测。

**(a) 在文字里找 `_method` 要按整词找。** 现在 `names_method_field` 找的是子串，`payment_method=card`、`shipping_method`、`auth_method` 这些常见字段名都含 `_method`。按文字读或按 JSON 读（类型不是 JSON）的请求体里有这种字段、同一路径在别的方法下又有管理档条目时，非管理员的正常请求会被当成尝试越权。改为：解码一遍之后，`_method` 的前一个字符和后一个字符都不是 ASCII 字母、数字或 `_` 才算（文字的开头和结尾算边界）。源站读成 `_method` 字段的名字必然紧跟在分隔符后面，所以这不放过任何绕过。2.4 最后一条“只要出现这几个字就从严”相应改写。

**(b) 按字段读的地方，`;` 分出来的 `_method` 也要算。** 表单类型的 `note=x;_method=DELETE` 现在读成一个字段 `note`，不标记，兜底不触发；把 `;` 也当分隔符的源站（旧版 Python 的 `parse_qsl`、Go 1.17 之前的 `ParseQuery`、Perl CGI）会读到 `_method`。没有类型又带 `;` 的请求体已经由按文字读的规则管着，缺的是表单类型和查询串。规则：查询串，以及按字段读的请求体（表单类型，或没有类型而按字段读的），把原文按 `&` 和 `;` 切开，某一段的名字（第一个 `=` 之前，按字段名的规则解码）按 (c) 算作方法字段，而读到的值里没有带名字的 `_method` 时，`method_field_unread` 置真。不能改成“字节里有 `_method` 就置真”：表单是最常见的请求体，那样会撞上 (a) 说的误拦。

**(c) PHP 会把 `.method` 读成 `_method`。** PHP 在登记请求变量时去掉名字开头的空格，把名字里的空格和 `.` 换成 `_`，并在第一个 NUL 处截断。Laravel、Symfony 的方法伪装读的就是登记后的 `_method`，所以表单体或查询串里的 `.method=DELETE`、`%2Emethod=DELETE`、`_method%00x=DELETE` 都会被源站当成 `DELETE`，而网关现在只认名字正好是 `_method` 的字段。规则：字段名解码之后，去掉开头的空白、在第一个 NUL 处截断，结果是 `_method` 或 `.method` 的，算作方法字段。适用于三处：读覆盖方法（`query`、`body` 的字段，multipart 的字段名）、“已经读成带名字的 `_method`”的判断、(b) 的分段判断。(a) 的文字查找仍只找 `_method`：PHP 不解析那些类型的请求体。建议的做法与 PR 227 处理两端空白的做法一致：名字按上面的规则算作方法字段、而字面不是 `_method` 时，值在 `_method` 这个名字下再读一次，这样 `override_methods` 不用改；实现以测试通过为准。

**(d) 带名字的方法字段，值里有 `;` 的也要算（2026-11-13 20:05Z 补，实现线程的探针发现）。** `_method=DELETE;x=1` 读成带名字的 `_method`，值是 `DELETE;x=1`，不是一个方法，覆盖读不到；又因为“已经读成带名字的 `_method`”，(b) 也不标记。按 `;` 切分的源站读到的是 `DELETE`，和 (b) 是同一个缺口。规则：查询串和按字段读的请求体里，名字按 (c) 算作方法字段、而值里含 `;` 的，`method_field_unread` 置真（走兜底，功能表里的每个方法都试）。正常请求的方法字段值里不会有 `;`，从严没有代价，不必再去切出 `;` 之前那一段。JSON 类型的请求体和 multipart 的具名部分不适用：那里没有源站把 `;` 当分隔符。测试：`values.rs` 加表单类型 `_method=DELETE;x=1` 和查询串 `?_method=DELETE;x=1` 标记为真、`_method=PUT`（没有 `;`）仍按字段判定不标记；`engine.rs` 加一条非管理员命中管理档 `DELETE` 记尝试；靶场 F27：表单类型 `_method=DELETE;x=1`，同 F16。红阶段 F27 在合入 PR 230 的 `main` 上失败。变异加第七个：去掉这个条件，F27 和对应单测失败。docs/07 7.9.18 里把它从已知限制改成已处理。

测试（名字可以调整，断言不能少）：

| 位置 | 断言 |
|---|---|
| `values.rs` | 不标记：`text/plain` 的 `{"payment_method":"card"}`；没有类型的 `note=x;payment_method=card`；`my_method`、`_methods`、`_method_x` 各一条。仍标记：没有类型的 `note=x;_method=DELETE`、`text/plain` 的 `a=1&_method=DELETE`、没有字段名的 multipart 部分里的 `_method=DELETE` |
| `values.rs` | 表单类型的 `note=x;_method=DELETE` 和 `note=x;%5Fmethod=DELETE` 标记；查询串 `a=1;_method=DELETE` 标记；表单类型的 `note=about;payment_method=card` 不标记；表单类型的 `_method=PUT;x=1`（已读成带名字的字段）不标记 |
| `values.rs` | 表单体的 `.method=DELETE`、`%2Emethod=DELETE`、` .method=DELETE`（开头有空格）、`_method%00x=DELETE`，查询串的 `.method=DELETE`，multipart 里名字是 `.method` 的字段：都读到值为 `DELETE` 的方法字段。`..method`、`xmethod`、`.methods` 不算 |
| `engine.rs` | `users_site` 上医生的 `POST /api/users/5`：表单类型 `note=x;_method=DELETE`、表单类型 `.method=DELETE`、查询串 `.method=DELETE`，各自有尝试标记，`entry` 为 `DELETE /api/users/{id}`；`text/plain` 的 `{"payment_method":"card"}` 和表单类型的 `payment_method=card` 没有尝试标记；管理员会话在这些请求上都没有 `attempt` |
| 靶场 | F24：表单类型 `note=x;_method=DELETE`，同 F16。F25：表单类型 `.method=DELETE`，同 F16。F26（对照）：医生 `POST` 自己新建的患者，`text/plain` 的 `{"payment_method":"card"}`，判定记录里没有 `trace.function.attempt` |

红阶段：在合入 PR 230 的 `main` 上，F24、F25 失败，F26 失败（被当成尝试越权）。变异：去掉左边界、去掉右边界、表单体不按 `;` 分、查询串不按 `;` 分、不认 `.method`、不在 NUL 处截断，各至少打掉一条测试。检查项与第 5 节相同；有效性流水线前后对比照跑，预期没有用例变化。

文档：docs/07 7.9.18 的“方法覆盖”和局限两处（整词、`;`、PHP 的名字改写；写明只按 PHP 的规则认 `.method`，别的框架自己的名字改写不处理），docs/04 4.3 和靶场 README 加 F24 到 F26，CHANGELOG 一条。

## 3. 测试（名字可以调整，每条要有）

前两行是回归钉子：在 `main`（b48c711）上失败，在 PR 227 的头（`b6f4d0e`）上通过。PR 里写明这一点。其余在 PR 227 的头上先失败，改完通过。

`engine.rs`（站点带管理档 `DELETE /api/users/{id}`，普通会话，`POST /api/users/5`）：

| 测试 | 断言 |
|---|---|
| `a_method_field_behind_two_hundred_values_is_judged_by_the_stricter_method` | `_method=DELETE` 分别排在查询、表单体、JSON 体的 200 个值之后：`trace.function` 的 `attempt` 为 `over_privilege`、`entry` 为 `DELETE /api/users/{id}`，state 里 `function.admin_attempt` 为真，不进放行缓存 |
| `a_method_field_in_a_multipart_body_is_judged_by_the_stricter_method` | `multipart/form-data`、`multipart/mixed` 的文本字段 `_method`，以及没有类型的表单 `a=1&_method=DELETE`：同上；各自把 `_method` 换成 `PUT` 而管理档在 `DELETE`：没有尝试标记（读到了就按读到的判，不走兜底） |
| `an_unread_method_field_is_judged_by_any_method_of_the_table` | 没有 `Content-Type` 的 `note=hello world&_method=DELETE`、`a=1&&_method=DELETE`、`_method=DELETE&`：有尝试标记，`entry` 为 `DELETE /api/users/{id}`；同样的请求体不含 `_method`：没有；路径在任何方法下都没有管理档条目：没有 |
| `an_administrator_is_not_held_by_an_unread_method_field` | 管理员会话发同样的请求：`attempt` 不出现 |
| 现有测试 | 断言一条不改且通过 |

`values.rs`：`a_body_read_as_one_text_that_names_a_method_field_is_flagged`：上面几种请求体的 `method_field_unread`；`text/plain` 含 `%5Fmethod` 为真；`multipart/form-data` 读成带名字的字段时为假。

靶场（`scripts/test_idor_lab.py`，F14、F15 留给 T4b）：

- **F16**：普通会话对 `DELETE /api/patients/{id}`（靶场已有的管理档条目）发 `POST`，`_method=DELETE` 排在 200 个值之后。断言 403，并且判定记录的 `trace.function.attempt` 是 `over_privilege`（只看 403 不够，别的原因也会 403）。
- **F17**：同一请求改成 `multipart/form-data`，`_method` 在一个表单字段里。断言同上。
- **F18**：同一请求不带 `Content-Type`，请求体带原始空格（`note=hello world&_method=DELETE`），仍按文字读。断言同上。

有效性回归：**不加用例**（16:25Z 定）。`SITE_TRUTH` 的管理档条目只有 `GET /api/admin/search` 和 `GET /api/admin/export`，没有能用 `_method` 够到的条目；`DELETE /api/patients/{id}` 在 truth 上是医生的正常流程，不能改成管理档。`POST /api/admin/export` 加 `_method=GET` 在修复前后都被假 Jev 按路径里的 `admin` 拒绝，区分不出修复。所以这次修复的回归证据是 F16 到 F18，PR 里写明这一点，并贴出红阶段：F16、F17 在 `main`（b48c711）上失败，F18 在 PR 227 的头（`b6f4d0e`）上失败。

## 4. 文档和 CHANGELOG

- docs/07 7.9.18 “方法覆盖”一条：`_method` 在多少个值之后、在 multipart 字段里都读得到；按文字读的请求体里有 `_method` 时按功能表里任一方法的管理档判；2.4 的残留边界。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录（修复，写明此前能绕过的情况和修复后的表现）。
- 文档、提交、PR 里不写线程代号和模型名。

## 5. 检查

- 三个 Python 检查；`cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`；`python3 scripts/test_idor_lab.py` 全量；`tests/security-lab/effectiveness` 的测试。
- 生产路径不用 `unwrap`、`expect`、`panic`；不加 `#[allow]`；不改已有断言。

## 6. 验收标准

1. 第 3 节的测试都在并通过，回归钉子在 `main` 上确实失败；第 5 节的检查全部通过。
2. 提示词版本号不变；不带功能表的站点判定与记录不变（现有测试不改）。
3. 变异：去掉 `method_field_unread` 的分支，兜底的测试和 F18 必须失败；把 `push` 的 200 上限加回去，F16 和第一条钉子必须失败。
4. 有效性回归不加用例（见第 3 节），PR 里有 F16 到 F18 的红阶段结果。
5. 不需要真实模型：判定标记由网关决定，指令没有变。

## 7. 顺序

PR 227 先合，本 PR 随后。与分批缺陷的修复（`engine.rs`、`state.rs` 的分批部分）和 T4b（`function_view` 里 `unknown` 那一行、`objects.rs`）有重叠，后合并的一方 rebase。

## 附录：PR 227 不合入时的独立做法

只在协调员通知改用时才做。下面的节号是这份做法自己的。

### A. 规格

**A.1 `values.rs`**

`ExtractedRequest` 加两个字段：

```rust
/// The values of the request's `_method` field: the query pair, the form body pair and the top-level
/// member of a JSON body, in request order. They are recorded whether or not the value cap was reached.
pub method_fields: Vec<String>,
/// The request may name a method that was not read: its body was not parsed and holds `_method`, or more
/// method fields were sent than are kept.
pub method_field_unread: bool,
```

- `pairs`（查询和表单体）里键解码后等于 `_method` 的，和 `walk_request` 里 `at == "body._method"` 的文本值，记进 `method_fields`，不看 `values` 是否已满。值去掉首尾空白后为空或超过 16 个字节的不记（不可能是方法）。最多记 8 个（新常量 `METHOD_FIELDS_MAX`），第 9 个起不记并把 `method_field_unread` 置真。
- 这些值照旧也进 `values`（有名额时），Jev 看到的 state 不变。
- 请求体非空且没有被解析（`parsed == false`）时：
  - 类型是表单或 JSON 而长度超过 `BODY_PARSE_MAX`：`method_field_unread` 置真，不看内容。
  - 其余没有解析的请求体（multipart、别的类型、解析失败的 JSON）：原始字节里含 `_method`、`%5Fmethod` 或 `%5fmethod` 时置真。
- 嵌套的 `_method`（`body.a._method`、`body[]._method`）不算，和现在一样。

**A.2 `engine.rs`**

- `override_methods` 的字段来源由 `extracted.values` 的过滤改为 `extracted.method_fields`。其余规则（去空白、转大写、3 到 7 个字母、去重、去掉传输方法）不变。
- `function_view`：传输方法和各覆盖方法都没有命中管理档条目，而 `extracted.method_field_unread` 为真时，再用功能表里出现过的每个方法（按功能表的顺序去重，去掉已经试过的）各试一遍每个模板，第一个命中的就是 `admin_entry`。也就是：请求可能点了一个读不到的方法，而这条路径在某个方法下是管理档，就按管理档判。管理员会话不受影响（`attempt` 仍为假）。
- `trace.function.key` 仍是传输方法的键，`entry` 是命中的条目。未知功能的判断不变。
- 不改 state 的结构，不改指令。**提示词版本号不能变**（有测试钉住的话保持通过）。
- 尽量只改 `xshield-judge`。确实要在 `xshield-core` 加查询方法时，另跑 `fuzz/` 的三项检查。

**A.3 已知的残留边界**

- multipart 的字段名用 RFC 2231 写法（`name*=utf-8''…`）或别的编码写出 `_method` 时，原始字节里找不到，不会按管理档判。
- 没有解析的请求体里只要出现 `_method` 这几个字（例如正文文字），而同一路径在别的方法下有管理档条目，非管理员的这次请求会被当成尝试越权。这是有意从严。

### B. 测试

`values.rs`：

| 测试 | 断言 |
|---|---|
| `a_method_field_behind_the_value_cap_is_still_recorded` | 查询 200 对之后跟 `_method=DELETE`；表单体同样；JSON 体 200 个排在前面的成员加顶层 `_method`：`method_fields == ["DELETE"]`，`truncated` 为真，`values.len() == 200` |
| `an_unparsed_body_that_names_a_method_field_is_flagged` | multipart 体含 `name="_method"`：`method_field_unread` 为真；不含：为假；`text/plain` 含 `%5Fmethod`：为真；解析成功的 JSON 只有嵌套的 `_method`：为假且 `method_fields` 为空 |
| `an_oversized_form_or_json_body_is_flagged` | 表单和 JSON 各一个 `BODY_PARSE_MAX + 1` 字节的请求体：为真 |
| `more_method_fields_than_are_kept_are_flagged` | 9 个 `_method` 对：记 8 个，`method_field_unread` 为真 |

`engine.rs`（站点带管理档 `DELETE /api/users/{id}`，普通会话）：

| 测试 | 断言 |
|---|---|
| `a_method_field_behind_the_value_cap_is_judged_by_the_stricter_method` | `POST /api/users/5`，`_method=DELETE` 分别藏在查询、表单体、JSON 体的第 200 个值之后：`trace.function` 的 `attempt` 为 `over_privilege`、`entry` 为 `DELETE /api/users/{id}`，state 里 `function.admin_attempt` 为真，不进放行缓存 |
| `an_unread_method_field_is_judged_by_any_method_of_the_table` | multipart 体含 `_method`：同上；multipart 体不含 `_method`：没有尝试标记；路径在任何方法下都没有管理档条目：没有尝试标记 |
| `an_administrator_is_not_held_by_an_unread_method_field` | 管理员会话发同样的 multipart 请求：`attempt` 不出现 |
| 现有测试 | 断言一条不改且通过 |

靶场（`scripts/test_idor_lab.py`，F14、F15 留给 T4b）：

- **F16**：普通会话对 `DELETE /api/patients/{id}`（靶场已有的管理档条目）发 `POST`，`_method=DELETE` 排在 200 个值之后。断言 403，并且判定记录的 `trace.function.attempt` 是 `over_privilege`（只看 403 不够，别的原因也会 403）。
- **F17**：同一请求改成 multipart，`_method` 在一个表单字段里。断言同上。

有效性回归（`tests/security-lab/effectiveness/regressions.py`）：加 `p0-3-function-method-field-hidden`，`must`、`block`、`access`、`SITE_TRUTH`，同步 `test_lab_smoke.py` 的名单。填充值要选假 Jev 不会因为别的原因拒绝的，PR 里贴出这条用例在修复前（被转发）和修复后（被拦）的结果。

### C. 文档和 CHANGELOG

- docs/07 7.9.18 “方法覆盖”一条：`_method` 字段不受 200 个值的上限影响；没解析的请求体里有 `_method` 时按功能表里任一方法的管理档判；2.3 的两条残留边界。
- `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录（修复，写明此前能绕过的三种情况和修复后的表现）。
- 文档、提交、PR 里不写线程代号和模型名。

### D. 检查

- 三个 Python 检查；`cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc`；`python3 scripts/test_idor_lab.py` 全量；`tests/security-lab/effectiveness` 的测试。
- 生产路径不用 `unwrap`、`expect`、`panic`；不加 `#[allow]`；不改已有断言。

### E. 验收标准

1. 第 3 节的测试都在，修复前失败、修复后通过；第 5 节的检查全部通过。
2. 提示词版本号不变；不带功能表的站点判定与记录不变（现有测试不改）。
3. 变异：把 `override_methods` 改回读 `extracted.values`，或去掉 `method_field_unread` 的分支，新测试和 F16、F17 必须失败。
4. 有效性用例登记为 `must`，修复前的结果是“意外通过”即被转发。
5. 不需要真实模型：判定标记由网关决定，指令没有变。

### F. 顺序

基于当前 `main`。与两个在途改动有重叠，后合并的一方 rebase：分批缺陷的修复（`engine.rs`、`state.rs` 的分批部分）和 T4b（`function_view` 里 `unknown` 那一行、`objects.rs`）。
