# WAF 批次 9 设计说明：正文读取方式

- 日期：2026-11-13
- 基线：`main` `75169eb`。`crates/xshield-edge/src/proxy.rs` 里 `REQUEST_BODY_MAX = 48 * 1024`（:27），`buffer_body` 在 `request_filter` 里读正文（:228–255），超过 48 KiB 或分块时 413（:413–426）。
- 依据：Pingora 0.9.0 的源码，即 crates.io 上的发布包，与 `Cargo.lock` 锁定版本一致。只读了源码，没有改仓库，也没有实际跑请求。文中写“推断”的地方要在批次 9 的测试里验证。规划见 [waf-p0-fix-plan.md](waf-p0-fix-plan.md) 第 10 节，评审见 [waf-strategy-review.md](../answers/waf-strategy-review.md) P0-1 第 6–10 点。
- 文中 `pingora-core/…` 指 `pingora-core-0.9.0/src/…`，`pingora-proxy/…` 同理。
- 状态：定稿。采用方案 A（vendor 改 pingora-core），2026-11-13 12:44 UTC 由用户选定。批次 9 代码等批次 3、8 合并后另行安排。
- 修订：2026-11-13，验收线程（“修复大请求绕过与限额降级”）对照源码核对了 §1–§3 的事实，同意本文件作为批次 9 规格的依据，并给出 §1.5、§4、§5、§6 的定法。另外核对了 0.9.1：同一位置的常量仍是 64 KiB。2026-11-13 12:44 UTC，用户选定方案 A。

## 0. 结论

1. **Pingora 0.9.0 的公开接口没有办法把超过 64 KiB、已经读走的正文交给上游。** 能交的只有重放缓冲里的内容，而它写死为 64 KiB。
2. **要做到 1 MiB 送判并原样转发，必须改 pingora-core 的一个常量。** 采用 vendor 一份补丁，只改两行（方案 A，§1.5）。验收线程同意，用户已于 2026-11-13 选定。方案 B 的问题是：超过 64 KiB 的正文只能恢复 413，或者不判正文直接转发（§1.5），两者都有问题。
3. **“攒够再判”不可行。** 请求头在正文被读之前就已经发给上游。
4. **分块可以做，但要取消网关自己加的拒绝。** Pingora 已经解码分块。`Expect: 100-continue` 要由网关先回 100。
5. **“1 MiB 送判”要分开理解。** 1 MiB 是读取和缓冲的上限。送判的文本仍受 16 批限制（约 128 KiB 文本，规划 3.4(a)），超出的部分照常转发，并标记“攻击判定不完整”。

| 问题 | 结论 | 章节 |
|---|---|---|
| 1 重放缓冲的上限、能否调、读完怎样交给上游 | 64 KiB，写死、不可配置。已读正文只能经重放缓冲交给上游，缓冲截断后就没有交付路径。在 request_body_filter 里攒够再判不可行 | §1 |
| 2 分块传输 | 与定长走同一条读取路径，缓冲按解码后字节计。取消 `proxy.rs:234–238` 的分块拒绝。先回 100 Continue | §2 |
| 3 超过 1 MiB | 前缀经重放缓冲送判并交付，剩余由 Pingora 循环原样转发。multipart 判前缀里完整的文本字段和文件名 | §3 |

## 1. 问题一：重放缓冲

### 1.1 上限，能不能调

- 上限是 `BODY_BUF_LIMIT = 1024 * 64`，位于 `pingora-core/src/protocols/http/v1/common.rs:32`，为 `pub(crate)`。H2 下游有同值的私有常量，位于 `pingora-core/src/protocols/http/v2/server.rs:49`。子请求路径经 `subrequest/server.rs:51` 复用 H1 的常量。
- 没有配置项。`pingora-core/src/server/configuration/mod.rs:34` 的重试项只管上游重试次数，与正文缓冲无关。`ProxyHttp` 的钩子里也没有设置缓冲上限的入口。
- 网关的 48 KiB（`proxy.rs:27`）是在这 64 KiB 下面留的余量。

### 1.2 缓冲怎样收正文，怎样截断

- `enable_retry_buffering()` 建一个 `FixedBuffer::new(BODY_BUF_LIMIT)`（`v1/server.rs:1161–1165`）。H1 代理在 `pingora-proxy/src/proxy_h1.rs:145`（`proxy_1to1` 内）对每个代理请求都会开启。
- 每次 `read_body_bytes()` 读到的块都写进缓冲（`v1/server.rs:586–596`，写入在 :591–593）。
- 超过容量时，缓冲置为 truncated 并释放内存（`protocols/http/body_buffer.rs:40–46`）。此后 `retry_buffer_truncated()` 为真（`v1/server.rs:1155–1159`），`get_retry_buffer()` 返回 None（`v1/server.rs:1167–1175`）。
- Pingora 自己的测试是同一语义：64 KiB 不截断，64 KiB+1 截断（`pingora-proxy/src/lib.rs` 的 `default_retry_policy_requires_an_untruncated_body_buffer`）。

### 1.3 request_filter 里读完的正文怎样交给上游

时序：`pingora-proxy/src/lib.rs:1189` 调用 `request_filter`；`proxy_h1.rs:122` 写请求头；`proxy_h1.rs:527` 起进入正文循环。

1. `request_filter` 里网关的 `buffer_body` 读正文。
2. 请求头写给上游（`proxy_h1.rs:122`）。
3. `proxy_h1.rs:483–499`：取 `get_retry_buffer()`。有内容，或者正文为空时，把它作为第一块经 `send_body_to_pipe` 送进 `request_body_filter`（`proxy_h1.rs:1039–1046`），再发给上游。

所以，request_filter 里读走的正文只有这一条路能交付。第 3 步之后：

- 正文已读完时，`DownstreamStateMachine::new(true)` 得到 `ReadingFinished`（`proxy_h1.rs:481`；`proxy_common.rs:413–436`）。循环里的 `read_body_or_idle` 只做连接空闲探测，不再返回正文（`v1/server.rs:1217–1262`）。也就是说，循环之后没有补发正文的机会。
- 缓冲截断时，`get_retry_buffer()` 为 None，第 3 步什么也不发，已经读走的正文就没了。上游按 Content-Length 等剩下的字节，直到 `ORIGIN_READ_TIMEOUT`（60 秒，`proxy.rs:29`）后 504。**这是从源码推断的，未实测。** 所以 `proxy.rs:251` 的 `retry_buffer_truncated()` 检查必须保留。它和 48 KiB 低于 64 KiB 的余量一起，防止静默丢正文。
- 只把 `REQUEST_BODY_MAX` 改成 1 MiB、不动 Pingora：`buffer_body` 读到 64 KiB 就截断，检查返回 None，结果是 64 KiB 处 413。阈值只是换了个数字。

### 1.4 在 request_body_filter 里攒够再判：不可行

- `request_body_filter` 确实能改写正文（`proxy_trait.rs:148–154` 的 `&mut Option<Bytes>`），但它只能处理循环里读到的字节，或者重放缓冲里的字节。
- 请求头在 `proxy_h1.rs:122` 已经发给上游。之后在 `request_body_filter` 里攒着不发（返回空块），可以拖住正文，但上游已经收到完整的请求行、请求头和 Content-Length。源站可能在收完正文之前就开始处理，比如流式上传先建文件、先写库、先调下游服务。
- 判拒时只能断开上游连接。Pingora 对非幂等请求不重试（`proxy_trait.rs:596`），副作用撤不回来。
- **结论：送判必须在 request_filter 里完成，也就是发头之前。**

### 1.5 三个做法

**A. vendor 一份 pingora-core 0.9.0，只改两行常量（已选定，验收线程同意）**

- 做法：仓库里放一份 pingora-core 0.9.0 的源码，`[patch.crates-io]` 指向它。把 `v1/common.rs:32` 和 `v2/server.rs:49` 的常量改为 1 MiB + 64 KiB。多出来的 64 KiB 是一块正文的余量，因为正文读取器的读缓冲就是 64 KiB（`v1/body.rs:31`、`:161`，推断一次交出的块不超过它）。
- 判定和转发路径不变。Cargo.lock 里 pingora-core 的来源会变成 path。
- 代价：仓库里多一份上游源码；每次升级 Pingora 都要重新打补丁。升级到 0.9.1 解决不了：0.9.1 的同一位置常量仍是 64 KiB（`v1/common.rs:32`、`v2/server.rs:49`，已核对）。`deny.toml` 的 `[sources]` 里 `unknown-git = "deny"`、`allow-git = []`（:53–57），所以只能用 path，不能用 git 分支。许可证 Apache-2.0 在允许列表里（`[licenses]`）。PR 里要跑 `cargo deny --locked check`。
- 内存：每个在预读中的请求，重放缓冲最多 1 MiB + 64 KiB，截断后释放（`body_buffer.rs:43–44`）；网关自己的 `body` 副本再占约 1 MiB；`get_buffer()` 整块复制一次（`body_buffer.rs:62`）。验收线程估算约 3 MiB。BytesMut 按倍增扩容，峰值可能更高（推断，待测）。
- H2：只有配了 TLS 的监听才启用 H2（`crates/xshield-edge/src/server.rs:31`），两处常量都要改。`proxy_h2.rs` 的结构与 H1 相同（`:297`、`:530`），这次没有逐行核对。
- 落地要求（验收线程补充）：
  - 只放构建需要的部分：`src/`、`Cargo.toml`、`LICENSE`。不带 `benches/` 和 `examples/`。上游的 `examples/keys/` 里有 5 个 PRIVATE KEY 文件，`scripts/check_secrets.py` 的 `private-key-block` 规则会报出（它只扫 git 跟踪的文件）。不要为此往 `ALLOW` 里加条目。
  - 根 `Cargo.toml` 的 `[workspace]` 里加 `exclude = ["vendor/pingora-core"]`（目录名由实现定）。它不是工作区成员，`cargo fmt --all` 和 `cargo clippy --workspace` 不扫它。
  - 目录里放一份说明：上游版本 0.9.0；crates.io 发布包的 SHA-256，即 `Cargo.lock` 里记录的 `7fd4d1ddc6d6dbc1a97164ce13c301980c25c35422aab87b512c4c8b5123729b`；两行改动的 diff。
  - 加一条检查（测试或脚本都行）：除这两处改动外，目录里每个文件都与上游发布包解压后的同名文件逐字节一致，否则不通过。这样以后有人顺手改 vendor 里的其他代码，检查就会失败。

**B. 不改 Pingora，送判上限定为 64 KiB（未采用）**

- 64 KiB 以内的请求行为不变。
- 超过 64 KiB 的正文，只剩两种做法，两种都有问题：
  - B1：恢复 413。与用户已答的“拒绝不可接受”冲突。
  - B2：正文不判，直接转发，只判路径、查询和请求头。正文里的对象引用也不核验，绕过面比现在更大。
- 两种都与已确认的 1 MiB 不一致，因此未采用。

**C. 不改 Pingora，判定通过的请求改由网关自己的 HTTP 客户端转发（未采用）**

- 能做到 1 MiB，但要自己重写响应流、连接管理和响应观察。工作量最大，不推荐。

A 比 B 多判的是 64 KiB 以上正文的前约 128 KiB 文本（16 批）。超过 16 批的部分仍然不判。

## 2. 问题二：分块传输

### 结论

- 分块请求和定长请求走同一条读取路径。Pingora 解码分块后交出正文（`v1/server.rs:1132–1134`，`init_chunked_owned`）。`read_body_bytes` 交出的是解码后的字节（`:586–596`），缓冲上限因此按解码后字节计。
- 网关拒绝分块是它自己加的（`proxy.rs:234–238` 的 `!chunked`），不是 Pingora 的限制，应当取消。
- 同时出现 `Content-Length` 和 `Transfer-Encoding` 时，Pingora 按分块处理（`v1/server.rs:1132–1134` 的注释）。所以网关的长度检查（`proxy.rs:251` 的 `body.len() != length`）只对定长有意义；分块以 `read_request_body()` 返回 None 为正文结束。
- 块头和 trailer 有大小上限（`v1/body.rs:33`、`:38`），超过的请求以错误结束（推断）。这类错误在 `fail_to_proxy` 里映射为 400（`proxy.rs:637`）。

### 需要改的

- 去掉 `proxy.rs:238` 的 `!chunked`。
- 长度按解码后计。
- `Expect: 100-continue`：Pingora 的代理路径不调用 `write_continue_response()`，只有子请求路径（`protocols/http/subrequest/server.rs:1578`）和测试会调。所以网关在预读前若看到 `Expect: 100-continue`，要先调 `session.as_downstream_mut().write_continue_response()`（`protocols/http/server.rs:767`）。否则客户端会等，curl 之类的客户端一般约 1 秒后直接发正文。现在 48 KiB 的路径也有这个问题，大上传里更常见。
- 先回 100 再判定。判拒时回 403 并关闭连接。正文没读完时连接不能复用，Pingora 的具体处理要在验收时确认。

### 取舍

- 分块无法在读取前知道总大小。这和定长一样，超过 1 MiB 之后走 §3 的流式路径。

## 3. 问题三：超过 1 MiB 的正文

### 结论

- 前缀，即读到的全部字节，经重放缓冲送判。判定通过后，由 `get_retry_buffer()` 那一条路交给上游（`proxy_h1.rs:483–499`）。前缀的界线是：累计字节第一次达到 1 MiB 时停止读取，不在块中间截断。前缀最多 1 MiB + 一块（64 KiB 以内）。
- 剩余正文由 Pingora 的正常循环读取，经 `request_body_filter` 原样转发（`proxy_h1.rs:527–600`、`:1039–1046`）。网关不再判它，也不缓冲它。
- 这条路径依赖 §1 的结论。前缀能不能交付，取决于 A、B、C。在 B 下，超过 64 KiB 的请求根本走不到这条路径，只能只判路径和查询。
- 截断后缓冲释放内存（`body_buffer.rs:43–44`），剩余正文不占内存。
- `retry_buffer_truncated()` 为真时，Pingora 不再重试这次请求（`proxy_trait.rs:596`）。超过 1 MiB 的请求只损失上游连接失败时的重试，可以接受。

### multipart 与残留风险

- multipart：前缀里完整的文本字段和文件名送判。字段值照常提取；文件 part 只判 filename，不判内容（规划 4.2，评审 P0-1 第 4 点）。被截断的 part（边界还没出现）不判，记入“攻击判定不完整”。
- 残留风险：1 MiB 之后的文本字段不判。评审 P0-1 的“残留风险”写过，批次 9 的文档要照写。
- 16 批之外的文本也不判（§0 第 5 点）。

## 4. 对批次 9 规格的影响

1. `proxy.rs`：`REQUEST_BODY_MAX` 改为 1 MiB（常量名由实现定）。`buffer_body` 读到 1 MiB 为止，支持分块。`retry_buffer_truncated()` 检查保留，但改为内部错误（500）。正常情况下它不会触发，因为缓冲容量比读取上限多一块。
2. `Expect: 100-continue` 先回 100（§2）。
3. 预读的总时长：Pingora 的读超时是每次读 60 秒（`v1/server.rs:189`）。慢速发送可以让一个请求在 `request_filter` 里停很久。总时长上限 30 秒（验收线程定），超时按 408 处理，不判定也不转发。排队等并发名额的时间也计入这 30 秒，等不到名额的回 503。数值是代码默认值，不做成配置。
4. 删除 413 路径：`proxy.rs:413–426` 的 `refuse(session, 413, …)`，以及 `DecisionPath::BodyNotInspectable`（`crates/xshield-core/src/context/log.rs:20–21`）。已经写入的判定记录仍可能含这个值，删掉枚举值会让旧行读不出来，所以只停止产生它，不删枚举值。`Outcome::Blocked` 注释里提到的 413（`log.rs:46–47`）同步改。
5. `status.rs:235` 的 `request_body_max` 显示值随常量变化，控制台文案要跟着改。
6. `tests/scenarios.rs:573–597` 的断言“60 KB 返回 413”要改为“照判、原样转发”。PR 描述里列出改了哪几条断言。
7. 文档：docs/01 §1.4 第 2 步、docs/02 §2.4 和 §2.5（上限含义、“攻击判定不完整”）、docs/07 §7.4.1（拒绝列表里去掉 413）、`CHANGELOG.md` 的 `Unreleased`。
8. 依赖：批次 3（multipart 提取）和批次 8（请求头）合并后再开工，与规划第 1 节一致。
9. 并发预读上限（验收线程定）：声明的正文超过 64 KiB（按 Content-Length）或分块的请求，占用预读名额。同时在预读的上限是代码默认值 64，不做成配置。超出的请求排队，排队时间计入第 3 条的 30 秒。每个在读的大请求约占 3 MiB（验收线程估算），BytesMut 扩容可能更高（§1.5），64 个并发约 192 MiB 至 256 MiB。

## 5. 需要决定或确认

| 事项 | 结论或建议 | 状态 |
|---|---|---|
| 是否 vendor 修改 pingora-core（A 或 B） | A，验收线程同意 | 用户已于 2026-11-13 12:44 UTC 在决定卡上选 A。批次 9 代码等批次 3、8 合并后再安排 |
| 需要正文才能命名的路由（`proxy.rs:395–400`，`names_from_body`）超过 1 MiB 时 | 不拒绝，按“取不到接口名”处理，与正文里缺少接口名字段时相同，判定记录标明。这是残留绕过口：接口名字段放在 1 MiB 之后就能避开。文档写明。批次 10 的路由大小学习收口，但只收口有学习数据、平时很小的路由；数据不足的路由按“平时就大”处理，仍有残留。功能级越权若要求这类请求拒绝，由它的规格决定 | 已定（验收线程） |
| 预读总时长上限 | 30 秒，超时 408；排队时间计入，等不到名额回 503 | 已定（验收线程） |
| 并发预读数上限 | 代码默认值 64，超出排队，排队计入 30 秒 | 已定（验收线程） |
| 放大倍数 | 限额按请求计一次（规划 3.2 的说明，`admit()` 只调一次）。一个 1 MiB 请求最多 16 次 Jev 调用。按每会话 60 次/分钟算，每分钟最多 960 次模型调用。最坏延迟约 2 轮 × 2 秒（并行上限 8，Jev 超时 2 秒）。限额规则不改 | 已定（验收线程）：知情，按规划 3.4 的 16 批执行 |

## 6. 批次 9 的验收测试

1. 原样到达：定长和分块各取 48 KiB、64 KiB、64 KiB+1、512 KiB、1 MiB、1 MiB+1、3 MiB，靶场源站回显并比对 SHA-256。
2. 送判覆盖：在 900 KiB 处放 `' OR 1=1--`，假 Jev 判 ATTACK 时返回 403（`jev_deny`）。同一注入放在 1 MiB 之后：转发，记“攻击判定不完整”，登记为 `known_gap`（有效性方案）。
3. `Expect: 100-continue`：客户端在收到 100 之前不发正文。网关回 100 后正常读取，不超时。
4. 变异测试：删掉 `retry_buffer_truncated()` 检查，或把常量改小，必须有测试失败。
5. H2（TLS 监听）上重复第 1、3 项。
6. 限额：一个 1 MiB 请求只消耗一次会话限额，但产生最多 16 次 Jev 调用；之后的请求照常计数（规划 3.3 第 8 条）。
7. 多个 1 MiB 请求并发（N 不超过并发上限 64）：RSS 增长的阈值按实测峰值定，初值取 N × 4 MiB。
8. 上游连接在发出请求头后被源站关闭（复用的 keep-alive 连接失败）：用 PUT 发 1 MiB 以内的正文，Pingora 重试后正文完整到达。只能用 PUT：非幂等方法不重试（`proxy_trait.rs:596`），POST 不会得到这条保障。
9. 并发上限：假 Jev 让前 64 个大请求挂住超过 30 秒，第 65 个请求回 503，且不调用 Jev。测试可以注入计时，实现线程定。
