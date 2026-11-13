# 安全靶场（v4 验收场景）

本目录是 [docs/04 §4.3](../../docs/04-deployment-testing.md#43-验收场景) 验收场景的靶场，由 `scripts/test_idor_lab.py` 驱动：

- `idor_origin.py`：一个 EMR 源站，没有对象级鉴权。任何登录的医生都能读取、删除、分享任何患者，所以拦截必须由 edge 完成。另有 `POST /api/admin/export`，不检查角色：这是故意的漏洞，界面上只有管理员看得到按钮，接口本身谁都能调。
- `fake_jev.py`：脚本化的 Jev 假服务，应答固定，不调用模型。
- `labkit.py`：`test_idor_lab.py` 与 clinic 流量共用的管道，负责启动 edge、发送请求，并把判定记录同时写入文件。
- 真实的 `xshield-edge` 二进制，站点由 `XSHIELD_EDGE_SITES_FILE` 提供。
- `effectiveness/`：防护有效性度量（`scripts/measure_effectiveness.py`），见下文“防护有效性度量”。

驱动逐条发送请求，核对三件事：客户端收到的状态码、源站是否收到了这个请求、edge 为该请求写下的判定记录（`decision_path`、`outcome`、`jev.failure`）。拦截类场景还会直接问源站一次，证明被拦的对象确实能从源站拿到。

## 运行

```sh
python3 scripts/test_idor_lab.py            # 全部场景
python3 scripts/test_idor_lab.py --only A2,C4
```

只需要 python3（标准库）和 Rust 工具链。脚本会先执行 `cargo build --locked -p xshield-edge`，构建目录遵循 `CARGO_TARGET_DIR`。不需要 Docker 和 PostgreSQL，也不调用任何模型。CI 的 `validate` 作业在 `cargo test` 之后运行它。

## 场景

| 编号 | 场景 | 预期 | 判定路径 |
|---|---|---|---|
| A1 | 医生 A 浏览"我的患者"后打开患者 B | 放行 | `fast_allow` |
| A2 | 医生 A 把地址改成患者 D | 拦截，源站未收到请求 | `jev_deny` |
| A3 | 医生 A 新开会话，直接打开患者 B | 拦截 | `jev_deny` |
| A4 | 医生 A 删除患者 D | 拦截，患者 D 仍在源站 | `jev_deny` |
| A5 | "我的患者"接口上加 `doctor=DR-B` | 拦截 | `jev_deny` |
| A6 | 接收者兑换患者 A 的分享码后打开患者 A | 兑换放行，打开放行 | `jev_allow`，`fast_allow` |
| A7 | 接收者未兑换分享码，直接打开患者 A | 拦截 | `jev_deny` |
| A8 | 医生 A 新建患者后打开新患者详情 | 新建放行，打开放行 | `jev_allow`，`fast_allow` |
| A9 | 医生 A 在搜索结果里看到医生 B 的患者，然后删除它；同样删除没被搜到的患者 | 两次删除都拦截，源站两个患者都还在。搜到的那次记为尝试越权，交 Jev 判 DENY，见下方说明 | `jev_deny`，`jev_deny` |
| A10 | 医生 A 搜到医生 B 的患者后，在它的备注接口上写入 | 放行。备注位置接受公共来源，搜到的患者在这里有效 | `fast_allow` |
| A11 | 没有标注档位的站点，同样的搜索后删除 | 与标注前相同：放行，源站删除。这是没有标注的站点的已知缺口 | `jev_allow` |
| A12 | 医生 A 在搜索结果里看到医生 B 的患者 D（慢速 id `PT-7004`），然后按这个 id 删除 | 拦截，记为尝试越权：慢速 id 按声明的 `DELETE /api/patients/{id}` 位置判定，源站不收到请求。见下方说明 | `jev_deny` |
| B1 | 搜索框、表单里的中英文文本 | 放行；重复的搜索走放行缓存 | `jev_allow`，`cached_allow` |
| B2 | 参数里的 SQL 注入、命令执行、路径穿越 | 拦截 | `jev_deny` |
| C1 | Jev 返回 503 或超时，`on_jev_unavailable=deny` | 拦截，注明 `JEV_HTTP_ERROR` / `JEV_TIMEOUT` | `jev_unavailable` |
| C2 | 同上，`on_jev_unavailable=allow` | 放行，记为未经判定 | `jev_unavailable`（`unjudged`） |
| C3 | 观察模式下的 A2 | 转发，记为本应拦截 | `jev_deny`（`would_block`） |
| C4 | 登录请求 | Jev 收到的是 `<redacted>`，判定日志里也没有口令 | `jev_allow` |
| C5 | 同一会话超过每分钟调用上限（站点设为 2） | 第三次拒绝并回 429（`{"error":"rate_limited"}`），`JEV_CALL_LIMIT`；不论 `on_jev_unavailable` | `jev_unavailable` |
| C9 | 同一来源地址的 11 个会话（站点设为每会话 2 次，合计上限 20 次） | 前 10 个会话各调用 2 次放行；第 11 个会话一次都没用过，也拒绝并回 429（`rate_limited`），Jev 没有被调用；另一个地址的会话不受影响 | `jev_unavailable` |
| G1 | JSON 凭证站点（凭证为 `Authorization` 头）：登录响应里 700 多字符的令牌绑定会话；登录响应和列表都没给过的患者 D | 登录放行；列表的判定记录带该次登录的 `login_request_id`，没有 `login_unbound`；患者 D 拦截，源站未收到请求 | `jev_allow`，`fast_allow`，`jev_deny` |
| G2 | 同一站点：源站没发过的 700 多字符令牌访问入口 | 放行到源站（源站答 401），记录的 `login_unbound` 为 `login_unmatched` | `fast_allow` |
| W1 | 声明了 `GET /api/home doctor.id` 为用户身份的站点：医生 A、B 各自登录后，判定记录的 `trace.session.identity.user` 是各自的键控哈希标签，换账号不同，同一账号相同；没有声明身份的站点不写 `identity` | 放行，身份标签按上述规则 | `fast_allow` |
| W4a | 管理员站点：管理员在管理档搜索（`GET /api/admin/search`）里搜到医生 B 的患者后删除 | 放行，删除的值核验为管理档来源，不是尝试 | `fast_allow` |
| W4b | 管理员没在管理档搜索里见过的患者，直接删除 | 拦截，源站不收到请求；角色不是放行理由 | `jev_deny` |
| W4c | 管理员在公共搜索里搜到医生 B 的患者后删除 | 拦截，记为尝试越权：公共档的见过不证明删除 | `jev_deny` |
| W4d | 管理员在管理档搜索里搜到患者后写备注（POST 子路径） | 放行，备注位置接受公共来源 | `fast_allow` |
| W6 | 同一站点的评论接口：医生 A 读取自己患者的评论时，作者医生 B 的手机号和邮箱让判定记录的 `trace.response.exposure` 记一条告警（字段名 `phone`、`email`，记录里没有值）；读取本人资料、未声明身份的站点不告警 | 放行，告警按上述规则 | `fast_allow` |
| F5 | 医生 A 登录后 `POST /api/admin/export`（功能表里的管理档功能） | 拦截，源站不收到请求。Jev 收到的 `state.request.function` 是 `{"tier":"admin","attempt":"over_privilege"}`，判定记录的 `trace.function.attempt` 为 `over_privilege`。见下方说明 | `jev_deny` |
| F5b | 医生 A 新建患者后，对它 `POST /api/patients/{新编号}`，带请求头 `X-HTTP-Method-Override: DELETE` | 拦截，源站不收到请求。按更严的 `DELETE /api/patients/{id}` 判为越权尝试；`trace.function.key` 是 `POST /api/patients/{id}`，`entry` 是 `DELETE /api/patients/{id}` | `jev_deny` |
| F6 | 管理员 `admin_root` 登录、访问首页（声明角色）后 `POST /api/admin/export` | 放行，源站收到，不新增 Jev 调用。`trace.function` 有 `tier`，没有 `attempt` | `fast_allow` |
| F7 | 医生 A 新建患者后 `DELETE` 它（编号在响应里见过） | 拦截，源站不收到请求。这个值 `verified: true`，同时带 `function.attempt`；已核验不等于快速放行 | `jev_deny` |
| F8 | 医生 A `GET /api/admin/search?q=x`（管理档条目可靠性为 medium） | 与没有条目时相同：Jev 收到的 `state` 没有 `function`，网关放行，源站答 403 | `fast_allow` |
| F9 | 基线站点（开关为真）的医生 A `GET /metrics`，功能表里没有它 | 拦截，源站不收到请求。`state.request.function` 为 `{"known":false}`，Jev 判 DENY | `jev_deny` |
| F10 | 基线站点的医生 A `GET /api/comments`，连续两次 | 第一次交 Jev 放行，源站收到；第二次走放行缓存，不新增 Jev 调用 | `jev_allow`，`cached_allow` |
| F11 | 不带凭证的 `DELETE /api/patients`（入口路径，基线里没有这个方法） | 交 Jev：`state.entry.matched` 为真，`function` 为 `{"known":false}`；Jev 放行，源站答 401 | `jev_allow` |
| F12 | 没有功能表的站点：医生 A 的 `POST /api/admin/export`、`GET /metrics` | 都快速放行（源站分别答 200、404），不新增 Jev 调用，判定记录没有 `trace.function`。与 F5、F9 对照 | `fast_allow`，`fast_allow` |
| F13 | 观察模式的功能表站点：医生 A 的 `POST /api/admin/export`、`GET /metrics` | 两个都转发（源站收到），记为本应拦截 | `jev_deny`（`would_block`） |

C5、C9 从回环的 127.0.0.2 至 127.0.0.4 发请求，使它们各有自己的来源地址（会话合计的 Jev 额度按来源地址算，见 [docs/02 §2.5](../../docs/02-jev.md)）。Linux 的回环整段 127.0.0.0/8 都可用；macOS 需要先给 `lo0` 加别名（`sudo ifconfig lo0 alias 127.0.0.2` 等），否则这两个场景连不上。

### A9 至 A11 说明：搜索结果与档位

源站的搜索接口没有按归属过滤，会把医生 B 的患者返回给医生 A。`emr` 站点的对象表把搜索响应标为公共档（`tier: public`，可靠性高），把删除位置标为 `accepts_public: false`。搜到的患者因此不能凭搜索结果被删除：这次删除记为尝试越权，网关不快速放行，交给 Jev，Jev 答 DENY，源站不会收到请求。没搜到的患者照旧拦截。

判定记录的 `trace.values` 里，搜到的患者那一项带 `"attempt": "over_privilege"` 和 `"public_access": {"accepts": false, "reliability": "high"}`，来源带 `"tier": "public"`；Jev 收到的 `state` 里同样带这些标记。

A10 的备注位置标为 `accepts_public: true`，搜到的患者在这里有效，快速放行。A11 的 `plain` 站点没有对象表，判定与标注前相同，所以同样的删除仍然放行。这是 [docs/00 §0.6](../../docs/00-overview.md) 的范围：没有标注的站点，源站搜索结果仍被当作展示过的证明。

A9 的第一条删除原来预期放行（已知缺口），标注档位之后改为拦截。

### A12 说明：慢速 id

患者 D 的 id 是 `PT-7004`，不是数字，所以删除请求的路径里没有可以替换成 `{id}` 的段。`DELETE /api/patients/{id}` 声明的 `{id}` 覆盖任何一段非空的 id，于是这次删除按该位置判定：闭合，搜索的公共档见过不证明删除，记为尝试越权，交给 Jev，Jev 答 DENY。在声明覆盖慢速 id 之前，这次删除被当作未声明、开放的路由，搜索结果就会证明它，于是放行，源站删除患者 D。这个场景在那个版本上会失败。

### W4a 至 W4d 说明：管理员会话

`admin` 站点的对象表把管理员搜索标为管理档（`tier: admin`，可靠性高），把首页的 `role` 声明为身份位置（`identity: role`）。源站只对角色为 `admin` 的会话返回管理员搜索，首页对管理员标注 `"role": "admin"`，其他会话没有这个字段。管理员会话见过的管理档响应证明它展示的对象，所以 W4a 的删除快速放行；W4b 的患者没有被见过，仍拦截；W4c 的管理员在公共搜索里见到的患者，删除仍是尝试越权；W4d 的备注位置接受公共来源，管理档的见过同样有效。

### F5 至 F13 说明：功能表

`functions` 站点的功能表列出三个管理功能：`POST /api/admin/export`、`DELETE /api/patients/{id}`（管理档，可靠性高）和 `GET /api/admin/search`（管理档，可靠性中），开关关闭。医生 A 不是管理员，所以 F5 和 F7 都是尝试越权。F7 的患者编号在医生 A 自己的响应里见过，值已核验，但越权尝试不快速放行，仍交给 Jev。F6 的管理员在首页声明了角色（`identity: role`），同一个请求快速放行，不交 Jev。F8 的条目可靠性是中，不收紧，与没有条目时相同。

F5b 用请求头 `X-HTTP-Method-Override` 把 `POST` 覆盖为 `DELETE`。网关先看传输方法，再看覆盖的方法，按更严的那个判定；判定记录的 `key` 仍按传输方法 `POST` 记。

`baseline` 站点的功能表列出基线里的接口（不带档位），开关打开。没有列出的 `GET /metrics`、`GET /api/comments`、`DELETE /api/patients` 交给 Jev：假 Jev 对路径里含运维词的未知功能答 DENY（F9，见下方「Fake Jev 的脚本」）；其他照值判定，放行后进入放行缓存（F10）。

`fobserve` 站点两张表都有，开关打开，是观察模式（F13）。`admin` 站点没有功能表，用来对照 F12。

靶场的站点地址限额都设为最大值 600：每次登录都从同一地址来，同一地址的调用共用一个限额，靶场只测会话限额（`limit.lab`）。

## Fake Jev 的脚本

- 请求值含 `JEVDOWN` 时返回 503，edge 记为 `JEV_HTTP_ERROR`；含 `JEVSLOW` 时一秒后才应答。C1、C2 的站点超时设为 100 ms，所以 `JEVSLOW` 记为 `JEV_TIMEOUT`。
- access：带 `attempt: over_privilege` 的值判 DENY（只由公共档响应展示过，请求位置不接受公共来源）。路径段或查询参数被 edge 标为 `reference` 且会话从未见过，也判 DENY。入口自身需要的输入（`/login` 的表单、`/share/` 下的分享码）不算。请求体里的自由文本（新患者的姓名、备注）不算对象引用，只有标识字段才算。
- attack：值或路径含 `union select`、`or 1=1`、`../`、`; cat `、`<script>` 时判 ATTACK。
- function：`request.function.attempt` 为 `over_privilege` 的请求判 DENY，不论值如何。`function.known` 为 `false` 且路径（转小写）里含 `admin`、`metrics`、`actuator`、`server-status`、`debug`、`swagger`、`console`、`phpinfo`、`ftp`、`backup`、`internal` 之一的，判 DENY；路径普通的，只按上面的 access 规则判值。词表是 `fake_jev.py` 的 `OPS_WORDS`，是指令那一段的摘录。
- 概率固定：所选选项 0.9，其余每个选项 0.05。

## clinic 源站与良性训练流量

`clinic_origin.py` 是第二个源站，对应规划文档第 4.1 节（规划文档未入库）。数据由种子决定（默认 `20261113`），规模由医生数决定（快速模式 12 位，完整模式 48 位）。它和 `idor_origin.py` 一样没有对象级鉴权，只能在靶场里运行，不得部署。除了接口，它还对外提供真值：`served`（处理过的每个请求）、`shown`（每个凭证见过哪些对象）、`owner_of()`（对象归属）和 `truth()`（位置真值，格式见规划文档第 9.3 节）。

`clinic_traffic.py` 产生良性训练流量（规划文档第 4.2 节）。每个医生每次登录走一条固定的旅程，全部是正常路径，同一种子发送的请求顺序完全相同。旅程里的固定安排如下。

- 每个医生搜自己的科室和另外两个科室。快速模式每个科室两位医生，所以每个搜索结果都被同科室的两位医生看到，这是公共档的证据。
- 每位医生的第一次登录会在管理搜索里被源站拒绝（403），共 12 次，是管理档的证据。
- 每次登录删除一个自己的患者，共 48 次。删除放在所有医生搜索之后：否则某个搜索结果会在它的主人删除后只剩一位医生见到，公共档的一致程度会低于高可靠性所需的 980‰。
- 每次登录给搜到的他人患者写一条备注，共 48 次。
- 文本输入取自良性语料的快速子集（`corpus/benign.jsonl` 中 `quick` 为 true 的条目，规划文档第 4.4 节）。检查时用理想模型的 Jev：只有语料中的完整攻击文本才判 ATTACK（`FakeJev(attack_texts=…)`）。

检查命令如下。

```sh
python3 tests/security-lab/clinic_traffic.py --check                      # 经网关跑一遍训练流量，核对真值与判定记录
python3 -m unittest discover -s tests/security-lab -p "test_*.py"         # 源站和流量的单元测试，不经网关
```

训练段在观察模式（`TRAINING_MODE`，`observe`）下经网关运行，观察行的 `mode` 与之一致，`category` 为 `train_<步骤名>`，便于按步骤看误拦率。

`--check` 核对四件事。第一，每个 `learnable` 位置的键和每个 `non_objects` 键都在判定记录里出现过（请求位置看 `trace.values[].slot`，响应位置看 `trace.response.fingerprints`）。第二，没有任何记录是拦截、本应拦截、未经判定或 Jev 失败。第三，每个请求的状态码符合旅程的预期。第四，四项证据达到学习规则判定 `high` 所需的数量。阈值沿用 `crates/xshield-core/src/context/learning.rs`：`SESSIONS_MIN` 为 5，`VOTES_MIN` 为 20，`high` 需要两倍的单位数或票数，公共档的一致程度需要 980‰。预算是 30 秒。

## 防护有效性度量

`scripts/measure_effectiveness.py` 度量防护的效果，代码在 `effectiveness/`。不带参数等同于 `lab --mode quick --jev ideal`，约几十秒：

```sh
python3 scripts/measure_effectiveness.py                                        # 快速模式，理想模型
python3 scripts/measure_effectiveness.py lab --only injection_sqli,no_session   # 只跑这些类别，不与基线比较
```

- 训练段在 `clinic-none` 的观察模式下经网关运行。学习段（批次 5）在有 PostgreSQL 时运行：它从训练段的判定学到对象表，作为 `clinic-learned` 站点进入防护段（只跑旅程和探针，回归用例仍只在各自的站点上跑）；没有运行时报告写明 SKIP 的原因。完整模式（批次 7）和 `--jev record|replay`（批次 9）以退出码 2 拒绝。
- 防护段在 `clinic-none`、`clinic-truth`、带每会话 Jev 额度的 `clinic-truth-limit` 和观察模式的 `clinic-truth-observe` 上运行：攻击探针（`corpus/attacks.jsonl`）、良性文本（`corpus/benign.jsonl`）、良性旅程，以及 `effectiveness/regressions.py` 里方案 4.5 的回归用例。载荷含路径分隔符、放不进一个路径段的，不送到“路径段”注入点，报告里分别计数。
- 理想模型是 `fake_jev.py` 传入攻击文本时的判定：攻击只看文本是否完整出现在路径或某个值里（两边先规范化）；访问规则与脚本相同，但值带 `object` 时，`seen_as` 里括号中类别不同的展示不算数。不传攻击文本时，判定与之前相同。
- `--jev live` 改用真实 Jev，需要环境变量 `XSHIELD_JEV_ENDPOINT` 和 `XSHIELD_JEV_API_KEY`，缺一即以退出码 2 退出。密钥只从环境变量读取，不写入报告和日志。页码当处方号这条探针只在这个模式下发送，理想模型比较不了没有类别的位置。
- 用例可以带能力要求（`requires`）：`tiers`（档位）、`functions`（功能表）、`classes`（对象表）。配置缺少所需能力时，用例显示为“需要…”，不计分。`none` 没有对象表，需要对象表的用例只在 `clinic-truth` 上计分。
- 已知缺口：判定器还不读功能表，所以 `clinic-truth` 也显示“需要功能表”的有 `p0-3-function-level`、医生的 `GET /api/admin/search`（旅程）。功能级判定合入后，补上 `clinic-truth` 的功能表并把 `p0-3-function-level` 改为 `must`。
- 退出码：门槛全部通过为 0，有门槛失败为 1，用法或环境错误为 2。

## 边界

- 源站故意不做对象鉴权，只能在靶场里运行，不得部署。
- 进程内的同一组场景（不启动二进制）见 `crates/xshield-edge/tests/scenarios.rs`，两者互补。
- 真实 Jev 的调用由 `crates/xshield-judge/tests/live_jev.rs` 负责（默认忽略）。本靶场不评估模型的准确率。
- `docker-compose.security-lab.yml` 只保留 Juice Shop，作为手工观察时的真实流量来源，本脚本不使用它。
