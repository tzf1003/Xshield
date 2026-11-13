# 安全靶场（v4 验收场景）

本目录是 [docs/04 §4.3](../../docs/04-deployment-testing.md#43-验收场景) 验收场景的靶场，由 `scripts/test_idor_lab.py` 驱动：

- `idor_origin.py`：一个 EMR 源站，没有对象级鉴权。任何登录的医生都能读取、删除、分享任何患者，所以拦截必须由 edge 完成。
- `fake_jev.py`：脚本化的 Jev 假服务，应答固定，不调用模型。
- 真实的 `xshield-edge` 二进制，站点由 `XSHIELD_EDGE_SITES_FILE` 提供。

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
| W1 | 声明了 `GET /api/home doctor.id` 为用户身份的站点：医生 A、B 各自登录后，判定记录的 `trace.session.identity.user` 是各自的键控哈希标签，换账号不同，同一账号相同；没有声明身份的站点不写 `identity` | 放行，身份标签按上述规则 | `fast_allow` |
| W4a | 管理员站点：管理员在管理档搜索（`GET /api/admin/search`）里搜到医生 B 的患者后删除 | 放行，删除的值核验为管理档来源，不是尝试 | `fast_allow` |
| W4b | 管理员没在管理档搜索里见过的患者，直接删除 | 拦截，源站不收到请求；角色不是放行理由 | `jev_deny` |
| W4c | 管理员在公共搜索里搜到医生 B 的患者后删除 | 拦截，记为尝试越权：公共档的见过不证明删除 | `jev_deny` |
| W4d | 管理员在管理档搜索里搜到患者后写备注（POST 子路径） | 放行，备注位置接受公共来源 | `fast_allow` |
| W6 | 同一站点的评论接口：医生 A 读取自己患者的评论时，作者医生 B 的手机号和邮箱让判定记录的 `trace.response.exposure` 记一条告警（字段名 `phone`、`email`，记录里没有值）；读取本人资料、未声明身份的站点不告警 | 放行，告警按上述规则 | `fast_allow` |

### A9 至 A11 说明：搜索结果与档位

源站的搜索接口没有按归属过滤，会把医生 B 的患者返回给医生 A。`emr` 站点的对象表把搜索响应标为公共档（`tier: public`，可靠性高），把删除位置标为 `accepts_public: false`。搜到的患者因此不能凭搜索结果被删除：这次删除记为尝试越权，网关不快速放行，交给 Jev，Jev 答 DENY，源站不会收到请求。没搜到的患者照旧拦截。

判定记录的 `trace.values` 里，搜到的患者那一项带 `"attempt": "over_privilege"` 和 `"public_access": {"accepts": false, "reliability": "high"}`，来源带 `"tier": "public"`；Jev 收到的 `state` 里同样带这些标记。

A10 的备注位置标为 `accepts_public: true`，搜到的患者在这里有效，快速放行。A11 的 `plain` 站点没有对象表，判定与标注前相同，所以同样的删除仍然放行。这是 [docs/00 §0.6](../../docs/00-overview.md) 的范围：没有标注的站点，源站搜索结果仍被当作展示过的证明。

A9 的第一条删除原来预期放行（已知缺口），标注档位之后改为拦截。

### A12 说明：慢速 id

患者 D 的 id 是 `PT-7004`，不是数字，所以删除请求的路径里没有可以替换成 `{id}` 的段。`DELETE /api/patients/{id}` 声明的 `{id}` 覆盖任何一段非空的 id，于是这次删除按该位置判定：闭合，搜索的公共档见过不证明删除，记为尝试越权，交给 Jev，Jev 答 DENY。在声明覆盖慢速 id 之前，这次删除被当作未声明、开放的路由，搜索结果就会证明它，于是放行，源站删除患者 D。这个场景在那个版本上会失败。

### W4a 至 W4d 说明：管理员会话

`admin` 站点的对象表把管理员搜索标为管理档（`tier: admin`，可靠性高），把首页的 `role` 声明为身份位置（`identity: role`）。源站只对角色为 `admin` 的会话返回管理员搜索，首页对管理员标注 `"role": "admin"`，其他会话没有这个字段。管理员会话见过的管理档响应证明它展示的对象，所以 W4a 的删除快速放行；W4b 的患者没有被见过，仍拦截；W4c 的管理员在公共搜索里见到的患者，删除仍是尝试越权；W4d 的备注位置接受公共来源，管理档的见过同样有效。

靶场的站点地址限额都设为最大值 600：每次登录都从同一地址来，同一地址的调用共用一个限额，靶场只测会话限额（`limit.lab`）。

## Fake Jev 的脚本

- 请求值含 `JEVDOWN` 时返回 503，edge 记为 `JEV_HTTP_ERROR`；含 `JEVSLOW` 时一秒后才应答。C1、C2 的站点超时设为 100 ms，所以 `JEVSLOW` 记为 `JEV_TIMEOUT`。
- access：带 `attempt: over_privilege` 的值判 DENY（只由公共档响应展示过，请求位置不接受公共来源）。路径段或查询参数被 edge 标为 `reference` 且会话从未见过，也判 DENY。入口自身需要的输入（`/login` 的表单、`/share/` 下的分享码）不算。请求体里的自由文本（新患者的姓名、备注）不算对象引用，只有标识字段才算。
- attack：值或路径含 `union select`、`or 1=1`、`../`、`; cat `、`<script>` 时判 ATTACK。
- 概率固定：所选选项 0.9，其余每个选项 0.05。

## 边界

- 源站故意不做对象鉴权，只能在靶场里运行，不得部署。
- 进程内的同一组场景（不启动二进制）见 `crates/xshield-edge/tests/scenarios.rs`，两者互补。
- 真实 Jev 的调用由 `crates/xshield-judge/tests/live_jev.rs` 负责（默认忽略）。本靶场不评估模型的准确率。
- `docker-compose.security-lab.yml` 只保留 Juice Shop，作为手工观察时的真实流量来源，本脚本不使用它。
