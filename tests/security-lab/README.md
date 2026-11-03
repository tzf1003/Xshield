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
| B1 | 搜索框、表单里的中英文文本 | 放行；重复的搜索走放行缓存 | `jev_allow`，`cached_allow` |
| B2 | 参数里的 SQL 注入、命令执行、路径穿越 | 拦截 | `jev_deny` |
| C1 | Jev 返回 503 或超时，`on_jev_unavailable=deny` | 拦截，注明 `JEV_HTTP_ERROR` / `JEV_TIMEOUT` | `jev_unavailable` |
| C2 | 同上，`on_jev_unavailable=allow` | 放行，记为未经判定 | `jev_unavailable`（`unjudged`） |
| C3 | 观察模式下的 A2 | 转发，记为本应拦截 | `jev_deny`（`would_block`） |
| C4 | 登录请求 | Jev 收到的是 `<redacted>`，判定日志里也没有口令 | `jev_allow` |
| C5 | 同一会话超过每分钟调用上限（站点设为 2） | 第三次拦截，`JEV_CALL_LIMIT` | `jev_unavailable` |

## Fake Jev 的脚本

- 请求值含 `JEVDOWN` 时返回 503，edge 记为 `JEV_HTTP_ERROR`；含 `JEVSLOW` 时一秒后才应答。C1、C2 的站点超时设为 100 ms，所以 `JEVSLOW` 记为 `JEV_TIMEOUT`。
- access：路径段或查询参数被 edge 标为 `reference` 且会话从未见过，判 DENY。入口自身需要的输入（`/login` 的表单、`/share/` 下的分享码）不算。请求体里的自由文本（新患者的姓名、备注）不算对象引用，只有标识字段才算。
- attack：值或路径含 `union select`、`or 1=1`、`../`、`; cat `、`<script>` 时判 ATTACK。
- 概率固定：所选选项 0.9，其余每个选项 0.05。

## 边界

- 源站故意不做对象鉴权，只能在靶场里运行，不得部署。
- 进程内的同一组场景（不启动二进制）见 `crates/xshield-edge/tests/scenarios.rs`，两者互补。
- 真实 Jev 的调用由 `crates/xshield-judge/tests/live_jev.rs` 负责（默认忽略）。本靶场不评估模型的准确率。
- `docker-compose.security-lab.yml` 只保留 Juice Shop，作为手工观察时的真实流量来源，本脚本不使用它。
