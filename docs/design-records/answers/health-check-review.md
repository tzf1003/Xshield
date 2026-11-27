# 全面体检：待审阅清单

2026-11-13，基于 main `ebc710b`。确定的问题已在 PR #180 修复并合并。下面是我没有直接动手的项，因为它们需要你做取舍，或者归其他线程处理。

## 需要你决定

1. **参考部署不存在。** docs/04 4.1 和 docs/07 7.2.3 说参考部署是单机 Docker Compose（网关、控制台、PostgreSQL 三个服务），仓库里只有启动开发用 PostgreSQL 的 `docker-compose.dev.yml`。docs/05 把它记为已知缺口。要么补一份 Compose 文件，要么把 04 和 07 的说法改成"尚未提供"。我已在 04.1 加了一句说明现状。
2. **源站地址没有网段限制。** v3 的 `XSHIELD_ALLOWED_UPSTREAM_CIDRS`、`XSHIELD_ALLOW_LOOPBACK_UPSTREAM` 在 docs/05 里原本标为"保留"，v4 代码没有实现。管理员可以把 `origin` 指向任何地址（包括回环和云元数据地址）。单管理员模型下这可以接受，但需要你确认是有意放弃。`XSHIELD_CONTROL_OPS_LISTEN` 同样没有实现。
3. **`validation/report.*` 是生成物却进了版本库。** 任何改动文档链接的 PR 都会让它落后，这次体检时就落后了 3 项，CI 不检查。建议二选一：不再跟踪它（加进 `.gitignore`），或在 CI 里加一步 `git diff --exit-code validation`。我倾向前者。
4. **登录失败限流按 TCP 对端地址计数。** 控制台放在反向代理后面时，所有人共用代理的地址，10 次失败会把所有人锁 10 分钟，攻击者也可以借此锁住管理员。直连部署没有这个问题。
5. **退出登录不会让会话令牌失效。** 令牌是无状态签名，`/api/logout` 只清浏览器 Cookie，被抄走的令牌在 12 小时内仍然有效。只有改管理员口令才能让全部令牌失效。这是文档里写明的设计，列出来供你确认。

## 小问题，改起来有判断成分

6. **站点配置校验失败时每 5 秒打一次日志。** `xshield-edge` 的 `SiteLoader::refresh` 对校验不过的新版本每轮都重新构建并 `eprintln`，直到管理员改好为止。行为是对的（继续用旧版本），只是日志会刷屏。
7. **分区删除中途失败后需要人工处理。** `drop_partitions_ended_before` 用 `DETACH PARTITION ... CONCURRENTLY`，如果语句被打断，分区会停在 detach pending 状态，之后每小时的维护都会在这个分区上报错，需要手动 `FINALIZE`。发生概率很低。
8. **导入接口内存占用偏高。** `POST /api/import` 接受 100 MiB，解析后的行又被 `clone` 一遍再写库，峰值大约是请求体的三倍。分块写入不在一个事务里，中途失败会留下部分数据（重新导入会跳过已有行，所以可以重试）。
9. **CI 的 `validate` 作业没有用 `--locked`。** `verify_all.sh` 和 Dockerfile 都用了，CI 的 clippy 和 test 没有，锁文件漂移时本地红、CI 绿。
10. **`ci.yml` 里一段注释放错了位置。** "Licenses, RustSec advisories…" 那段说的是 `supply-chain` 作业，却写在 `fuzz-replay` 上面。精简线程正在改这一段，我没有动。
11. **十六进制解码写了三份。** `xshield-edge/src/settings.rs`、`xshield-control/src/main.rs`、`xshield-control/src/auth.rs` 各有一个 `decode_hex`。
12. **控制台 `npm run lint:debt` 有 25 条警告**（`noImportantStyles`、`useOptionalChain` 等）。`npm run lint` 本身是绿的。

## 归其他线程

- xshield-core 里不再被任何 crate 引用的 v3 模块（access、admin、admission、application、audit、calibration、edge_channel、edge_descriptors、grant、identity、investigation、model_evaluation_admission、ports、provenance、query、query_pagination、secret_env 等），以及只测 v3 解析器的 fuzz 目标和 `tests/site-config/`：由"精简代码库删除多余部分"线程删除。
- `scripts/bench_fsync.py`（测的是已删除的 v3 journal）、`scripts/register_juice_shop.py`、`templates/adr.md` 等无人引用的文件：同上。
- AGENTS.md 里"代码里残留的 v3 实现"的说法：由"审查 Agent 配置与防护"线程处理。

## 体检时验证过的基线

`cargo fmt --check`、`cargo clippy -D warnings`、全部工作区测试、`scripts/test_idor_lab.py`（150/150）、`scripts/test_postgres.sh`、`validate_library.py`、`check_env_docs.py`、`check_secrets.py`、控制台 lint、单元测试和构建，全部通过。生产路径里没有 `unwrap`、`expect`、`panic`，没有 TODO 或 FIXME。
