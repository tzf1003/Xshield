# Xshield 开发 Agent 约束

本文件给在本仓库里写代码的 agent（Claude Code、Codex 等）看。`CLAUDE.md` 只导入本文件，规则只在这里维护。

## 开工前
阅读 README 和 docs/00–03。改判定或靶场再读 docs/04；改控制台时按章节查 docs/06、docs/07（两份各十多万字，不要整篇读入）。

代码已按 docs/05 改造为 v4。遇到残留的 v3 代码、注释或脚本说明时以 docs/00–07 为准，按 docs/05 处理，不要照着残留扩展。代码注释和脚本头部里 docs/08 及以上的编号（如 `docs/17`、`docs/20`）指提交 `ad524d4` 中的 v3 旧文档，用 `git show ad524d4:docs/<文件名>` 查看。

## 产品规则
只接受正常访问路径：请求里的业务对象必须在本会话此前的源站响应中出现过，或请求来自登记的入口；否则交给 Jev 判定，Jev 判为越权或攻击即拦截，即使源站本身允许这次访问。不要求源站接入 SDK。单管理员，不加审批流程。

## 做减法
新增配置项、角色、表、crate 或环境变量之前，先确认现有机制确实不够用。能用代码默认值解决的不做成配置。同样适用于 agent 配置本身：新增 skill、hook、子代理或 MCP 服务之前，先确认本文件加一句话解决不了。

## 结构
`xshield-core` 是纯领域逻辑，只通过 ports 访问存储、模型、秘密和网络：不得依赖数据库驱动、HTTP 栈、异步运行时、TLS 或其他工作区 crate（`crates/xshield-core/tests/dependency_boundary.rs` 会让违反的构建失败）。其余 crate 的分工见 README 的仓库地图。

## 安全
会话凭证和口令类字段不得原样写日志或发给 Jev。Jev 超时、出错或答不上来时按站点 `on_jev_unavailable` 处理，不得默认放行。判定日志不作为授权依据。

测试不调用真实模型：用 `tests/security-lab/fake_jev.py`。`live_jev` 测试默认忽略，只在用户明确要求并提供密钥时运行。真实密钥只从环境变量读取，不写进仓库、提交信息、PR 或日志。`scripts/check_secrets.py` 的 `ALLOW` 只登记合成的测试值，并写明原因。

## 质量
提交前按改动范围执行下面的检查；缺少运行环境须明确说明哪一步未执行，不要写成通过。生产输入路径禁止 unwrap/expect/panic 兜底。新增依赖说明原因和许可证（`deny.toml` 是许可证与公告的门槛）。

| 改动 | 检查（与 CI 的 `validate`、`console`、`fuzz-replay`、`supply-chain` 作业一致） |
|---|---|
| 任何改动 | `python3 scripts/validate_library.py`、`python3 scripts/check_env_docs.py`、`python3 scripts/check_secrets.py` |
| Rust（`crates/`、`Cargo.*`） | `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo test --workspace --doc` |
| 判定路径（`xshield-core`、`xshield-judge`、`xshield-edge`），以及学习代码（`xshield-control` 的 `object_learning.rs`、`object_agent.rs`、`tightening.rs`，`xshield-core` 的 `context/learning.rs`） | 另加 `python3 scripts/test_idor_lab.py`（可用 `--only A2,C4` 只跑相关场景）和 `python3 scripts/measure_effectiveness.py`（快速模式，需要 PostgreSQL，见 docs/04 4.6） |
| `xshield-postgres`、`xshield-control`、`migrations/` | 另加 `scripts/test_postgres.sh`（需要 PostgreSQL 和 `PG*` 环境变量） |
| `xshield-core`、`fuzz/` | 另加在 `fuzz/` 下执行 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`（独立工作区） |
| `web/console/` | 在该目录执行 `npm ci`、`npm run lint`、`npm test`、`npm run build`、`npm run test:e2e` |
| 依赖（`Cargo.lock`、`deny.toml`） | `cargo deny --locked check` |

`scripts/verify_all.sh [rust] [console]` 一次跑完整组并按步骤留日志；工具缺失的步骤报告为 SKIP，不算通过。

环境注意：
- 调试构建加测试约 16 GB。磁盘紧张时设 `CARGO_INCREMENTAL=0`、`CARGO_PROFILE_DEV_DEBUG=line-tables-only`（CI 的做法），并把 `CARGO_TARGET_DIR` 指向大容量卷。先用 `-p <crate>` 跑相关 crate，提交前再跑整个工作区。
- Rust 工具链固定在 `rust-toolchain.toml`（与 `.github/workflows/ci.yml` 同步）。升级工具链是单独的改动，不要为了消除 lint 顺手升级。
- 脚本需要 bash ≥ 4.1（macOS 自带 3.2，会少检查）。

## 提交与 PR
- 改动经 PR 合入 `main`，不直接推送 `main`，不强推（改写自己分支用 `--force-with-lease`）。
- 提交标题用英文 Conventional Commits，带范围：`feat(judge): …`、`fix(control): …`、`test(lab): …`、`docs(design): …`。
- 用户可见的行为变化在 `CHANGELOG.md` 的 `Unreleased` 顶部加一条中文记录，并同步对应的 docs 章节；行为与文档不一致算缺陷。
- PR 描述按 `templates/pull-request.md` 的五个标题填写（它不在 `.github/` 下，GitHub 不会自动带出）。
- `validation/report.*` 由 `scripts/validate_library.py` 每次运行时生成，不入库（已在 `.gitignore`），不要提交。

## 不要为了变绿而做的事
跳过、忽略或删除失败的测试；放宽 clippy 或 biome 规则、加 `#[allow]` 压掉告警；修改 `.github/workflows/` 或 `deny.toml` 让检查不再运行；给 e2e 加重试掩盖真实失败。检查失败时修原因；确实要调整门槛时，在 PR 里单独说明理由。
