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

## 协作：issue、标签与看板

工作用 issue 管理，状态和执行方都打在 issue 上，方便多个 agent 领任务和交接。

标签：
- 状态（每个 issue 和 PR 只打一个）：`状态/待办`、`状态/进行中`、`状态/待评审`、`状态/等用户`、`状态/阻塞`、`状态/完成`。
- 执行方：`执行/claude`、`执行/antigravity`。认领时打上，表示有人在做。
- 类型：`类型/bug`、`类型/功能`、`类型/文档`。`发版前冒烟` 标记发版前要跑一遍的项。

流程：
1. 开工前认领一张 `状态/待办` 的 issue：打上自己的 `执行/*` 标签，状态改为 `状态/进行中`。已有 `执行/*` 的不碰。交接时，交出方移除自己的 `执行/*` 标签；接手方认领后打上自己的。交接一个 `状态/进行中` 的任务时，接手方可以直接认领，不必先由交出方改回 `状态/待办`。
2. 分支用 `claude/*` 或 `antigravity/*`。不碰对方的分支；要用对方的改动，先在 issue 里说明。
3. 每个 PR 在描述里写 `Closes #编号` 关联 issue。没有 issue 的先补一个。
4. PR 先开成草稿；交叉评审前改为 ready，状态改为 `状态/待评审`。
5. 每个 PR 由另一个会话交叉评审。同账号 PR 无法 approve，评审会话以 PR 评论写结论即视为评审通过。评审无阻塞、CI 全绿才合并；合并后 issue 随 `Closes` 关闭。合并 PR 的会话把关联 issue 和 PR 的状态改为 `状态/完成`。
6. 需要人决定或操作时，状态改为 `状态/等用户`，在 issue 里写清要定的事；被别的工作卡住时，状态改为 `状态/阻塞`，写清卡在哪。
7. 改 `main` 只走 PR，不直接推送。不提交密钥、口令或个人信息。

`HANDOFF.md` 是在飞工作的快照：谁在做什么、卡在哪、等谁决定。交接或收尾时更新它，随代码一起走 PR。
