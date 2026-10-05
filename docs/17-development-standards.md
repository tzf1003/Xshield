# 17 开发规范：必须进入代码评审与 CI

## 17.1 规范用词

MUST 为合并门槛；SHOULD 为默认做法，偏离需解释；MAY 为可选。模块职责、外部效果、失败和日志都属于设计的一部分，不能以“后面再补”为借口合并关键路径。

## 17.2 结构与命名

MUST：一模块一项主要职责，依赖单向；业务语义使用领域名字。`utils.rs`、`common.rs` 不作为不明职责的堆场；共享代码须有明确主题和至少一个合理复用点。

SHOULD：普通业务函数控制在约 80 行以内、模块约 500 行以内；解析器、状态机表和生成代码可例外，但 PR 解释边界。限制用于促使拆分，不以机械切函数替代清晰逻辑。

MUST：保持入口薄、用例编排清晰、纯计算可独立测试；不为“高扩展”提前做自定义消息总线、反射容器和无限泛型。crate 公共 API 最小化，优先 pub(crate)。

## 17.3 注释与文档

每个 crate/module 说明职责、信任边界、主要类型、允许依赖和外部效果。公共 API 写 rustdoc：输入、返回、不变量、错误、是否会产生副作用与简短用例。

身份轮换、nonce、资格发行、状态检查、加密 AAD、证据落盘屏障必须解释“为什么”和并发边界，不能只写“调用函数”。所有 unsafe 块有 SAFETY 前提和证明责任；TODO 必须关联 issue/验收项，不留无主 TODO。

复杂状态转换用表格/测试链接替代长篇流水账。代码变更同时更新相关协议与设计；文档示例来自可验证 fixture。Rust API 习惯与公共接口一致性可参照官方 API Guidelines。[S26]

## 17.4 日志规范

业务日志用 tracing 结构化字段，MUST 不使用 println!/dbg! 输出生产日志。必需安全事件只走 AuditSink，不依赖日志级别或 span 采样。异步 span 采用正确的 instrument/传播方式，不跨 await 长持 entered guard。[S07]

每个安全分支至少包含 request_id、stage、outcome、reason_code、policy_revision、duration 和 evidence_refs。异常记录 error_kind/retryable，不泄露原始 body、凭证或连接串。日志消息说明发生了什么，字段说明谁/哪条请求/依据何在，避免同一错误逐层重复堆栈。

禁止 `#[instrument]` 自动捕获整个 request、token 或密钥；默认 `skip_all` 再白名单字段。普通 Debug 类型也不得包含未标注秘密。生产 panic 处理器、崩溃转储、临时文件与 stderr 同样受秘密政策约束。

## 17.5 错误处理与取消

生产外部输入路径禁止 unwrap/expect/panic；确有不可达不变量需说明并测试，测试代码可适用例外。禁止吞错 `let _ = ...`，尤其 AuditSink、资格写入和证据保存失败必须有策略。

错误只在负责处理/映射的边界记录一次主要日志。所有可重试操作定义上限、指数退避和抖动；请求转发不得自动重试非幂等动作。每个后台任务有 owner、取消、deadline 和结束事件。

## 17.6 数据与安全

输入验证在边界完成，领域对象构造器拒绝非法状态。SQL 参数化，租户域从已认证操作者注入，不由客户端 JSON 直接指定。路径、URL、主机名与文件名均经用途校验，防 SSRF/路径穿越。

禁止自研密码学、硬编码生产密钥、关闭 TLS 验证、允许任意插件 hostcall。秘密类型不序列化；必要证据保留使用专用受限路径。逻辑日志记录资格引用，不打印整个资格所属的用户资料。

## 17.7 测试和合并门槛

每个安全规则至少：允许、拒绝、缺失、过期/撤销、跨身份、并发/重试、依赖故障、审计断言。关键解析/转换使用 property testing 与 fuzz。状态和 replay 使用可注入 Clock 与固定 fixture，测试不访问生产服务。

CI：fmt、clippy、cargo test、doc test、schema/example validation、依赖图、依赖/许可证审查、secret scan、迁移验证、接口兼容检查。Clippy lint 按 workspace 管理；不能为了通过 CI 全局 allow 警告。[S27]

覆盖率只辅助。新安全分支需要断言覆盖，关键不变量用性质测试；不以总体行覆盖率替代边界测试。压力/模糊/浏览器矩阵可夜间执行，但影响安全语义的最小回归必须阻止合并。

## 17.8 分支与 Agent 开发规范

每项任务一个有边界的工作单元。先读本库与 AGENTS.md，再改协议/代码；不得用 mock 测试冒充真实集成通过。临时 worktree、构建产物和下载模型设配额，任务结束清理自有临时资源，不删除他人工作或未合并分支。

AI 生成的代码与人工代码同门槛。修改授权根、秘密处理、加密、审计耐久和回退策略需要额外审查。不得通过跳过测试、降低保护模式、关闭日志来“修复”失败。

## 17.9 Definition of Done

行为与失败路径实现；契约及文档一致；单元/集成/安全测试通过；必需日志和证据可检索；没有秘密泄露；超时/配额/取消有效；迁移和回滚已验证；PR 说明残余风险与尚未执行的测试。未完成项标清，不宣称部署就绪。

## 17.10 本地验证清单

合并前在仓库根目录按下列命令验证，并在说明里写明未能执行的项（例如缺少 Docker 或 ClickHouse）：

- 一次性运行下列全部门槛：`scripts/verify_all.sh [rust] [gateway] [console]`，每步一份日志（`XSHIELD_VERIFY_LOG_DIR`），缺少工具的步骤记为 SKIP 而不是成功，任一步失败则退出码非零；`CARGO_TARGET_DIR` 应指向大容量磁盘而不是系统盘。
- Rust：`cargo fmt --all --check`；`cargo clippy --workspace --all-targets --locked -- -D warnings`（工作区启用 pedantic 规则，首次构建需数分钟）；`cargo test --workspace --all-targets --locked` 与 `cargo test --workspace --doc --locked`。
- 文档与契约：`python3 scripts/validate_library.py`（会重写 `validation/report.*`，随改动一起提交）；`python3 scripts/check_audit_event_coverage.py`（控制面每个审计事件必须出现在 worker 发布矩阵中，见 11.14）；`python3 scripts/check_env_docs.py`（产品代码读取的每个 `XSHIELD_*` 环境变量必须在文档中出现，测试专用变量除外）。真实二进制脚本需要 bash ≥ 4.1（macOS 自带 3.2 会让 `set -e` 静默忽略失败的 `[[ ]]`）：脚本在旧 bash 下拒绝运行，`scripts/verify_all.sh` 会用 `XSHIELD_BASH` 或 Homebrew 的 bash 重新执行；脚本里的“不得出现”断言用 `refute`，不要写 `! grep`。
- PostgreSQL 集成：`scripts/test_postgres.sh` 会创建并在退出时删除唯一命名的临时库；也可手动 `createdb`、按序应用 `migrations/*.sql`、设置 `XSHIELD_TEST_DATABASE_URL` 运行单个 `--ignored` 测试后 `dropdb`。不要对包含他人数据的库运行，测试库名必须是一次性的。
- ClickHouse 与端到端：需要 Docker 的回归（CI 的 ClickHouse 步骤、`scripts/test_gateway_*.sh`、Keycloak OIDC）在无法运行的环境中必须标注“未执行”，不得以本地单测代替。
- 控制台（`web/console`）：`npm ci`；`npm run lint`（若已配置）；`npm test`；`npm run build`；`XSHIELD_E2E_PORT=<端口> npm run test:e2e`（并行 worktree 使用不同端口对，默认 5175/5176）。
- 提交前不要使用 `git add -A` 把本地 agent worktree 或生成目录加入索引；按层、按功能分提交，提交说明写明验证结果与残余风险。

