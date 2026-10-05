# Xshield 设计与开发文档库 v3.0

**纯前置 WAF · 界面操作来源准入 · Rust 主干 · 全链路可审计**

基线日期：2026-09-17。此库包含完整设计基线、开发规范、配置/数据契约和验收计划，以及正在实现的 Rust 产品代码。Word 总册为正文便于评审的排版版；本目录 Markdown 与机器可读文件作为工程协作源文件。

## 实现状态

Xshield 是用 Rust 实现的上下文增强型 WAF，采用纯前置代理，不要求站点接入 SDK。核心机制是界面操作来源验证：没有当前有效认证绑定下、来自认可界面的操作来源，请求就在进入源站前被拒绝（默认拒绝）。组成：Pingora 边缘网关（`xshield-gateway`）、axum 控制面（`xshield-control`）、PostgreSQL 资格与配置账本、ClickHouse 日志索引、本地封存审计 journal 与加密证据库，以及 `web/console` 管理控制台。

**整体进度约 35%（区间 30–45%）的可试点首版**，按代码而不是文档表述核查，口径与缺口见 [22 分阶段实施与交付物](docs/22-delivery-roadmap.md) 的“实现状态核查”：

| 里程碑 | 完成度 | 现状 |
|---|---|---|
| M0 基础契约与骨架 | 完成 | 领域类型、原因码、阶段事件与 Schema、Mock Ports |
| M1 身份与有迹可循 | 约 80% | 身份绑定与代际、资源资格、分享、界面动作准入；页面交付签发、探针 1.1.0 出示引用，真实浏览器闭环已回归；控制台还不能编写页面动作与 HTML 适配 |
| M2 双向协议接管 | 约 45% | AES-256-GCM JSON 封包适配、observe/compatibility 透传、探针注入、原生 TLS/HTTP/2 与 PROXY protocol |
| M3 完整日志后台 | 约 85–90% | 封存 journal、ClickHouse 检索与因果、加密证据库、案件/保留/审批/导出、OIDC + MFA step-up |
| M4 模型与调查 | 约 35% | QueryPlan、检索、因果、离线 Jev 评估、校准基础设施；模型不在请求路径 |
| M5 持续适配与产品化 | 约 10% | 期望/生效修订、危险变更审批、回滚、HMAC 应用通道；构建监测与灰度尚无代码 |

控制台已按 [30](docs/30-console-redesign.md) 重构完成（站点向导与工作区、请求调查、案件与审批、运维与治理）。逐机制的实现说明在 [31 已实现机制说明](docs/31-implemented-mechanisms.md)，接口契约在 [29](docs/29-api-endpoint-catalog.md)。

**已验证（本机，2026-10-06）**：Rust 745 个测试与 119 个 PostgreSQL 集成测试通过，控制台 346 个单测与 480 个 Playwright 用例（含无障碍扫描）通过；真实二进制回归包括原生 TLS/ALPN/PROXY 传输、动态监听器、双向加密、身份、Docker 外的 IDOR 靶场，以及真实 Chromium 驱动的界面操作来源闭环。另有 142 个 Rust 测试需要 PostgreSQL/ClickHouse/Docker 而默认忽略。**尚未验证**：容器镜像构建、ClickHouse 端到端发布、Keycloak 真实 OIDC 登录、GitHub CI、真实负载均衡与性能（本机没有 Docker，文档里的延迟预算仍是待测目标）。验收用例目录见 [验证方法](#验证方法)。

**运行与验证**：`scripts/verify_all.sh [rust|gateway|console]` 按 docs/17 §17.10 逐步执行并给出每一步结果（缺少工具时显示 SKIP，不算通过）；构建输出体积很大，请把 `CARGO_TARGET_DIR` 指向大容量卷。发行包由 `scripts/package_release.sh` 生成（见 [19](docs/19-deployment-operations.md) §19.7）。开发栈与控制台用法见 [19](docs/19-deployment-operations.md)、[20](docs/20-testing-and-acceptance.md) 与 [控制台 README](web/console/README.md#回归验证)。

**仓库地图**：`crates/`（`xshield-core` 纯领域与端口、`xshield-audit` 封存 journal、`xshield-evidence` 加密证据库、`xshield-postgres` 账本适配器、`xshield-gateway` 边缘网关、`xshield-control` 控制面、`xshield-worker` 发布器与离线评估）、`web/console`（控制台）、`sensor/`（浏览器探针源码与测试）、`migrations/`（PostgreSQL 迁移）、`scripts/`（验证、打包与真实二进制回归脚本）、`tests/`（浏览器闭环靶场、PostgreSQL SQL 回归、安全靶场）、`docs/`（设计与交付文档 00–31）、`schemas/` 与 `examples/`（设计库的 Schema 与样例，校验见 `validation/`）。

## Rust 运行时依赖

| 依赖 | 用途 | 许可证与更新策略 |
|---|---|---|
| Pingora 0.9.0 + OpenSSL backend | HTTP 代理生命周期、固定源站连接、请求过滤、journal AES-256-GCM、段清单 Ed25519 签名及模型缓存安全域的 HMAC-SHA-256 派生；`xshield-core` 只用其 SHA-256 计算 edge 管理的动作描述集规范摘要（`edge_descriptors`，纯计算、无 I/O），使 edge 与控制面得到逐字节相同的摘要，未引入新 crate | Apache-2.0；精确版本并锁文件，部署同步审查 OpenSSL 版本与许可证，升级先复跑协议歧义、加密恢复、签名验证、缓存键隔离、转发和故障测试 |
| SQLx 0.9.0 | PostgreSQL 异步事务和连接池 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 migration、回滚和并发测试 |
| clickhouse 0.15.2 | 已封存审计段的类型化查询、同步批量投递与传输加密 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 RowBinary schema、重复投递、并发冲突和故障水位测试 |
| hyper 1.x / hyper-util 0.1.x / http-body-util 0.1.x / hyper-rustls 0.27.x | 复用已锁定依赖提供单次 Jev HTTPS、原生信任根和有界响应读取 | hyper 系列为 MIT，hyper-rustls 为 Apache-2.0 OR ISC OR MIT；锁文件固定，升级复跑 TLS 配置、精确报文、取消、超时、限流与秘密排除回归 |
| Tokio 1.51 LTS | SQLx 异步运行时 | MIT；跟随 1.51 LTS 补丁，变更 minor 前执行故障与负载回归 |
| serde / serde_json 1.x | 类型化配置 DTO 与 outbox JSON | MIT OR Apache-2.0；锁文件固定，补丁升级执行配置和契约测试 |
| UUID 1.x | 生成服务器侧 UUIDv7 请求 ID | MIT OR Apache-2.0；锁文件固定，补丁升级执行 ID 契约测试 |
| async-trait / bytes / http 1.x | 实现 Pingora 异步过滤器、有界拒绝响应体及 trailer 边界类型 | MIT OR Apache-2.0；锁文件固定，随 Pingora 兼容线评估更新 |
| Axum 0.8.x / Tower 0.5.x | 独立管理 HTTP 路由与可测试 Service 边界 | MIT；锁文件固定，升级先执行管理认证、作用域、限流、错误契约及审计回归 |
| openidconnect 4.0.1 | OIDC discovery、授权码 + S256 PKCE、ID token/JWKS/nonce/audience 校验 | MIT；精确版本并锁文件，升级复跑 callback/parser、issuer/audience、MFA ACR、密钥轮换与故障回归 |
| reqwest 0.12.x / url 2.x | 有界、禁重定向的 Rustls IdP discovery 与 token endpoint HTTPS | MIT OR Apache-2.0；锁文件固定，升级复跑 TLS、endpoint allowlist、超时、重定向拒绝与秘密排除回归 |
| crc32fast / zeroize 1.x | journal 快速损坏检测与秘密缓冲清零 | MIT OR Apache-2.0；锁文件固定，升级执行篡改、恢复和秘密生命周期测试 |
| chrono 0.4.x | 生成审计契约要求的 UTC RFC 3339 时间戳 | MIT OR Apache-2.0；锁文件固定，补丁升级执行审计契约与时钟异常测试 |
| Python cryptography 49.0.0（仅测试） | 生成 Gateway→Origin 加密请求测试向量，不进入产品运行时 | Apache-2.0 OR BSD-3-Clause；精确版本，升级先执行认证失败、不回退与源站不可见反例 |
| ClickHouse Server 25.8.29.51 LTS（集成测试服务） | 执行实际部署 DDL、RowBinary 与查询回归 | Apache-2.0；CI 固定版本，升级先复跑建库/重入、发布、权限、分页和保留回归，运行方式见 [20.6](docs/20-testing-and-acceptance.md#206-clickhouse-真实集成回归) |

当前 workspace MSRV 为 Rust 1.94，与 SQLx 0.9.0 一致。生产依赖升级需审查许可证、安全公告和 Cargo.lock 差异。

## 开始阅读

打开 [Word 总册（48 页）](Xshield_Design_Book_v3.0.docx) 进行评审，或双击 [START_HERE.html](START_HERE.html) 离线阅读全部正文；或从 [产品需求](docs/00-product-requirements.md) 和 [最终对话决策](docs/28-conversation-decisions-and-traceability.md) 开始。

- 架构/产品评审：00 → 01 → 02 → 04 → 05 → 06 → 09 → 28。
- 日志后台实施：11 → 12 → 13 → 14 → 15 → 18 → 26 → 29。
- 开发 Agent：先读 [AGENTS.md](AGENTS.md)，再读 16、17、22 与相关模块。
- 站点适配：07 → 08 → 10 → 27；发布前执行 20 中安全/兼容验收。

## 已确定的最终规则

没有当前有效认证绑定下的认可界面操作来源就拒绝，即使源站实际有权限。已取得的具体资格在有效期内可复用；新浏览器、未查询的新资源须重新经过认可入口。看到 ID 不代表可执行任何操作。WAF Cookie 与真实业务凭证、身份代际、资格账本强绑定。日志/模型/普通成功响应不自行创造资格。

双向加密接管检查并重建同一实际业务参数；兼容回退由服务器批准且标注覆盖缺口。心跳/堆栈提供线索，不是权限证明。Jev/Agent只在受控任务边界工作，代码执行确定性约束。

审计包含每请求、每阶段、实际模型及Agent输入输出、解密与转换证据；普通检索索引和加密证据库分离。秘密脱敏、捕获上限、不可用和裁剪必须显示，不能把脱敏包声称为字节级原件。确定性规则与Noul不伪造置信度。

## 正文目录

| 编号 | 文档 |
|---|---|
| 00 | [产品定位与需求基线](docs/00-product-requirements.md) |
| 01 | [威胁模型与安全不变量](docs/01-threat-model-and-invariants.md) |
| 02 | [总体架构与技术选型](docs/02-system-architecture.md) |
| 03 | [请求、响应及提交时序](docs/03-request-response-pipeline.md) |
| 04 | [身份与会话绑定](docs/04-auth-session-binding.md) |
| 05 | [界面操作来源验证：Xshield 核心准入机制](docs/05-ui-action-provenance.md) |
| 06 | [资格账本、根入口及分享](docs/06-capability-ledger.md) |
| 07 | [自动注入探针、心跳与请求关联](docs/07-browser-sensor.md) |
| 08 | [双向应用层加密接管](docs/08-crypto-takeover.md) |
| 09 | [策略引擎与判定合成](docs/09-policy-engine.md) |
| 10 | [Jev、OpenJev 与分析 Agent](docs/10-jev-and-agents.md) |
| 11 | [全链路审计事件与 ID 契约](docs/11-audit-event-contract.md) |
| 12 | [内容证据采集、秘密隔离与加密证据库](docs/12-evidence-capture-and-vault.md) |
| 13 | [审计存储、耐久性、完整性与容灾](docs/13-audit-storage-reliability.md) |
| 14 | [按 ID 检索、证据分析与安全回放](docs/14-investigation-query-replay.md) |
| 15 | [管理后台与调查 API](docs/15-console-and-api.md) |
| 16 | [Rust 代码架构与模块边界](docs/16-rust-code-architecture.md) |
| 17 | [开发规范：必须进入代码评审与 CI](docs/17-development-standards.md) |
| 18 | [数据模型、契约版本及存储责任](docs/18-api-and-data-models.md) |
| 19 | [部署、隔离、升级与运行策略](docs/19-deployment-operations.md) |
| 20 | [测试策略与验收矩阵](docs/20-testing-and-acceptance.md) |
| 21 | [性能、容量与成本模型](docs/21-performance-capacity.md) |
| 22 | [分阶段实施与交付物](docs/22-delivery-roadmap.md) |
| 23 | [剩余风险与待验证决策](docs/23-risks-and-open-decisions.md) |
| 24 | [架构决策记录（ADR）](docs/24-adrs.md) |
| 25 | [来源与核验登记](docs/25-source-register.md) |
| 26 | [运维与调查 Runbook](docs/26-runbooks.md) |
| 27 | [站点规则编写指南与评审清单](docs/27-rule-authoring-cookbook.md) |
| 28 | [对话决策汇总与需求追踪](docs/28-conversation-decisions-and-traceability.md) |
| 29 | [控制 API 与审计责任清单](docs/29-api-endpoint-catalog.md) |
| 30 | [控制台重构方案与实施记录](docs/30-console-redesign.md) |
| 31 | [已实现机制说明](docs/31-implemented-mechanisms.md) |

## 配套材料

| 路径 | 内容 |
|---|---|
| schemas/ | 4份自定义 JSON Schema：审计事件、证据manifest、模型调用、站点策略 |
| examples/ | 禁用状态的站点配置，合成审计事件与证据，78 项验收用例（每项标注 planned/partial/automated，见 docs/20） |
| sql/ | PostgreSQL migration 与 ClickHouse 部署 schema；真实数据库回归见 [20.6](docs/20-testing-and-acceptance.md#206-clickhouse-真实集成回归) |
| templates/ | PR、ADR、crate说明和只读调查Agent约束 |
| scripts/ | 可重复运行的文档/Schema/合成证据验证脚本 |
| reference/ | 原始资料来源、旧输入文件哈希和决策基线 |
| validation/ | 本次实际执行的验证结果；不等于产品测试报告 |

## 验证方法

```bash
python3 -m pip install -r scripts/requirements.txt
python3 scripts/validate_library.py     # 设计库的 Schema、样例与交叉引用
scripts/verify_all.sh                    # 产品代码：fmt、clippy、测试、PostgreSQL、真实二进制与控制台
```

设计库验证结果见 [report.md](validation/report.md)。验收用例的 `planned` 是未执行状态，不得在项目报告里作为已通过的安全测试。

## 版本与维护

新增需求先更新 RQ/INV/ADR，再同步 Schema、配置与用例。参考资料中的供应商能力是核验时状态；模型与依赖版本必须在实现时锁定并重新验证，不能将文档中的性能目标当成已实测指标。变更说明见 [CHANGELOG.md](CHANGELOG.md)。
## 后端统一站点配置与 Agent API Key

受保护站点以 `xshield-control + PostgreSQL` 为唯一配置源。Gateway 只接受控制面通过 loopback HMAC `/internal/v1/apply` 发布的签名快照；没有已确认快照时数据面保持拒绝。Agent 使用一次性显示的 `X-Xshield-API-Key`，Key 绑定 tenant、site 和能力集合，不能访问 Gateway 内部接口。

本地 `dev.sh` 会生成独立的 API Key 指纹密钥与 edge apply HMAC 密钥，并以 bootstrap-only 模式启动 Gateway。Juice Shop 应通过 `POST /control/v1/sites` 创建并应用，不能通过旧静态 Gateway 配置注册。

开发环境的受保护站点 HTTPS 入口由 `dev.sh --all` 自动生成：`https://juice.local:5443` 使用 `target/xshield-dev/tls/juice.local.crt` 的本地自签证书，并转发到 Gateway 的 `56188` HTTP 监听器。macOS 可执行 `scripts/generate_dev_tls_cert.sh target/xshield-dev/tls --install` 安装本地信任；生产环境不使用该开发终止器。
