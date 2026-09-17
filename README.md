# Xshield 设计与开发文档库 v3.0

**纯前置 WAF · 界面操作来源准入 · Rust 主干 · 全链路可审计**

基线日期：2026-09-17。此库包含完整设计基线、开发规范、配置/数据契约和验收计划，以及正在实现的 Rust 产品代码。Word 总册为正文便于评审的排版版；本目录 Markdown 与机器可读文件作为工程协作源文件。

## 实现状态

M0 已提供 Cargo workspace、强类型 ID、稳定原因码、独立管理身份、审计端口及禁用站点的 `NOT_CONFIGURED` 阶段树。M1 已实现 WAF 会话与业务凭证的精确组合绑定、身份生命周期和有界精确资格账本领域规则；网络入口、PostgreSQL 持久化、持久审计和源站转发仍在后续闭环中。

```bash
cargo test --workspace --all-targets
cargo run -p xshield-core --example m0_stage_tree
scripts/test_postgres.sh
```

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

## 配套材料

| 路径 | 内容 |
|---|---|
| schemas/ | 4份自定义 JSON Schema：审计事件、证据manifest、模型调用、站点策略 |
| examples/ | 禁用状态的站点配置，合成审计事件与证据，78项待实施验收用例 |
| sql/ | PostgreSQL与ClickHouse数据模型草案，未执行数据库集成验证 |
| templates/ | PR、ADR、crate说明和只读调查Agent约束 |
| scripts/ | 可重复运行的文档/Schema/合成证据验证脚本 |
| reference/ | 原始资料来源、旧输入文件哈希和决策基线 |
| validation/ | 本次实际执行的验证结果；不等于产品测试报告 |

## 验证方法

```bash
python -m pip install -r scripts/requirements.txt
python scripts/validate_library.py
```

验证结果见 [report.md](validation/report.md)。验收用例的 `planned` 是未执行状态，不得在项目报告里作为已通过的安全测试。

## 版本与维护

新增需求先更新 RQ/INV/ADR，再同步 Schema、配置与用例。参考资料中的供应商能力是核验时状态；模型与依赖版本必须在实现时锁定并重新验证，不能将文档中的性能目标当成已实测指标。变更说明见 [CHANGELOG.md](CHANGELOG.md)。
