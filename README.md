# Xshield 设计与开发文档库 v3.0

**纯前置 WAF · 界面操作来源准入 · Rust 主干 · 全链路可审计**

基线日期：2026-09-17。此库包含完整设计基线、开发规范、配置/数据契约和验收计划，以及正在实现的 Rust 产品代码。Word 总册为正文便于评审的排版版；本目录 Markdown 与机器可读文件作为工程协作源文件。

## 实现状态

`xshield-control` 已提供首个独立管理接口 `GET /control/v1/audit/health`：固定从服务端配置注入 tenant/site 作用域，以常量时间摘要比对管理 Bearer 凭证，仅允许 `AuditAdministrator`，执行每分钟有界限流，并在返回前把 `console.health.read` 结果写入独立加密 journal。

M0 已提供 Cargo workspace、强类型 ID、稳定原因码、独立管理身份、审计端口及禁用站点的 `NOT_CONFIGURED` 阶段树。M1 已实现 WAF 会话与业务凭证的精确组合绑定、六类 operation 入口准入、页面证据与精确动作来源、有界资源资格账本，以及对应 PostgreSQL 约束和原子事务。Pingora MVP 网关可按可信 JSON 配置转发精确 `PUBLIC` / `AUTH_ENTRY` 操作；配置身份存储后，`AUTHENTICATED_ROOT` 会用租户隔离 HMAC 核对 `__Host-xshield_sid`、Bearer 凭证、当前 generation、epoch 和服务端期限。`UI_ACTION_REQUIRED` 会按不透明动作引用重验当前策略、页面证据和动作描述；GET 查询资源操作还会从实际 URI 严格提取资源与字段，以租户、站点和资源类型带域 HMAC 精确匹配资格账本。`SERVICE_IDENTITY` 使用独立边缘凭证头，按租户和站点带域 HMAC 精确加载 PostgreSQL 中的活动服务身份，并再次校验有限 operation 集和期限。`SHARE_ENTRY` 使用独立分享头，按租户、站点、资源、operation 和 view 精确加载 PostgreSQL 中活动且未过期的只读分享资格。分享发行 API 使用已验证的响应事实派生凭证与指纹，随后重新锁定当前身份与精确 ResourceGrant，要求活动策略中的独立发行规则批准目标 operation/view，并将 ShareGrant 与 outbox 原子提交后才把明文凭证交给响应适配器；来源失效、规则偏差、TTL 越界、幂等冲突或容量耗尽均不发行。分享令牌使用独立密钥按租户、站点和幂等键派生可重试的不透明长凭证，持久化与入口验证只接触另一用途密钥生成的 HMAC 指纹。按 operation 配置的 `BUFFERED_JSON` 响应适配器会在释放正文前完成 Content-Type、Content-Encoding、Content-Length、单请求与共享内存上限和完整 JSON 校验；非法、超限或共享配额耗尽均不释放正文，并以稳定原因写入 `origin.response` 与 `request.aborted`。响应资源规则会把已认证来源、业务成功状态、严格 JSON Pointer、唯一目标资源 operation、单响应数量、TTL 和会话容量在启动时一起编译；完整正文解析会拒绝重复 JSON 键、形状偏差、无效或重复资源值。已验证响应会保留原请求的 AuthSnapshot，在一个短事务内重验当前 binding、auth epoch、活动策略、精确动作描述和整批容量，再原子写入 ResponseEvidence、逐资源 ActionGrant、ResourceGrant 与 outbox；正文只在事务成功或精确重放确认后释放，失败不留下部分资格。显式 `resource_path_parameter` 可启用单个最终路径段适配器；它严格解码一次并拒绝额外查询、嵌套路径、编码斜杠、歧义路由和未精确命中的资格。缺失、替换、退休、过期、资源偏差、字段扩张或歧义查询均在源站前拒绝。WAF Cookie、动作引用、服务凭证头与分享头在访问源站前剥离。网关已接入加密分段 journal：准入、阶段、判定和转发意图必须批量持久化成功后才能访问源站，配额、写入或恢复失败均关闭转发。journal 按 `segment_max_bytes` 自动关闭并轮转；网关重启时在开放流量前认证扫描历史关闭段，为缺少终态或只留下合法批次前缀的请求耐久追加 `origin.unknown` / `request.aborted`，保留已收到的源站响应且不发起业务重试。独立封存命令可在 edge 持续写入时重验关闭段的 AEAD、CRC 与哈希链，生成包含整段摘要和链头的 Ed25519 签名清单，并以不覆盖方式持久化到独立私有位置。`xshield-worker` 按段顺序重新认证并解析事件，投递前后检查稳定 `event_id` 的正文摘要，ClickHouse 确认同步插入后才原子推进目标绑定的本地水位；同 ID 不同正文、缺失清单或水位冲突均停止后续段。worker 还可从重新认证的段与精确 checkpoint 生成连续索引水位、pending、unsealed、gap 和本地占用健康快照。

```bash
cargo test --workspace --all-targets
cargo run -p xshield-core --example m0_stage_tree
cargo test -p xshield-audit
scripts/test_postgres.sh
scripts/test_gateway_identity.sh
XSHIELD_CONFIG=examples/gateway-config.json \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_DATABASE_URL="$YOUR_POSTGRES_URL" \
XSHIELD_FINGERPRINT_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
cargo run -p xshield-gateway

install -d -m 0700 target/xshield-audit-manifests
XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_KEY_HEX="$YOUR_ED25519_SEED_AS_64_LOWERCASE_HEX" \
cargo run -p xshield-audit --bin xshield-audit-seal -- \
  target/xshield-audit-demo target/xshield-audit-manifests

XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_PUBLIC_KEY_HEX="$YOUR_ED25519_PUBLIC_KEY_AS_64_LOWERCASE_HEX" \
XSHIELD_CLICKHOUSE_URL="https://clickhouse.example.invalid:8443" \
XSHIELD_CLICKHOUSE_DATABASE="xshield" \
XSHIELD_CLICKHOUSE_USER="xshield_publisher" \
XSHIELD_CLICKHOUSE_PASSWORD="$YOUR_CLICKHOUSE_PASSWORD" \
XSHIELD_INDEX_TARGET_ID="clickhouse-primary" \
XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES="67108864" \
cargo run -p xshield-worker -- \
  target/xshield-audit-demo target/xshield-audit-manifests target/xshield-index-checkpoints

install -d -m 0700 target/xshield-control-audit
XSHIELD_TENANT_ID="tenant_demo" \
XSHIELD_SITE_ID="site_demo" \
XSHIELD_CONTROL_SUBJECT="audit-operator" \
XSHIELD_CONTROL_TOKEN="$YOUR_RANDOM_MANAGEMENT_TOKEN" \
XSHIELD_CONTROL_TOKEN_ISSUED_AT="$TOKEN_ISSUED_UNIX_SECONDS" \
XSHIELD_CONTROL_TOKEN_EXPIRES_AT="$TOKEN_EXPIRY_UNIX_SECONDS" \
XSHIELD_CONTROL_REQUESTS_PER_MINUTE="30" \
XSHIELD_CONTROL_LISTEN="127.0.0.1:9443" \
XSHIELD_JOURNAL_KEY_ID="journal-key-r1" \
XSHIELD_JOURNAL_KEY_HEX="$YOUR_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_SEAL_KEY_ID="seal-key-r1" \
XSHIELD_SEAL_PUBLIC_KEY_HEX="$YOUR_ED25519_PUBLIC_KEY_AS_64_LOWERCASE_HEX" \
XSHIELD_CONTROL_AUDIT_KEY_ID="control-audit-key-r1" \
XSHIELD_CONTROL_AUDIT_KEY_HEX="$YOUR_DISTINCT_64_CHAR_LOWERCASE_HEX_KEY" \
XSHIELD_CONTROL_AUDIT_MAX_BYTES="1073741824" \
XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES="858993459" \
XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES="67108864" \
XSHIELD_INDEX_TARGET_ID="clickhouse-primary" \
XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES="67108864" \
cargo run -p xshield-control -- \
  target/xshield-audit-demo target/xshield-audit-manifests \
  target/xshield-index-checkpoints target/xshield-control-audit
```

身份存储由可选的 `identity_store` 配置启用；`AUTHENTICATED_ROOT`、`UI_ACTION_REQUIRED`、`SERVICE_IDENTITY` 或 `SHARE_ENTRY` 路由存在时必须配置。运行时从 `XSHIELD_DATABASE_URL` 和 `XSHIELD_FINGERPRINT_KEY_HEX` 读取数据库连接与 32 字节 HMAC 密钥。UI 动作由自动注入探针通过 `X-Xshield-Action-Ref` 携带服务端发行的不透明引用；服务调用通过 `X-Xshield-Service-Credential` 携带独立边缘凭证；限权分享通过 `X-Xshield-Share-Token` 携带不透明凭证。这些边缘证明在转发前剥离，网关只信任 PostgreSQL 中与当前作用域、期限和活动状态精确匹配的记录。封存目标目录须预先以私有权限创建；独立任务周期运行 `xshield-audit-seal`，其 Ed25519 私钥仅注入封存进程。生产秘密均应由秘密管理器按用途注入和轮换，不写入配置文件或日志。

## Rust 运行时依赖

| 依赖 | 用途 | 许可证与更新策略 |
|---|---|---|
| Pingora 0.9.0 + OpenSSL backend | HTTP 代理生命周期、固定源站连接、请求过滤、journal AES-256-GCM 及段清单 Ed25519 签名 | Apache-2.0；精确版本并锁文件，部署同步审查 OpenSSL 版本与许可证，升级先复跑协议歧义、加密恢复、签名验证、转发和故障测试 |
| SQLx 0.9.0 | PostgreSQL 异步事务和连接池 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 migration、回滚和并发测试 |
| clickhouse 0.15.2 | 已封存审计段的类型化查询、同步批量投递与传输加密 | MIT OR Apache-2.0；精确版本并锁文件，升级先跑 RowBinary schema、重复投递、并发冲突和故障水位测试 |
| Tokio 1.51 LTS | SQLx 异步运行时 | MIT；跟随 1.51 LTS 补丁，变更 minor 前执行故障与负载回归 |
| serde / serde_json 1.x | 类型化配置 DTO 与 outbox JSON | MIT OR Apache-2.0；锁文件固定，补丁升级执行配置和契约测试 |
| UUID 1.x | 生成服务器侧 UUIDv7 请求 ID | MIT OR Apache-2.0；锁文件固定，补丁升级执行 ID 契约测试 |
| async-trait / bytes 1.x | 实现 Pingora 异步过滤器及有界拒绝响应体 | MIT OR Apache-2.0；锁文件固定，随 Pingora 兼容线评估更新 |
| Axum 0.8.x / Tower 0.5.x | 独立管理 HTTP 路由与可测试 Service 边界 | MIT；锁文件固定，升级先执行管理认证、作用域、限流、错误契约及审计回归 |
| crc32fast / zeroize 1.x | journal 快速损坏检测与秘密缓冲清零 | MIT OR Apache-2.0；锁文件固定，升级执行篡改、恢复和秘密生命周期测试 |
| chrono 0.4.x | 生成审计契约要求的 UTC RFC 3339 时间戳 | MIT OR Apache-2.0；锁文件固定，补丁升级执行审计契约与时钟异常测试 |

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

## 配套材料

| 路径 | 内容 |
|---|---|
| schemas/ | 4份自定义 JSON Schema：审计事件、证据manifest、模型调用、站点策略 |
| examples/ | 禁用状态的站点配置，合成审计事件与证据，78项待实施验收用例 |
| sql/ | PostgreSQL migration 与 ClickHouse 部署 schema；真实 ClickHouse 集成验证尚待执行 |
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
