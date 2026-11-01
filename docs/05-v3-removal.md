# 05 从 v3 到 v4 的删减清单

本次只重写了设计文档；`crates/`、`migrations/`、`web/console/` 等代码仍是 v3 实现。本章列出代码改造要删什么、留什么、补什么，作为后续改造的任务清单。旧文档可在提交 `ad524d4` 中查看（`git show ad524d4:docs/<文件名>`），代码注释里引用的 `docs/NN` 编号指的都是这些旧文档。

## 5.1 机制去留

| v3 机制 | v4 处理 |
|---|---|
| 策略发布双人审批（发起人 + 独立审批人） | 删除，单管理员直接生效（[03.1](03-admin-config-audit.md#31-单管理员)） |
| 界面操作来源验证、浏览器探针、心跳 | 删除，网关直接观察响应（[01.1](01-request-flow.md#11-组件)） |
| 资格账本（ActionGrant / ResourceGrant 精确匹配） | 删除，由会话上下文 + Jev 取代（[01.2](01-request-flow.md#12-会话与上下文)） |
| 按接口配置资源字段、响应提取规则、动作映射 | 删除，网关自动提取所有值（[01.3](01-request-flow.md#13-请求值)） |
| 六类入口（PUBLIC / AUTH_ENTRY / FLOW_ROOT / UI_ACTION_REQUIRED / SHARE_ENTRY / SERVICE_IDENTITY） | 合并为 `entries` 和 `bypass` 两个列表 |
| 网关签发分享凭证 | 删除，分享码由源站生成，兑换接口登记为入口（[00.4](00-overview.md#04-入口)） |
| WAF Cookie 与业务凭证强绑定、身份代际 | 删除，直接用业务凭证作为会话键 |
| 服务身份凭证 | 删除；服务间调用不经过网关，或把路径放进 `bypass` |
| 双向应用层加密接管 | 删除，首版不处理加密报文 |
| 策略引擎与规则型攻击检测 | 删除，攻击判定交给 Jev（[02.2](02-jev.md#22-调用内容)） |
| Jev 离线评估 CLI、模型 journal、证据重验缓存、校准、血缘审查、批量读取能力、校准报告 | 删除，Jev 改为请求路径内的同步调用（[02](02-jev.md)） |
| 封存审计 journal、ClickHouse 索引、outbox 发布器、加密证据库（本地 / S3） | 删除，改为 PostgreSQL 判定日志（[03.4](03-admin-config-audit.md#34-判定日志)） |
| 案件、证据访问申请与审批、保全、导出、调查检索 | 删除 |
| OIDC 登录、多角色、step-up、管理 API Key、Agent 管理 API | 删除，管理员口令登录 |
| 控制面向网关推送签名快照、快照持久化、收敛回放 | 删除，网关直接读 PostgreSQL |
| 观察 → 拦截上线模式 | 保留并简化为站点 `mode` 字段 |
| 反向代理、TLS、监听器、Jev 供应商接入 | 保留 |

## 5.2 代码模块去留

| 位置 | 处理 |
|---|---|
| `crates/xshield-core` | 保留领域 ID 和站点配置类型（按 [03.2](03-admin-config-audit.md#32-站点配置) 精简）；新增会话上下文、请求值提取、判定步骤；删除 `calibration`、资格与审批相关类型 |
| `crates/xshield-gateway` | 已删除；代理、TLS、监听器、上下文存储、Jev 调用与判定日志写入由全新的 `crates/xshield-edge`（配合 `crates/xshield-judge`）取代，而非在原地改造 |
| `crates/xshield-control` | 保留站点增改、模式切换；新增判定日志查询、配置历史与回滚、口令登录；删除审批状态机、案件、证据访问、保全、导出、校准报告、任务管理、API Key、OIDC |
| `crates/xshield-worker` | 已删除离线 CLI（`xshield-model-eval`）、`model_eval` 的 Jev 传输与响应解析（`transport.rs`、`wire.rs`）、outbox 发布器（模块与 `xshield-outbox-worker`）、校准（`calibration_audit`、`calibration_evaluator`、`calibration_vault_reader`）与证据迁移/清理二进制（`xshield-evidence-migrate`、`xshield-evidence-retain`）；没有移入网关，因为 `crates/xshield-judge` 已自带独立的 Jev 客户端。审计 journal 转 ClickHouse 索引的发布器（`PublisherConfig`、`publish_sealed_segments`、`inspect_publication_health`）与检索（`search.rs`、`local_request.rs`）仍被 `crates/xshield-control` 直接调用，整个 crate 暂不能删除；等 `xshield-control` 改造完成去掉这些调用后才能继续删到只剩本表其余各项同等程度 |
| `crates/xshield-audit`、`crates/xshield-evidence` | 删除 |
| `crates/xshield-postgres` | 只留站点配置、配置历史、判定日志三张表 |
| `migrations/`、`sql/` | 产品尚未上线，用一份新的基线迁移取代现有迁移；删除 ClickHouse schema |
| `web/console` | 只留站点配置、模式切换、判定日志、Jev 状态（[03.5](03-admin-config-audit.md#35-控制台范围)） |
| `sensor/` | 删除 |
| `deploy/` | 已删除（含 `compose`）；v4 尚无参考部署，这是已知且接受的缺口（[04](04-deployment-testing.md)），不在本次改造中补上 |
| `schemas/`、`examples/`、`validation/`、`templates/` | 换成 v4 的站点配置和判定日志样例，删除 v3 契约及其校验 |
| `tests/`、`scripts/` | IDOR 靶场改造成 [04.3](04-deployment-testing.md#43-验收场景) 的场景；删除只服务于已删机制的回归脚本 |
| `fuzz/` | 保留请求值提取、响应解析相关的 fuzz 目标，其余删除 |

建议按"先新增 v4 判定路径并跑通验收场景，再批量删除 v3 模块"的顺序改造，避免中间状态既没有旧能力也没有新能力。

## 5.3 环境变量去留

v3 代码读取下列 109 个变量。CI 的 `scripts/check_env_docs.py` 要求代码读取的每个变量都在文档里出现，这张表在代码改造期间同时满足这项检查；变量随代码删除后，从表中移除。

**保留（必需）**：`XSHIELD_DATABASE_URL`、`XSHIELD_EDGE_LISTEN_PORTS`、`XSHIELD_CONTROL_LISTEN`。

**保留（可选部署项）**：`XSHIELD_JEV_ROUTE`、`XSHIELD_JEV_API_KEY`、`XSHIELD_EDGE_TLS_CERT_PATH`、`XSHIELD_EDGE_TLS_KEY_PATH`、`XSHIELD_CONTROL_OPS_LISTEN`、`XSHIELD_CONTROL_CONSOLE_ORIGIN`、`XSHIELD_ALLOWED_UPSTREAM_CIDRS`、`XSHIELD_ALLOW_LOOPBACK_UPSTREAM`；`XSHIELD_EDGE_SITES_FILE`（仅开发，新增）。

**被替换**：

| v3 变量 | v4 |
|---|---|
| `XSHIELD_FINGERPRINT_KEY_HEX` | `XSHIELD_CONTEXT_KEY_HEX` |
| `XSHIELD_CONTROL_OIDC_CLIENT_ID`、`XSHIELD_CONTROL_OIDC_CLIENT_SECRET`、`XSHIELD_CONTROL_OIDC_ISSUER`、`XSHIELD_CONTROL_OIDC_REQUIRED_ACR`、`XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON`、`XSHIELD_CONTROL_ROLES`、`XSHIELD_CONTROL_SUBJECT`、`XSHIELD_CONTROL_TOKEN`、`XSHIELD_CONTROL_TOKEN_EXPIRES_AT`、`XSHIELD_CONTROL_TOKEN_ISSUED_AT` | `XSHIELD_ADMIN_PASSWORD_HASH` |
| `XSHIELD_CONFIG`、`XSHIELD_PUBLIC_HOSTS`、`XSHIELD_EDGE_APPLY_KEY_HEX`、`XSHIELD_EDGE_APPLY_LISTEN`、`XSHIELD_EDGE_APPLY_URL`、`XSHIELD_EDGE_BOOTSTRAP_ONLY`、`XSHIELD_EDGE_SNAPSHOT_PATH`、`XSHIELD_CONTROL_RECONCILE_INTERVAL_SECONDS` | 网关从 PostgreSQL 读取站点配置（含 `hosts`） |

**改为代码默认值**：`XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS`、`XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS`、`XSHIELD_CONTROL_REQUESTS_PER_MINUTE`、`XSHIELD_EDGE_RATE_LIMIT_SHARE`。

**删除**：

| 所属机制 | 变量 |
|---|---|
| 网关 TLS 多证书、PROXY 协议、运维监听（xshield-edge 只保留单证书 TLS） | `XSHIELD_EDGE_TLS_SNI_CERTS`、`XSHIELD_EDGE_TLS_SNI_CERTS_DIR`、`XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED`、`XSHIELD_EDGE_OPS_LISTEN` |
| 租户 / 站点固定作用域 | `XSHIELD_TENANT_ID`、`XSHIELD_SITE_ID` |
| 管理 API Key 与分页游标 | `XSHIELD_API_KEY`、`XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX`、`XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX`、`XSHIELD_CONTROL_CURSOR_KEY_HEX` |
| 案件、证据访问与调查查询 | `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS`、`XSHIELD_CONTROL_MAX_OPEN_CASES`、`XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS`、`XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS`、`XSHIELD_CONTROL_MAX_QUERY_EVENTS` |
| 控制面审计 journal | `XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES`、`XSHIELD_CONTROL_AUDIT_KEY_HEX`、`XSHIELD_CONTROL_AUDIT_KEY_ID`、`XSHIELD_CONTROL_AUDIT_MAX_BYTES`、`XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES` |
| 封存 journal 与常驻任务 | `XSHIELD_AUDIT_MAX_BYTES`、`XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES`、`XSHIELD_AUDIT_METADATA_RETENTION_DAYS`、`XSHIELD_JOURNAL_KEY_HEX`、`XSHIELD_JOURNAL_KEY_ID`、`XSHIELD_SEAL_KEY_HEX`、`XSHIELD_SEAL_KEY_ID`、`XSHIELD_SEAL_PUBLIC_KEY_HEX`、`XSHIELD_RUN_HEARTBEAT_FILE`、`XSHIELD_RUN_INTERVAL_SECONDS` |
| ClickHouse 索引 | `XSHIELD_CLICKHOUSE_DATABASE`、`XSHIELD_CLICKHOUSE_PASSWORD`、`XSHIELD_CLICKHOUSE_TABLE`、`XSHIELD_CLICKHOUSE_URL`、`XSHIELD_CLICKHOUSE_USER`、`XSHIELD_INDEX_TARGET_ID` |
| 加密证据库（本地） | `XSHIELD_EVIDENCE_BACKEND`、`XSHIELD_EVIDENCE_KEY_HEX`、`XSHIELD_EVIDENCE_KEY_ID`、`XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES`、`XSHIELD_EVIDENCE_MAX_RETENTION_DAYS`、`XSHIELD_EVIDENCE_ROOT` |
| 加密证据库（S3） | `XSHIELD_EVIDENCE_S3_ACCESS_KEY_ID`、`XSHIELD_EVIDENCE_S3_ADDRESSING`、`XSHIELD_EVIDENCE_S3_ALLOW_PLAIN_HTTP`、`XSHIELD_EVIDENCE_S3_BUCKET`、`XSHIELD_EVIDENCE_S3_ENDPOINT`、`XSHIELD_EVIDENCE_S3_OBJECT_LOCK`、`XSHIELD_EVIDENCE_S3_PREFIX`、`XSHIELD_EVIDENCE_S3_REGION`、`XSHIELD_EVIDENCE_S3_REQUEST_TIMEOUT_SECONDS`、`XSHIELD_EVIDENCE_S3_SECRET_ACCESS_KEY`、`XSHIELD_EVIDENCE_S3_SESSION_TOKEN`、`XSHIELD_EVIDENCE_S3_SSE_KMS`、`XSHIELD_EVIDENCE_S3_SSE_KMS_KEY_ID` |
| 应用层加密接管 | `XSHIELD_REQUEST_DECRYPTION_KEYS`、`XSHIELD_REQUEST_DECRYPTION_KEY_HEX`、`XSHIELD_RESPONSE_ENCRYPTION_KEYS`、`XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX` |
| 网关签发分享凭证 | `XSHIELD_SHARE_TOKEN_KEY_HEX` |
