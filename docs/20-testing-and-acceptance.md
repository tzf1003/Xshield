# 20 测试策略与验收矩阵

## 20.1 分层测试

单元：纯政策、ID/时间/字段校验、同主体续期与换账号隔离。性质测试：任意目标/动作扩张不应通过精确资格；不同租户同 ID 不串域；输入排序/重复键不会引入解析差异。Fuzz：HTTP/JSON/压缩/协议适配/插件/事件解码。

集成：PostgreSQL 条件提交、outbox、journal 崩溃恢复、ClickHouse 重复事件和水位、证据加密/读取授权、模型 timeout/cancel。端到端：受控浏览器 + 含有已知授权缺陷的测试源站，验证 Xshield 附加流程，不访问真实业务用户数据。

审计测试是功能测试的一部分：每个结果的 event_id、stage、cause、input/output refs 与完整性清单均有断言。stdout 中没有报文，不代表证据库已留存；二者分别验证。

## 20.2 关键验收组

| 组 | 用例范围 | 必须满足 |
|---|---|---|
| IDENTITY | 新 Cookie、A/B 拼接、冲突认证、刷新、换租户、旧响应 | 认证链不能混搭或继承错误账本 |
| FLOW | 列表/创建、无来源直达、TTL 内复用、共享、隐藏组件 | 只认可有效动作与目标 |
| CRYPTO | 三种接管、响应不可见、版本变更、AAD/签名失败 | 实际检查/重建内容一致，失败不被洗成兼容 |
| POLICY | 读写、字段、批量、父子对象、GraphQL、角色功能 | 不把见过 ID 扩展为操作权 |
| MODEL | NONE、低信心、Score 档位/加权评分、Noul、提示注入、超时、缓存、版本变动 | 不伪造 confidence，不覆盖硬拒绝 |
| AUDIT | 每层、跳过、证据链、断网、磁盘满、重启、去重 | 必需事件可追溯，缺失可见 |
| CONSOLE | ID 横向访问、原文审批、导出、自然语言查询 | 不绕过租户/敏感权限，查看本身可审计 |
| RECOVERY | 重放、取消、未知源站结果、撤权、备份恢复 | 不重发非幂等写，不复活旧资格 |

机器化验收目录见 examples/acceptance-cases.json，包含独立 case_id、步骤、期望和关联不变量；这里只提供设计用例，不声称已经对运行产品执行。

## 20.3 误拒与安全收益

离线阈值内核用 `cargo test -p xshield-core --all-targets` 验证固定阈值、未知标签、模型缺失、零分母、重复样本、概率边界和可靠性桶。`tests/threshold_metrics.rs` 的独立手算集合包含一次 timeout 与一个未知标签：误放为 1/3、误拒为 1/2、决定覆盖为 4/6、弃权为 2/6，Brier 仅四个可评分样本得 0.41。这些测试验证统计计算，真实数据独立性、模型质量和生产阈值须另行验收。

同一命令还运行 `calibration::dataset` 回归：四份训练/校准/评估/标签 manifest 必须引用不同 artifact，且不能与任何样本模型调用或标签 evidence 复用；单样本模型调用与标签 evidence 不得别名；同角色重复 artifact、跨角色复用、重复 `ModelCallId`、模型身份或映射修订漂移均被拒绝。成功路径断言保留冻结 provenance、按输入顺序的调用 ID—模型记录—标签证据三元关联、显式阈值和未知的 resolved provider revision。该组只验证纯领域约束，不能验证 artifact 内容独立、证据读取授权/解密、标签审查、持久报告/审计或真实供应商质量。

同一 core 命令还运行 `calibration::publication` 回归：新 `calr_` report ID 与 report artifact 会保留冻结的 approval、六项 revision、四份 manifest 和 ModelIdentity，未知 resolved revision 保持未知；report artifact 与任一 manifest 或任何已选模型记录/标签 artifact 的别名都被拒绝，成功及错误原因分别稳定为 `CALIBRATION_REPORTED` 与 `CALIBRATION_REPORT_EVIDENCE_ALIASED`。artifact 回归还固定 canonical JSON、浮点 bit 表示及 source/metrics 闭合约束，拒绝重复、未知、敏感或非规范字段。`xshield-evidence` 回归确认专用 request-free sidecar、tenant/site/report/artifact AAD、读取回环和 generic retention 隔离。`calibration_report` 的真实 PostgreSQL 回归覆盖 artifact-first 数据库冲突不消费 lease、报告 metadata/completion/report outbox 同事务、精确未知提交重试，以及 runner 不符、catalog drift 和到期拒绝；它们不验证外部内容独立、真实 evaluator/供应商质量、阈值选择或策略发布。

同一 core 命令还运行 `calibration::read_capability` 和 `CalibrationEvidenceReadPort` 契约回归：`calcap_` batch capability 只允许冻结 tenant/site、有效期、四份不同 manifest、按样本顺序的 model-record/label artifact 对及明确 role；空集、样本或 512 MiB 字节上限越界、无效期限、artifact 别名、跨 scope、尚未生效和到期均必须拒绝。`CalibrationEvidenceReadRequest::new` 还要求一个同 capability、同 scope、完全处于 capability 期限内的已发行 batch lease/session；无效 lease handle、错 capability/tenant/site、超出 capability 期限或未到开始时间均拒绝，且不同内存 capability 的 session 不能复用。其余反例把 scope/lease/session 偏差、来自另一 capability 的克隆 ref、集合外或 role/reference 不符的目标统一映射为 `EvidenceNotAuthorized`（`CALIBRATION_EVIDENCE_NOT_AUTHORIZED`），且不得以控制台 `EvidenceReadPort`、`ApprovalRef`、案件或审批记录授权 batch。`CalibrationEvidenceBatchCompletion` 还要求成功 `EvaluationReport` 的 provenance 与有序完整 source pair 精确匹配 capability，且消耗 session；部分、替换或另一 provenance 的 report 均拒绝。它们只是纯领域/port 约束：不验证 capability 的独立发行与单次消费、真实 PostgreSQL catalog/期限/字节核算、vault digest/AEAD、内容 DTO、读取审计、报告写入/producer/outbox 或真实校准。

同一 core 命令还运行 `calibration::lineage_review` 回归：四个声明角色必须逐项绑定冻结的训练/校准/评估/标签 manifest，独立 `calrev_` review artifact 不能复用任何 manifest；训练/校准/评估只能声明 corpus，标签只能声明 reviewed-label。每一个 root 与 parent 都绑定 source ID 和 revision，输入次序会被规范化。测试覆盖 unknown、重复、self parent、跨分区 parent、环、不可达来源、review artifact 别名、provenance artifact 漂移、版本错配及排序等价。该组只验证提交的有界声明图，不读取 corpus、不验证未提交 ancestry、内容去重、外部数据独立、标签质量、存储/审计/outbox 或阈值发布；这些各有独立验收门槛。

当前 review artifact/vault/outbox 单元覆盖还检查 canonical body 的闭合表示、tenant/site/review/artifact/kind/encoding AAD 绑定、认证 sidecar 与 fresh attestation，以及 `calibration.partition_lineage.reviewed` 的封闭 parser。parser 反例覆盖 unknown/重复字段、producer、policy、aggregate、request、时钟、trace/span、artifact/evidence-ref 漂移和 source graph、source ID/revision、source-graph digest、样本、标签、指标等敏感字段注入；索引摘要保持 deterministic 空置信度和非业务终态。这些是本地契约覆盖，不能替代真实 PostgreSQL 的事务、行锁、registry 并发冲突或 vault-first crash recovery 验收。

`calibration_read_capability_is_atomic_exact_and_recovery_safe` 在专有临时 PostgreSQL 16 数据库运行：顺序应用迁移 0001–0028，覆盖完整成员/聚合字节冻结、scope digest 与完整 snapshot 的精确重试、catalog 漂移拒绝、header/member/issuance outbox 原子提交、并发单 lease、数据库时钟到期后的 recovery-required、旧 lease 弃置与 16 次恢复上限，并确认数据库只保存私有 handle digest。发行和每次 active use 都将 manifest、model-call、reviewed-label role 绑定至专用 kind、受限 JSON content-type、semantic fidelity 与 restricted classification；任一 metadata 漂移统一拒绝。该回归还覆盖内容打开前的再授权及 release reservation：精确 session/lease token digest 与 artifact/role/sample slot 返回私有 catalog 预期，伪造 token 或 catalog 漂移统一拒绝；reservation 存活期间 catalog 变更被拒绝，release-boundary 提交后变更恢复可用；普通未保留 catalog 删除可继续执行；控制的 lease 到期发生在 receipt 后、release-boundary 前时，最终提交拒绝且不交付内容。completion 回归证明普通单对象授权后 capability/lease 仍为 `leased/active`；只有完整 evaluator result、相同 runner 与私有 token digest 才在一事务变为 `consumed/completed`，错误 runner 不改变状态，同一 token 的未知提交重试返回既有完成，完成后再读被拒绝，并核对 capability completion reference 与内容无关的 `calibration.read_batch.completed` outbox 终态同事务存在。worker 已对 issuance/completion 的封闭 payload 及 capability aggregate 进行严格解析；真实 ClickHouse 端到端投递和真实校准仍需各自验收。

`cargo test -p xshield-worker --lib calibration_audit` 验证专用 `calibration.evidence_read` journal 事件的封闭 envelope、UTC 毫秒、producer/trace/span 绑定、所有 `PASS`、`DENY`、`ERROR` 原因码、无内容字段和收到的 receipt；helper 还验证冻结 sequence 被并发写入推进时拒绝 append。`cargo test -p xshield-worker --lib calibration_vault_reader` 验证 vault 完整性与不可用错误分别映射为 `CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED` 和 `CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE`。`scripts/test_postgres.sh` 在专有临时 PostgreSQL 库与私有 vault/journal 目录中运行真实 reader 回归：已发行 capability、active lease、catalog 与密文对象逐一读取，返回前读回 `PASS` journal record；AEAD 损坏只产生无字节 `ERROR`；journal append 失败不交付 plaintext；completion 后再次读取为无内容拒绝。journal 无法准备、追加或确认时不会伪造 `ERROR`，而是返回 audit-unavailable 并扣留 plaintext。该组同时确认读取不消费 batch，只有独立 completion 改变 lease/capability 终态。

本产品主动禁止的无资格直达、换浏览器未重获资格，不计为违反需求的误报；应另计 intentional_flow_denial 与恢复体验。被认可流程中的正常请求因竞态/映射错误拒绝，才是实现误拒。

固定测试身份、源站版本和授权/流程矩阵，分别比较 baseline、加密可见性、确定性资格、UI 来源、模型增量。不要把账本收益全部算作 JEV 模型收益。

## 20.4 并发/故障必测

匿名会话同来源并发创建、跨来源站点容量和限流窗口恢复；登录切换与旧列表响应；双刷新乱序；授权查询与撤销交叉；多个 edge 重复消费 nonce；资格事务提交但 outbox publisher 崩溃；转发后终态日志未写；内容已持久但索引未到；对象丢块/重复 event_id 不同内容；模型请求已计费但响应超时；节点 journal 与 KMS 同时不可用。

每个故障注入注明实际故障范围，进程 kill 测试不等于整盘损坏测试，单节点测试不等于跨区域一致性测试。

资格读取回归覆盖服务身份、分享、资源资格、UI 动作及页面/响应来源证据：应用时间先到期时拒绝；数据库已到期而应用时间滞后时也返回既有拒绝语义。测试复用真实 PostgreSQL 读取端口及合成账本，修改的时间字段在局部事务后恢复。

`scripts/test_postgres.sh` 另运行 `request_replay`：双唯一键与并发消费、快时钟实例的容量检查和 nonce 保留、慢时钟实例的过期拒绝，以及 advisory lock 和插入唯一键等待跨期。测试以 `pg_blocking_pids` 确认实际等待，期限后释放锁，断言消息未消费且清理同步回滚；正常消费仍清理过期行。`scripts/test_gateway_request_crypto.sh` 验证真实 HTTP 封包、稳定原因码及源站接收次数。

资格发行回归通过 `provenance_waits_recheck_short_action_expiry_and_revocation` 验证短动作期限在身份、策略、描述、页面、已有动作与 outbox 等待后生效：过期写入整笔回滚，已有记录保留，后续有效发行成功；另覆盖策略/描述退休和页面/动作撤销的并发提交。响应批量回归核对各项实际落库期限，并覆盖最短项在身份锁、已有证据/资格锁或后项 outbox 唯一键等待时到期，验证整批资格和 outbox 的原子回滚及精确重试状态。锁等待均以 `pg_blocking_pids` 确认，数据库服务调用纳入 `scripts/test_postgres.sh`。

## 20.5 发布闸门

P0 硬不变量全部通过；无资格与凭证串用拒绝可解释；秘密不进入普通日志；审计断网恢复有测试；高危操作模型停机策略明确；真实业务协议闭环通过；性能和容量达批准预算；未知项在控制台可见；可回滚版本已验证。

Schema/Markdown/示例校验只是文档质量检查，不能替代以上产品验收。

## 20.6 ClickHouse 真实集成回归

CI 使用固定版本 `clickhouse/clickhouse-server:25.8.29.51`，开发机可连接同版本的专用测试服务。测试账号需要创建/删除测试库、表、视图及用户、授予测试视图读取权限和暂停测试表 TTL 合并的权限；生产控制账号继续只读取 active 视图。

```bash
XSHIELD_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
cargo test -p xshield-worker --lib real_schema_publisher -- --ignored
XSHIELD_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
cargo test -p xshield-worker --test clickhouse_search -- --ignored
```

需要认证时另设 `XSHIELD_TEST_CLICKHOUSE_USER` 和 `XSHIELD_TEST_CLICKHOUSE_PASSWORD`。测试使用 UUID 命名的独占数据库，直接加载 `sql/clickhouse.sql` 并重复执行完整 DDL。普通视图采用 `CREATE OR REPLACE VIEW` 更新定义。断言失败后仍同步清理测试创建的资源；进程被强制终止时由测试服务的生命周期回收资源。

查询回归覆盖 `audit_events_active` 和通过物化视图填充的 `events_by_time_active`：租户/站点隔离、可空 LowCardinality 字段、`ALLOW`、微秒及同时间戳 keyset 双向分页、闭开时间窗口、全部类型过滤器与同事件 AND 语义、重复事件合并、最早期限优先及物理 TTL 清理前隐藏过期行。查询使用只获两个 active 视图 `SELECT` 的独占测试账号，同时断言直接读取两张底表返回权限拒绝。

案件/证据过滤回归包含实际契约的事件/阶段与目标字段、evidence_refs 成员、失败管理目标、空/缺失/嵌套字段、无关类型/错配阶段、作用域和同事件 AND，以及双向 keyset 分页。控制层 `reference_search` 测试验证规范 ID、严格/重复字段、8 项预算、原有摘要兼容、每个 ID 与过滤顺序的游标绑定、返回脱敏和计划摘要审计。

发布回归从加密 journal 与签名清单开始，验证真实 `FixedString` 编码、两张物理表的精确摘要和微秒时间读回、同步确认后的水位提交与 checkpoint 重用；继续追加同 event_id 的不同内容时，发布器必须返回完整性冲突，保留原水位并显示待投递段。

模型阶段回归由实际加密 journal 经封存和发布入库，验证 `mdl_` 调用引用、已知/缺失模型版本以及有界模型版本过滤。阶段汇总回归在同一阶段先写数值置信度，再写 `not_applicable`、`not_provided` 或 `unavailable` 的 null，确认两套 active 视图都返回最新 null 与匹配状态。常规测试另覆盖置信度矛盾、非法模型引用和版本、时间线分页预读行校验；这些合成事件验证审计链路，不代表实际模型推理或准确率测量。

模型调用回归在同一隔离测试库封存并发布 `started → requested → responded`，通过生产 `query_model_call` 验证 tenant/site 隔离、版本、置信度、四类证据引用与因果链完整性；模型完成仍保持业务请求未终结，精确重投复用三段 checkpoint 且物理行数不增加。常规 worker 测试覆盖可见前缀/后缀/中间缺失、发出前失败、Noul 空置信度、畸形生命周期及响应上限；控制测试覆盖 Observer 权限、非法 UTF-8 路径、未命中、审计故障扣留结果、查询预算和 search/model 共用许可在客户端断连后保持到终态审计。

查询预算测试以同一小数据集收紧服务端结果行数上限，验证真实预算异常映射为 `QueryBudgetExceeded`。普通 `cargo test --workspace --all-targets` 会编译这些测试但按 `ignored` 跳过服务调用，必须执行上述命令才能形成真实数据库验证结果。执行时间/扫描/内存预算、集群故障和生产规模容量仍须分别验证。

## 20.7 模型评估回归

`cargo test -p xshield-worker --lib model_eval` 运行严格 DTO、重复键、版本、候选/概率/置信度、文本/字节上限及真实 loopback HTTP 传输测试；覆盖固定目标、单次 429/529/重定向、超时、取消、响应前缀和 API key 排除。另验证私有输入、目录排他/容量与中断终态恢复。

`scripts/test_postgres.sh` 在独立临时库迁移后运行 `model_eval::tests::postgres_evaluation`：实际 HTTP 字节与解密输入证据一致，供应商输出捕获、规范化记录和目录均可读取，所有 `model.*` journal 事件通过生产索引解析；验证成功、429、非法响应和秘密排除，并注入 catalog/outbox 写入失败确认 HTTP 未调用。该测试单独运行需要 `XSHIELD_TEST_DATABASE_URL`，默认常规测试会跳过。全部样本和 API key 均为合成数据；真实供应商推理、计费、检测率与校准另行批准和测量。

## 20.8 案件证据关联回归

`cargo test -p xshield-control case_evidence --lib` 验证机器凭证、角色、作用域、过期身份、速率限制、严格 DTO、重复字段/幂等头、非法 UTF-8 路径、4 KiB 请求上限、在途容量与存储故障的审计和安全错误。

`scripts/test_postgres.sh` 应用迁移 0017 后执行存储并发/反例测试及 `case_evidence_is_durable_idempotent_and_disconnect_safe`：真实案件创建、vault/catalog 发布、加入证据、精确重试、冲突、缺失目标、客户端在行锁等待时断连后继续提交与终态审计、管理审计失败后的 outbox 保留及幂等确认。回归确认关联不改变对象到期时间、不创建原文审批，单有案件关联的 Reader 仍无法读取正文。独立数据库测试验证跨租户/站点、非本人/关闭案件、到期/删除对象、容量竞争与 outbox 故障回滚；这些测试默认 ignored，需可用 PostgreSQL 环境运行。

## 20.9 案件证据集合查询回归

控制层回归覆盖坏路径、坏/越界游标、跨案件/主体 HMAC 绑定、鉴权与速率、共享在途许可、数据库故障以及审计失败扣留结果。真实 PostgreSQL 回归验证单快照下的 open/closed 案件归属、跨租户/站点与非本人统一不可用、稳定 artifact 游标分页、active/expired/deleted catalog 状态、成员顺序/128 项上限以及缺失或错绑 outbox 的拒绝；`unavailable` 仅作为防御性 catalog 缺失分支保留并由纯函数状态测试覆盖。查询为只读，不改变 membership、期限或内容授权。

## 20.10 案件关闭回归

`cargo test -p xshield-control case_close` 覆盖强类型路径、严格 DTO/重复字段、重复幂等头、4 KiB 上限、角色/作用域/凭证期限/速率、共享在途容量、数据库故障与审计失败扣留响应。

`scripts/test_postgres.sh` 应用迁移 0018 后运行存储幂等、归属、作用域、并发和 outbox 故障回滚测试，以及 `case_close_is_durable_revokes_new_access_and_survives_disconnect`。HTTP 闭环从创建案件、关联真实 vault/catalog 证据、独立批准和读取开始，验证关闭后集合保留、后续关联/访问申请/读取拒绝、证据期限与批准历史保持、open 容量释放；另验证客户端在案件锁等待时断连后提交与终态审计、管理审计失败后的幂等恢复。这些集成测试默认 ignored，由脚本在独立临时数据库执行。

存储组合回归还验证 pending 配额恢复：申请占满额度后关闭案件，另一 open 案件的新申请仍受限；独立审批人拒绝 closed 案件的原申请后，新申请成功，原申请的 denied 历史保留。

## 20.11 管理审计发布回归

`cargo test -p xshield-worker --lib control_audit` 覆盖严格 DTO、事件/方法/路由绑定、主体和目标 ID、成功/拒绝/依赖失败、查询摘要、读取字节数、证据引用及确定性空置信度；损坏或事务 outbox 形状不会被当作管理访问日志接受。

`cargo test -p xshield-control --lib management_audit` 由实际管理事件生产者及 HTTP 路由写入 journal，经封存和现有发布器验证报文兼容与 checkpoint 重用。配置 20.6 的专用 ClickHouse 后，执行 `cargo test -p xshield-control --lib management_audit -- --ignored`，在独占数据库运行同一路径并读回索引、时间线、有界搜索及跨租户/站点隔离。该真实数据库测试纳入 CI；普通 workspace 测试只编译并跳过其服务调用。

保留锁管理的三类 `console.evidence.hold.*` 也走同一生产 journal、封存和投递回归，覆盖创建/释放及精确重试原因、空列表、拒绝和依赖故障；worker 与 Schema 同时拒绝目标/方法/路由错绑、越权携带 hold 目标及未知字段。

同一真实数据库回归通过 `/control/v1/search` 按 case_id、artifact_id 及两者组合双向逐页读取上述已发布管理事件，逐项与生产 journal 对照；检查已发布水位、脱敏字段、每页终态审计及查询日志再次发布。查询日志只保留计划摘要，目标 ID 不进入该访问日志。

`cargo test -p xshield-control case_holds` 覆盖严格路径/JSON/UTC 毫秒（含闰秒反例）、重复认证和幂等头、4 KiB/UTF-8 长度、权限/作用域/凭证期限/速率、在途上限、存储故障及审计扣留。`scripts/test_postgres.sh` 另执行 `case_holds_are_scoped_idempotent_paginated_and_audited`：真实 vault/catalog/案件关联后由独立管理员创建、释放和分页，检查幂等冲突、过期/超长新期限、目标隔离、游标全部绑定、同对象多条历史去重引用、关闭后释放与查询、原期限和审批保持、提交后审计故障恢复及断连后的提交/审计。核心主体测试检查启动身份规范且保持原值。

保留管理控制台另以 Node 单测验证规范请求、目标和原参数关联、时间/状态/释放字段完整性、128 项上限及升序游标边界；Playwright 使用显式合成响应覆盖创建→查询→释放、冻结原请求恢复、权限与晚到响应、会话清态及响应式布局。`console_hold_client_mutates_postgres_http_contract`（纳入 `scripts/test_postgres.sh`）运行真实 PostgreSQL、Axum、Node 客户端和独立管理 journal，核对非案件所有者管理员的创建/释放、精确重试、参数冲突、跨租户/站点隔离、独立角色拒绝、关闭后释放及分页历史；同时验证 outbox 数量和目标、catalog 原期限、原文申请表与管理理由脱敏。它使用专有临时库与合成对象，未访问生产证据或企业身份服务。

## 20.12 outbox 发布回归

`scripts/test_postgres.sh` 的 `case_evidence_holds` 回归使用真实加密 vault、catalog 发布和案件成员事务，覆盖创建/释放幂等、作用域和目标状态、历史/活动容量、outbox 故障回滚及损坏事实拒绝。`pg_blocking_pids` 确认创建和清理两种锁顺序，检查活动锁阻止新删除意图、释放/到期恢复、多个案件共享对象和既有意图拒绝新锁；原始期限与过期拒读单独断言。测试只操作脚本拥有的数据库与独占临时文件。

同一存储回归覆盖保留历史的单 SQL 快照、1–128 页界、空/缺失/跨域案件、closed/过期/已释放记录、创建及释放 outbox 缺失/错绑/损坏（含预读行）整页拒绝，并在释放提交前后读取一致历史。查询前后对相关持久表作完整快照比较，确认只读。

`cargo test -p xshield-worker --lib outbox::hold` 覆盖两类保留锁完整事件、未知/重复/缺失字段、主体与目标、创建/释放因果、规范 UTC 毫秒和 30 天期限。真实清理 producer 回归另创建并释放案件锁，同一发布测试消费实际生成的两类 hold 及六类删除事实；维护族的其余确认、查询和故障行为沿用下述检查。

`cargo test -p xshield-worker --lib outbox` 覆盖三个 `case.*` 类型、`evidence.cataloged` 的两个真实 producer、`evidence.access.*` 的请求/批准/拒绝、`calibration.reported` 的受限元数据、五种身份事务形状、`grant.issued`、`response_grant.issued`、`share.issued` 以及六种清理事件。反例包含显式 nullable TTL、目标与请求/boot 绑定、匿名/认证初态、代际递增与 bigint 上限、上下文变化、重复凭证 kind、非法指纹、重复/未知键及 journal/outbox 来源隔离；响应资格另覆盖封闭 payload、批内序号/candidate_count、ID/动作引用、单字段/GET/2xx（排除 204）约束、HMAC/正文摘要、TTL 和规范 UTC 整秒与发行时间的一致性。通用资源资格另覆盖 event/boot、来源请求/策略一致、scoped action_ref、约束摘要和整秒/TTL 约束。分享另覆盖 event/boot/share 绑定、独立发行序号、来源资格与规则形状、GET/reusable_read、秘密字段拒绝和整秒/TTL 约束。清理另覆盖十种原因/outcome、独立 boot、显式 null request_id/confidence、artifact/cause、catalog/孤儿形状隔离、UTC 毫秒与失败尝试时钟倒退。索引摘要固定为确定性空置信度，不设置业务终态。

`cargo test -p xshield-worker --lib outbox::calibration` 还覆盖 `calibration.reported` 及报告保留维护的完整受限 envelope：固定 producer/policy/聚合、report artifact 与唯一 evidence_ref、四份 manifest 的 distinctness、显式 null 或合法 resolved revision、UTC 毫秒、trace/span、intent/完成/失败因果和非终态 deterministic 摘要，以及缺失、未知、重复 JSON 键、错误 identity/时钟、artifact 别名和敏感字段反例。该组验证 schema/消费端拒绝与索引摘要；它不替代受控 evidence 读取、专用 report vault/数据库提交、阈值/策略发布或真实模型质量的验收。

同一 calibration outbox 单元已加入 `calibration.partition_lineage.reviewed`：只接受固定 producer/policy、`calrev_` aggregate、null request、数据库 UTC 毫秒、review artifact 的唯一 evidence_ref、冻结 provenance 与四份不同 manifest；对 source graph、source ID/revision、source-graph digest、样本、标签、指标和正文实行封闭字段拒绝。该覆盖只验证 producer/consumer 契约与索引摘要，不能证明持久 review 事务、全局 artifact registry、catalog 活性重验或 corpus 独立。

`calibration_lineage_review` 的专有 PostgreSQL 16 回归顺序应用迁移 0001–0033，vault-first/fresh-attest-first 地提交 review artifact、projection 与 restricted outbox，并断言精确 `Existing` 在正常 catalog retention 后仍可恢复、catalog semantic-fidelity drift 收敛为无落库的 `Unavailable`，以及同 artifact ID 已被 request catalog 占用时收敛为 `Conflict`。新的 report projection 也冻结 capability 的 lineage review ID，使 consumed 状态的未知提交恢复同时精确比较 capability header 和 report projection，不能借正常 retention 绕过该绑定；0032 另拒绝普通数据库 writer 重绑已经提交的 capability 或 report review ID。报告回归另以 `pg_blocking_pids` 确认其已在 capability header 行锁后，再提交使用相同 artifact ID 的新 lineage review；解除锁后只允许 review 保留 registry owner、artifact/projection/outbox，report 必须返回 `Conflict`，并保持 capability `leased`、lease `active` 及零 report 行/事件。0033 的独立回归覆盖 review body 和 request-free orphan 的 intent-first 记录、同一 intent 恢复、already-absent 完成及 deleted tombstone；schema/library checks 覆盖六类 maintenance event 的封闭 envelope。`scripts/test_postgres.sh` 显式运行 `calibration_lineage_review_retention` ignored 测试。尚待覆盖 review/report 的反向或更多交错、event/provenance/每种 manifest drift、kind/expiry/deleted/purge 的更多组合、无 capability/lease/reader 授权状态改变、以及实际 ClickHouse 投递；本结果不把声明审核表述为 corpus 内容独立性证明。

`scripts/test_postgres.sh` 在专有临时数据库运行 `xshield-postgres` 的全量 ignored 回归、报告提交与报告保留回归，以及 worker 的 `postgres_outbox_publishing` ignored 测试。存储层用显式行锁和数据库时间验证按族/tenant/site 领取、行/字节预算、`SKIP LOCKED` 并发、过期租约重领、旧 token/跨作用域拒绝、精确确认及有界重试。worker 使用真实 PostgreSQL 与受控 ClickHouse HTTP 响应，验证校准报告提交、报告 body 保留、request-free orphan 回收及各族按生产契约构造的 envelope；同时检查确认后不再领取、未适配族不被修改、索引失败后重试成功、插入前后完整性冲突、scope/aggregate 错绑和历史稀疏身份/通用资源资格/响应资格/分享行保留未确认状态。该回归不验证真实 ClickHouse DDL、去重和 active 视图。

同一脚本的 `grant_issue` 集成测试用数据库时钟和 `pg_blocking_pids` 确认真实锁等待，覆盖 binding、已有 grant 和 outbox 唯一键三个位置的跨期拒绝，失败不新增账本或 outbox。它还覆盖并发撤销后的重放拒绝、动作/策略失效、独立 grant ID/trace/冻结时间冲突（含存储子秒偏差），以及 outbox aggregate/type 错绑；批准约束含嵌套指数数字、小数、负零、Unicode 与大整数，并覆盖 JSONB 展开超限时原子拒绝。普通单测验证 trace、约束对象/16 KiB 上限、容量和 TTL/整秒时间范围。

`postgres_outbox_publishing_generic_grant_producer` 读取以上 `GrantPersistence` 实际提交的行，逐字段核对授权事实与完整 envelope、批准约束摘要及冻结时间，再经通用资格发布 API 验证索引、精确确认和空重跑。未配置 ClickHouse 时使用受控 HTTP；配置后使用独占 ClickHouse 库和生产 DDL，读回两个底表及两个 active 视图。它只接受脚本拥有的 `xshield_test_*` 数据库，验证范围是库生产者至双库投递。`GrantPersistence` 不设独立 HTTP 面；真实站点来源发行的 HTTP 闭环由下述网关响应资格回归验证。

`scripts/test_gateway_identity.sh` 通过真实网关、合成源站和专有 PostgreSQL 库执行匿名创建、登录、刷新与同主体上下文切换，保留原有认证、CAS、旧资格隔离及错误响应断言，同时检查生产 v3 envelope 与请求 ID。脚本结束前运行 `postgres_gateway_identity_outbox_publishing`，将实际生产的四种身份事务通过 worker 投递给受控 ClickHouse HTTP 服务，核对 RowBinary 索引、摘要、确认和重复运行空批次；该测试只接受脚本拥有的 `xshield_gateway_*` 数据库。

配置 20.6 的 `XSHIELD_TEST_CLICKHOUSE_URL` 及测试账户后，同一网关脚本还会运行 `real_gateway_response_grant_outbox_delivery`。脚本产生两个响应、三个实际响应资格事件，其中一个响应含两个资源；测试把 envelope 与 PostgreSQL 响应证据、动作及资源资格行逐项比对，检查批内连续序号，再通过生产发布器写入真实 ClickHouse，读回两个底表与两个 active 视图，验证精确确认和重复运行空批次。源路径只接受已认证会话的严格成功响应，字段碰撞、重复键、资源偏差、来源撤销、epoch/policy/action 变化、容量耗尽和锁等待跨期均不会释放正文或留下部分资格。该链路已在真实 PostgreSQL 与 ClickHouse 联调通过；入口仅接受脚本拥有的数据库，未配置 ClickHouse URL 时明确报告跳过。

配置同一 ClickHouse 环境后，`scripts/test_postgres.sh` 还会运行 `real_outbox_clickhouse_delivery`：在专有 PostgreSQL 临时库和独占 ClickHouse 数据库内重复应用生产 DDL，通过八族发布 API 投递十七组按生产契约构造的合成 envelope，读回两个底表及两个 active 视图，核对作用域、事件引用、SHA-256 digest、事件时间（通用资源资格、响应资格和分享为整秒，其他样本含微秒）、保留期限、确定性空置信度和非业务终态，并逐行检查 PostgreSQL 精确确认与重复运行空批次。该回归已在真实 PostgreSQL 与 ClickHouse 执行通过；真实数据库回归入口均纳入 CI。普通 workspace 测试将其标为 ignored，必须实际运行相应脚本才能形成验证结果。

同一脚本先执行实际 `evidence_retention` CLI/存储故障回归，再运行 `real_retention_outbox_clickhouse_delivery`，把原数据库中六种真实清理事件投递至独占 ClickHouse 生产 DDL。逐项检查阶段、原因、payload、时间、digest、artifact/cause、索引期限、null 请求和空置信度，并通过脱敏查询核对事件与跨租户隔离。测试验证按族领取、其他族保持原值、精确 ACK、重投去重、缺表后延迟重试及恢复；另用明确标记的合成副本注入跨作用域、正文冲突及无效载荷，确认失败保留未确认状态。入口只接受脚本拥有的 `xshield_test_*` 数据库，数据库和文件均随测试清理；未配置 ClickHouse 时明确跳过该发布链路。

同一脚本执行 `xshield-gateway --test share_issue`，直接调用真实 `ShareIssueApi`，核对返回凭证的账本读取、GET 与精确资源范围、并发精确重试、上下文/时间冲突、无效上下文、容量和 outbox 冲突回滚；事件 payload 与提交的 ShareGrant/规则逐项比对，秘密不进入 envelope。配置 ClickHouse 后，将这条实际库 API 生产事件通过分享发布器写入独占数据库，读回两表两视图、digest、冻结发行时间和确定性摘要，验证 ACK 与空重跑；未配置时明确报告该部分跳过。该测试已在双库执行通过，范围是库发行与消费/投递；HTTP 发行交付由下述独立网关回归覆盖。

`scripts/test_gateway_identity.sh` 另覆盖 `response.share_issue`：独立 GET 分享来源、获准界面动作与精确资源资格、完整成功 JSON、64 字节凭证交付和固定分享入口访问。断言私有缓存策略、边缘凭证剥离、outbox 契约及秘密排除；字段碰撞、重复键、截断、注入后超限、缺失动作、资源偏差、规则退休、容量耗尽及等待响应期间的来源撤销/epoch 变化均检查资格与事件行数。该 HTTP 回归使用真实网关、合成源站和脚本拥有的 PostgreSQL 数据库。

分享存储回归还检查同名规则跨策略版本拒绝、原 share/outbox 身份与正文精确一致、历史事件丢失的完整性故障、分享及来源动作撤销、等待来源行锁或 outbox 唯一键期间到期、等待分享撤销事务后重放拒绝。时钟由测试数据库读取并在单次发行内冻结；事务在取得授权锁后及插入后提交前按实时时钟重新检查期限。

分享 API 集成测试复用 workspace 固定版本的 `clickhouse`（MIT OR Apache-2.0）和内部 `xshield-worker`（Apache-2.0）作为开发依赖，用于检验实际生产事件和发布器；版本及许可证检查随 workspace 统一维护，网关运行时依赖不变。

故障回归以数据库时间强制租约过期，验证索引写入成功后旧 token 确认被拒绝，重新领取可确认且底表重复行在 active 视图合并为一条。真实缺失目标表返回 `OUTBOX_INDEX_UNAVAILABLE`，延迟期间不领取，到期并恢复目标后重试成功；同一 event_id 修改合成正文返回 `OUTBOX_INTEGRITY_CONFLICT` 并保持未确认。断言失败后仍等待清理本测试所属的双库数据。该回归验证数据库集成与故障注入，不覆盖进程崩溃、网络分区或生产负载。

真实 Outbox 回归还覆盖请求摘要的混合来源：较早 ID、序号为 1 的 GET 目标资格先到，摘要保持来源方法/操作为空；同一 request_id 的 POST 来源请求随后到达，两个查询视图均返回来源方法与操作，资格事件继续保留其目标语义。
