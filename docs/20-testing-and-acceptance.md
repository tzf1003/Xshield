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
| MODEL | NONE、低信心、Noul、提示注入、超时、缓存、版本变动 | 不伪造 confidence，不覆盖硬拒绝 |
| AUDIT | 每层、跳过、证据链、断网、磁盘满、重启、去重 | 必需事件可追溯，缺失可见 |
| CONSOLE | ID 横向访问、原文审批、导出、自然语言查询 | 不绕过租户/敏感权限，查看本身可审计 |
| RECOVERY | 重放、取消、未知源站结果、撤权、备份恢复 | 不重发非幂等写，不复活旧资格 |

机器化验收目录见 examples/acceptance-cases.json，包含独立 case_id、步骤、期望和关联不变量；这里只提供设计用例，不声称已经对运行产品执行。

## 20.3 误拒与安全收益

本产品主动禁止的无资格直达、换浏览器未重获资格，不计为违反需求的误报；应另计 intentional_flow_denial 与恢复体验。被认可流程中的正常请求因竞态/映射错误拒绝，才是实现误拒。

固定测试身份、源站版本和授权/流程矩阵，分别比较 baseline、加密可见性、确定性资格、UI 来源、模型增量。不要把账本收益全部算作 JEV 模型收益。

## 20.4 并发/故障必测

匿名会话同来源并发创建、跨来源站点容量和限流窗口恢复；登录切换与旧列表响应；双刷新乱序；授权查询与撤销交叉；多个 edge 重复消费 nonce；资格事务提交但 outbox publisher 崩溃；转发后终态日志未写；内容已持久但索引未到；对象丢块/重复 event_id 不同内容；模型请求已计费但响应超时；节点 journal 与 KMS 同时不可用。

每个故障注入注明实际故障范围，进程 kill 测试不等于整盘损坏测试，单节点测试不等于跨区域一致性测试。

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

## 20.12 outbox 发布回归

`cargo test -p xshield-worker --lib outbox` 覆盖三个 `case.*` 类型、`evidence.cataloged` 的两个真实 producer、`evidence.access.*` 的请求/批准/拒绝、四种身份事务形状、`grant.issued`、`response_grant.issued` 和 `share.issued`。反例包含显式 nullable TTL、目标与请求/boot 绑定、匿名/认证初态、代际递增与 bigint 上限、上下文变化、重复凭证 kind、非法指纹、重复/未知键及 journal/outbox 来源隔离；响应资格另覆盖封闭 payload、批内序号/candidate_count、ID/动作引用、单字段/GET/2xx（排除 204）约束、HMAC/正文摘要、TTL 和规范 UTC 整秒与发行时间的一致性。通用资源资格另覆盖 event/boot、来源请求/策略一致、scoped action_ref、约束摘要和整秒/TTL 约束。分享另覆盖 event/boot/share 绑定、独立发行序号、来源资格与规则形状、GET/reusable_read、秘密字段拒绝和整秒/TTL 约束。索引摘要固定为确定性空置信度，不设置业务终态。

`scripts/test_postgres.sh` 在专有临时数据库运行 `xshield-postgres --test outbox_delivery` 及 worker 的 `postgres_outbox_publishing` ignored 测试。存储层用显式行锁和数据库时间验证按族/tenant/site 领取、行/字节预算、`SKIP LOCKED` 并发、过期租约重领、旧 token/跨作用域拒绝、精确确认及有界重试。worker 使用真实 PostgreSQL 与受控 ClickHouse HTTP 响应，验证十五组按生产契约构造的合成 envelope 的索引字段/摘要、确认后不再领取、未适配族不被修改、索引失败后重试成功、插入前后完整性冲突、scope/aggregate 错绑和历史稀疏身份/通用资源资格/响应资格/分享行保留未确认状态。该回归不验证真实 ClickHouse DDL、去重和 active 视图。

同一脚本的 `grant_issue` 集成测试用数据库时钟和 `pg_blocking_pids` 确认真实锁等待，覆盖 binding、已有 grant 和 outbox 唯一键三个位置的跨期拒绝，失败不新增账本或 outbox。它还覆盖并发撤销后的重放拒绝、动作/策略失效、独立 grant ID/trace/冻结时间冲突（含存储子秒偏差），以及 outbox aggregate/type 错绑；批准约束含嵌套指数数字、小数、负零、Unicode 与大整数，并覆盖 JSONB 展开超限时原子拒绝。普通单测验证 trace、约束对象/16 KiB 上限、容量和 TTL/整秒时间范围。

`postgres_outbox_publishing_generic_grant_producer` 读取以上 `GrantPersistence` 实际提交的行，逐字段核对授权事实与完整 envelope、批准约束摘要及冻结时间，再经通用资格发布 API 验证索引、精确确认和空重跑。未配置 ClickHouse 时使用受控 HTTP；配置后使用独占 ClickHouse 库和生产 DDL，读回两个底表及两个 active 视图。它只接受脚本拥有的 `xshield_test_*` 数据库，验证范围是库生产者至双库投递，HTTP 发行适配器仍待交付。

`scripts/test_gateway_identity.sh` 通过真实网关、合成源站和专有 PostgreSQL 库执行匿名创建、登录、刷新与同主体上下文切换，保留原有认证、CAS、旧资格隔离及错误响应断言，同时检查生产 v3 envelope 与请求 ID。脚本结束前运行 `postgres_gateway_identity_outbox_publishing`，将实际生产的四种身份事务通过 worker 投递给受控 ClickHouse HTTP 服务，核对 RowBinary 索引、摘要、确认和重复运行空批次；该测试只接受脚本拥有的 `xshield_gateway_*` 数据库。

配置 20.6 的 `XSHIELD_TEST_CLICKHOUSE_URL` 及测试账户后，同一网关脚本还会运行 `real_gateway_response_grant_outbox_delivery`。脚本产生两个响应、三个实际响应资格事件，其中一个响应含两个资源；测试把 envelope 与 PostgreSQL 响应证据、动作及资源资格行逐项比对，检查批内连续序号，再通过生产发布器写入真实 ClickHouse，读回两个底表与两个 active 视图，验证精确确认和重复运行空批次。该链路已在真实 PostgreSQL 与 ClickHouse 联调通过；入口仅接受脚本拥有的数据库，未配置 ClickHouse URL 时明确报告跳过。

配置同一 ClickHouse 环境后，`scripts/test_postgres.sh` 还会运行 `real_outbox_clickhouse_delivery`：在专有 PostgreSQL 临时库和独占 ClickHouse 数据库内重复应用生产 DDL，通过七族发布 API 投递十五组按生产契约构造的合成 envelope，读回两个底表及两个 active 视图，核对作用域、事件引用、SHA-256 digest、事件时间（通用资源资格、响应资格和分享为整秒，其他样本含微秒）、保留期限、确定性空置信度和非业务终态，并逐行检查 PostgreSQL 精确确认与重复运行空批次。该回归已在真实 PostgreSQL 与 ClickHouse 执行通过；真实数据库回归入口均纳入 CI。普通 workspace 测试将其标为 ignored，必须实际运行相应脚本才能形成验证结果。

同一脚本执行 `xshield-gateway --test share_issue`，直接调用真实 `ShareIssueApi`，核对返回凭证的账本读取、GET 与精确资源范围、并发精确重试、上下文/时间冲突、无效上下文、容量和 outbox 冲突回滚；事件 payload 与提交的 ShareGrant/规则逐项比对，秘密不进入 envelope。配置 ClickHouse 后，将这条实际库 API 生产事件通过分享发布器写入独占数据库，读回两表两视图、digest、冻结发行时间和确定性摘要，验证 ACK 与空重跑；未配置时明确报告该部分跳过。该测试已在双库执行通过，范围是库发行与消费/投递；HTTP 发行交付由下述独立网关回归覆盖。

`scripts/test_gateway_identity.sh` 另覆盖 `response.share_issue`：独立 GET 分享来源、获准界面动作与精确资源资格、完整成功 JSON、64 字节凭证交付和固定分享入口访问。断言私有缓存策略、边缘凭证剥离、outbox 契约及秘密排除；字段碰撞、重复键、截断、注入后超限、缺失动作、资源偏差、规则退休、容量耗尽及等待响应期间的来源撤销/epoch 变化均检查资格与事件行数。该 HTTP 回归使用真实网关、合成源站和脚本拥有的 PostgreSQL 数据库。

分享存储回归还检查同名规则跨策略版本拒绝、原 share/outbox 身份与正文精确一致、历史事件丢失的完整性故障、分享及来源动作撤销、等待来源行锁或 outbox 唯一键期间到期、等待分享撤销事务后重放拒绝。时钟由测试数据库读取并在单次发行内冻结；事务在取得授权锁后及插入后提交前按实时时钟重新检查期限。

分享 API 集成测试复用 workspace 固定版本的 `clickhouse`（MIT OR Apache-2.0）和内部 `xshield-worker`（Apache-2.0）作为开发依赖，用于检验实际生产事件和发布器；版本及许可证检查随 workspace 统一维护，网关运行时依赖不变。

故障回归以数据库时间强制租约过期，验证索引写入成功后旧 token 确认被拒绝，重新领取可确认且底表重复行在 active 视图合并为一条。真实缺失目标表返回 `OUTBOX_INDEX_UNAVAILABLE`，延迟期间不领取，到期并恢复目标后重试成功；同一 event_id 修改合成正文返回 `OUTBOX_INTEGRITY_CONFLICT` 并保持未确认。断言失败后仍等待清理本测试所属的双库数据。该回归验证数据库集成与故障注入，不覆盖进程崩溃、网络分区或生产负载。

真实 Outbox 回归还覆盖请求摘要的混合来源：较早 ID、序号为 1 的 GET 目标资格先到，摘要保持来源方法/操作为空；同一 request_id 的 POST 来源请求随后到达，两个查询视图均返回来源方法与操作，资格事件继续保留其目标语义。
