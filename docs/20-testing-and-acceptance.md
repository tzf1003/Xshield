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
cargo test -p xshield-worker --lib -- --ignored
XSHIELD_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
cargo test -p xshield-worker --test clickhouse_search -- --ignored
```

需要认证时另设 `XSHIELD_TEST_CLICKHOUSE_USER` 和 `XSHIELD_TEST_CLICKHOUSE_PASSWORD`。测试使用 UUID 命名的独占数据库，直接加载 `sql/clickhouse.sql` 并重复执行完整 DDL。普通视图采用 `CREATE OR REPLACE VIEW` 更新定义。断言失败后仍同步清理测试创建的资源；进程被强制终止时由测试服务的生命周期回收资源。

查询回归覆盖 `audit_events_active` 和通过物化视图填充的 `events_by_time_active`：租户/站点隔离、可空 LowCardinality 字段、`ALLOW`、微秒及同时间戳 keyset 双向分页、闭开时间窗口、全部类型过滤器与同事件 AND 语义、重复事件合并、最早期限优先及物理 TTL 清理前隐藏过期行。查询使用只获两个 active 视图 `SELECT` 的独占测试账号，同时断言直接读取两张底表返回权限拒绝。

发布回归从加密 journal 与签名清单开始，验证真实 `FixedString` 编码、两张物理表的精确摘要和微秒时间读回、同步确认后的水位提交与 checkpoint 重用；继续追加同 event_id 的不同内容时，发布器必须返回完整性冲突，保留原水位并显示待投递段。

模型阶段回归由实际加密 journal 经封存和发布入库，验证 `mdl_` 调用引用、已知/缺失模型版本以及有界模型版本过滤。阶段汇总回归在同一阶段先写数值置信度，再写 `not_applicable`、`not_provided` 或 `unavailable` 的 null，确认两套 active 视图都返回最新 null 与匹配状态。常规测试另覆盖置信度矛盾、非法模型引用和版本、时间线分页预读行校验；这些合成事件验证审计链路，不代表实际模型推理或准确率测量。

查询预算测试以同一小数据集收紧服务端结果行数上限，验证真实预算异常映射为 `QueryBudgetExceeded`。普通 `cargo test --workspace --all-targets` 会编译这些测试但按 `ignored` 跳过服务调用，必须执行上述命令才能形成真实数据库验证结果。执行时间/扫描/内存预算、集群故障和生产规模容量仍须分别验证。
