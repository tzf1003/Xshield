# 18 数据模型、契约版本及存储责任

## 18.1 主实体

Tenant/Site：管理边界与上游域；PolicyRevision：不可变配置和签名；AuthBinding/CredentialGeneration：认证组合、主体、授权上下文引用、epoch 与期限；PageEvidence/ResponseEvidence/ActionDescriptor/ActionGrant：页面或完整已验证响应产生的界面操作来源；ResourceGrant：精确操作资格；ServiceIdentity：租户/站点、凭证指纹、有限操作集合、状态与期限；ShareGrant：发行者绑定、凭证指纹、精确资源/操作/视图、使用策略、状态与期限；RequestRecord/StageEvent：执行事实；Artifact/Transform：内容与转换；ModelCall/AgentRun：AI 调用；Case/Approval/Export/Replay：调查生命周期。

实体不能以数据库自增 ID 暴露跨租户信息。业务 user/order ID 作为带类型的受限引用，不和 Xshield 自己的管理 ID 混用。对外展示脱敏引用，原值按保密策略加密。

## 18.2 存储分工

| 存储 | 保存 | 不保存/不负责 |
|---|---|---|
| PostgreSQL | 配置、认证、资格、短事务、审批、案件、outbox | 不用于每个大报文全文扫描 |
| ClickHouse | 事件、请求摘要、模型调用统计、按 ID 和时间查询 | 不提供在线资格真值、全局唯一保证 |
| 对象证据库 | 加密报文、模型/Agent 载荷、页面、manifest、签名段 | 不直接公开下载、不充当可搜索明文日志 |
| 本地 journal/spool | 远端中断期间的耐久缓冲 | 不作为无限容量长期唯一副本 |
| 运行时缓存 | 短时已验证配置、候选、遥测 | 不恢复过期或已撤销身份 |

## 18.3 事务边界

匿名会话创建按 tenant/site 取得事务级 advisory lock，以不保存原始 IP 的来源 HMAC 和站点作用域原子消费固定窗口计数，清理已过期匿名 binding 并重验配置容量后，提交无主体、无授权上下文、无凭证、epoch/generation 为 0 的 AuthBinding 与 `session.created` outbox。容量拒绝仍提交已消费的速率计数，速率拒绝回滚到既有上限；提交完成前不向客户端签发 Cookie，任一拒绝不创建部分身份状态。

认证建立将 AuthBinding（含主体与授权上下文引用）、初始 CredentialGeneration 与 `binding.created` outbox 一起提交，提交前响应正文保持缓冲。同上下文刷新在同一事务中 CAS 重验 binding、主体、授权上下文、auth epoch、generation、完整旧凭证集合及期限，撤销旧 generation，并提交新 CredentialGeneration 与 `identity.refreshed` outbox；epoch 不变，使仍有效资格继续可用。身份上下文切换同样按旧 snapshot 与完整旧凭证集合 CAS，但在一个事务内更新主体/授权上下文、推进 auth epoch 与 generation、撤销旧 generation、写入新 generation 及 `epoch.changed` outbox；旧资格通过 epoch 校验立即失效，物理清理不参与在线授权。引入授权上下文字段的迁移会撤销无法证明该字段的既有活动绑定。资格发行与 outbox 一起提交；响应派生资格须在同一短事务中重验 binding、auth epoch、活动策略、动作描述、证据期限和整批容量，并原子写入 ResponseEvidence、ActionGrant、ResourceGrant 与 outbox。资源分享还须在同一短事务中重验发行者 binding、auth epoch、精确资源资格、活动策略、发行规则、TTL 和容量。只更新 status 字段的异步删除不能成为唯一撤销机制。

调查案创建按 tenant/site/owner 串行化精确幂等和容量检查，并把案件与 `case.created` outbox 同事务提交。敏感证据访问申请复用独立用途域幂等密钥，先锁定申请主体，再锁定其 open 案件和 active 未过期 artifact，限制 pending 数并原子提交申请与 `evidence.access.requested` outbox；pending 状态不等于内容读取授权。

附带 SQL 是可审查草案，生产前需迁移测试、并发隔离和索引验证。RLS 可作防御纵深，但应用仍必须使用完整 tenant/site 作用域；连接池中租户会话设置使用事务局部机制，避免连接复用串域。

## 18.4 协议规则

外部 API 与 audit event 含 schema_version。未知 critical enum 或版本拒绝；可扩展 metadata 只能保存非授权数据。金额、资源 ID、期限等使用明确类型，不靠浮点或 JS 自动类型转换。

时间 UTC RFC3339，内部单调耗时单独保存。可选字段区分 null/not_provided/not_applicable/unavailable，不能空字符串兼任所有状态。概率在 [0,1]，分布和允许数值误差、NaN/Infinity 拒绝需专门校验。

## 18.5 Schema 清单

schemas/audit-event.schema.json：强类型审计公共字段与 outcome/信心约束。

schemas/artifact-manifest.schema.json：加密证据、长度、fidelity、保留与转换引用。

schemas/model-call.schema.json：实际输入输出引用、概率、置信度与版本。

schemas/site-policy.schema.json：入口、认证、模式、来源与采集策略。

examples 仅合成数据；scripts/validate_library.py 检查语法、Schema、引用和演示链。校验通过不代表数据库/网关/模型已实现。

## 18.6 兼容演进

增加字段优先可选并给清晰默认；改变授权语义升 major。每个版本带读写兼容矩阵、迁移脚本和回放测试。旧证据保持原版本，可用只读转换器展示新视图，但不能改写历史事实。策略和解析器的版本与数据库迁移版本独立记录。
