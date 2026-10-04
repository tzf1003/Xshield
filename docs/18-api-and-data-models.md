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

调查案创建按 tenant/site/owner 串行化精确幂等和容量检查，并把案件与 `case.created` outbox 同事务提交。敏感证据访问申请复用独立用途域幂等密钥，先锁定申请主体，再锁定其 open 案件和 active 未过期 artifact，限制 pending 数并原子提交申请与 `evidence.access.requested` outbox；pending 状态不等于内容读取授权。决策按 tenant/site/decider 串行化幂等键并锁定申请行，拒绝申请主体自批和重复终态；批准再次锁定 open 案件与 active artifact，以数据库时钟将资格期限钳制到客户端 TTL 与 artifact 期限，并把终态与 `evidence.access.approved` 或 `evidence.access.denied` outbox 原子提交。EvidenceReadPort 按 tenant/site/request/subject/artifact 重验 approved 行、案件与 catalog 状态，再委托 vault 认证 manifest、ciphertext digest 和 AEAD；成功释放前写入 `evidence.read` 及实际字节数。

附带 SQL 是可审查草案，生产前需迁移测试、并发隔离和索引验证。RLS 可作防御纵深，但应用仍必须使用完整 tenant/site 作用域；连接池中租户会话设置使用事务局部机制，避免连接复用串域。

案件证据关联按 tenant/site/actor 取得用途隔离 advisory lock，再锁定本人 open 案件，串行化幂等和每案 128 项容量；新关联另锁定 active artifact，并在取得锁后及插入时按数据库时钟重验期限。`case_items` 与 `case.evidence.added` outbox 同事务提交；自然唯一键绑定 tenant/site/case/artifact，幂等唯一键绑定 tenant/site/actor/摘要。精确重试仍重验当前案件归属及 open 状态，再返回历史关联时间；artifact 到期或删除后该关联也不产生内容能力或保留锁。

案件证据集合读取使用 tenant/site/case/owner 的单条 PostgreSQL 只读快照，并把案件授权、成员行、`case.evidence.added` outbox 关联和 catalog 状态一并解码；不存在、跨作用域及非本人案件统一不可用。游标只定位 artifact ID，绑定管理凭证摘要、主体、作用域、案件和页大小，坏游标在访问数据库前拒绝。读取不锁定业务行、不延长期限、不读取内容；数据库当前时间决定 active/expired，deleted 优先，缺 catalog 为防御性 unavailable 状态（`case_items` 外键和 retention tombstone 使正常路径使用 deleted），open 与 closed 均保留历史引用。结果释放前必须写独立 `console.case.read` 管理审计，审计失败不返回查询结果。

案件关闭复用创建时的 tenant/site/owner advisory lock，再锁定本人案件行；`status=closed`、`case_closures` 和 `case.closed` outbox 同事务提交，因此关闭与 open 容量创建有明确先后关系，案件行锁同时串行化证据关联和审批。自然唯一键为 tenant/site/case，幂等键绑定作用域、owner 和关闭用途；精确重试重验当前归属、closed 状态及原 outbox 完整绑定。关闭保留既有 membership、catalog 和访问审批历史，后续资格校验通过案件状态拒绝读取；已获准在途读取沿用其校验快照。自由文本理由留在受限案件表，outbox 保存请求摘要，管理事件记录目标与结果。

本地证据到期清理使用两段短事务：先按 tenant/site/key 和数据库当前时间锁定候选，将删除意图与 outbox 原子提交；文件系统认证、删除与目录同步后，再锁定并比较相同 manifest/意图，提交 catalog tombstone 与完成 outbox。无 catalog 的本地孤儿复用同一根目录排他锁和两段事务，按稳定长度/mtime 观察提交意图，按 artifact 全局检查迟到 catalog，并在 sidecar/摘要复验后写入 `evidence.orphan.deleted` 或失败事件。数据库事务不跨文件操作持锁；两事务之间由本地根目录排他锁约束写入者。中断恢复依赖耐久意图和保留的签名 manifest，不把数据库提交与文件删除描述为一个原子事务。

案件保留锁使用 `case_evidence_holds`，创建事件 ID 即稳定 hold ID。关联外键绑定完整 tenant/site/case/artifact，未释放目标、创建幂等键和释放幂等键分别唯一；创建/释放与各自完整 outbox 原子提交。作用域 advisory lock 串行化容量，案件/catalog 行锁串行化状态与删除意图。保留期限与原文读取期限独立，边界及部署次序见 [12.9](12-evidence-capture-and-vault.md#129-案件证据保留锁存储与发布)。

保留锁历史按 AuditAdministrator 的精确 tenant/site 查询，允许 open/closed 及其他所有者案件。只读单 SQL 快照连接案件、hold 和创建/释放 outbox，按 hold ID 取有界页及一个预读行；所有可见记录（含预读）均校验完整 outbox envelope。原始期限与释放字段连同数据库 `as_of` 返回，分页为实时快照；游标绑定凭证、主体、作用域、案件、页大小和最后 hold ID。列表和操作结果释放前须写独立管理 journal；自由文本理由不进入 journal 或 outbox。管理主体构造统一拒绝首尾空白，避免已认证主体与存储身份规则不一致。

本人案件列表在 tenant/site/owner 范围内按 case ID 的 `C` 排序降序键集分页，包含 open/closed；迁移 `0021_m3_case_listing.sql` 为相同前缀建立覆盖排序的索引。单条只读 SQL 同时取得数据库时间、摘要和创建 outbox 关联，包括用于判断下一页的预读记录；坏行或关联偏差使整页失败。空页仍包含数据库观察时间，各页为实时观察。读取不修改案件或生成事务 outbox，释放结果前写独立 `console.case.list` 管理审计。

证据访问申请、决策及内容资格查询的行锁等待后，使用新的 PostgreSQL 时钟重新核对对象/资格期限；批准 TTL 从取得目标锁后的决策时刻计算。申请写入再验对象未过期。三类存储入口的事务局部语句/锁等待上限为 5 秒，控制层将含池等待的数据库操作限制为 15 秒；已准入控制任务独立于 HTTP 等待者完成事务结果及访问审计。内容资格事务在 vault I/O 前结束，明文对象持有独立的响应生命周期许可。

证据申请详情通过单 SQL 只读快照同时限定 tenant/site、申请主体或可信审批角色，并校验案件归属、catalog 及申请/决策 outbox 关联。返回有限的审批元数据和数据库观察时间，历史状态与时间到期分别表达；不锁定业务行或修改申请。管理 journal 仅记录读取目标与结果，审计完成后才释放详情。

证据访问申请列表复用详情的案件、catalog 和申请/决策 outbox 一致性校验，按固定 tenant/site 和 `mine`/`review` 主体谓词取得单 SQL 只读快照。`mine` 包含本人各历史状态，`review` 只含其他主体的 pending；申请 ID 使用 `C` 排序降序与排他游标，每页最多 128 条加一条预读，预读坏行同样使整页失败。空页仍返回数据库观察时间；分页间批准可移除待办，新增高位 ID 须刷新首页查看。迁移 `0022_m4_evidence_access_listing.sql` 添加 owner/scope 排序索引和 pending 部分索引，事务内构建期间阻塞该表写入；回滚应用可保留加法索引。查询保留案件关闭、对象过期或已删除时的历史记录，不改变申请或生成事务 outbox，响应经独立 `console.evidence.access.list` 审计后释放。

调查导出列表（29.33）以同样的 `mine`/`review` 谓词和单 SQL 只读快照发现导出，`review` 固定为持久状态 `pending_approval`。导出行没有逐行 outbox，且由复合外键绑定案件，所以不做案件/catalog/outbox 关联；改为校验导出 ID、规范主体、状态与决定/期限/包的一致性、请求人与决定人分离及时间单调，预读坏行同样使整页失败。投影只选取元数据列，用途、决定理由和包标识不会被读出。导出 ID 使用 `C` 排序降序与排他游标；迁移 `0050_m4_investigation_export_listing.sql` 添加 requester 排序索引和 `pending_approval` 部分索引，事务内构建期间阻塞该表写入，回滚应用可保留加法索引。响应经独立 `console.export.list` 审计后释放。

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

## 18.7 多站点配置与 edge 生效边界

`protected_site_configs` 是旧接口的兼容投影；`site_port_leases` 使用租户事务锁和 active 唯一索引分配内部监听端口，释放的端口可以安全复用。`site_apply_intents` 保存 desired revision、active revision、apply ID、状态、失败原因和独立审批摘要，`site_snapshot_sequences` 为完整租户快照提供跨控制实例的单调 revision。写入配置先提交 desired revision，再等待 edge 的签名确认；没有确认时控制台只能显示 `pending`，不能把持久化成功当作流量已切换。edge 侧的 `GatewaySnapshot`、`SiteRouteTable`、`ConfigSnapshotStore` 和 `ApplyCoordinator` 使用端口与 Host/SNI 双重选择，并在同一锁内拒绝已落后的并发快照后原子替换不可变快照，现有请求继续使用开始时绑定的 revision。0046–0048 将 typed policy、路由附加约束和独立高风险批准以 expand-contract 方式加入旧投影；策略密钥只以 reference/key ID 进入快照。
