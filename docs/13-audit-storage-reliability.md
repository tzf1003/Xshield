# 13 审计存储、耐久性、完整性与容灾

## 13.1 推荐数据流

```text
业务阶段生成强类型事件/证据
    → 隐私分类与内容引用
    → 有界 AuditSink + 加密本地 journal
    → 持久确认（按端点等级）
    → 异步批量投递
       ├─ ClickHouse：事件/请求/模型检索
       ├─ 对象库：加密内容、manifest、签名段
       └─ PostgreSQL：配置、案件、审批、资格 outbox
    → 索引水位、缺口检测和完整性验证
```

事件/证据耐久提交与索引可搜索是不同状态。ClickHouse 暂不可用不一定要阻断业务，只要所需 journal 耐久级别和容量仍满足策略；证据不可恢复时不能报告“已完整存档”。

## 13.2 耐久级别

| 等级 | 确认条件 | 能声称什么 |
|---|---|---|
| memory_only | 仅在有界内存队列 | 仅调试，不满足生产安全审计 |
| local_durable | 加密 journal 的相应数据已持久写入并得到确认 | 可承受进程重启；本地磁盘/整机损坏仍有损失窗口 |
| remote_durable | 另一个受信故障域的持久日志/对象存储完成确认 | 按部署模型减少节点丢失窗口，仍须故障测试 |

首版受保护请求至少 local_durable；高危请求可要求 remote_durable。生产者记录 durability_ack_at、required_level、achieved_level 和 receipt_id。fsync/磁盘写在专门线程池或进程中执行，绝不阻塞 Tokio worker。

## 13.3 转发前审计屏障

ALLOW 的高危请求至少在转发前耐久记录：request.accepted、必要输入证据 manifest、所有必需阶段结果、final decision、origin.forward_intent、实际重建请求引用。没有 receipt 就不向源站释放该请求。

不能把源站网络发送与 journal 写入变成跨系统原子事务。进程可能在 journal 批次中途或发送成功后、结果事件落盘前崩溃，因此网关下次启动在接收流量前认证扫描关闭段：未完成的准入前缀追加 REQUEST_INCOMPLETE 补偿终态，已记录转发意图但缺少结果时追加 outcome_unknown 和补偿终态；扫描超过配置上限、事件结构冲突或补偿写入失败均阻止启动。恢复保留已经耐久记录的 response_received，不执行写请求重发，也不补造成功日志。

**屏障恢复。** 持久写入失败（journal 配额耗尽或写/同步错误）会关闭准入屏障：此后所有请求仍以 503 `AUDIT_DURABILITY_FAILED` 拒绝，不转发也不丢记录。此前该屏障只会关闭、没有任何重开路径，一次 journal 写满就让网关停摆到重启。现在后台监督以有界退避（1 秒起、每次翻倍、上限 30 秒）重试，期间保持拒绝。仅当 journal 目录低于配置的高水位时才尝试重开，探测一个仍然满的目录只列目录、不创建段；条件满足后先释放失败的写入器（单写者锁不允许两个句柄），再经与启动相同的恢复流程重开 journal（重新认证所有段、修复不完整尾部、从磁盘重算已用字节），并先耐久追加 `audit.recovered`（`reason_code=AUDIT_BARRIER_REOPENED`，`truncated_bytes=0`）事件，成功后才恢复准入，使中断区间在审计轨迹中可见。空间由发布与保留角色释放；若不释放，网关保持关闭而不是降级。屏障关闭期间丢失终态事件的在途请求不在重开时补偿（它们可能仍在途，补偿会造成第二个终态），仍由下次启动的既有对账补偿。

DENY 也应记录；磁盘耗尽时预留独立的小型紧急事件区。若紧急区也失败，节点退出就绪状态并触发独立监控，不能许诺物理故障下 100% 永不丢失。

## 13.4 journal 实现契约

分段追加；段头含 format、producer_boot_id、key_id；记录有长度、CRC/校验、event_id 与密文；定期 seal。启动恢复扫描最后段，识别不完整尾部，保存损坏范围并生成恢复事件。必须有独立配额和高水位，不与系统盘无界争抢。

投递采用至少一次，event_id 在重试中不变。消费者按事件 ID/版本去重，并验证重复内容一致；相同 ID 不同内容触发 integrity.conflict。ClickHouse 普通 MergeTree 不提供全局唯一约束，不能只靠表主键宣称去重。[S24]

推荐初版使用查询视图进行基于 event_id 的确定性去重；若换 ReplacingMergeTree，也要处理后台合并前重复。聚合统计从去重逻辑输入产生，不把重试重复计费或重复算攻击。

避免审计递归：AuditSink 自己的写入、投递和重试不得重新进入用户请求审计管线，否则会无限生成“记录日志的日志”。存储传输按批次/receipt 记录控制事件，故障使用独立紧急通道；管理人员查看、导出或解密证据仍必须产生一次明确的访问审计。AI 对日志的分析也要有任务预算和来源标记，不能让分析产生的日志自动触发无限自分析。

管理 journal 可复用 `xshield-audit-seal` 与 `xshield-worker` 的封存和发布流程。运行时将 worker 的 journal key-id/key 指向对应 `XSHIELD_CONTROL_AUDIT_KEY_ID` / `XSHIELD_CONTROL_AUDIT_KEY_HEX`，为该源预建独立私有 manifest、checkpoint 目录，并使用匹配的独立封存签名公钥；保留期、表和目标配置仍由服务端注入。不要将网关、模型与管理日志的目录或水位混用；健康结果只描述配置的那个 journal 源，不代表其他源已追平。发布直接写分析索引，查询接口产生的访问事件由下一次发布处理，不触发自动自查询。

## 13.5 outbox 与资格发行

资格与 grant_event outbox 同 PostgreSQL 事务提交，publisher 按 ID 重试发送审计。当前发布器已交付案件、证据目录、证据访问、证据清理、身份生命周期、通用资源资格、响应资格发行和分享发行八族闭环，精确事件清单见 [11.8](11-audit-event-contract.md#118-已实现的按事件族-outbox-发布)：租约字段与业务状态同库但不与 ClickHouse 网络共持事务锁，消费者在独立 ClickHouse 写入和 event_id/content_digest 冲突复核成功后，才以精确 tenant/site/event/token 更新 `published_at`。连接失败、结构无效和完整性冲突都保留原行并写稳定 `last_error_code`，不把日志或 ClickHouse 结果当授权真值。通用资源资格库入口从冻结的类型化内部命令生成事件，只索引批准约束摘要；它不暴露独立 HTTP 发行面。站点 HTTP 发行由 `response.resource_grant` 在已验证源站响应、响应证据、动作和资源资格的同一事务中产生 `response_grant.issued`，以免把管理身份或客户端输入变成资格真值。响应资格完整事件保留冻结发行时间与批内序号；分享库 API 保留稳定 event/share ID、冻结时间和精确重试正文。身份撤销与 HTTP 分享发行已接入，历史稀疏行以 `OUTBOX_INVALID_EVENT` 保持未确认，发布重试不会重新发行资格。证据清理族只发布已有删除事务事实，重投不会执行文件操作；数据库意图/tombstone 与对象侧认证仍是恢复依据。响应释放前等待资格事务成功及该请求要求的审计耐久屏障；尚未适配的 outbox 族继续可见地积压，不得静默丢弃或按 journal 契约解释。

Xshield 事务只保护本系统状态，不覆盖原站数据库或外部支付。长时模型/网络工作在事务外完成，提交时再验 epoch 和策略版本。[S08]

## 13.6 防篡改

每个 producer/shard 的事件形成规范编码的 hash chain，段封存记录末尾序号与链头。对封存 manifest 做数字签名，并将周期性根摘要写到独立控制权限的审计位置。证据密文单独校验摘要，签名密钥不在普通 edge 日志写权限里。

规范化哈希需排除签名字段并固定字段顺序/编码，版本明确。不同 producer 之间不造全局链；通过请求 DAG 与段清单联接。hash chain 能检测已锚定范围内的改写、缺口或替换，但不能证明生产者记录前未撒谎、也不能识别从未进入系统的流量。

## 13.7 容灾与保留

journal 重启恢复、异地副本与 KMS 恢复流程都必须测试。热索引可从加密事件段重建；恢复时保留原 ID、版本和事件时间，新增恢复来源标记。

ClickHouse TTL 在后台合并时清除数据，不是到秒精确删除；查询与 EvidenceReadPort 必须先执行过期策略，不依赖后台清理及时发生。[S24] 当前发布器要求 1–3650 天的元数据保留配置，按事件发生时间把绝对 `retention_expires_at` 固化到每个索引行；DDL 以该字段执行后台 TTL，并提供按 `event_id` 去重、按当前时间过滤的 `audit_events_active` / `events_by_time_active` 视图，重复投递采用最早期限，查询 API 只能使用 active 视图。升级时旧行以原 30 天策略扩展字段，新发布器显式写入配置期限。已批准案件可 pin 对象并设置受控保留；解除保留也需要审计，案件 pin 与原文对象保留在对象证据库阶段实现。

两个 active 视图通过 `CREATE OR REPLACE VIEW` 更新，以执行 DDL 的账号作为 `SQL SECURITY DEFINER`。该账号必须在运行期保持有效并保留对应底表的 `SELECT`；生产控制账号仅获 active 视图的 `SELECT`，不能直接读取尚未物理删除的过期行。重新执行 DDL 会更新 definer，部署时须核验账号生命周期与权限。视图约束保留期限，API 仍负责注入认证后的 tenant/site 作用域。

## 13.8 故障策略

| 故障 | 行为 |
|---|---|
| ClickHouse 慢/断开 | journal 继续，显示索引水位；积压到配额则背压 |
| 对象库不可用 | 内容进入受限本地证据 spool；严格远端级别请求不执行 |
| journal 磁盘高水位 | 限流、停止非必要调试采集、告警；不静默删除必需审计 |
| required journal 无法持久写 | 高危/强制审计端点 503；记录独立紧急事件 |
| KMS 不可用 | 不回退明文；按现有授权缓存密钥的限定寿命或拒绝 |
| 索引有记录但对象缺失 | evidence.missing 告警，禁止伪造空内容为完整 |
| 签名/摘要失败 | 隔离证据，标记 corrupt，保留调查痕迹 |

严格拒绝与可用性之间的选择写入 site policy 并审批；不可用不自动等同于“用户攻击”。

## 13.9 组提交（group commit）

每个请求写两次必须耐久的审计批次：准入批次（决定、必要的阶段与转发意图，之后才能联系源站）和终态批次。原先每个批次各自 `write` 后 `sync_data`，且由 journal 互斥锁串行，所以一个 edge 实例的吞吐被锁定在 `1 / fsync 延迟` 上，与并发无关，排队的请求还要替前面的所有请求付 fsync 的钱。`scripts/bench_gateway.py` 在一台 macOS 笔记本上量到：journal 在 SSD 上时约 8 ms、约 130 请求/秒（1 个或 4 个并发客户端几乎相同，4 个并发时单请求延迟涨到约 28 ms），journal 放在内存盘上同一流程只需约 0.4 ms、2000 请求/秒以上，差值就是 fsync。

现在 journal 提供 `LocalJournal::append_batch_unsynced`（只写入，不保证耐久）与 `LocalJournal::sync`（对此前所有批次做一次耐久同步，之后才按段大小旋转），原有的 `append_batch` 就是两者的串联，语义不变。网关只有一个写线程：它取走队列里所有等待的提交，按到达顺序依次追加，只做一次 `sync`，然后才逐个应答调用者。

保证与失败规则（均有测试）：

- **回执只在耐久之后才交出。** 调用者在自己的字节耐久前得不到回执，也就不会转发请求或认为事件已记录；与改动前相同的“先审计、后转发”边界仍然成立，改变的只是并发提交共享同一次 sync。单个客户端仍要等一次 sync（两个批次共两次），所以单请求延迟不变，吞吐才随并发增长。
- **组内一个批次在写入前被拒绝（配额、事件非法）只让它自己失败**，句柄保持健康，同组其他批次照常耐久（`a_refused_batch_leaves_the_rest_of_its_group_intact`）。
- **写入或 sync 错误会让句柄中毒**，自上次成功 sync 之后追加的所有批次的耐久性未知，因此全部以错误应答并关闭屏障；第一个批次携带根因，其余报告 journal 已中毒。恢复路径不变：只能经 `LocalJournal::open` 重新认证、修复不完整尾部后重开。
- **旋转发生在 sync 之后**，已封闭的段从不含未耐久的字节；一组可以超出段大小限制一个组的体量（`rotation_waits_for_the_sync_of_the_group`）。
- **每个提交带着自己的 tenant/site/策略修订/producer 作用域**，多站点共享同一个写线程与 journal，事件仍按各自作用域写入；一组内各请求的事件序号连续、同一请求的事件相邻（`concurrent_commits_share_syncs_and_keep_their_events_contiguous`：64 个并发提交最多 2 次 sync）。
- **取消不撤销提交**：请求被取消时已排队的批次仍会写入，与此前阻塞追加在请求结束后仍会完成一致。
- 一组最多 256 个提交，只用来限制持锁时间和内存；丢弃最后一个句柄会关闭队列并 join 写线程，所以 `drop` 返回时 journal 已关闭，可立即重新打开。

容量含义：吞吐上限由“同步延迟 × 每请求两次同步 ÷ 并发度”决定，因此 journal 应放在本地低延迟存储上（本地 NVMe 的 `fdatasync` 通常在亚毫秒到毫秒级；网络盘更慢）。macOS 上 `sync_data` 是 `F_FULLFSYNC`，开发机的数字不能代表 Linux 生产环境，见 [21.7](21-performance-capacity.md#217-基线测量与已知瓶颈2026-10-06)。
