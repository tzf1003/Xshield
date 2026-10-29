# 12 内容证据采集、秘密隔离与加密证据库

## 12.1 “全量”分为事件完整与内容完整

事件完整：每个被接收的请求、每个实际判定和每次模型/工具调用必须有记录，不因结果正常被抽样丢弃。

内容完整：对已配置的受保护 API、HTML、Jev/Agent 逻辑输入输出及解密结果，保存全部可取得内容；对认证秘密、超限、未支持、未取得的部分显式标记，绝不默认为完整。全量不是所有秘密明文复制到 ClickHouse 或 stdout。

默认 full_protected：受保护业务请求/响应、页面证据、模型和 Agent 逻辑载荷全量进入加密证据库；公开二进制静态资源按内容寻址引用已保存版本。业务密码、OTP、原始认证凭证、分享秘密、密钥等走强制秘密排除/替代策略。受批准的短时 forensic_raw 可提高指定业务载荷的保真度，但永不将 Xshield 主密钥、供应商 API key、KMS 解封密钥或进程完整环境变量写入证据。

任何脱敏或排除都输出清单并将 fidelity=redacted，而不是标 byte_exact。用户要求逐字节取证的端点必须在启用前明确其秘密策略、期限、审批和容量；不暗中改变采集语义。[S22]

## 12.2 请求和响应证据版本

| kind | 内容 | 用途 |
|---|---|---|
| request_ingress | 网关收到的 HTTP 语义头及实体 | 还原真实输入、重复头和编码 |
| request_decoded | 业务解密后、标准化前的载荷 | 检查真实明文和转换正确性 |
| request_normalized | 带解析版本的业务对象 | 对应资格、Schema 与模型证据 |
| request_to_origin | 实际重建发送的请求 | 检查内容是否被偷偷更换 |
| response_from_origin | 源站返回的头与实体 | 原始响应来源 |
| response_decoded | 解密/解析后的真实响应 | 页面和资格发行证据 |
| response_to_client | 改写/再加密后实际返回内容 | 确认是否已释放敏感内容 |
| model_input/output | 实际 API 逻辑载荷及输出 | 调用复核，不事后猜模板 |
| agent_tool_input/output | 调用参数、结果、文件清单 | 重建 Agent 行为 |
| page/action_manifest | 页面来源和动作候选 | 验证有迹可循的依据 |

HTTP/2/3 经库解析后的头顺序、压缩帧不是完整线缆级报文；本方案记录 application_semantics/entity_bytes，不自称 PCAP。需要线缆抓包另设严格取证能力，非首版默认。

## 12.3 采集点与对照

每个内容产物记录 artifact_id、kind、content_type、content_encoding、byte_length_observed、byte_length_saved、fidelity、capture_status、redaction_manifest_ref、plaintext_commitment、ciphertext_digest、transform_parent_refs 和 policy_revision。

capture_status：complete、partial_limit、partial_cancelled、unavailable、not_applicable、excluded_policy、expired、deleted、corrupt。相同字节不重复存多份，可引用同一证据但保留用途；去重限制在同安全域及相同保密策略内，避免跨租户存在性泄露。

原文中的攻击语句在普通业务字段可保存用于审计，不应因“看起来危险”被清理成良性样本。秘密字段的脱敏是单独、有记录的操作。模型实际输入是在发送前固定的版本，记录的是发送的那一份，而不是脱敏规则更新后的版本。

## 12.4 大体积与流式

小内容按对象保存；大内容分块压缩并独立 AEAD 加密，manifest 记录 chunk 序号、长度、散列、状态和最终结束标记。缺任一 chunk 均不能标 complete。解压有绝对上限与压缩比上限，防止压缩炸弹。

建议初始 capture 上限：普通请求 1 MiB、普通响应 8 MiB、模型逻辑载荷按 provider 限制、单工具输出 16 MiB；限额可按端点调整。严格需全量检查的端点超限不放行；可流式端点按明确粒度检查并显示覆盖。提前拒绝恶意超大 body 不要求为了“全量日志”继续无限读取；保存收到部分和拒绝原因。

## 12.5 信封加密与访问

每证据对象/分块使用独立随机数据密钥或经审查的密钥派生，AEAD 绑定 tenant/site/artifact/version/chunk 作为 AAD，nonce 保证密钥范围内唯一。数据密钥由 KMS 管理的 KEK 包裹；master key 和解密权限与日志写入者分离。

对象名不包含真实姓名、病历 ID、账号、Cookie 或 Token。普通索引只有脱敏摘要、受限引用和密文摘要；低熵秘密不得用公开 SHA256 充当匿名化，关联用租户隔离 HMAC。

使用 EvidenceReadPort 统一授权：读元数据、读脱敏内容、读敏感原文、导出是不同权限。访问前记审批/目的/范围，访问后记实际对象和字节数。敏感原文的临时访问授权短期有效，不能靠长期公开下载 URL。

当前 `xshield-evidence` 本地 MVP 只接受完整且在配置容量/最长保留期内的单对象写入，整对象硬上限 64 MiB，业务配置只能继续收紧。对象使用随机 nonce 与 artifact 作用域 HMAC 派生数据密钥执行 AES-256-GCM，AAD 绑定 tenant/site/request/artifact/kind 和最终 chunk 标记；typed manifest 另以用途隔离 HMAC 认证。manifest 读取使用库内当前时钟重验私有路径、作用域、期限与 key-id，内容读取额外重验密文摘要和 AEAD。对象先于 manifest 耐久发布，崩溃最多留下不可达孤儿密文，不会产生指向缺失密文的已返回 manifest。同一对象格式也可以存进 S3 兼容存储桶并启用 Object Lock，见 12.10；S3 后端额外支持大对象的 multipart 传输与存储桶侧 SSE-KMS，但两者都是存储层特性，不改变这里的单对象整体 AEAD 信封——12.4 描述的按 chunk 独立加密、manifest 记录逐 chunk 状态的流式设计，以及用 KMS 包裹应用层数据密钥（而不是本地 HMAC 派生），仍未实现。

PostgreSQL catalog adapter 只接受 `VerifiedEvidenceManifest`，因此普通 wire struct 不能进入发布命令。首次发布把显式列与 `evidence.cataloged` outbox 事件原子提交；精确重放返回 existing，同 artifact 绑定不同 manifest 或事件返回 conflict。按 request 查询强制 tenant/site/request 三元组、数据库当前时钟、active/deleted 条件与 128 条上限。catalog 用于检索，内容释放仍必须由 vault 认证对象侧 manifest HMAC、ciphertext digest 与 AEAD，并经过独立 EvidenceReadPort 审批。

控制面 `GET /control/v1/requests/{request_id}/evidence` 已接入该 catalog：仅向精确作用域的 Observer 返回 typed manifest 与 catalog 时间，不访问对象内容。列表按 artifact UUIDv7 身份稳定排序，服务端页大小上限 128；下一页游标以独立分页密钥和用途域 HMAC 绑定管理主体、tenant/site、目标 request、页大小及最后 artifact，错误作用域或接口不能复用。每次成功、拒绝或依赖失败均写 `console.manifest.read` 管理审计。

`GET /control/v1/artifacts/{artifact_id}` 复用同一 Observer 与服务端 tenant/site 作用域，精确返回一个 active、未删除、未过期的 typed manifest。不存在、已删除、已过期和其他作用域统一返回 `found=false`，避免对象存在性探测；响应与审计保留请求目标，只有实际返回的对象进入 `evidence_refs`。该接口同样不访问对象内容。

`POST /control/v1/cases` 已提供敏感访问审批所需的目的与案件基础记录。`POST /control/v1/artifacts/{artifact_id}/access` 要求 Investigator、自己拥有的 open 案件、同作用域 active 未过期证据、严格原文访问类型与理由；pending 申请和 `evidence.access.requested` outbox 原子提交并受主体级容量约束。独立 `SensitiveEvidenceApprover` 通过批准/拒绝端点执行一次性终态，申请人自批被拒绝；批准事务重新锁定 open 案件和 active 未过期 artifact，将客户端 TTL 限制在服务配置与对象期限内，并原子提交 `evidence.access.approved` outbox。`GET /control/v1/artifacts/{artifact_id}/content` 要求同一申请主体的 `SensitiveEvidenceReader` 及 `X-Xshield-Evidence-Access-Request`，EvidenceReadPort 先在 PostgreSQL 重验批准资格、open 案件和 active catalog，再在 vault 侧重验 scope、期限、manifest HMAC、ciphertext digest 与 AEAD；内容以附件形式返回前写入包含实际字节数的 `evidence.read` 管理审计。

本地控制面每个 EvidenceReadPort 只允许一个整对象读取或保留响应在途，覆盖解密、审计与 HTTP 缓冲生命周期；超过容量的尝试以 503 和稳定原因码审计拒绝。响应直接持有清零明文及读取许可，最后引用释放后归还容量。该上限优先约束敏感下载峰值，后续并发扩展需同时提供共享字节预算。

## 12.6 保留与删除

建议初始：解密业务原文 24 小时，脱敏证据和模型调用 7 天，决策索引 30 天，已封存调查案按案设置；这些是工程默认，不是合规结论。所有期限由站点确认，不能无限保存“以后也许有用”的病历和凭证。

证据到期后查询层立即禁止读取，后台再删除对象/副本并记录 tombstone。对象锁的保留期与删除计划需一致；不要把所有敏感原文默认锁定多年。保留锁可防止指定期限内删除/覆盖，但不证明内容在产生时真实。[S23]

日志管理人员不能直接解除所有原文加密或抹除完整性告警。既有导出副本和已读取数据无法通过删除原对象收回，文档不得声称可全面撤回泄露内容。

## 12.7 已实现：有界 JSON 响应采集屏障

网关可在可信启动配置的 `operations[].response` 中为 `BUFFERED_JSON` 显式启用下列版本化采集策略；该配置须经站点秘密路径审查并随 `policy_revision` 批准：

```json
"evidence_capture": {
  "profile_revision": "orders-capture-r1",
  "max_bytes": 1048576,
  "retention_seconds": 3600,
  "secret_pointers": ["/session/credential", "/payment/authorization_code"]
}
```

`max_bytes` 为原响应 JSON 上限（1 字节至 1 MiB，且不超过 response.max_bytes）；保留期为 1–86400 秒。最多 64 个 RFC 6901 秘密路径，支持对象键转义及精确数组下标。适配器另外在任意深度强制排除大小写不敏感的 password/passwd/pwd/otp/token/access_token/refresh_token/authorization/cookie/set-cookie/secret/api_key/share_token 字段，并自动合并同一响应认证建立、刷新或上下文切换规则的 bearer_pointer。保留字段名不能替代站点完整的秘密清单；新增或变更业务秘密路径须先更新批准配置。普通业务字段中的攻击文本保留供调查使用。

采集点位于完整 JSON 校验后、身份/资格提交和响应加密前，只转换证据副本。对象 kind=response_decoded、classification=RESTRICTED、fidelity=redacted，content_type=application/vnd.xshield.captured-json+json；密文内的版本 1 文档含 value、profile_revision、source_representation=application_json、source_bytes_observed、excluded_http_headers=true 和逐路径 exclusions（EVIDENCE_SECRET_EXCLUDED），被排除值为 null。manifest 的 bytes_observed/bytes_saved 是该文档长度，源实体长度在文档中；complete 只表示这一受限表示完整。单路径最长 1024 字节，排除清单最多 1024 项，序列化文档最多 4 MiB；重复键、超限或解析失败关闭正文释放。当前不采集 HTTP 头、请求、最终客户端封包、HTML 或流式实体；全站 full_protected 覆盖仍待后续采集点实现。

启用采集必须配置 identity_store 和 `XSHIELD_DATABASE_URL`。部署 Unix 本地文件系统，预建独立私有证据根目录（0700），注入 `XSHIELD_EVIDENCE_ROOT`、`XSHIELD_EVIDENCE_KEY_ID`、独立 32 字节小写 hex 的 `XSHIELD_EVIDENCE_KEY_HEX` 及 `XSHIELD_EVIDENCE_MAX_TOTAL_BYTES`（4259901 字节至 1 TiB）。根目录只允许一个网关写入者；同根控制面只读，共享文件系统部署需另行验证锁语义。启动时计入所有已有常规文件，包括孤儿对象，最多 100000 文件；每次写入先保守预留文档、最大 manifest 与认证侧车占用，失败也保留预留。进程内一个采集许可覆盖解析、加密、落盘、catalog 和 journal，忙时立即拒绝。到期立即禁止读取；已登记密文和超过宽限期的孤儿 `.xev` 可按 12.8 的维护流程清理。网关内置的定期清理每轮结束后重新计算余量；用一次性命令清理时，重启网关后重新计算。

释放顺序为：加密对象及侧车耐久写入 → PostgreSQL catalog 与 evidence.cataloged outbox 原子提交 → 本地 evidence.captured 耐久审计 → 后续响应处理和正文释放。catalog 操作的整体等待受 identity_store.acquire_timeout_ms 约束；事务结果不确定时也保留独立 request_seq，避免终态复用序号。事件只含受限引用、版本和结果，正文不进入索引或普通日志；规则 confidence=null。EVIDENCE_CAPTURE_INVALID、EVIDENCE_CAPTURE_LIMIT_EXCEEDED、EVIDENCE_CAPTURE_CAPACITY_EXHAUSTED、EVIDENCE_CAPTURE_UNAVAILABLE 形成 request.aborted；必需 journal 失败关闭网关就绪状态并在重启恢复缺失终态。源站已返回和客户端已释放是独立事实，失败不触发业务重放。落盘后目录或审计失败可能保留有界对象，已登记对象沿用独立审批读取流程。

`scripts/test_postgres.sh` 包含真实 HTTP→vault→catalog/outbox→journal 集成测试：原正文保持、秘密排除、业务攻击文本保留、超限关闭、数据库约束故障/锁等待超时关闭、事件引用及失败后重启。单测覆盖采集配置、目录单写者、在途许可、磁盘配额和重启孤儿计费。本阶段复用 workspace 的 xshield-evidence（Apache-2.0）及既有 SQLx/Tokio，仅启用 Tokio time；第三方依赖版本与锁文件更新策略沿用 workspace。

## 12.8 已实现：到期密文、孤儿维护与故障重试

迁移 `0015_m3_evidence_retention.sql` 为 catalog 增加删除意图/完成事件引用与有界检索索引，`0016_m3_evidence_orphan_retention.sql` 为无 catalog 的本地孤儿观察增加意图表。`xshield-evidence-retain TENANT_ID SITE_ID BATCH_LIMIT` 是一次性维护命令，批量为 1–32；复用 `XSHIELD_DATABASE_URL`、`XSHIELD_EVIDENCE_ROOT`、`XSHIELD_EVIDENCE_KEY_ID`、`XSHIELD_EVIDENCE_KEY_HEX`，可用 `XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS` 调整 1 秒至 30 天的孤儿宽限期（默认 1 小时）。根目录须为 Unix 私有本地目录，与该 catalog/key 对应的唯一活动存储位置。命令取得与网关写入者相同的排他目录锁，需先停对应网关；控制面到期检查继续有效。具体步骤见 RB-10。

网关也可以自己定期执行同一轮清理，不必停机。设置 `XSHIELD_EVIDENCE_RETENTION_INTERVAL_SECONDS`（1–86400 秒）后，网关在独立线程、独立运行时和独立的单连接数据库池上每隔该间隔执行一轮，批量由 `XSHIELD_EVIDENCE_RETENTION_BATCH_LIMIT` 设定（1–32，默认 32），孤儿宽限期同样读 `XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS`。这些设置在启动时校验，无效值或未启用证据采集时拒绝启动；未设置间隔时行为不变。

- **与采集并行**：清理不占用采集许可。采集写入的密文在 catalog 提交前只短暂处于无登记状态，远小于孤儿宽限期，已登记密文只在到期后删除，所以清理不会删掉在途写入。
- **配额回收**：每轮结束后，无论成败，网关在配额锁内重新扫描根目录、重算剩余字节和文件数，效果与重启相同。扫描期间新的采集写入会等待扫描结束。根目录无法扫描时保留原来的保守余量。
- **观测**：`/metrics` 增加 `xshield_edge_evidence_capacity_remaining_bytes`、`xshield_edge_evidence_capacity_remaining_files`、`xshield_edge_evidence_retention_passes_total`、`xshield_edge_evidence_retention_failures_total{reason_code}`、`xshield_edge_evidence_retention_deleted_total` 和 `xshield_edge_evidence_retention_last_success_timestamp_seconds`。失败的一轮留下可重试的意图，下一轮重试，并在标准错误输出原因码。
- **代码位置**：一轮清理的实现是 `xshield_postgres::retention_pass::run_retention_pass`，一次性命令与网关共用。

启用后不要再对同一根目录运行一次性命令：命令会因目录锁返回 `EVIDENCE_PURGE_BUSY`，不会造成损坏。

流程：按完整 tenant/site/key 与数据库时钟选择 active 到期行 → 行锁内原子提交 `evidence.purge_requested` outbox 与意图引用 → 本地重验 manifest HMAC、全部 catalog 字段、作用域、key、期限、私有常规文件与密文摘要 → 只删除精确 `.xev` 并同步目录 → 重验 catalog 快照，原子提交 `status=deleted`、`deleted_at`、完成引用和 `evidence.deleted` outbox。读取已在过期时关闭，不依赖本流程执行及时性。删除不解密对象，最多读取单对象 64 MiB 加封包开销；一次只有一个对象在途。

既有意图重试复用事件 ID。删除后崩溃或完成事务失败时，下一次命令用仍在的签名 sidecar 证明同一对象，再同步目录并以 `EVIDENCE_DELETE_ALREADY_ABSENT` 完成；实际首次删除使用 `EVIDENCE_DELETED`。孤儿流程只接受精确 `.xev`、稳定的文件长度/mtime 和专用根目录；完整 sidecar 集合先通过 manifest HMAC、作用域/key，提交删除意图后再重验密文摘要；没有 sidecar 的对象或完整有效集合才会进入删除意图。catalog 行按 artifact 全局优先于孤儿观察，partial/损坏 sidecar（含符号链接）保留调查。孤儿删除以 `evidence.orphan.purge_requested` 和 `evidence.orphan.deleted` 记录，数据库意图在物理删除前提交；进程中断后从 pending 意图恢复，已删文件以 `EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT` 收敛。签名、摘要、期限、路径或 mtime 偏差保持文件并提交 `EVIDENCE_ORPHAN_PURGE_REJECTED`；孤儿存储失败提交 `EVIDENCE_ORPHAN_PURGE_UNAVAILABLE`，失败行保持可重试。意图/终态入库失败直接停止，CLI 输出稳定原因码且非零退出；提交结果不确定时保留意图供重试。SQL 单语句/锁等待限 5 秒，每次数据库操作整体限 15 秒。文件操作依赖健康的本地文件系统，运维须监控进程运行时间与存储故障。

保留 catalog tombstone、manifest JSON/HMAC 和孤儿意图表作为恢复和调查元数据；只有本地目录中的文件继续占用网关的 100000 文件上限，达到上限前需安排元数据保留功能迭代。当前清理不涵盖远端副本、备份与已导出内容。案件或原文访问批准不延长对象期限；需要案件 pin 的站点在该独立能力完成前不启用此删除流程。损坏对象需隔离调查，若连续失败填满批次，先处理这些对象再继续维护。复用既有 UUID/SQLx 和内部 Apache-2.0 crates，未引入新第三方依赖；更新策略沿用 workspace 锁文件。

清理事实通过 `XSHIELD_OUTBOX_FAMILY=evidence_retention` 独立发布：六类事件进入 ClickHouse 的 `evidence_retention` 或 `evidence_orphan_retention` 阶段，可按事件 ID、类型、原因或阶段进行有界脱敏检索，结果保留 artifact 与 cause 引用。原请求 ID 只保留在 catalog 事件受限载荷中，维护事件的 request_id 为 null；发布失败按既有 outbox 租约规则重试，不再次执行物理清理。契约、配置和升级见 [11.8](11-audit-event-contract.md#118-已实现的按事件族-outbox-发布)。

真实 PostgreSQL 与 CLI 测试覆盖批量边界、租户/站点/key 隔离、目录锁、意图和完成 outbox 故障回滚、删除后重启、幂等完成、损坏密文保留与重试、孤儿宽限/审计/删除、篡改 catalog 提前期限拒绝；库单测覆盖未到期、错误密钥、错误作用域、符号链接、HMAC、摘要和 partial-sidecar 保留。配置 ClickHouse 后，同一脚本继续把实际清理生产者的六类事件投递至真实生产 DDL 并验证脱敏查询、精确确认、重投去重、故障恢复及内容冲突，执行方式见 [20.12](20-testing-and-acceptance.md#2012-outbox-发布回归)。

### 12.8.1 已实现：校准 lineage-review 专用 body retention

迁移 `0033_m4_calibration_lineage_review_retention.sql` 将 committed lineage-review 的加密 body 与 request catalog retention 分离：review projection、冻结 provenance 和认证 sidecar 继续保留，只有到期 `.xev` 可由 `xshield-evidence-retain` 删除。命令复用 12.8 的 tenant/site/key、目录锁、批量和 orphan 宽限配置；每个 lineage-review phase 每次最多处理 32 项。数据库先锁定 active、到期的 review metadata 并写入 purge intent，vault 随后精确重验 sidecar、scope、key、expiry、文件安全属性和密文摘要，完成目录同步后才写 `deleted` tombstone。已有 intent 在进程中断或数据库完成不确定时可重试，已不存在的密文以稳定的 already-absent 完成事实收敛；reject/unavailable 不删除文件并留下可恢复 intent。

专用 orphan 路径只接收超过宽限期、完整认证且与 committed review metadata 无对应关系的 sidecar。它将文件长度、mtime、sidecar digest、scope、expiry 和精确 artifact/review identity 绑定到独立 intent，再次认证观察后才删除密文；partial、替换、跨域或未认证 sidecar 留作调查。通用 orphan 扫描显式跳过带 lineage-review sidecar 的对象，因此不会将其误当作 catalog 孤儿。新 capability 不能绑定有 intent 或 tombstone 的 review；维护 outbox 不授予读取或恢复资格。六类 maintenance event 的受限 envelope 见 [11.9.2](11-audit-event-contract.md#1192-已实现-calibrationlineage_review_retention-维护契约)。

## 12.9 案件证据保留锁存储与发布

迁移 `0020_m3_case_evidence_holds.sql` 和 `PostgresIdentityStore` 已实现案件级保留锁；管理 HTTP 创建、释放及分页历史入口见 [29.21](29-api-endpoint-catalog.md#2921-已实现的案件保留锁管理契约)。调用方须认证精确 tenant/site 的 AuditAdministrator 并审计操作尝试，该角色可处理同作用域内其他所有者的案件。锁只暂停指定 artifact 的物理删除，catalog/vault 原始 expires_at、读取审批和到期拒读规则保持有效。创建要求 open 案件、已有案件成员、active catalog 且尚未提交删除意图；已过期但尚未进入删除意图的对象可保留供后续合规处置。

hold_until 使用规范 UTC 毫秒（秒为 00–59），创建时按数据库时钟限制为未来 720 小时（30×24 小时）内；每案累计最多 128 条历史，每 tenant/site 最多 1000 条活动锁。相同案件/artifact 的未释放记录保持唯一，过期后需显式释放才能新建；释放允许案件关闭、对象到期和对象已删除。创建和释放分别按作用域、主体、用途幂等摘要精确重试，返回已提交历史，不延长锁；参数偏差返回冲突。自由文本理由持久化于受限表，仅在获权管理员的操作结果和历史响应中返回，事件保存请求摘要及目标引用。

事务先取得作用域 advisory lock，再锁案件和 catalog。清理选择候选时排除活动锁，取得 catalog 锁后使用新语句快照重验；创建与删除意图因此有明确先后顺序。已有耐久意图永久阻止新增锁，恢复该意图时不会因时钟回退使旧锁重新活动而阻塞。多个案件持有同一 artifact 时，所有活动锁释放或到期后才能创建删除意图；关闭案件不自动释放锁。

锁行与完整 `evidence.hold.created` / `evidence.hold.released` outbox 同事务提交，精确重试重新校验已存事实的完整绑定。两种事件由现有 `evidence_retention` 族发布至 ClickHouse 的 `evidence_hold` 阶段，释放事件引用原创建事件；查询摘要保持空请求、空置信度、非业务终态。

升级顺序：暂停全部旧版清理任务 → 应用 `0020` → 升级清理任务、outbox 及管理 journal 发布器 → 启用保留锁 HTTP 入口 → 恢复清理。旧版清理代码不检查此表，存在保留锁后禁止恢复旧版清理实例。SQL 权限按服务职责授予，当前维护进程需要保留锁表 SELECT；控制进程需要案件、成员、catalog、保留锁及 outbox 的相应读写权限。先完成站点范围的权限与审计验收，再启用清理调度。

## 12.10 已实现：S3 兼容存储与 Object Lock 后端

本地证据库只能写在一台主机的私有目录，且只允许一个网关写入（12.7）。`xshield_evidence::S3EvidenceVault` 把同样的加密对象存进 S3 兼容存储桶：密文信封、typed manifest 和 manifest HMAC 与本地逐字节相同，catalog、控制面读取和审批流程不变，只是存储位置不同。

- 对象键：`{前缀}t-{tenant}/s-{site}/{artifact_id}.xev`，另有 `.manifest.json` 与 `.manifest.hmac` 两个侧车。tenant/site 只含 `[A-Za-z0-9_.-]`，`t-`/`s-` 前缀避免出现 `.` 或 `..` 段。键里没有请求内容。
- 写入：先写密文，再写两个侧车，每次都带 `If-None-Match: *`，已存在的键不会被覆盖，因此多个网关和控制面实例可以写同一个桶，不需要目录锁和单写入者。中途失败只留下不可达的孤儿密文，与本地语义相同。密文超过 8 MiB 时改走 S3 multipart upload（分 8 MiB 一片，最后一片可更小），完成请求（`CompleteMultipartUpload`）同样带 `If-None-Match: *`，create-only 语义不因分片而改变；任一分片或完成请求失败都会先尝试 `AbortMultipartUpload` 再把错误返回给调用者。S3 后端的单对象上限是 1 GiB（而不是本地/MVP 的 64 MiB），因为桶对象不必像本地一次写入那样整体放进一次写；真正的按 chunk 独立 AEAD（12.4）仍未实现——multipart 只是同一个已整体加密的信封分成多次 HTTP 请求传输。
- 服务端加密：配置后，每次写入（单次 `PUT` 或 multipart 的 `CreateMultipartUpload`）都带 `x-amz-server-side-encryption: aws:kms`，可选再带显式 KMS key id/alias/ARN；留空则用存储桶自己的默认 KMS key。这是存储桶自己的加密，叠加在本加密证据库自身的 AEAD 信封之上，用于防御存储侧单点失守和满足"桶内数据必须走 KMS"的合规要求；不是把应用层数据密钥交给 KMS 包裹（那部分仍是本地 HMAC 派生，未实现）。
- Object Lock：配置后，三个对象都以所选模式（`compliance` 或 `governance`）锁定到 manifest 的 `expires_at`。到期前存储桶本身拒绝删除或替换，即使拿到写入凭据也不行；到期后清理才能删除。打开证据库时会探测存储桶：要求锁定但存储桶未开启 Object Lock 或未开启版本控制时拒绝启动。
- 删除：清理先读回密文并核对摘要，再按读到的那个版本号永久删除，所以开了版本控制的桶不会只加一个删除标记、把到期密文留在旧版本里。锁未到期时删除失败，记为可重试，下一轮再试。
- 孤儿：按 `ListObjectsV2` 分页列出超过宽限期、且锁已到期的 `.xev`；侧车判断规则与本地相同，单次扫描最多 100000 个键。删除前重新核对大小、修改时间（到秒）和侧车，只删除核对过的版本。
- 请求：SigV4 签名，报文摘要按实际内容计算；整请求超时 1–300 秒，按单次 HTTP 请求计算（multipart 的每个分片、创建与完成请求各自独立计时，不是整个上传过程共用一个超时）；不读取环境代理，不跟随重定向；默认只允许 `https://`。错误信息不含响应正文和凭据。
- 不在 S3 上的对象：校准报告与 lineage-review 对象仍只存本地。使用 S3 后端的清理轮次跳过这两类，由本地根目录上的 `xshield-evidence-retain` 处理。

配置（网关、控制面与 `xshield-evidence-retain` 读同一组变量，见 docs/19 19.4）：

| 变量 | 说明 |
|---|---|
| `XSHIELD_EVIDENCE_BACKEND` | `local`（默认，读 `XSHIELD_EVIDENCE_ROOT`）或 `s3` |
| `XSHIELD_EVIDENCE_S3_ENDPOINT` | `https://host[:port]`，不带路径、查询和用户信息 |
| `XSHIELD_EVIDENCE_S3_REGION` | SigV4 区域，如 `us-east-1` |
| `XSHIELD_EVIDENCE_S3_BUCKET` | 存储桶名，按 S3 命名规则校验 |
| `XSHIELD_EVIDENCE_S3_PREFIX` | 可选，空或以 `/` 结尾的若干段 |
| `XSHIELD_EVIDENCE_S3_ADDRESSING` | `path`（默认，自建服务通常需要）或 `virtual-hosted` |
| `XSHIELD_EVIDENCE_S3_OBJECT_LOCK` | 必填：`compliance`、`governance` 或 `off` |
| `XSHIELD_EVIDENCE_S3_SSE_KMS` | 可选，默认 `off`；`aws-kms` 时每次写入都请求存储桶侧 SSE-KMS |
| `XSHIELD_EVIDENCE_S3_SSE_KMS_KEY_ID` | 可选，仅在 `XSHIELD_EVIDENCE_S3_SSE_KMS=aws-kms` 时允许设置；显式 KMS key id/alias/ARN，留空用存储桶默认 KMS key |
| `XSHIELD_EVIDENCE_S3_ALLOW_PLAIN_HTTP` | `true` 时允许 `http://` 端点，仅用于可信网络；对象本身仍加密，但键和元数据不加密 |
| `XSHIELD_EVIDENCE_S3_REQUEST_TIMEOUT_SECONDS` | 默认 30，范围 1–300 |
| `XSHIELD_EVIDENCE_S3_ACCESS_KEY_ID`、`XSHIELD_EVIDENCE_S3_SECRET_ACCESS_KEY` | 签名凭据，可用 `_FILE` 形式（19.3） |
| `XSHIELD_EVIDENCE_S3_SESSION_TOKEN` | 可选，临时凭据的会话令牌，可用 `_FILE` 形式 |

S3 后端下网关不再计算本地配额，`/metrics` 也不输出 `xshield_edge_evidence_capacity_remaining_*`，容量由存储桶配额负责；`XSHIELD_EVIDENCE_MAX_TOTAL_BYTES` 与 `XSHIELD_EVIDENCE_ROOT` 不再需要。网关内置清理（12.8）与 `xshield-evidence-retain` 都可在网关运行时执行，S3 后端下后者不取目录锁。

验证：`cargo test -p xshield-evidence --lib s3_minio -- --ignored` 对真实 MinIO 运行（CI `object-storage` 作业，MinIO 启动时带一个临时单密钥 KMS 用于 SSE-KMS 用例），覆盖：锁定对象在到期前被存储桶拒绝删除，到期后清理删除已核对的版本，且该版本确实不存在；未开启锁的桶在要求锁定时拒绝启动，错误密钥被拒绝；篡改密文与 manifest 被识别；孤儿列出、分页、核对与删除，未完成侧车与未到期锁定的对象不被列出；超过 multipart 阈值的大对象走分片上传、读回内容一致，且 multipart 完成请求同样拒绝覆盖已有键；SSE-KMS 配置后存储桶 HEAD 确实报告 `x-amz-server-side-encryption: aws:kms`（小对象单次 `PUT` 与大对象 multipart 两条路径都覆盖）。SigV4 实现另有 AWS 文档签名样例的单测。

**未覆盖**：AWS S3 本身及其他兼容服务（只测了 MinIO）；用 KMS 包裹应用层数据密钥本身（当前仍是本地 HMAC 派生，SSE-KMS 只加密存储桶里的字节）；12.4 描述的按 chunk 独立 AEAD 加密与逐 chunk manifest（multipart 只是同一个整体信封的传输优化）；大于 1 GiB 的对象；存储桶默认保留策略与我们写入的保留期冲突时的行为；跨区域复制。

