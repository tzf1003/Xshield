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

当前 `xshield-evidence` 本地 MVP 只接受完整且在配置容量/最长保留期内的单对象写入，整对象硬上限 64 MiB，业务配置只能继续收紧。对象使用随机 nonce 与 artifact 作用域 HMAC 派生数据密钥执行 AES-256-GCM，AAD 绑定 tenant/site/request/artifact/kind 和最终 chunk 标记；typed manifest 另以用途隔离 HMAC 认证。manifest 读取使用库内当前时钟重验私有路径、作用域、期限与 key-id，内容读取额外重验密文摘要和 AEAD。对象先于 manifest 耐久发布，崩溃最多留下不可达孤儿密文，不会产生指向缺失密文的已返回 manifest；远端 catalog reconciliation、分块、S3/KMS 与审批读取在后续 adapter 闭环实现。

PostgreSQL catalog adapter 只接受 `VerifiedEvidenceManifest`，因此普通 wire struct 不能进入发布命令。首次发布把显式列与 `evidence.cataloged` outbox 事件原子提交；精确重放返回 existing，同 artifact 绑定不同 manifest 或事件返回 conflict。按 request 查询强制 tenant/site/request 三元组、数据库当前时钟、active/deleted 条件与 128 条上限。catalog 用于检索，内容释放仍必须由 vault 认证对象侧 manifest HMAC、ciphertext digest 与 AEAD，并经过独立 EvidenceReadPort 审批。

控制面 `GET /control/v1/requests/{request_id}/evidence` 已接入该 catalog：仅向精确作用域的 Observer 返回 typed manifest 与 catalog 时间，不访问对象内容。列表按 artifact UUIDv7 身份稳定排序，服务端页大小上限 128；下一页游标以独立分页密钥和用途域 HMAC 绑定管理主体、tenant/site、目标 request、页大小及最后 artifact，错误作用域或接口不能复用。每次成功、拒绝或依赖失败均写 `console.manifest.read` 管理审计。

`GET /control/v1/artifacts/{artifact_id}` 复用同一 Observer 与服务端 tenant/site 作用域，精确返回一个 active、未删除、未过期的 typed manifest。不存在、已删除、已过期和其他作用域统一返回 `found=false`，避免对象存在性探测；响应与审计保留请求目标，只有实际返回的对象进入 `evidence_refs`。该接口同样不访问对象内容。

`POST /control/v1/cases` 已提供敏感访问审批所需的目的与案件基础记录。`POST /control/v1/artifacts/{artifact_id}/access` 要求 Investigator、自己拥有的 open 案件、同作用域 active 未过期证据、严格原文访问类型与理由；pending 申请和 `evidence.access.requested` outbox 原子提交并受主体级容量约束。独立 `SensitiveEvidenceApprover` 通过批准/拒绝端点执行一次性终态，申请人自批被拒绝；批准事务重新锁定 open 案件和 active 未过期 artifact，将客户端 TTL 限制在服务配置与对象期限内，并原子提交 `evidence.access.approved` outbox。批准记录是服务端短时资格真值，实际内容读取仍须 `SensitiveEvidenceReader` 与 EvidenceReadPort 重验该资格和对象完整性。

## 12.6 保留与删除

建议初始：解密业务原文 24 小时，脱敏证据和模型调用 7 天，决策索引 30 天，已封存调查案按案设置；这些是工程默认，不是合规结论。所有期限由站点确认，不能无限保存“以后也许有用”的病历和凭证。

证据到期后查询层立即禁止读取，后台再删除对象/副本并记录 tombstone。对象锁的保留期与删除计划需一致；不要把所有敏感原文默认锁定多年。保留锁可防止指定期限内删除/覆盖，但不证明内容在产生时真实。[S23]

日志管理人员不能直接解除所有原文加密或抹除完整性告警。既有导出副本和已读取数据无法通过删除原对象收回，文档不得声称可全面撤回泄露内容。
