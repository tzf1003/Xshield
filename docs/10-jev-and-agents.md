# 10 Jev、OpenJev 与分析 Agent

## 10.1 职责分离

RuntimeJudge：对当前相关证据做有限候选选择、内容攻击信号和流程一致性判断；无生产网络工具、无密钥读取、无资格写入、无规则发布权。

AdaptationAgent：分析 JS/协议变化，生成适配候选及测试；只访问批准样本与隔离测试环境。

InvestigationAgent：在操作者已有权限内读取日志证据、构建时间线、提出原因和测试建议；不能自行解锁原始凭证、执行生产请求或修改策略。

Rust 统一 ModelPort/AgentJobPort；OpenJev 可由 Python/CUDA 伴随进程执行，生成式 Agent 可替换供应商。不要把 Jev 的有限输出能力当成任意代码生成工具。

## 10.2 已核验能力与契约

2026-09-17 核验：Jev 文档包含 Choice、Score、Noul。Choice/Score 有 probabilities 与 confidence；Noul 返回 noul，没有独立 confidence。官方 primitives 页面说明 state 与 questions 共享约 32k token 预算；不可按无限全历史设计。[S15][S16]

OpenJev 复刻接口思路，不是官方 Jev 权重或训练；实际上下文、性能和校准取决于底座及部署，必须单独测量。[S17] 文档不把官网宣传或共享状态基准当作 Xshield 实测。

本项目 JudgeRequest 为内部契约；供应商适配器负责转换。记录转换前内部证据包与转换后实际 API 逻辑载荷，不能事后仅凭模板和摘要重建冒充当时真实输入。

## 10.3 输入结构

trusted_policy：固定规则、操作候选、必要限制与版本。

auth_facts：脱敏后的当前身份绑定与资格查询结果。

page_evidence：经过认可流程取得的响应片段、构建与动作映射引用。

untrusted_content：需要检测的实际业务字段、评论等攻击者可控文本。

coverage：各输入是否完整、截断、隐藏、不可用及原因。

trace_context：request_id、model_call_id、对应 input_artifact_id，不放原始 Session/JWT。

禁止把全部站点历史无条件发送；以 request → source chain 检索必要证据。初始内部预算 2k–8k token，最终以实际供应商 token 计算和上限验证为准。图像输入支持必须按 provider capability 声明，不能假定 Jev 接受截图。[S18]

## 10.4 任务拆分

UI action match：在预批准候选中选择 action_id/NONE/UNKNOWN。

semantic consistency：请求目标和业务语义与所选动作是否一致。

content risk：SQLi、命令注入、路径风险等独立检测项；不把所有攻击强制单选。

workflow anomaly：已知来源图中的异常跳转/批量枚举特征。

签名、时间、ID 存在性、方法、字段集合、资源 scope 仍由代码检查。模型不得改变请求内的身份或替代精确账本。

## 10.5 输出与校准

记录原始供应商响应、selected_option、完整 probabilities、provider_confidence、probability_semantics、calibration_revision、threshold_policy_revision、abstained 和 schema_validation。模型/供应商无返回置信度时填 null + not_provided，不填 1，也不把 HTTP 200 当作高置信度。

confidence 不是正确率。使用跨站/跨构建/跨攻击家族独立测试集校准阈值；记录可靠性、误放率、误拒率、unknown 比例和成本。Jev 官方也要求按任务验证阈值。[S16]

## 10.6 失败、缓存与重试

固定 deadline、每站预算、并发 semaphore、熔断和取消。缓存键包括模型具体版本、模板、全部决策相关输入摘要和安全域；不缓存“用户一直安全”。缓存命中要引用原 model_call_id 与新调用采用原因。

重试独立 attempt_id，记录每次输入是否相同、供应商 request id、耗时与用量。只有最终成功请求不能代表之前失败未计费；拿不到 token/cost 时标 unknown。外部模型动态升级后，记录 `resolved_model_revision=null`（未知），禁止声称可逐位复现。

## 10.7 Agent 全调用取证

一个 agent_run 关联任务触发、批准范围、模型消息、检索 manifest、工具 Schema、实际调用参数、结果、stdout/stderr 限制、退出码、文件变更、产出工件及审批。工具输出超限分块保存，索引保存摘要与缺失标记，不把截断后的字符串标为完整结果。

记录供应商实际可见的推理/说明输出；不能获取的内部思考过程不伪造。供应商的通用 system prompt 或内部检索不可见时标 provider_internal_unavailable。

## 10.8 提示注入与发布

所有网页、日志、代码、评论都作为不可信数据。调查 Agent 不执行日志里出现的命令；自然语言查询只能编译为受限查询 AST。权限扩张、入口公开、兼容范围扩大必须经人工/独立策略审批后签名发布，不由模型自批。[S09]

离线适配只在批准测试环境运行。WASM 插件明确 host capabilities、内存与 fuel 限额，复杂 JS 再加进程/容器隔离；Wasmtime 的沙箱仍需要正确约束宿主接口，不是允许任意 hostcall。[S19]

## 10.9 已实现一次性离线评估

`xshield-model-eval --approved-input PRIVATE_JSON_FILE` 接受操作员已批准对外披露、预先脱敏的单个私有 JSON 文件。`approval_ref` 是关联批准记录的标识，不是权限证明；部署账号、文件权限和外发审批由操作者保证。tenant/site 来自可信环境，request/model-call ID 由服务端生成。CLI 只产出评估证据，不连接网关资格写入路径；`MODEL_EVALUATED/PASS` 表示调用与取证完成，不表示业务操作获准。

默认请求固定发送到 `https://ai-gateway.vercel.sh/typesafe/v1/systemone`，wire model 为 `typesafe-ai/jev`，Bearer 由 `AI_GATEWAY_API_KEY` 独立注入；使用原生 TLS 信任根，拒绝重定向和动态目标。`XSHIELD_JEV_ROUTE=direct` 才启用兼容的 TypeSafe 直连（`XSHIELD_JEV_API_KEY`、`https://api.typesafe.ai/v1/systemone`、`jev-1.13.0`）。模型生命周期和调用记录分别保留 `provider` 与独立的 `provider_model_id`；内部审计仍记录固定 `jev-1.13.0`，Gateway 别名没有精确版本证明时 `resolved_model_revision=null`。支持单题 Choice、Score 与 Noul（Score 详见 10.11）；Choice 要求 2–32 个候选，包含 NONE/UNKNOWN，返回完整候选概率且最高概率选项匹配。Noul 的 confidence 始终为 `null/not_applicable`。缺少用量保持 unknown，不估造 token 或成本。

闭环顺序：`model.started` → 内部输入证据 → 冻结实际 API JSON 证据 → `model.requested` → 单次 HTTP → 响应捕获及规范化调用记录 → `model.responded/failed/timeout/cancelled`。每个证据对象先在 vault 耐久落盘，再与 `evidence.cataloged` outbox 原子提交目录。输入目录或审计屏障失败会阻止 HTTP；调用后的取证失败产生依赖失败终态。终态自身持久失败时退出非零，下次启动将未完成调用补记为 `MODEL_OUTCOME_UNKNOWN`，供应商是否已计费保持未知。

四类对象分别为 `model_internal_input`、`model_input`、`model_output`、`model_call`，通过 parent_refs 和事件 evidence_refs 关联。输入保存内部 typed DTO 与实际发送的 JSON。输出对象为 `representation=entity_bytes_array` 的完整 JSON 捕获文档，body 保存实际收到的字节数组，`capture_status/bytes_observed/bytes_saved/http_status` 描述供应商实体的覆盖；对象 manifest 的 complete 只代表捕获文档完整。超限/断流/超时保留有界前缀；响应不可用或命中 API key 排除策略时 output_artifact_id 为 null，调用记录仍明确说明原因。普通审计仅保存版本、状态、置信度与证据引用。正文沿用独立申请、批准与 SensitiveEvidenceReader 读取流程。

资源上限：输入与实际 API JSON 各 8 KiB，文本合计最多 6144 字符，响应最多 64 KiB，每个证据文档最多 512 KiB、保留 24 小时；发送至读体总期限 10 秒，catalog 操作每步 5 秒。证据根目录排他锁限制一次一个任务，预留四对象最坏空间，目录最多 100000 文件。429 记 `MODEL_RATE_LIMITED`、529 记 `MODEL_OVERLOADED`，保留合法 Retry-After 秒数供操作员决策；每次 CLI 调用至多一次 HTTP。重启认证扫描最多 10000 条专用 journal 记录，补记中断终态并保留因果引用；接近上限时按 RB-11 轮换目录。

后续增量包括缓存、多实例站点预算、自动重试、OpenJev/SemIf 伴随进程和调查 Agent，分别完成安全域、能力与恢复契约后接入。Score 增量见 10.11；当前未执行真实供应商推理或准确率/校准测试。

## 10.10 Jev 供应商接入决定

2026-09-20 确定：Jev 后续通过 [Vercel AI Gateway 的 Jev 入口](https://vercel.com/ai-gateway/models/jev) 接入，模型标识为 `typesafe-ai/jev`。[官方 TypeSafe 兼容 API 文档](https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe) 列出的请求地址为 `https://ai-gateway.vercel.sh/typesafe/v1/systemone`，模型目录为 `GET https://ai-gateway.vercel.sh/typesafe/v1/models`，使用 Gateway Bearer 凭证。

秘密由运行环境管理，约定引用 `AI_GATEWAY_API_KEY`；仓库、前端构建、样例和审计只保留引用，禁止保存密钥值。macOS 本地开发可使用钥匙串服务 `Xshield.Jev.VercelAIGateway`、账号 `Xshield` 保存该秘密，并在适配器运行时由秘密端口读取或注入进程环境。

已完成固定 Gateway 适配并将其作为默认路由；当前 CLI 仍不执行自动重试、fallback 或资格写入。`XSHIELD_JEV_API_KEY` 仅可在显式 `direct` 路由发往 TypeSafe 直连目标，不得注入 Gateway；Gateway 响应的 `provider_metadata.gateway.routing` 仅做有界契约校验，不把 alias 当作精确版本。外发输入审批、固定 HTTPS 目标、硬拒绝优先及 Noul 空置信度要求继续生效。

## 10.11 已实现 Score 离线评估

同一 `xshield-model-eval` 入口接受 `question={"type":"score","instructions":"按批准档位评估严重程度","criteria":["低","中","高"]}`。`criteria` 必须为 2–10 项有序字符串数组，位置对应零起始档位；每项最多 512 字符，指令最多 1024 字符，全部文本继续计入 6144 字符和 8 KiB 输入/API 预算。内部输入与实际外发载荷分别保存，批准与脱敏责任沿用 10.9。

2026-09-20 核验的 [TypeSafe HTTP API](https://docs.typesafe.ai/api#score) 与 [Score 响应契约](https://docs.typesafe.ai/primitives/score#response-structure) 定义 `score` 为各档位编号的概率加权平均。响应必须提供精确匹配输入的 `legend`、完整 `probabilities`、有限且位于 `[0,n-1]` 的评分；档位键严格为 `0` 至 `n-1`，重复、缺失、额外或非规范键均拒绝。概率各在 `[0,1]`，总和与 1 的绝对误差最多 `1e-6`；评分与加权平均的绝对误差最多 `1e-5`。两项容差为本地序列化校验策略，供应商文档未承诺舍入精度。

成功调用证据记录数值 `result`、完整 `legend` 与 `probabilities`。`provider_confidence` 保留供应商原值，缺失或 null 时为 `null/not_provided`；评分、概率和置信度分别表达不同事实。非法响应仍保存实际响应捕获文档，以 `MODEL_RESPONSE_INVALID` 收敛终态，规范化结果为 null；429 使用 `MODEL_RATE_LIMITED`，一次评估只发送一次，中断恢复补记 `MODEL_OUTCOME_UNKNOWN`。模型元数据查询与控制台可显示 Score 生命周期，评分和档位正文通过原文审批读取。

Gateway 元数据支持官方 `provider_metadata.gateway` 中的 `generationId` 和 `cost`、`marketCost`、`surchargeCost`、`gatewayCost` 十进制字符串。标识最多 256 字节可见 ASCII，费用字符串最多 64 字节；同时保留已接受的 routing 字段。费用只校验并保存在原响应证据，不据此推算用量或结算，Gateway 别名仍保留未知精确版本。

先升级模型 journal 发布器、控制查询服务及控制台，再启用 Score 生产者；旧版读取端只接受 Choice/Noul，遇到 Score 会严格拒绝。需要回退时先停止新增 Score 调用，保留已产生的 journal、证据、catalog 与水位，并继续用支持 Score 的读取/发布端处理历史。本次无需数据库迁移或新依赖。

## 10.12 离线阈值评估内核

`xshield_core::calibration` 提供无 I/O 的固定阈值评估：最多 10000 个唯一 `ModelCallId` 样本，真值为 benign/malicious/unknown，信号为已验证二元恶意概率或有原因的缺失。概率须有限且位于 `[0,1]`，阈值满足 `0 ≤ low < high ≤ 1`；`p ≤ low` 归为离线 allow 建议，`p ≥ high` 归为 deny，中间值及缺失归为 abstain。输出建议只用于统计，应用层仍执行确定性规则。

报告保留真值与建议的九格计数，以及概率缺失原因、未知标签和可评分样本数。误放率分母是全部已知 malicious，误拒率分母是全部已知 benign，均包含概率缺失的样本；覆盖率与弃权率分母是全部样本。分母为零返回 `None`。Brier 与十个固定可靠性桶只使用真值已知且概率有效的样本，未知标签与缺失分别计数。所有比例提供原始分子和分母，便于判断样本覆盖。

二元恶意概率需要按批准任务从 Choice 风险候选或 Score 风险档位的完整分布映射；供应商 confidence 与 Score 加权均值不具备这一含义。UNKNOWN 概率质量必须按预先约定处理，不能删除后重归一。网关别名的精确版本未知状态必须保留。`calibration::dataset` 已负责冻结引用、版本和声明的分区边界，具体契约见 10.14；受控证据读取、内容独立性审查和耐久报告仍由后续应用层负责。

运行 `cargo run -p xshield-core --example offline_threshold_evaluation` 可查看固定合成样本的分母和 Brier 计算；示例只输出合成指标。当前交付包括统计内核和数据集领域契约；持久报告/审计、跨站独立数据集审查、阈值选择与真实校准继续交付。

## 10.13 已实现批准概率映射

离线评估输入可选 `risk_mapping={"revision":"risk-map-r1","classes":{"0":"benign","1":"unknown","2":"malicious"}}`，该示例对应三档 Score。Choice 使用候选名称作为键，必须将 `UNKNOWN` 标为 `unknown`。所有批准候选/档位必须精确覆盖，每个只能属于 benign、malicious 或 unknown，且至少有一个 benign 与 malicious。Noul 不接受此映射；省略映射的既有输入保持原有行为。

映射修订和类别保存在内部输入证据，实际外发题目保持供应商原始契约。成功响应经完整分布校验后按批准类别求和，调用证据新增 `risk_projection`，保存 `mapping_revision`、三类原始概率质量、`abstained` 和稳定原因 `MODEL_RISK_PROJECTED` / `MODEL_RISK_ABSTAINED`。任意正的 unknown 质量均弃权；质量不删除、不重归一。总和容差沿用 `1e-6`；类别和高于 1 仅允许 `32 * f64::EPSILON` 的计算舍入，原始质量保留，转换为阈值内核信号时仅夹紧此数值边界。失败响应不生成投影，原响应取证与终态沿用现有流程。

纯计算端口位于 `calibration::mapping`，限定 2–32 个唯一档位，规范化键顺序后累加；阈值评估器消费投影信号，供应商 confidence 和 Score 均值独立保存。映射名称是批准记录引用，批准权限、任务语义、分区与模型版本仍由调用者验证。启用读取调用记录的消费者应先升级支持可选 `risk_projection`；关闭新增映射输入可停止生成该字段，历史证据继续保留。

## 10.14 已实现校准数据集领域契约

`xshield_core::calibration::dataset` 在调用纯阈值内核前构造 `EvaluationProvenance` 和 `DatasetSample`。前者冻结 `approval_ref`、dataset/label/task/mapping/threshold-policy 修订、训练/校准/评估/标签四份 manifest artifact，以及 `ModelIdentity`；模型身份包含 provider、provider wire model、内部模型修订、提示修订和可选的 resolved provider revision。无法证明 Gateway alias 的精确实现修订时，`resolved_model_revision=None` 会保留在报告中，而不会从当前路由推断版本。

四份 manifest 必须是不同 artifact，且任一 manifest 不得复用为样本的模型调用记录或标签 artifact；每个样本的两类 artifact 也必须不同。评估前会拒绝同一角色的重复 artifact、跨模型记录/标签角色复用、重复 `ModelCallId`、样本模型身份与冻结身份不一致，以及样本映射修订漂移。成功结果保留按样本顺序的 `ModelCallId`、模型记录与标签证据三元关联、冻结 provenance、阈值和原始指标，并以 `CALIBRATION_DATASET_EVALUATED` 供调用方写入自己的耐久审计。

此层不读取、解密或授权任何 evidence，不调用模型、不发布策略、不改变资格，也不写 audit、journal、catalog 或报告。artifact ID 不同只能证明本次提交的引用集合不同，不能证明 manifest 或外部样本内容没有重叠，亦不能排除同源数据、重试相关性、标签质量或分区泄漏。后续应用层必须使用独立的校准批量能力和受控读取端口，重新验证作用域、保留期、记录身份、映射、标签审查和内容独立性，并将报告证据及终态写入独立审计链；不得复用 `model.*` 生命周期冒充校准报告。

使用 `cargo test -p xshield-core --all-targets` 运行该契约的纯 Rust 回归。测试验证冻结 provenance 与来源三元关联顺序、未知 resolved revision 的保留、四份 manifest 与样本来源的引用隔离，以及样本 artifact、模型身份、映射修订和 `ModelCallId` 的反例；它们不是授权读取、持久化、供应商调用或真实校准验证。

## 10.15 已实现校准报告持久化

`xshield_core::calibration::publication::CalibrationReportPublication` 从已完成的 `EvaluationReport` 投影一个新的 `calr_` UUIDv7 report ID 和独立 report artifact。该不可变投影只保留 approval、dataset/label/task/threshold-policy/mapping revision、训练/校准/评估/标签四份 manifest 及 `ModelIdentity`；后者继续保留 provider、wire model、内部模型/提示修订和可选的 resolved provider revision。report artifact 不得与任一 manifest 或选中样本的模型记录/标签 artifact 同 ID；冲突固定返回 `CALIBRATION_REPORT_EVIDENCE_ALIASED`，成功原因固定为 `CALIBRATION_REPORTED`。

该类型有意不投影 source tuple、`ModelCallId`、标签、概率、ground truth、统计指标、提示词或供应商正文，且不重新计算阈值评估。`CalibrationReportArtifact` 固定使用 canonical JSON 与浮点 bit 表示，拒绝重复、未知、敏感或非规范字段，并逐项复核 report/source/provenance/metrics 的闭合关系。`LocalEvidenceVault::write_calibration_report` 仅接受完整 artifact，写入 request-free 的专用认证 sidecar；其 AEAD AAD 绑定 tenant、site、report ID、artifact ID、kind 和 canonical encoding。通用 manifest、request ID、通用 catalog 与 report sidecar 互不复用，通用 orphan 清理也不会处理受专用 sidecar 保护的 report ciphertext。

迁移 `0026_m4_calibration_report_publication.sql` 与 `PostgresIdentityStore::complete_and_publish_calibration_report` 将已经写入 vault 的认证 report manifest 与完整 `CalibrationEvidenceBatchCompletion` 合并为一个短事务：锁定 capability/member/live catalog，重验 scope digest、数据库期限、active lease、私有 token digest 和 configured runner；再持久化 report artifact 元数据及冻结 projection，写入 `calibration.read_batch.completed` 和 `calibration.reported` 两个受限 outbox 事实，并同时把 lease `active → completed` 和 capability `leased → consumed`。报告 metadata 不进入 `artifact_catalog`，不伪造 request ID；失败或冲突回滚数据库状态且不消费 lease。已消费 capability 的恢复只接受完全匹配的 report、专用 manifest、runner、token digest 与两个固定事件，不因 catalog retention/drift 重新授权。数据库拒绝和过期、runner 不符、catalog drift 都以无内容终态收敛。该组是可组合的 vault/PostgreSQL 适配器 API；受控 evaluator/application 尚未调用它，因此不是可运行报告生产服务的验收。

`cargo test -p xshield-core --all-targets`、`cargo test -p xshield-evidence --all-targets` 与 PostgreSQL 回归覆盖 canonical artifact、专用 vault/AAD、artifact-first 失败、原子成功、精确重试、事件绑定、runner 不符、catalog drift 和到期拒绝。它们不验证外部内容独立、真实 evaluator/供应商质量、阈值选择或策略发布；`calibration.reported` 的受限元数据 schema 与 outbox 消费端约束见 [11.9](11-audit-event-contract.md#119-已实现-calibrationreported-发布契约)。

## 10.16 已实现校准批量读取能力与端口契约

`calibration::read_capability::CalibrationEvidenceReadCapability` 是由未来发行器提供给一次离线校准批次的精确、只读输入：独立 `calcap_` ID 冻结 tenant/site、`not_before`/`expires_at`、`EvaluationProvenance`、四份分区 manifest，以及每个样本位的 model-call record 和 reviewed-label artifact 对。`evidence_refs()` 只能导出这份封闭集合及其 `CalibrationEvidenceRole`；四份 manifest、每一对样本来源和跨样本来源均不得别名。能力的样本数受 `MAX_SAMPLES` 限制，聚合 catalog 字节预算必须为正且不超过 512 MiB；调用方还须在每次读取前以可信时钟重验 capability 的 tenant/site 和有效期。

`CalibrationEvidenceReadPort` 只接收由 `CalibrationEvidenceReadRequest::new` 用 capability 导出的精确 artifact/role 引用及同一 capability 的非可复制 batch session 构造的请求；构造器重验 session 实例、tenant/site、租约和 capability 的完整成员关系，不能伪造或替换引用的 capability ID。`CalibrationEvidenceBatchLease` 是权威发行器开始批次后返回的私有 lease handle：包含独立 `callease_` ID 与不可格式化、不可复制的私有会话凭据，绑定 tenant/site、capability 和有限区间；`CalibrationEvidenceReadSession` 仅在 lease 完全位于 capability 期限内且当前有效时绑定该精确内存 capability。它们均不记录、序列化或打印私有 handle，且只作本地形状与绑定检查，不证明持久发行、消费或恢复。所有本地 scope、期限、session、成员或 role/reference 不匹配统一映射为 `EvidenceNotAuthorized`（`CALIBRATION_EVIDENCE_NOT_AUTHORIZED`），避免成为 evidence 枚举 oracle。它不是 `xshield-control` 的单对象 `EvidenceReadPort`，也不接受控制台 `EvidenceAccessRequestId`、案件、`ApprovalRef` 或 Reader/Approver 角色作为校准批量授权；后者只可关联数据集 provenance，不能替代目的限定的 batch capability。`LocalCalibrationEvidenceReader` 在每次打开对象前通过 PostgreSQL 重验独立发行、活动 lease、catalog 的 tenant/site/有效期/大小、完整冻结集合和角色，再比较 vault 认证 manifest 与 catalog 预期，并由 vault 复验密文摘要和 AEAD；任一失败只可返回无内容的拒绝或依赖错误。成功明文只在专用加密 journal 获得读取终态 receipt 后交给 evaluator。

`CalibrationEvidenceBatchCompletion::from_successful_evaluation` 是与单对象读取严格分离的 evaluator 完成证明：它消费 session，只接受一个已经成功构造的 `EvaluationReport`，并逐项比较冻结 provenance 及有序 model-record/label source pair。部分样本、重排/替换来源或其他 provenance 固定拒绝为 `CALIBRATION_READ_BATCH_COMPLETION_SOURCE_SET_MISMATCH` 或 `CALIBRATION_READ_BATCH_COMPLETION_PROVENANCE_MISMATCH`；它不接受单个 artifact、控制台审批或读取 audit receipt。该纯类型不读取 vault、不写审计、不发布报告或策略，也不能自行证明调用者曾释放所有内容；受控 evaluator 必须在成功构造 report 前完成全部 reader-owned 读取与审计屏障。

这组领域/port 契约本身不发行 capability、也不直接消费耐久状态；耐久发行、lease completion、batch lease 与本地 vault reader 见 10.17–10.18。端口及其纯能力测试不能证明报告 artifact 写入、内容独立性审查、真实校准、阈值/策略发布或业务资格发行。

## 10.17 已实现耐久发行与批次会话

迁移 `0023_m4_calibration_read_capabilities.sql` 和 `PostgresIdentityStore::issue_calibration_read_capability` 形成校准批量输入的耐久发行闭环。发行事务先取得 issuer 范围 advisory lock，以确定顺序锁定完整 catalog 集合，再以数据库时钟核对 tenant/site、active/未删除状态、对象期限不短于 capability、字节预算和完整 artifact/role 集合。它在一个事务中写入 capability header、所有成员的 artifact/role/sample-index 与 catalog snapshot（字节数、完整性摘要、kind/content-type/fidelity/classification、期限、catalog event），并保存 SHA-256 的版本化规范 `scope_digest`；header、成员与聚合字节数受 deferred 完整性约束，禁止残缺、扩展或非连续样本对提交。

发行使用 capability ID、issuer 与请求/幂等摘要进行精确恢复。相同耐久 header、成员和 issuance envelope 返回既有记录；任一已提交输入差异返回 `CALIBRATION_READ_CAPABILITY_ISSUANCE_CONFLICT`，catalog 缺失、到期、删除、漂移或超预算返回 `CALIBRATION_READ_CAPABILITY_SOURCE_UNAVAILABLE`。成功同时写入受限 `calibration.read_capability.issued` outbox 事实：`request_id=null`、无 evidence refs，仅包含 capability ID、scope digest、成员数、冻结字节数和有效期；其 producer 为 `calibration-capability-issuer`，稳定原因是 `CALIBRATION_READ_CAPABILITY_ISSUED`。成员表、标签、模型内容、lease handle 与控制台身份均不进入该 envelope。既有 calibration outbox family 已对该小型 payload、聚合 capability ID、producer/时钟/trace 绑定及全部边界严格解析，可按原有 at-least-once 流程发布；本里程碑尚未执行其真实 ClickHouse 端到端集成，不能以 parser/producer 单元实现宣称索引投递已经通过。

`PostgresIdentityStore::begin_calibration_evidence_batch` 为已发行 capability 创建或恢复完整批次 lease。它在同一短事务重新锁定 header、成员和 live catalog，逐项比较冻结快照、期限与聚合字节数；每份 capability 同时只能有一个 active lease。lease 最长一小时，带新的 `callease_` ID；数据库只保存其 SHA-256 digest，明文会话凭据只通过不可复制、自动清零的 `CalibrationEvidenceBatchLease` 返回给调用者，再绑定为 `CalibrationEvidenceReadSession`。活跃 lease 未到期返回 `CALIBRATION_READ_BATCH_BUSY`；到期 lease 先转为 `recovery_required` 并弃置，再从完整冻结集合生成下一代 lease，最多 16 次恢复，超过上限以 `CALIBRATION_READ_BATCH_RECOVERY_EXHAUSTED` 终结为 expired。

`PostgresIdentityStore::authorize_calibration_evidence_read` 是每次 vault 打开前的用途专属再授权步骤。它锁定 durable header、全部 member 和 live catalog，并以数据库时钟核对能力期限、冻结 scope/聚合字节、精确 artifact/role/sample slot、活动 lease 和私有 handle 的 SHA-256 digest。成功仅返回私有构造的 `AuthorizedCalibrationEvidence` catalog 预期；租约、scope、成员或 catalog 任一偏差统一为 `CALIBRATION_EVIDENCE_NOT_AUTHORIZED`，不泄露对象存在性。它不读取 vault、不消费 batch、不写读取审计或终态，且不把 console approval 转化为校准授权。vault 认证 manifest、密文摘要和 AEAD 成功后，reader 必须用迁移 0025 的精确 lease/token/artifact release reservation 重验全部 live state；reservation 的存活期阻止受影响 catalog 行被改变，reader 先取得耐久 journal receipt，再在短事务中重新核验并删除 reservation。该删除事务是明文交付的 release boundary；任一步失败均清零并扣留内容。

`PostgresIdentityStore::complete_calibration_evidence_batch` 只接收 `CalibrationEvidenceBatchCompletion` 和与 acquisition 一致的配置 runner。短事务先锁定 header：若相同 lease ID、runner 与私有 token digest 已经是 `completed/consumed`，返回 `CALIBRATION_READ_BATCH_ALREADY_COMPLETED`，即使随后 catalog retention/drift 已发生，供未知提交结果安全恢复。否则它重验耐久 capability/member scope、当前 live catalog/聚合预算、数据库时间、活动 lease 与 token digest；仅当全部成立时同一事务把 lease `active → completed`、capability `leased → consumed`，并以迁移 0024 原子写入受限 `calibration.read_batch.completed` outbox 终态，成功原因为 `CALIBRATION_READ_BATCH_COMPLETED`。该事实只含 capability ID，不含 lease、样本、artifact、evaluator 输出或 report，且 capability header 的 completion event 引用与 outbox 同事务绑定。错误 runner、伪造 token、过期/撤销、catalog 漂移、部分 evaluator result 或任一非活动状态均为无内容的 `CALIBRATION_READ_BATCH_COMPLETION_UNAVAILABLE`。单 artifact authorization/read 没有该 API 的输入类型，绝不消费 lease。completion 不复用 `evidence.read`，也不把 journal/index receipt 当授权真值；各对象的 pre-plaintext calibration-read audit 与后续 report producer/audit 仍各自独立。

## 10.18 已实现校准明文释放审计契约

`xshield_worker::calibration_audit::CalibrationEvidenceReadAuditEvent` 是 `LocalCalibrationEvidenceReader` 的 reader 本地加密 journal writer。它按当前 journal 的 boot/next sequence 冻结 `calibration.evidence_read`，成功只记录 capability ID 与已通过预释放屏障的有界字节数；它不是 evaluator 已收到明文的断言。reader 先取得 0025 reservation，helper 的 `append` 返回被绑定的 journal receipt，随后由 release-boundary 事务决定是否交付；reservation 最终提交失败时清零并扣留内容，且不会写入矛盾的第二个终态。拒绝或依赖错误只记录 capability ID、结果和稳定原因。该 helper 不替代每次读取前的 `authorize_calibration_evidence_read`，也不替代 evaluator completion。

事件 payload、schema 与 sealed-segment publisher 都拒绝 artifact、role、sample index、lease/handle、evidence refs 和内容，以免分析索引成为批量源证据目录。journal event 不使用 outbox：outbox 的 at-least-once 投递只记录数据库事务事实，不能证明 reader 已在明文释放前获得本地耐久确认。reader/vault、受限报告 artifact 及报告提交闭环已交付；内容独立性审查和真实校准仍由后续闭环交付。
