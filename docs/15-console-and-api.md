# 15 管理后台与调查 API

## 15.1 信息架构

Overview：防护状态、未覆盖端点、拒绝趋势、证据完整率、journal/索引水位、模型成本。

Sites：域名与上游、认证 profile、根入口、UI 映射、资格来源、加密版本、模式与覆盖。

Requests：全请求检索、保存过滤器、详情时间线与关联证据。

Identity & Grants：认证绑定、代际、资格来源图、过期/撤销与异常串用。

Models & Agents：调用列表、概率分布、输入/输出、工具链、成本、失败重试与评估。

Evidence & Cases：敏感证据审批、调查案、保留、验证与导出。

Rules & Releases：差异、测试、审批、签名、灰度、回滚。

Operations：节点、队列、存储、密钥引用、告警与审计访问。

## 15.2 请求详情布局

顶部摘要：request_id、站点、方法/路由、decision、主要原因、发生时间、身份引用、是否转发、业务结果是否已确认。

左侧阶段树：每层 outcome、耗时、证明类型、概率/置信度（适用时）、未执行原因。点击节点定位右侧证据。

内容页签：输入与输出；界面来源；资源操作资格；加密转换；Jev 判别；Agent 关联；审计完整性。

原文默认脱敏折叠；解密查看单独授权。字节版本与 JSON 视图可对照，展示截断长度、字符编码、格式化是否改变字节。风险颜色不代替文字标签，界面“ALLOW”旁明确实际检查范围。

## 15.3 后台身份与权限

Observer：只读脱敏摘要；Investigator：创建案件、查询授权证据；SensitiveEvidenceApprover：为其他主体批准或拒绝原文访问；SensitiveEvidenceReader：在获批短时范围内读原文；PolicyAuthor：提交候选；PolicyApprover：审批策略；ReleaseOperator：发布已签名工件；AuditAdministrator：保留与完整性运维；SystemAdmin：基础配置但不自动获得全部原文读取权。

高危原文导出、全站降级、权限扩大、关键签名操作要求再认证及独立审批。拒绝作者自批高危变更。控制台 MFA、CSRF、会话超时、每站访问范围、管理员操作审计为首版要求。

## 15.4 API 最小集（自定义契约）

| 方法与路径 | 用途 |
|---|---|
| POST /control/v1/search | 结构化 QueryPlan，返回游标和水位 |
| GET /control/v1/requests/{request_id} | 聚合摘要、阶段、覆盖和关联 |
| GET /control/v1/requests/{request_id}/events | 不可变事件分页 |
| GET /control/v1/requests/{request_id}/evidence | 作用域内证据 manifest 分页，不读取内容 |
| GET /control/v1/model-calls/{model_call_id} | 逻辑调用与实际尝试、输入输出引用 |
| GET /control/v1/grants/{grant_id} | 资格与当前绑定的脱敏账本快照、来源请求引用 |
| GET /control/v1/auth-bindings/{binding_id} | 身份绑定的代际、状态与期限快照 |
| GET /control/v1/agent-runs/{agent_run_id} | 子调用、工具、产物和权限快照 |
| GET /control/v1/artifacts/{artifact_id} | 作用域内单个证据状态、长度、保密和完整性，不读取内容 |
| POST /control/v1/artifacts/{id}/access | 申请受限原文访问 |
| POST /control/v1/evidence-access-requests/{id}/approve | 独立批准并建立短时读取资格 |
| POST /control/v1/evidence-access-requests/{id}/deny | 独立拒绝并终结申请 |
| POST /control/v1/cases | 建立调查案与证据集合 |
| POST /control/v1/cases/{case_id}/items | 将同作用域有效证据引用加入本人开放案件 |
| GET /control/v1/cases/{case_id}/items | 查询本人案件的有界证据引用集合及 catalog 状态 |
| POST /control/v1/cases/{case_id}/close | 关闭本人案件并保留调查历史 |
| POST /control/v1/replays | 异步安全回放任务 |
| POST /control/v1/exports | 加密调查包导出任务 |
| POST /control/v1/candidates/{id}/validate | 类型、依赖、扩权和覆盖检查 |
| POST /control/v1/candidates/{id}/publish | 发布已审批工件，不直接接受自由脚本 |
| GET /control/v1/audit/health | 已认证的连续索引水位、缺口与本地存储状态 |

浏览器探针仅能访问 `/__xshield/v1/bootstrap` 和 `/__xshield/v1/events/prepare`，不能访问管理 API。API path 中的 ID 均需按 tenant/site 和资源权限再验，不使用“知道 ID 就可读取”。

当前案件创建接口要求 `Investigator`、管理机器凭证和 16–128 字节规范 `Idempotency-Key`；tenant/site 与 owner 均由服务端身份确定，请求只接受严格 JSON `purpose`。每个 owner/tenant/site 的 open 案件数受启动配置限制，案件与 `case.created` outbox 同事务提交；精确重试返回原案件，不同参数复用键返回 409。

案件关闭要求相同角色与本人归属，严格接受 `reason` 与独立用途的幂等键。关闭状态、理由及 `case.closed` outbox 同事务提交，并释放 open 案件容量；精确重试返回原关闭时间。关闭后的历史集合仍可查询，后续新增关联、访问申请/批准及读取资格校验继续要求 open 状态；既已通过校验的在途读取可能完成。具体失败、审计和迁移边界见 [29.18](29-api-endpoint-catalog.md#2918-已实现的案件关闭契约)。

案件证据关联要求同一角色、固定作用域与幂等键，只接受本人 open 案件及同作用域 active 未过期 artifact。每案最多 128 项，关联与 `case.evidence.added` outbox 原子提交；关联不授予内容读取权限，也不延长 artifact 保留期限。精确重试返回原关联时间，详情见 [29.16](29-api-endpoint-catalog.md#2916-已实现的案件证据关联契约)。

案件集合查询同样要求 `Investigator`、服务端固定作用域和本人 owner；open/closed 案件均可读取。仅接受可选的 HMAC `cursor`，服务端在同一 PostgreSQL 只读快照中校验案件归属、成员关系、outbox 关联和 catalog 状态，最多返回 128 个引用。响应只含案件摘要、数据库 `as_of`、artifact ID、加入者/时间及 `active`、`expired`、`deleted`、`unavailable` 状态；其中 `unavailable` 是外键保护下的防御性一致性状态，正常 retention 以 `deleted` tombstone 表示。不返回 manifest、locator、hash、key ref 或内容能力；每次成功、拒绝或依赖故障均写 `console.case.read`，审计失败扣留结果，详见 [29.17](29-api-endpoint-catalog.md#2917-已实现的案件证据集合查询契约)。

保留锁管理已提供创建、释放和分页历史 API，要求独立的 `AuditAdministrator` 与精确作用域，可管理同域内其他所有者案件。操作具有用途隔离幂等键，历史响应含原期限、理由和释放事实；每次可审计尝试写 `console.evidence.hold.created/released/read`。它只控制物理保留，原文权限和到期拒读保持独立，详见 [29.21](29-api-endpoint-catalog.md#2921-已实现的案件保留锁管理契约)。

原文访问申请接口同样要求 Investigator 与规范幂等键，只接受自己拥有的 open 案件、同作用域 active 未过期 artifact、固定 `sensitive_raw` 类型和有界理由。服务在事务内锁定目标、限制主体 pending 数，并原子提交申请与 `evidence.access.requested` outbox。批准/拒绝要求用途独立的 `SensitiveEvidenceApprover` 和规范幂等键；决策主体不能等于申请主体，申请只允许一次终态。批准时重新验证并锁定案件与 artifact，短时资格不超过请求 TTL、服务端 `XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS` 和 artifact 期限；拒绝不产生资格。内容端口通过 EvidenceReadPort 消费该资格，并在释放前重验数据库、vault 完整性及必需读取审计，详见 [29.13](29-api-endpoint-catalog.md#2913-已实现的证据内容读取契约)。

## 15.5 交互和错误语义

查询成功但索引未完成：200 + completeness/pending，并提供可重试水位；长任务 202 + job_id。后台未认证/无权限分别 401/403；扫描超限 429/422；依赖不可用 503。响应不泄露敏感对象是否存在。

所有列表使用游标和受限排序字段。多租户筛选在服务端注入，不信任页面传来的 tenant_id。查询、解密查看、导出和回放均有自己的 request_id 并写管理审计，避免审计工具成为无记录旁路。

## 15.6 第一版不做

不内嵌可执行源站页面，不提供任意 SQL 控制台，不一键重放生产写请求，不默认开放跨站原文全文搜索，不让 Agent 自动对流量下发永久封禁或发布新权限规则。可增加经过批准的自动告警，不等于赋予自动修改准入权。

## 15.7 已实现只读请求调查控制台

`web/console` 以 React + TypeScript 实现请求 ID → 摘要 → 事件时间线 → 证据目录/单项元数据、模型调用 ID → 脱敏生命周期 → 证据元数据，以及结构化事件检索的可交互闭环。请求、模型和证据详情调用 29.7–29.10、29.15 的五类 GET，要求 Observer；结构化检索调用 29.14 的 `POST /control/v1/search`，要求 Investigator。两种角色分别校验，Investigator 不隐含 Observer。范围由首次成功响应确认并在同一会话后续响应中逐一校验。事件和证据分页显式触发，证据目录按需查询，每页替换当前页。

检索使用原生表单输入 UTC 整秒半开时间窗（1970 至 2300，最长 31 天）、1–1000 条页大小及事件时间升/降序。最多 8 个 allowlist 条件按同事件 AND 组合，包含 request/event/grant/auth binding/case/artifact ID、五类精确文本、outcome 和整数基点置信度上限；数值阈值不匹配空置信度。界面展示已提交计划、服务端查询摘要、管理请求 ID、实际扫描行/字节和索引水位/pending/gap，区分统计未知与 0。分页冻结已提交计划；编辑任何查询条件使旧结果、详情、摘要和游标失效，后续新发布或到期记录仍可能改变分页可见集合。

搜索事件保留 nullable 请求、阶段、结果、证明、置信度和模型版本，并原样显示 RFC3339 微秒时间。空结果与索引完整性独立呈现；水位只覆盖配置日志源，不能推断独立 Outbox 已追平。已知请求和 artifact 引用可显式打开 Observer 详情，仍由各端点重新鉴权。客户端只展示脱敏事件投影，payload、存储地址、密钥和原文保持在展示边界之外。完整资格/身份关联图、自然语言查询和跨事件遍历继续迭代。

摘要保留缺失、未知和未确认语义；`complete` 与索引 gap/pending 独立呈现，分别披露摘要/事件观察时间与配置日志源水位。事件展示证明类型、置信度可用性、修订和证据引用；确定性规则不填造置信度。目录只展示采集状态、保真度、字节数、分级及期限，`found=false` 统一为“当前不可用”；存储地址、密钥引用和密文摘要不进入展示 DTO。

模型查询展示 provider/provider_model_id、内部模型与提示版本、问题类型、置信度可用性和按 request_seq 排序的有界生命周期；Noul 保持空置信度，历史供应商双空字段保持未知。界面区分 complete、pending、partial 和 not_indexed，强调配置日志源水位不证明模型追平，模型评估完成不表示业务操作获准。输入、输出与调用记录仅以 artifact 引用打开元数据；概率正文和供应商原文须经独立证据内容授权。

凭证保存在当前页面内存，刷新、页面离开、闲置 15 分钟、401 或主动断连后清态；异步响应绑定查询代际和操作序号，旧响应不能恢复已清除数据，跨范围响应断连。原生 Fetch 固定同源路径、禁止重定向和 Cookie，实施 15 秒读体总期限及 16 MiB 上限，错误只呈现固定安全文案、稳定代码和管理请求 ID。管理审计继续由服务端控制端点完成。

当前是机器 Bearer 接入的只读 UI MVP；OIDC/MFA 登录、服务端浏览器会话、案件/模型列表/导出界面继续迭代。生产启用须先满足 15.3 的身份边界及 TLS、专用管理 origin、缓存/CSP 配置。开发和部署步骤、测试数据语义见 [控制台说明](../web/console/README.md)。
