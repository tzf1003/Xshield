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

Observer：只读脱敏摘要；Investigator：创建案件、查询授权证据；SensitiveEvidenceReader：审批范围内读原文；PolicyAuthor：提交候选；PolicyApprover：审批；ReleaseOperator：发布已签名工件；AuditAdministrator：保留与完整性运维；SystemAdmin：基础配置但不自动获得全部原文读取权。

高危原文导出、全站降级、权限扩大、关键签名操作要求再认证及独立审批。拒绝作者自批高危变更。控制台 MFA、CSRF、会话超时、每站访问范围、管理员操作审计为首版要求。

## 15.4 API 最小集（自定义契约）

| 方法与路径 | 用途 |
|---|---|
| POST /control/v1/search | 结构化 QueryPlan，返回游标和水位 |
| GET /control/v1/requests/{request_id} | 聚合摘要、阶段、覆盖和关联 |
| GET /control/v1/requests/{request_id}/events | 不可变事件分页 |
| GET /control/v1/model-calls/{model_call_id} | 逻辑调用与实际尝试、输入输出引用 |
| GET /control/v1/agent-runs/{agent_run_id} | 子调用、工具、产物和权限快照 |
| GET /control/v1/artifacts/{id} | 证据状态、长度、保密和完整性 |
| POST /control/v1/artifacts/{id}/access | 申请受限原文访问 |
| POST /control/v1/cases | 建立调查案与证据集合 |
| POST /control/v1/replays | 异步安全回放任务 |
| POST /control/v1/exports | 加密调查包导出任务 |
| POST /control/v1/candidates/{id}/validate | 类型、依赖、扩权和覆盖检查 |
| POST /control/v1/candidates/{id}/publish | 发布已审批工件，不直接接受自由脚本 |
| GET /control/v1/audit/health | 已认证的连续索引水位、缺口与本地存储状态 |

浏览器探针仅能访问 `/__xshield/v1/bootstrap` 和 `/__xshield/v1/events/prepare`，不能访问管理 API。API path 中的 ID 均需按 tenant/site 和资源权限再验，不使用“知道 ID 就可读取”。

## 15.5 交互和错误语义

查询成功但索引未完成：200 + completeness/pending，并提供可重试水位；长任务 202 + job_id。后台未认证/无权限分别 401/403；扫描超限 429/422；依赖不可用 503。响应不泄露敏感对象是否存在。

所有列表使用游标和受限排序字段。多租户筛选在服务端注入，不信任页面传来的 tenant_id。查询、解密查看、导出和回放均有自己的 request_id 并写管理审计，避免审计工具成为无记录旁路。

## 15.6 第一版不做

不内嵌可执行源站页面，不提供任意 SQL 控制台，不一键重放生产写请求，不默认开放跨站原文全文搜索，不让 Agent 自动对流量下发永久封禁或发布新权限规则。可增加经过批准的自动告警，不等于赋予自动修改准入权。
