# 29 控制 API 与审计责任清单

本章定义自定义接口；当前 `GET /control/v1/audit/health` 已由 `xshield-control` 实现，其余条目仍是设计契约。所有 `/control/v1` 接口经管理身份验证、tenant/site作用域检查与速率限制；用户数据API和控制API必须分网络/认证边界。状态变更使用CSRF或对应机器凭证防护，GET不得产生重放或生产业务副作用。

| 方法与路径 | 用途 | 必需审计 |
|---|---|---|
| GET /control/v1/requests/{request_id} | 请求概要和完整性状态 | console.request.read |
| GET /control/v1/requests/{request_id}/events | 事件游标分页和阶段树 | console.events.read |
| GET /control/v1/requests/{request_id}/evidence | 证据manifest清单 | console.manifest.read |
| GET /control/v1/model-calls/{model_call_id} | 模型调用、实际输入输出引用 | console.model.read |
| GET /control/v1/agent-runs/{agent_run_id} | Agent 运行及工具树 | console.agent.read |
| GET /control/v1/artifacts/{id} | 单个证据manifest | console.manifest.read |
| POST /control/v1/search | 受限查询AST，非任意SQL | console.query.executed |
| POST /control/v1/artifacts/{id}/access | 申请解密/原文查看能力 | evidence.access.requested |
| GET /control/v1/artifacts/{id}/content | 获批后读取，短时作用域能力 | evidence.read，含批准引用 |
| POST /control/v1/cases | 建立调查案例 | case.created |
| POST /control/v1/cases/{id}/items | 把获准证据加入案例 | case.evidence.added |
| POST /control/v1/cases/{id}/analyze | 启动只读调查Agent | agent.started，工具/模型独立事件 |
| POST /control/v1/replays | 离线规则评估，不送原站 | replay.requested/completed |
| POST /control/v1/exports | 带用途/范围/审批的导出任务 | export.requested/approved/downloaded |
| GET /control/v1/jobs/{id} | 查看任务进度与错误 | console.job.read |
| POST /control/v1/sites/{id}/candidates | 提交配置候选 | policy.proposed |
| POST /control/v1/candidates/{id}/validate | 受控验证 | policy.tested |
| POST /control/v1/candidates/{id}/approve | 审批不等于部署 | policy.approved |
| POST /control/v1/candidates/{id}/publish | 灰度签名发布 | policy.published |
| POST /control/v1/sites/{id}/rollback | 回退已验证版本 | policy.rolled_back |
| GET /control/v1/audit/health | 各层watermark、gap与存储状态 | console.health.read |

## 29.1 查询契约

请求包含 tenant/site（服务端仍校验）、时间窗、类型化过滤器、允许的sort、limit、cursor。禁止自由SQL或可注入表达式。request_id精确查找不要求用户猜日期；先经热定位目录到所属时间桶。返回 index_watermark、as_of、has_gaps、next_cursor。分页令牌绑定调用者作用域和查询摘要，不能跨租户复用。

对未获权ID返回不泄露存在性的统一结果。证据读取另走授权，不因能查摘要就能解密原包。大内容预览与下载分离，浏览器不执行证据中的脚本。

## 29.2 任务语义

长任务返回202和job_id，调用方查询进度。任务状态为queued/running/succeeded/failed/cancelled；失败附稳定原因码、可重试性和最后耐久点。幂等键绑定主体、动作和参数摘要；不同参数不复用。取消保留此前产生的审计证据，禁止删掉历史伪装任务没有发生。

## 29.3 权限角色

Observer 看脱敏概要；Investigator 执行受限查询和申请证据；SensitiveEvidenceReader 在审批范围看受限内容；PolicyAuthor 提交候选；PolicyApprover 批准；ReleaseOperator 发布；AuditAdministrator 管理保留与完整性；KeyAdministrator 管理密钥但默认不能解密业务证据。支持职责分离和紧急break-glass，但紧急操作也须理由、短时权限和独立审计。

## 29.4 错误契约

统一结构包含error_code、message_safe、request_id、retryable、next_action；禁止堆栈、凭证、资源归属和内部SQL进入客户端错误。401用于管理认证要求，403用于已认证的禁止操作，409用于代际/修订冲突，429用于预算限制，503用于必需依赖不可用。具体重试不自动重新执行生产业务。

## 29.5 已实现的审计健康契约

`GET /control/v1/audit/health` 的 tenant/site 由服务启动配置固定注入，请求不能选择作用域。管理 Bearer 凭证只保存摘要并采用常量时间比对，签发和过期时间在启动时限制为最长 24 小时且每次请求重验；主体还须持有该精确作用域的 `AuditAdministrator`。服务仅监听 loopback，由独立管理 TLS 边界接入。

成功响应包含 request_id、tenant_id、site_id、观察时间、目标索引、关闭段数量与字节、published/pending/unsealed 数量、连续水位和 gap 状态，并设置 `Cache-Control: private, no-store`。401、403、429 和 503 使用 29.4 的统一错误结构。可审计尝试在响应前写入独立加密 journal 的 `console.health.read` 事件；该耐久写失败时返回 503。
