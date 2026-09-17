# 03 请求、响应及提交时序

## 3.1 一条请求的标准阶段

| stage_id | 阶段 | 关键产物 |
|---|---|---|
| ingress | 接收与请求标识 | request_id、trace_id、连接上下文、受限原始证据 |
| framing | HTTP/压缩/尺寸校验 | 规范化版本、歧义或超限原因 |
| route | 站点与实际操作识别 | 固定 policy_revision、operation_id |
| identity_pre | 明文头中的认证预检查 | 认证候选，非最终授权 |
| crypto_decode | 实际请求解密/协议接管 | 明文证据、覆盖状态 |
| identity_bind | 实际有效业务凭证验证 | 不可变 AuthSnapshot |
| request_binding | CSRF/可选票据/nonce | 请求绑定结果 |
| ui_provenance | 对应认可界面动作 | action_id、候选、来源证据 |
| capability | 资源、动作、字段、范围资格 | 精确匹配及拒绝原因 |
| baseline | Schema、基础规则及速率 | 各检测项结果 |
| model | 按预算执行有限语义判别 | model_call_id、原始概率与适用性 |
| compose | 合成最终准入结果 | decision_id、原因图、冻结载荷摘要 |
| audit_commit | 转发前耐久提交 | journal_receipt、证据持久状态 |
| origin_send | 按冻结内容重建与发送 | 实际上游请求摘要、发送状态 |
| response_decode | 响应验证、解密及安全解析 | 响应各版本证据 |
| grant_commit | 认可来源的资格写入 | grant_id、outbox_id、代际校验 |
| client_release | 注入/重加密/返回 | 实际发送字节、返回状态 |
| finalization | 终态、耗时及完整性清单 | request.completed / aborted / outcome_unknown |

阶段有依赖关系，未必全部串行。必须保留每个计划阶段的终态，包括 skipped_by_hard_deny、not_applicable、cancelled、timeout。不能把早期拒绝之后未做的模型检查记录为“通过”。

## 3.2 转发前后的责任边界

先保存输入证据、阶段结果及 forward_intent，再向源站发送。记录准入允许不等于源站执行成功；记录发送完成也不等于业务成功。origin_result 分为 not_sent、send_attempted、response_received、business_confirmed、unknown。

请求转换后的实体由 CheckedRequest 私有构造器生成，任何适配器不能在签发后改变业务目标。重建过程中生成的 nonce/时间戳可以变化，但必须与同一冻结语义绑定，记录适配版本与输出摘要。发现语义变化重新决策，不复用旧 allow。

## 3.3 资格写入时序

获准列表/创建响应：完整解密和验证 → 使用原请求 AuthSnapshot → 锁定/比较当前 epoch → 写入资格与 outbox → 提交事务 → 交付可触发后续请求的数据。来源请求的准入失败、兼容不可见或来源未批准时不发行资格。

不要在数据库事务中等待模型、浏览器或源站网络请求。先获得外部证据，再进行短事务重验版本；冲突则拒绝发行或重新评估。事务锁用于 Xshield 自身一致性，并不锁住源站数据库。[S08]

## 3.4 缓存、流式及取消

敏感内容不放跨身份共享缓存。缓存命中也经过准入；304 必须关联同一安全上下文中仍有效的受验证版本。浏览器缓存不能在新会话复活旧资格。

首版私有 JSON 响应采用有界完整缓冲；HTTP 流式、SSE、超大附件和业务 WS 必须声明各自的记录、决策和释放粒度。不可能在最后一字节尚未到达时声称已完整检查全部内容。将部分转发记为 response.partially_released，不能称为完全阻断。

客户端中断、上游超时、节点退出都留下可调和终态。由后台 reconciler 扫描只有 request.accepted 而无终态的请求，追加 incomplete/outcome_unknown；不伪造成功记录。

## 3.5 重放与重试

每个网络尝试独立 attempt_id。高危请求可使用短期票据绑定准确方法、路由、实体摘要、身份代际和 nonce。nonce 消费原子化。源站不支持幂等键时，不自动重试写请求；“WAF 保留了请求”不代表可以安全重发。审计回放与真实业务重放是两个不同权限。
