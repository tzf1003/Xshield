# 11 全链路审计事件与 ID 契约

## 11.1 审计目标

输入一个请求 ID，调查者能够回答：收到什么、使用哪个身份绑定、经过哪些层、每层依据是什么、规则/模型怎么判、为什么跳过某层、是否降级、实际转发了什么、源站返回什么、给客户端返回什么、是否发行新资格、完整证据保存到哪里。

所有被 Xshield 解析接收的 HTTP 请求均有 request.accepted 和最终/补偿状态；包括正常、拒绝、静态资源、内部管理、模型调用及失败请求。连接在形成 HTTP 请求前失败时记 connection/security 事件并带 connection_id，不虚构完整请求。业务 WS 支持时，每个业务消息有 message_id，与连接握手请求分开。

## 11.2 ID 体系

| ID | 作用 | 生成与安全 |
|---|---|---|
| request_id | 一次边缘请求 | 服务器生成 req_ + UUIDv7；客户端值另存不可信引用 |
| trace_id/span_id | 分布式关联 | 采用 W3C 格式；外部 traceparent 不得覆盖内部安全 ID |
| event_id | 一条不可变审计事件 | ev_ + UUIDv7，重发不换 ID |
| decision_id | 一次决策合成 | dec_ + UUIDv7 |
| stage_execution_id | 阶段一次执行 | 区分重试、并发与取消 |
| artifact_id | 一份内容证据或 manifest | art_ + UUIDv7，不是公开下载凭证 |
| transform_id | 解密/标准化/重建关系 | 关联输入、输出及配置版本 |
| model_call_id | 一次实际模型调用尝试 | mdl_ + UUIDv7；另有 logical_call_id |
| agent_run_id/tool_call_id | Agent 运行及工具调用 | agt_/tool_，父子运行明确关联 |
| grant_id/page_evidence_id | 资格与界面来源 | 用于完整追溯发行链 |
| case_id/export_id/replay_id | 调查案、导出与回放 | 各自审批、权限和审计 |

UUIDv7 可提供时间局部性，但 ID 不是身份凭证或严格全局事件顺序。[S20] trace/span 使用标准互操作字段；对外传入追踪信息视为不可信，限制 baggage 且不承载秘密。[S21]

所有查询先限定操作者可访问 tenant/site，再查 ID。ID 再长也不能替代后台授权。

## 11.3 事件公共字段

schema_version、event_type、event_id、tenant_id、site_id、request_id/subject_refs、trace_id/span_id、producer_id、producer_boot_id、producer_seq、request_seq、occurred_at、observed_at、monotonic_duration_us、policy_revision、sensitivity、payload、evidence_refs、prev_event_hash、event_hash。

occurred_at 是服务器 UTC，浏览器时间另存 client_reported_at；时区只影响显示。producer_seq 用于发现本生产者序列缺口；request_seq 由单一请求协调器分配。跨服务以因果 links 和 span 树表达，不伪装为严格全局时间顺序。

原始 append-only 事件不可修改；聚合的 request summary 可以以 revision 更新，但必须能回到原事件。

## 11.4 阶段结果契约

```json
{
  "stage": "capability",
  "outcome": "DENY",
  "reason_code": "OPERATION_NOT_GRANTED",
  "proof_kind": "deterministic",
  "confidence": null,
  "confidence_status": "not_applicable",
  "rule_revision": "policy-demo-r3",
  "input_refs": ["art_example"],
  "facts": {"required_operation":"user.password.admin_reset"},
  "duration_us": 320
}
```

值为纯语义示例，完整机器 Schema 见 schemas。不得对规则检查硬填 100% 置信度。`severity`、`risk_score`、`probability`、`confidence`、`coverage` 不共用字段。

模型结果另存全概率、Noul 值或评分、供应商置信度、校准版本、阈值和采取的动作。可解释文本是独立 explanation，不等同于决策事实；如果来自另一个模型，必须有另一条 model_call_id。

## 11.5 必须记录的事件族

request.accepted/completed/aborted；stage.started/completed/skipped；identity.bound/refreshed/revoked/mismatch；page.accepted/rejected；grant.issued/denied/expired/revoked；crypto.decode/encode/failed/fallback；model.requested/responded/timeout/cache_hit；agent.started/tool_called/tool_result/artifact_created/finished；origin.forward_intent/response/unknown；evidence.captured/sealed/expired/deleted/read；policy.proposed/tested/approved/published/rolled_back；audit.gap/backpressure/durability_failed；console.query/export/decrypt/replay。

不可采样事件：每请求最小记录、每个实际安全判定、资格变更、模型调用、Agent 工具调用、管理动作、证据访问与完整性异常。调试 span 和性能采样可独立配置，但不能让 required 审计消失。

## 11.6 可解释拒绝图

final decision 保存 cause_event_ids、required_checks、completed_checks、skipped_checks、coverage_gaps 和 origin_state。后台展示“身份通过 → 无相应页面动作 → 拒绝 → 模型未执行”，而不是“模型没有发现异常”。明确区分 WAF 策略拒绝、已验证业务拒绝、疑似攻击及内部服务失败。

审计字段的一致性、来源质量和敏感内容处理参考 OWASP 的日志设计原则；本事件格式是 Xshield 自定义契约。[S22]
