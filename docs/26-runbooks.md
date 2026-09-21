# 26 运维与调查 Runbook

## RB-01 用户提供 request_id，排查被拦截

先验操作者 site 权限 → 查询 request summary 与索引水位 → 看主要 cause_event_ids → 区分绑定、来源、资源范围、模型、基础设施拒绝 → 打开对应界面/资格/模型证据 → 比较 policy/adapter/build 版本 → 判断是预期流程拒绝还是实现误拒 → 建案/候选修复。不得直接给该用户 wildcard 资格或关闭全站检查。

成功输出：原始事实、当时规则、主要原因、证据引用、可执行的安全恢复入口和是否需要配置修复。调查报告中的推测单列。

## RB-02 JS 更新后大量 UI_ACTION_NOT_AVAILABLE

核实 WAF 观察到的真实构建指纹；按版本/端点分组，而非相信客户端声称的版本。比较旧动作映射；触发隔离适配；测试通过后灰度。必要兼容回退由审批限定站点、构建、操作和期限，仍保持身份及审计，结束时验证覆盖恢复。

## RB-03 解密失败突增

区分无效 Xshield 封包与已确认源站协议变更；前者不得回退。查看 transform_id、适配版本和原始/响应覆盖；验证密钥轮换、AAD、序列和并发。模型不负责猜解密成功，验签失败不保存为有效明文。

## RB-04 journal 高水位或对象库断连

检查剩余空间、写速率与可支撑中断时间；确认远端持久状态；限制非必要调试并增加受控资源；不得删除未确认投递的必需段。达到严格阈值让相关节点停止接收高危请求。恢复后按 event_id 去重投递并验证无缺口。

## RB-05 证据读取/导出

确认目的、案件、范围和操作者权限；Investigator 发起申请，由不同主体的 SensitiveEvidenceApprover 给出有理由、短时且不超过对象期限的决定；批准后仅允许同一申请主体以 SensitiveEvidenceReader 身份经 EvidenceReadPort 解密返回。每次尝试写审计。导出提供加密包、签名/摘要和缺失清单。日志 HTML 以安全文本显示，不在控制台同源渲染。

## RB-06 模型误放或提示注入嫌疑

固定原 model_call_id、input/output artifact、模型/模板/阈值版本；核对模型是否越过代码硬约束；使用只读副本重复评估；新的结果写新调用，不改旧记录。临时关闭某项模型自动采用可以，但不能同步关闭确定性资格。

## RB-07 源站执行结果未知

网关启动恢复会在开放流量前认证扫描关闭段：只留下 request.accepted 或部分准入批次时追加 `UNKNOWN / REQUEST_INCOMPLETE` 的 request.aborted；有 forward_intent 且缺少源站结果时追加 origin.unknown 与 request.aborted；已有 origin.response 时只补相应请求终态。补偿终态使用 status=null，表示没有可证明的客户端响应。超过 `audit.reconcile_max_records`、历史结构冲突或 journal 写入失败时节点保持未启动。后续核实优先使用原站已有幂等/状态查询流程，由业务方确认真实副作用。

## RB-08 密钥或凭证泄露

定位 secret 类型和影响域 → 撤销/轮换 → 失效相关绑定/epoch → 关闭受影响读取权限 → 调查谁读过/导出过证据 → 记录泄露窗口与不可撤回副本。不能只删除一条日志就宣布风险消失。

## RB-09 备份恢复

恢复状态/证据/密钥引用 → 验证签名段 → 重放 outbox/journal 至索引 → 过期/撤销检查 → 处理未完成请求 → 受控 canary → 恢复流量。恢复时间与数据缺口实测记录，不以备份文件存在判定恢复成功。

## RB-10 本地到期证据清理

确认站点批准的保留计划、tenant/site、根目录与 key-id 对应关系，完成迁移 0015/0016；需要案件 pin 的站点先等待该能力落地。停止共享该根目录的网关写入者，保留现有私有目录权限，使用秘密管理设施注入维护环境变量，可按现场计划设置 `XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS`（无效值会在任何删除前拒绝）。执行 `cargo run -p xshield-worker --bin xshield-evidence-retain -- TENANT_ID SITE_ID 32`，检查 `selected/deleted/failed`、`orphan_selected/orphan_deleted/orphan_failed` 和 outbox 中的 `evidence.purge_requested`、`evidence.deleted`、`evidence.purge_failed`、`evidence.orphan.purge_requested`、`evidence.orphan.deleted`、`evidence.orphan.purge_failed`。每次每类最多 32 个，成功后按维护计划重复至各项 selected=0，再启动网关重新计量配额。

配置 [11.8](11-audit-event-contract.md#118-已实现的按事件族-outbox-发布) 的发布环境并完成迁移 0019 后，按相同 tenant/site 调度 `XSHIELD_OUTBOX_FAMILY=evidence_retention` 的 `xshield-outbox-worker`。检查 claimed/published、未确认行及 last_error_code；发布器升级可消费既有完整清理事件，索引期限仍按原始发生时间计算。通过有界搜索按 event_id 或两个维护阶段复核 artifact/cause 引用；request_id 为 null，维护事实不出现在原请求时间线。确认发布成功仅表示索引可追踪，不替代删除意图、tombstone 与本地文件复验。

BUSY 表示目录仍有写入/维护所有者；TIMEOUT 或 COMPLETION_UNAVAILABLE 时保留签名 sidecar/孤儿意图并重试同一作用域，文件已经删除也可完成 tombstone。REJECTED 对象保留现场并调查 HMAC、摘要、路径、mtime 或 sidecar 状态，不手改 catalog/HMAC 来通过检查。此操作实际移除密文，不能靠 tombstone 还原内容；签名元数据不含正文。备份/副本按各自批准计划处置，不能把本地成功解释为所有副本已消失。

## RB-11 一次性模型离线评估

先批准外发范围并脱敏，仅在受控离线评估账号执行；输入文件须为普通文件，Unix 权限 0600。以下是输入形状，实际任务应填写对应批准、策略和模板引用：

```json
{
  "schema_version": 1,
  "approval_ref": "approved-evaluation-r1",
  "model_revision": "jev-1.13.0",
  "policy_revision": "policy-r1",
  "prompt_revision": "prompt-r1",
  "untrusted_content": "待评估的已批准脱敏文本",
  "question": {
    "type": "choice",
    "instructions": "仅按候选描述选择；证据不足选择 UNKNOWN。",
    "criteria": {"NONE": "无候选适用", "UNKNOWN": "证据不足"}
  }
}
```

Noul 使用 `question={"type":"noul","instructions":"所需判断的问题"}`。指令最多 1024 字符，候选描述最多 512 字符，候选名为最多 128 字节的 ASCII scoped name；所有层级拒绝未知字段与重复键。

Score 使用 `question={"type":"score","instructions":"按有序档位评估","criteria":["低","中","高"]}`，档位数组为 2–10 项，每项最多 512 字符。返回评分是零起始档位的概率加权平均，独立于供应商置信度；完整档位及概率保存在调用证据中。启用前先升级模型发布器、控制服务及控制台，数值验证和回退边界见 [10.11](10-jev-and-agents.md#1011-已实现-score-离线评估)。

需要二元风险统计时，在输入顶层增加经批准的 `risk_mapping`，精确覆盖题目全部候选/档位，形式与未知质量处理见 [10.13](10-jev-and-agents.md#1013-已实现批准概率映射)。映射保存在内部输入证据，成功调用记录保存投影；先升级消费模型调用记录的工具，再启用此可选字段。

完成 PostgreSQL 全部迁移；受控部署须先为每个允许评估的 tenant/site 写入 `model_evaluation_admission_scopes`，设置审核过且与本次输入 `policy_revision` 精确一致的 `policy_revision`、`max_active_calls`（1–32）及 30–60 秒 lease（生产建议 45 秒）。普通 `xshield-model-eval` 不会从环境变量创建或扩大该 scope，缺失时以 `MODEL_EVALUATION_ADMISSION_NOT_CONFIGURED`、revision 不符时以 `MODEL_EVALUATION_ADMISSION_POLICY_MISMATCH` 终态退出；可用 `XSHIELD_MODEL_EVALUATION_RUNNER_ID` 指定已配置 runner 标识，默认 `xshield-model-eval`。复用控制服务可访问的 vault/key，预建 0700 evidence 根目录并暂停共享该根目录的其他写入/清理者。journal 使用本评估器专属私有目录。默认 Gateway 路由通过秘密管理器注入 `AI_GATEWAY_API_KEY`；只有显式 `XSHIELD_JEV_ROUTE=direct` 才注入 `XSHIELD_JEV_API_KEY`。两者均不得同时作为对方凭证使用。macOS 本地启动可从钥匙串服务 `Xshield.Jev.VercelAIGateway`、账号 `Xshield` 取得 Gateway 凭证，再由启动包装器注入进程；`xshield-model-eval` 本身只读取环境变量。另注入 `XSHIELD_TENANT_ID`、`XSHIELD_SITE_ID`、`XSHIELD_DATABASE_URL`、`XSHIELD_EVIDENCE_ROOT`、`XSHIELD_EVIDENCE_KEY_ID`、`XSHIELD_EVIDENCE_KEY_HEX`、`XSHIELD_EVIDENCE_MAX_TOTAL_BYTES`、`XSHIELD_MODEL_JOURNAL_DIRECTORY`、`XSHIELD_JOURNAL_KEY_ID`、`XSHIELD_JOURNAL_KEY_HEX`、`XSHIELD_AUDIT_MAX_BYTES`。证据与 journal 密钥独立；证据预算需至少能容纳四个 512 KiB 对象及 sidecar，journal 预算范围 1 MiB–1 GiB，并保留至少 64 KiB 终态空间。

执行 `cargo run -p xshield-worker --bin xshield-model-eval -- --approved-input /private/approved-evaluation.json`。stdout 仅包含 request/model-call ID、终态与 artifact 引用，非成功退出码为 1；SIGINT 请求取消并等待取证/终态完成。429/529 后检查调用记录中的 HTTP 状态及 Retry-After，由批准流程决定是否发起新的独立调用，旧调用不变。强制终止后重新启动会补记结果未知，再执行本次新任务，可能已发生的供应商计费需另行核对。

每个 journal 事件即时关闭段，可用既有 `xshield-audit-seal` 与 `xshield-worker` 封存/发布，使用独立目标绑定 checkpoint；证据目录发布采用 PostgreSQL outbox。维护时接近 10000 条记录，应先完成未终结调用恢复、封存与投递，再切换到新的专用 journal 目录；保留旧目录及水位作为审计材料，不删除未投递段。正文通过现有管理案件/申请/批准/读取链路查看；24 小时后按 RB-10 清理，需更长保留的评估计划应先调整并验证实现。

使用同一 tenant/site 的 `Observer` 调用 `GET /control/v1/model-calls/{model_call_id}` 检查模型摘要和证据引用；`completeness` 说明可见生命周期是否完整。`not_indexed` 表示 active 索引当前未命中，需核对模型专属 journal 的封存、发布、水位与保留期限；`partial` 需核对缺失事件及保留情况。控制响应中的 `watermark_scope=configured_journal` 只覆盖该控制实例配置的 source journal/manifests/checkpoints：需要模型投递水位时，将这些路径及对应验证密钥指向该模型发布源；网关日志水位不能证明模型发布已追平。查询超出扫描预算时联系操作员核对保留规模与索引计划，按当前记录的调用 ID 排查即可。
