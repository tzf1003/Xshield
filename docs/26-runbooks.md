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

确认站点批准的保留计划、tenant/site、根目录与 key-id 对应关系，完成迁移 0015；需要案件 pin 的站点先等待该能力落地。停止共享该根目录的网关写入者，保留现有私有目录权限，使用秘密管理设施注入上述四个维护环境变量。执行 `cargo run -p xshield-worker --bin xshield-evidence-retain -- TENANT_ID SITE_ID 32`，检查 `selected/deleted/failed` 和 outbox 中的 `evidence.purge_requested`、`evidence.deleted`、`evidence.purge_failed`。每次最多 32 个，成功后按维护计划重复至 selected=0，再启动网关重新计量配额。

BUSY 表示目录仍有写入/维护所有者；TIMEOUT 或 COMPLETION_UNAVAILABLE 时保留签名 sidecar 并重试同一作用域，文件已经删除也可完成 tombstone。REJECTED 对象保留现场并调查 HMAC、摘要、路径或时钟差异，不手改 catalog/HMAC 来通过检查。此操作实际移除密文，不能靠 tombstone 还原内容；签名元数据不含正文。备份/副本按各自批准计划处置，不能把本地成功解释为所有副本已消失。
