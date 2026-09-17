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

重试独立 attempt_id，记录每次输入是否相同、供应商 request id、耗时与用量。只有最终成功请求不能代表之前失败未计费；拿不到 token/cost 时标 unknown。外部模型动态升级后，记录 resolved_model_revision=unavailable，禁止声称可逐位复现。

## 10.7 Agent 全调用取证

一个 agent_run 关联任务触发、批准范围、模型消息、检索 manifest、工具 Schema、实际调用参数、结果、stdout/stderr 限制、退出码、文件变更、产出工件及审批。工具输出超限分块保存，索引保存摘要与缺失标记，不把截断后的字符串标为完整结果。

记录供应商实际可见的推理/说明输出；不能获取的内部思考过程不伪造。供应商的通用 system prompt 或内部检索不可见时标 provider_internal_unavailable。

## 10.8 提示注入与发布

所有网页、日志、代码、评论都作为不可信数据。调查 Agent 不执行日志里出现的命令；自然语言查询只能编译为受限查询 AST。权限扩张、入口公开、兼容范围扩大必须经人工/独立策略审批后签名发布，不由模型自批。[S09]

离线适配只在批准测试环境运行。WASM 插件明确 host capabilities、内存与 fuel 限额，复杂 JS 再加进程/容器隔离；Wasmtime 的沙箱仍需要正确约束宿主接口，不是允许任意 hostcall。[S19]
