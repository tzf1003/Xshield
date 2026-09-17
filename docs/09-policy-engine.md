# 09 策略引擎与判定合成

## 9.1 决策类型

Decision：ALLOW、DENY、RETRY_LATER、STEP_UP。Coverage 为独立结构，不能通过 ALLOW 推出“所有检测已完成”。business_authz、flow_admission、attack_signal 和 origin_result 分开保存。

StageOutcome：PASS、DENY、UNKNOWN、ERROR、SKIPPED、CANCELLED。每个结果记录 reason_code、规则版本、输入证据、输出事实和单调耗时。规则检查使用 proof_kind=deterministic，confidence=null。

## 9.2 硬约束优先

```text
协议或认证绑定不合法       → DENY
必要界面/资源/动作资格缺失 → DENY
业务明确拒绝              → DENY
必要基础设施不可用         → RETRY_LATER
内容规则拒绝              → DENY
其余                       → 按已批准模型策略及覆盖要求合成
```

模型的 ALLOW/低风险不能覆盖硬拒绝。FlowAllowed 只是附加流程准入，不绕过源站的已有权限。原始模型概率、阈值与命中规则保存，以便解释合成，不把数值简单取平均生成“总体安全率”。

## 9.3 模式独立

site_mode、crypto_mode、model_mode、audit_mode 独立但发布时验证组合。严格 UI 资格的必要目标隐藏在不支持密文时，不允许通过 crypto compatibility 隐式跳过 UI 资格。要允许此覆盖缺口，必须显式登记该 endpoint 的兼容豁免，控制台醒目标注。

model_required_for_action_mapping=true 且没有有效缓存描述时，模型超时即不能发行该资格；已经经确定性规则验证的现有资格不因无关模型停机自动丢失。分开“模型是本次准入必要条件”和“模型只做附加风险分析”。

## 9.4 DSL 与编译

配置经 JSON Schema/类型校验 → 引用解析 → 来源图验证 → 循环/不可达规则检查 → 权限扩张 diff → 测试 → 签名版本发布。规则只能访问明确的 request/auth/page/grant 字段，不提供 eval 或任意网络请求。

入口需至少限定站点、方法、真实路由或 RPC operation。JSON 重复键、重复 ID、方法覆盖、解码差异和路由重写必须拒绝歧义或与源站严格一致。批量和 GraphQL 按真实子操作检查，不白名单整个 /graphql。

## 9.5 规则版本与冲突

请求开始固定 policy_revision、schema_revision、adapter_revision、model_policy_revision；中途热更新不改变正在执行的引用。显式 emergency deny 可以作为额外只收紧屏障，记录其独立版本。

allow 与 deny 冲突按 deny 优先；来源规则发行范围必须是预批准范围的子集。修改字段、目标、有效期、公开入口及兼容范围均需可视化 diff。回滚不能把已撤销的身份或资格复活。

## 9.6 原因码最低集

AUTH_REQUIRED、AUTH_BINDING_MISMATCH、AUTH_EPOCH_CHANGED、UI_ACTION_NOT_AVAILABLE、UI_EVIDENCE_UNVERIFIED、CAPABILITY_MISSING、OPERATION_NOT_GRANTED、TARGET_SCOPE_MISMATCH、FIELD_NOT_ALLOWED、GRANT_SOURCE_UNTRUSTED、SHARE_SCOPE_MISMATCH、PARSE_AMBIGUOUS、CRYPTO_INVALID_ENVELOPE、PAYLOAD_OPAQUE、MODEL_UNAVAILABLE、MODEL_LOW_CONFIDENCE、AUDIT_DURABILITY_UNAVAILABLE、EVIDENCE_CAPTURE_INCOMPLETE、ORIGIN_OUTCOME_UNKNOWN。

稳定 code 用英文枚举，用户可见描述中文可本地化。禁止通过解析 log message 来驱动业务逻辑。
