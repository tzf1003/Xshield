# 08 双向应用层加密接管

## 8.0 当前实现边界

首个可运行增量实现请求侧 enforce `DIRECT_DECRYPT`：`application/vnd.xshield.encrypted+json` v1 封包使用 AES-256-GCM，必须携带规范 `msg_<UUIDv7>`、`issued_at`、`expires_at`，nonce 固定 12 字节、tag 固定 16 字节，二进制字段采用小写十六进制。AAD 以长度前缀绑定 tenant、site、operation、method、实际 path、adapter revision、key-id、message-id、消息时间窗和重建 Content-Type。网关在任何源站连接前认证解密，严格校验有界 JSON object，再通过 PostgreSQL 原子消费同一 key 作用域的 message-id 与 nonce，随后只把这份已验证且未重放的明文冻结并重建为 `application/json` 请求。

每个 operation 必须由服务端配置 `DIRECT_DECRYPT`、adapter revision、key-id、密钥生效/失效时间、消息最大寿命、未来时钟偏差、活跃消息容量、封包上限和明文上限；当前 Pingora 重放边界将封包上限硬限制为 64 KiB，同一进程只允许一个 request key-id，且加密 operation 拒绝未纳入 AAD 的查询串。请求侧加密 operation 必须配置 PostgreSQL 存储；所有实例共享双唯一防重放账本，过期记录在容量检查前清理。密钥从独立环境秘密注入后仍须通过 tenant/site/purpose/time 精确匹配的 `KeyAccessPort` 才能使用。无效封包、认证失败、过期、超前、重放、账本不可用或容量耗尽均以稳定原因终止，不转发原封包。审计 `crypto_decode` 阶段记录确定性终态、适配版本、算法、非秘密 key-id、message-id、nonce 摘要、消息时间窗及输入/重建 SHA-256，不记录密钥或明文。

该增量尚未声明解密字段到 UI 动作字段映射、响应侧接管、observe/compatibility、KEY_REWRAP、ENVELOPE_HOOK、构建版本共存和证据库原文保留完成；因此配置会拒绝在 `UI_ACTION_REQUIRED` operation 启用当前适配器，这些能力继续按本章后续约束迭代。

## 8.1 三条路径

DIRECT_DECRYPT：协议、密钥取得方式和密钥使用授权已明确，WAF 解密实际请求/响应，必要时重建。

KEY_REWRAP：在经过验证的混合加密协议中替换可接管的公钥分发；WAF 解出内容密钥，检查实际内容，再用源站公钥重封装。签名、AAD、key-id、响应密钥与会话状态都要核对；不能只知道 AES/RSA 名称就认定兼容。

ENVELOPE_HOOK：注入 JS 在稳定业务封装入口将参数按 Xshield 协议封装；WAF 解开实际封包，检查 P，再由固定适配器仅使用同一 P 重建原站请求。

网页仍使用 HTTPS。应用层额外封包采用成熟库和固定协议版本，不自研密码算法。以算法识别代替协议复刻、以前端镜像代替实际内容，均不符合本设计。

## 8.2 适配包内容

站点与端点、构建指纹、序列化/压缩/编码、请求及响应格式、密钥来源与作用域、算法参数、签名覆盖、AAD、nonce/计数器、时间窗口、异常路径、版本并行、测试向量和回滚目标。

密钥调用经 KeyAccessPort 限定站点、用途、有效期；推理模型和普通日志无读取密钥权限。适配器不能代理任意 URL、任意签名或跨站密钥使用。

## 8.3 不可变转换链

```text
ingress_entity → decoded_plaintext → canonical_business_request
  → checked_request → rebuilt_origin_entity
origin_entity → decoded_response → canonical_response
  → grants_commit → rebuilt_client_entity
```

每一边均有 artifact_id、transform_id、input_refs、output_refs、adapter_revision、算法元数据、质量状态与摘要。实际请求身份若在加密 body 内，必须解出后再完成最终认证绑定。

不能在 model 检查 P 后继续转发客户端独立提供的其他密文。已校验参数禁止被后续插件或模板自由修改；输出变化必须解释为协议元数据变化或重新决策。

## 8.4 失败与回退

observe：原有流量流程，记录候选，新资格不用于强制放行。

compatibility：服务端批准的端点/构建范围可透传原协议；保留已经能执行的身份、路由、规则和审计，标记 opaque。该链路不得为未知内容发行新资格。

enforce：依赖解密取得目标/动作的请求无法检查就拒绝/暂不可用。无效 Xshield 封包、认证标签错误、伪造版本一律拒绝，不能落到兼容原包透传。

客户端自称 Hook 失败、关闭 JS 或生成大量异常不能更改模式。真正的站点构建变化由 WAF 取证及独立验证后触发控制面决策。

## 8.5 动态维护

按 JS/协议指纹、提取失败和成功流量分布触发分析；合并重复任务、限制预算。Agent 的产出是候选适配包，先隔离单元向量与测试站闭环、再 shadow/canary。修改字段映射可以走受控低风险发布；扩大入口、资格或目标范围必须审批。

随机加密不能用每次密文逐字节相等作为唯一测试。应使用隔离测试向量或验证解出的业务内容和原站接受结果；不得把固定 nonce 带到生产。超大、不支持或截断包的覆盖状态必须显式，见证据分册。
