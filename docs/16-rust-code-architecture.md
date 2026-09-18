# 16 Rust 代码架构与模块边界

## 16.1 Workspace 结构

```text
xshield/
  crates/
    xshield-domain/          # 值对象、不变量、纯判定、领域事件
    xshield-contracts/       # API/事件DTO、Schema、协议版本
    xshield-ports/           # 状态、模型、秘密、证据、时钟接口
    xshield-application/     # 请求/响应/会话/资格用例编排
    xshield-policy/          # 规则编译、图检查、确定性执行
    xshield-provenance/      # 页面、动作、资源映射验证
    xshield-protocol/        # 内容解析与加密适配编排
    xshield-audit/           # 必需审计API、journal、manifest
    xshield-evidence/        # 加密证据对象、typed manifest、期限与完整性
    xshield-adapters/        # pg/clickhouse/s3/model/keys/wasm
    xshield-edge/            # Pingora入口及HTTP生命周期
    xshield-control/         # Axum管理API和管理鉴权
    xshield-worker/          # 任务、索引、分析Agent及恢复
  web/console/              # TS/React；只调用控制API
  web/sensor/               # TS→普通JS；按站注入
  plugins/                  # 签名的声明式/WASM/隔离JS适配包
  schemas/ migrations/ config/ docs/ tests/ xtask/
```

这是目标源码布局，不是要求首日创建几十个空 crate。首版可先合并相近内部模块，只有形成独立测试、依赖或发布边界才拆 crate。Cargo workspace 共享依赖、锁文件和工具配置，避免各 crate 漂移。[S25]

## 16.2 单向依赖

领域层不能依赖 HTTP、数据库、模型 SDK、异步运行时或管理 UI。DTO 不直接成为领域对象，边界必须显式校验。ports 只依赖 domain；application 依赖 domain/ports/policy；adapter 实现 ports；可执行程序负责装配。contract 与 domain 通过显式转换连接，不把 serde_json::Value 传遍全系统。

```text
入口/装配 → application → domain
                  ↓
                 ports ← adapters
policy/provenance → domain
```

禁止 domain → adapters，禁止 policy 直接查询 ClickHouse，禁止 evidence reader 调用浏览器 UI，禁止通过全局 ServiceLocator 绕过端口。构建图检查在 CI 执行；测试替身实现同一 ports。

## 16.3 强类型与不可变上下文

RequestId、AuthBindingId、Epoch、OperationId、GrantId、ArtifactRef、TenantId 使用 newtype，避免字符串互换。Secret 不实现明文 Debug/Display，使用明确生命周期的秘密包装。

RawRequest、DecodedRequest、AuthenticatedRequest、CheckedRequest 分别表达处理状态；CheckedRequest 构造器仅由成功的政策用例调用。OriginSender 只接受 CheckedRequest 或显式受批准的 CompatibilityRequest，后者必须携带覆盖缺口和批准引用。

RequestContext 保存不可变的身份快照、配置版本、取消令牌、deadline 和 AuditContext。阶段输出新对象，不在一个巨大的 mutable context 中到处改字段。

## 16.4 Port 契约

IdentityVerifier 验证本次认证及继承；GrantStore 精确查询/条件提交；ActionResolver 返回有限候选；ProtocolAdapter decode/encode；ModelJudge 返回类型化信号；EvidenceVault 保存/读取受限证据；AuditSink 提交并返回耐久 receipt；Clock 提供 wall/monotonic 时间；OriginSender 控制转发。

每个 Port 明确错误类型、超时、可重试性、幂等、线程安全、取消语义、审计责任和资源预算。借 trait 复用能力，不为只有一个简单函数的模块强造泛化层。

## 16.5 错误与资源

领域错误用具体 enum 表达违反约束；应用错误区分 invalid_input/denied/dependency_unavailable/timeout/cancelled/internal。thiserror 等仅作实现选择；不以错误 message 字符串分支。顶层附加 context 不得自动打印完整请求或秘密。

避免在 async 中持有锁跨 await；不在 Tokio worker 做 fsync、CPU 大解析或同步压缩。所有队列有界，获得并发许可后再分配大缓冲。网络、模型、数据库和插件 deadline 从请求预算衍生；取消后要收敛任务并生成终态审计。

## 16.6 可复用性

将身份验证、协议转换、规则判定、证据保存分别抽象；禁止复制整套业务流程只为新增站点。站点差异放签名 profile/adapter，不散布 `if site == ...`。字段解析器、编码器、脱敏器和证据 manifest 共用稳定契约，未知版本拒绝或明确升级。

库默认无 unsafe；确需 FFI/unsafe 的模块需独立边界、SAFETY 注释、测试及审查。Rust 内存安全不能代替协议和授权测试。
