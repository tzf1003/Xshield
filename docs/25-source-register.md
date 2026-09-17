# 25 来源与核验登记

核验日期：2026-09-17。以下均为一手官方文档、标准或项目维护者材料。此处登记技术依据，不表示这些来源已经实现 Xshield。本库的数据结构、阈值、流程组合、部署和验收均为项目设计。版本会变化，实施时固定并复核依赖。

## S01｜OWASP Authorization Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

用途：默认拒绝、每请求授权、资源/操作与外部执行位置。

## S02｜OWASP Transaction Authorization Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html

用途：服务端状态顺序、执行前授权及检查/执行边界。

## S03｜Cloudflare Pingora 官方仓库

https://github.com/cloudflare/pingora

用途：Rust 网络框架、HTTP/1/2、TLS 后端及实验性/平台支持说明。

## S04｜Axum 官方 crate 文档

https://docs.rs/axum/latest/axum/

用途：管理 API 框架候选。

## S05｜SQLx 官方 crate 文档

https://docs.rs/sqlx/latest/sqlx/

用途：Rust 数据库访问组件。

## S06｜OpenTelemetry Rust 官方文档

https://opentelemetry.io/docs/languages/rust/

用途：Traces/Metrics/Logs 文档状态为 Beta；版本边界需隔离。

## S07｜tracing 官方 crate 文档

https://docs.rs/tracing/latest/tracing/

用途：结构化事件、span 和异步跟踪。

## S08｜PostgreSQL Explicit Locking

https://www.postgresql.org/docs/current/explicit-locking.html

用途：行锁、事务并发与持锁期限。

## S09｜OWASP LLM Prompt Injection Prevention

https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

用途：外部内容不可信、工具与模型权限边界。

## S10｜OWASP Session Management

https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

用途：会话标识、期限、身份改变与轮换。

## S11｜RFC 8725: JWT Best Current Practices

https://www.rfc-editor.org/rfc/rfc8725.html

用途：令牌验证、用途和上下文混淆防护。

## S12｜OWASP WebSocket Security

https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html

用途：Origin、消息、会话与长连接约束。

## S13｜MDN Subresource Integrity

https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity

用途：被修改脚本的完整性匹配。

## S14｜Chrome Page Lifecycle API

https://developer.chrome.com/docs/web-platform/page-lifecycle-api

用途：后台页面冻结、丢弃与执行暂停。

## S15｜TypeSafe Primitives (Questions)

https://docs.typesafe.ai/primitives

用途：Choice/Score/Noul、有限问题与约 32k 请求预算。

## S16｜TypeSafe Confidence

https://docs.typesafe.ai/confidence

用途：概率分布、confidence 含义及任务校准。

## S17｜TheoLeeCJ/OpenJev 官方仓库

https://github.com/TheoLeeCJ/openjev

用途：独立开放实现，不是官方 Jev 权重。

## S18｜TypeSafe State

https://docs.typesafe.ai/concepts/state

用途：模型 state 输入组织和支持边界。

## S19｜Wasmtime Security

https://docs.wasmtime.dev/security.html

用途：WASM 沙箱与宿主能力边界。

## S20｜RFC 9562: UUID

https://www.rfc-editor.org/rfc/rfc9562.html

用途：UUIDv7 格式、时间局部性与安全考虑。

## S21｜W3C Trace Context

https://www.w3.org/TR/trace-context/

用途：traceparent、trace-id、parent-id 互操作格式。

## S22｜OWASP Logging Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

用途：事件关联、完整性、敏感数据、故障及日志保护。

## S23｜Amazon S3 Object Lock

https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html

用途：WORM 保留、治理与合规模式边界。

## S24｜ClickHouse MergeTree

https://clickhouse.com/docs/reference/engines/table-engines/mergetree-family/mergetree

用途：排序、稀疏索引、分区和后台 TTL 合并。

## S25｜Cargo Workspaces

https://doc.rust-lang.org/cargo/reference/workspaces.html

用途：workspace 依赖、包和构建组织。

## S26｜Rust API Guidelines

https://rust-lang.github.io/api-guidelines/

用途：公共接口设计规范参考。

## S27｜Clippy Lints

https://rust-lang.github.io/rust-clippy/master/index.html

用途：Rust 静态检查与 lint 配置。

## 历史输入

用户当前对话的最后决定优先于早期建议。已完整读取 v2 设计及示例配置，并结合后续会话绑定、UI 操作来源、Rust 与全量审计要求重构。旧文件仅作为来源，不作为新版并行规范。文件哈希见 reference/input-provenance.json。
