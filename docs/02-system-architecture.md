# 02 总体架构与技术选型

## 2.1 四个平面

```text
浏览器/代理/脚本
       |
[数据面 xshield-edge / Rust]
 TLS、HTTP规范化、探针注入、身份绑定、协议转换
 资格与流程检查、基础WAF、模型路由、源站转发
       |                 |                |
[状态面]            [智能工作面]       [审计证据面]
 PostgreSQL          xshield-worker     专用持久journal
 会话/资格/版本       Jev服务适配        ClickHouse索引
 可选有界缓存        隔离分析Agent      加密对象证据库
       |                 |                |
[控制面 xshield-control / Rust + Web Console]
 站点/策略/身份/审批/检索/回放/告警/版本发布
       |
源站：保持既有应用协议，不要求接入SDK
```

平面表示权限和职责边界，不强制每模块一个微服务。初版三个 Rust 可执行程序：edge、control、worker。审计 journal 为 edge 内受控组件并可独立进程化；日志索引和远端证据存储可以独立扩展。模型推理及浏览器运行使用隔离伴随进程。

## 2.2 推荐基线

| 部位 | 选择 | 约束 |
|---|---|---|
| 反向代理 | Rust Pingora | 先验证可等待的请求/响应完整缓冲钩子；禁止在检测前发送 body |
| 业务与管理运行时 | Tokio；Axum 管理 API | Axum 不承担自研 HTTP 协议解析器 |
| 核心策略 | Rust 强类型纯函数 + 编译后的站点规则 | 不在热路径解释任意脚本或拼接自然语言策略 |
| 事务状态 | PostgreSQL + SQLx | 会话代际、资格提交、撤销与 outbox 事务一致 |
| 大规模审计检索 | ClickHouse | 仅检索/统计，不作为在线授权真值 |
| 大对象证据 | S3 兼容对象存储 + 信封加密 | 支持版本/保留锁时按能力启用，不能假设所有兼容服务等价 |
| 耐久缓冲 | 加密、分段、带校验的本地 journal | 不是 stdout；严格级别可增加远端持久确认 |
| 遥测 | tracing + 独立 AuditSink + OTel 适配 | 安全日志不依赖 OTel 采样及 exporter 成功 |
| 探针 | TypeScript 编译成同源普通 JS | 自动注入，业务方不安装 SDK |
| 管理台 | TypeScript + React | 独立认证，不接收站点用户 Cookie 作为管理身份 |
| AI 推理 | Rust ModelPort；OpenJev 可用 Python/CUDA 伴随服务 | 不是把模型全栈强行重写为 Rust |
| 适配测试 | Rust 编排 + Playwright 浏览器执行器 | 仅受控测试账户/环境；生产写入回放默认关闭 |
| 插件 | 声明式优先；受限 WASM；复杂 JS 隔离进程 | 网络、文件、密钥能力按清单授予 |

Pingora 官方提供 HTTP/1、HTTP/2 和 WebSocket 代理能力；其 rustls 与缓存集成存在实验性标记，Linux 为主要平台。因此首版 Linux 容器运行，TLS 后端选经过本项目验证的受支持构建，不默认使用实验性缓存，更不直接据此宣称 Xshield 的吞吐。[S03] Axum、SQLx 提供对应 Web 与数据库组件。[S04][S05]

OTel Rust 当前文档将主要信号标为 Beta，需封装版本边界；tracing 适合结构化事件和 span，但不是耐久审计数据库。[S06][S07]

## 2.3 基础 WAF 规则接入

保持已有规则引擎，不为了“全 Rust”在首版重新发明成熟 SQLi/XSS 规则库。定义 BaselineInspectionPort，可接既有网关规则服务或隔离的现有引擎；确需非 Rust 依赖时限于适配器/伴随进程，单独记录版本、预算与失败策略。规则引擎尚未确定时，控制台必须显示 baseline=not_configured，不能用模型替代后声称传统规则已启用。

## 2.4 数据权威性

PostgreSQL 是配置与资格的首版权威状态；ClickHouse 是可重建的查询副本；对象库与签名 manifest 是内容证据；本地 journal 是远端不可达时的耐久缓冲。Redis 仅在确有必要时加速遥测和非授权计数，不能用一个未说明一致性的 Redis 缓存承担全部撤权。

## 2.5 伸缩边界

以 site_id 划分配置与限额，以 auth_binding_id 定位资格。首版单区域事务状态，edge 可多副本。跨区域先明确主区域路由、延迟和分区策略，再扩展；不以“分布式缓存同步”承诺立即全局撤权。控制面故障可使用已签名且未过期配置，但身份与资格不可验证时严格端点仍拒绝。
