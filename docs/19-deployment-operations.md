# 19 部署、隔离、升级与运行策略

## 19.1 首版部署

生产目标 Linux x86_64/aarch64 容器。macOS 可开发，Windows 使用 Linux 容器/WSL；不宣称所有 Pingora 平台具有同等支持。[S03]

基础部署：edge、control、worker；PostgreSQL；ClickHouse；S3 兼容证据库；可选独立 OpenJev 推理服务。所有版本固定镜像 digest、Cargo.lock、模型 revision 与适配包哈希，不使用 floating latest 作为发布依据。

## 19.2 网络与源站

域名流量进入 Xshield，源站限制直连/备用入口；API 子域、下载与业务 WS 列入覆盖表。入口与控制台分域/分网络，管理 API 不通过业务用户会话访问。内部调用认证并限制网络目的地，模型 worker 无源站管理网络权限。

WAF 终止 TLS 并重新验证上游证书，固定 upstream allowlist，不接受客户端任意 Host 变成开放代理。浏览器→WAF 与 WAF→源站的信任变化必须在站点接入说明中体现。

匿名会话来源限流只使用 Pingora 看到的传输层对端地址，不信任客户端转发头。当前版本应由客户端直接连接 Xshield；若前置代理未透传受信的对端身份，来源限流会把该代理后的客户端归为同一来源，站点总限流仍生效。启用多层代理前须增加并验证受信 PROXY protocol 适配器。

## 19.3 密钥与秘密

独立管理 TLS、协议适配、WAF session HMAC、票据签名、证据 KEK、日志签名、模型 API key。按用途和站点隔离，轮换带 key_id、并行验证期、撤销与审计；不得把所有密钥装进一个共享配置 JSON。

密钥不进入 Git、普通日志、模板、测试 fixture 或 Crash dump。服务最小权限获取，KMS 故障不能退回硬编码默认密钥或明文证据。

edge 配置用 `audit.segment_max_bytes` 控制关闭段大小，达到阈值的持久批次完成后自动切换 producer boot。部署方预建仅封存身份可写的私有 manifest 目录，并周期运行 `xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY`。该进程读取 journal 密钥并独占日志签名私钥；edge 不取得签名私钥。重复任务会验证既有清单与关闭段完全一致，再处理新段。

## 19.4 配置与升级

草稿 → validate → 独立测试 → 审批 → 签名 → shadow → canary → active。数据面固定版本读，旧新构建并行范围明确。控制面丢失连接可使用未过期签名配置，但不得跳过身份/资格存储不可用。

数据库采用 expand-contract 迁移，先兼容再删旧字段；回滚版本不得复活撤销 epoch。ClickHouse 保留策略升级先执行 `retention_expires_at` 扩展和 active 视图 DDL，再部署显式写期限的新 worker；旧行沿用 30 天默认值。每次升级验证队列 drain、journal seal、未完成请求、插件终止与模型取消。

## 19.5 运行状态

liveness 仅说明进程存活；readiness 根据必要配置、状态存储和审计耐久性判断；推理不可用是否撤 readiness 依赖该节点承接的模型必需端点。拒绝流量尖峰不自动认定业务故障或自动降级。

自动化指标：资格发行失败、绑定串用、无来源操作、解密覆盖、兼容比例、模型低信心/超时、journal 剩余空间、索引延迟、证据缺失/摘要失败、原文读取与大导出。

## 19.6 备份与恢复

PostgreSQL 配置/资格及 outbox 按恢复目标备份；证据库版本化与独立权限复制；签名验证材料和 KMS 恢复流程同样不可缺少。恢复演练包括身份 epoch、过期资格、保留 tombstone、未完成请求和重复投递。密钥丢失导致证据不可读应记录为不可恢复，而不是显示空白。

首版不作跨区域强一致承诺。新增多区域时先给出故障域、RPO/RTO、网络分区策略和实际演练报告。
