# 24 架构决策记录（ADR）

## ADR-001｜采用附加 UI 流程准入而非推断全部 ACL

状态：采纳。理由：符合“不走认可入口就拒绝”的明确产品规则。后果：部分原有直达流程被有意拒绝；普通用户在完全获准流程中错误获得高权按钮仍需补规则。既有源站权限保留，不能由 WAF 放行覆盖。

## ADR-002｜认证与资格强绑定并版本化

状态：采纳。Cookie 只作随机索引；以实际业务凭证、epoch 和 scope 验证。合法同上下文刷新与换账号分离。后果：需要认证适配器、并发版本和旧响应防污染。

## ADR-003｜Rust 主干，允许边界明确的非 Rust 组件

状态：采纳。三 Rust 程序 + 独立 TS 探针/管理台；OpenJev 或浏览器执行器可用生态原语言。后果：跨语言边界通过版本化 API，核心授权不分散到脚本。

## ADR-004｜冻结实际解密参数后重建源站请求

状态：采纳。避免明文镜像与实际密文不一致。后果：要验证完整协议、响应方向和重建语义；不兼容必须显示缺口。

## ADR-005｜精确资格由代码执行，Jev 只选受限候选

状态：采纳。模型可参与 UI 语义识别，但不自行扩大操作或目标。后果：部分动态站点需模板特调；低置信/无匹配不发行资格。

## ADR-006｜全请求审计与内容证据分层

状态：采纳。必要事件不采样；大报文、实际模型/Agent 载荷入加密对象库；秘密和超限显式标记。后果：有持久化成本、权限与保留管理，不把全量等同于明文日志。

## ADR-007｜审计 journal 独立于 tracing/OTel

状态：采纳。安全事件需要耐久、去重和证据状态，不能依赖调试日志采样。后果：增加 AuditSink 与恢复逻辑；OTel 继续提供性能关联。

## ADR-008｜PostgreSQL 授权真值，ClickHouse 查询副本

状态：采纳。授权需要精确版本与条件提交，分析需要扫描聚合。后果：outbox、索引水位与至少一次去重必须实现。

## ADR-009｜按端点配置严格/兼容，不由客户端降级

状态：采纳。保留用户要求的 Hook 失败回退，但限制为服务端已批准范围。后果：兼容阶段的检查缺口不能假装安全或发资格。

## ADR-010｜默认只读回放与受控适配发布

状态：采纳。调查和复现实验不能重复执行生产副作用。后果：协议测试使用测试源站，权限扩张与原文读取需要审批。

## ADR-011｜模块化单仓优先于微服务堆叠

状态：采纳。以清晰 crate/trait/进程权限边界形成高内聚低耦合。后果：不要求每领域单独服务，性能或权限需要出现后再拆分部署。

## ADR-012｜不把规则命中伪装成模型置信度

状态：采纳。proof_kind、outcome、概率、confidence、风险和覆盖独立。后果：前后端必须支持 null/不适用与未知，不能要求每层都有一个百分数。

## ADR-013｜SQLi/XSS 等通用签名检测由前置的现有 WAF/CDN 承担

状态：采纳（2026-10-29）。Xshield 的价值在界面操作来源、身份绑定与资格准入，以及全链路审计；成熟的 SQLi/XSS 规则库、DDoS 清洗与通用 Bot 管理已由现有 WAF/CDN 提供，首版不自研签名引擎，也不实现 2.3 的 BaselineInspectionPort 适配器。部署链路固定为：客户端 → 现有 WAF/CDN（签名规则、清洗）→ Xshield edge（来源准入、资格、加密接管、审计）→ 源站。

后果：
- edge 不执行基线检测阶段；站点策略的 `waf.blocked_query_fragments` 只是有界的查询片段拒绝列表，不能当作签名规则库对外宣称。没有前置 WAF/CDN 的部署不具备通用注入防护，接入评审必须确认这一层存在。
- 客户端地址经 PROXY protocol 从前置层传入（19“Edge 传输配置”与“按来源限流”）；edge 不信任 `X-Forwarded-For` 等转发头。前置层不支持 PROXY protocol 时，所有客户端在 edge 上归为同一来源，按来源限流与匿名会话来源指纹退化为站点总量。
- 前置层拦截的请求不进入 Xshield 审计，调查时需结合前置层自身日志；Xshield 审计只覆盖到达 edge 的请求。
- 源站只接受来自 Xshield edge 的连接，edge 的数据面只接受来自前置层的连接（网络策略或 PROXY 可信地址列表），否则可绕过任一层。
- 以后若要内置签名检测，按 2.3 新增 BaselineInspectionPort 适配器并另立 ADR，不改变本 ADR 对已部署站点的要求。

## ADR-014｜Helm 高可用：放开副本数 + 控制面收敛回放，不引入外部协调服务

状态：采纳（2026-10-29）。

背景：docs/19 19.8/19.9/19.10 三种参考部署都明确写着"不是高可用方案"。Helm chart 把 edge、control 与两组 journal 封存/发布任务放进单副本 StatefulSet 的同一个 Pod（因为 control 管理 API 与 edge apply 通道按设计只监听 loopback，必须共享网络命名空间），该 Pod 是单点故障；10 个 outbox 发布任务已经是独立 Deployment，但同样固定 1 个副本。KMS 的通用密钥管理集成不在本次范围内。

调研结论（crates/xshield-audit、crates/xshield-worker、crates/xshield-postgres、deploy/helm）：

- `xshield-outbox-worker` 基于 PostgreSQL 行级租约认领任务（`xshield_postgres::OutboxLeaseConfig`），多个实例并发跑天然安全、不会重复处理，Helm 里 `deployment-outbox.yaml` 本身的注释也写明"claims are leased... may be rolled at any time"。
- `xshield-audit-seal` 与 journal 发布任务都按已存在的清单/checkpoint 幂等重放（已有清单按内容复验、`AlreadyExists` 分支处理），两个实例同时处理同一 journal 目录不会冲突、不需要互斥。
- 真正的单写者约束只在"同一个 journal 目录只能有一个 edge（或 control）进程在追加写"（docs/13），这是进程自己持有的文件锁，与副本数无关：只要每个副本有自己独立的 journal 目录（现有 StatefulSet 的 `volumeClaimTemplates` 本来就按 Pod 序号分配独立 PVC），这条约束天然满足。

因此 journal 封存/发布与 outbox 都不需要新增 leader election，只需放开副本数。真正阻碍多副本的是 edge↔control 的耦合：apply 由一次管理写请求同步触发，只推给发起方那个 control 实例自己的本地 edge（`crates/xshield-control/src/site_config.rs` 的 `apply_site_snapshot`）；多个 edge+control 副本各自独立运行时，没有机制把配置变更扇出到其余副本的本地 edge，它们会停在旧快照上——这才是 19.9 目前只能单副本的真正原因，不是审计链路本身。

决定：

1. 保留 edge+control 同 Pod、同网络命名空间的 loopback 耦合，不新增跨 Pod 的 apply 网络面、不改变既有安全边界；把 StatefulSet 的副本数放开为可配置的 N（默认建议 ≥2 用于生产），每个副本各自一套 edge+control+两组 journal 任务+独立 PVC（现有 `volumeClaimTemplates` 已支持，只是从未把 `replicas` 调大过）。
2. 新增 control 侧的收敛回放任务，复用已有的 `XSHIELD_RUN_INTERVAL_SECONDS` 常驻模式：按固定间隔对本地 edge 重放当前已批准（approved/active）的完整租户快照。这正是 `apply_site_snapshot` 已经在做的计算（它本来就从 PostgreSQL 重新算出全量快照再整体下发），只是目前只在收到写请求时跑一次；让每个副本独立、定期地把同一个计算结果重放给自己的本地 edge，依赖的是已有、已验证的幂等 apply 协议（`EDGE_APPLY_IDEMPOTENCY_CONFLICT` 等语义）——不需要副本互相通信，不需要引入 etcd/Redis 等外部协调服务，也不需要新的分布式锁。
3. 不引入 leader election：调研没有找到真正要求"全局恰好一个活跃实例"的组件；PostgreSQL 已有的 `pg_advisory_xact_lock` 用于互斥单次写操作已经足够，不需要会话级常驻 leader 或额外依赖。
4. 新增 Pod 反亲和（尽量分散到不同节点）与 PodDisruptionBudget（`maxUnavailable: 1`），outbox Deployment 的副本数同样放开为可配置项。

已知限制（见 docs/23）：现有"desired/active" apply 状态位按"至少一个 edge 已收敛"记录，不是"全部副本已收敛"；本次不新增按副本粒度的收敛状态表，运维通过每个 Pod 的签名健康接口或 control `/metrics` 的 snapshot revision 观察滚动是否完成。跨 Region/跨故障域的强一致不在本次范围内（19.6 已有此限制，继续保留）。

后果：

- Helm chart：`values.yaml` 新增副本数、Pod 反亲和与 PodDisruptionBudget 相关字段；`statefulset-core.yaml` 顶部"Exactly one replica"的注释与假设需要重写；`deployment-outbox.yaml` 的副本数同样放开。
- control 新增一个收敛回放任务及其配置项（间隔、开关），复用既有 `EdgeApplyClient`，不新增网络面、不新增密钥材料。
- CI 的 `helm`/kind 作业需要扩展到 N≥2 副本场景：验证配置变更收敛到全部副本、删除一个 Pod 后数据面不中断、恢复的副本重新收敛到当前 revision。
- compose 与 systemd 两种参考部署仍是单机（19.8、19.10 维持原状），本次 HA 范围只覆盖 Kubernetes/Helm。

## ADR-015｜不接入外部 KMS，密钥继续由运营方生成并经环境变量/`_FILE` 注入

状态：采纳（2026-10-29）。

背景：此前的部署文档（19 §19.3）写着"KMS 故障不能退回硬编码默认密钥或明文证据"，但项目没有、也没打算接入任何外部 KMS（AWS KMS、Vault 等），这条要求一直是空话。曾就"接入通用 KMS"写过技术方案（三条路线：A 最小可行一次性拉取、B 加 Vault 与运行时热轮换、C KMS 插件协议）并新增了一个路线无关的 `SecretSource` trait 抽象层（PR #62），用户审阅后决定不需要这层能力，直接要求撤掉。

决定：

1. 不接入任何外部 KMS。证据根密钥、journal/seal 密钥、各 HMAC 密钥（fingerprint/share-token/cursor/idempotency/api-key-hash）、请求/响应加密密钥环、OIDC client secret 等全部密钥材料继续由运营方自行生成，经现有的环境变量或 `<NAME>_FILE` 挂载文件注入（`xshield_core::secret_env`，19 §19.3），这一机制不变。
2. 撤回 PR #62 引入的 `SecretSource` trait 抽象层，不合入 `main`：没有第二个 provider 要接，这层间接性没有对应的使用场景。
3. 密钥材料本身的机密性、分发与轮换由部署方负责（Docker/Kubernetes secret、Vault 等运营方自己的秘密管理手段都可以把值放进挂载文件，Xshield 侧不关心来源），不是 Xshield 的职责范围。密钥丢失按不可恢复处理（19 §19.6），不依赖任何恢复流程找回。
4. S3 证据后端可选的存储桶侧 SSE-KMS（12.10 `XSHIELD_EVIDENCE_S3_SSE_KMS`，默认关闭）是存储层特性，和这里撤回的应用层密钥管理无关，不受本决定影响，继续保留。

后果：

- docs/19 §19.3、§19.6，docs/13 §13.7/§13.8，docs/20 §20.4，docs/12 §12.5/§12.10 里描述"KMS 故障 fail-closed"或"KMS 包裹应用层数据密钥待实现"的措辞一并订正为"不在计划内"，避免再被当成遗留缺口排期。
- docs/22 部署与运维缺口表不再列 KMS 为待办（更新记录见该文档"核查记录"）。
- 后续如果运营方确有外部 KMS 托管密钥材料的需求，仍可把密钥的值放进 `_FILE` 指向的文件（文件由运营方自己的 KMS 客户端写入），不需要 Xshield 代码改动；只有需要 Xshield 进程自己持有 KMS 凭据、直接调用 KMS API 解密时，才需要重新评估并另立 ADR。

## ADR-016｜业务 WebSocket 流量接管先做 OBSERVE 级代理+逐消息审计，不做内容级加解密或逐帧重新鉴权

状态：采纳（2026-10-29）。

背景：docs/22 M2 列出的"无 WSS"缺口指的是受保护站点自身业务 WebSocket 流量的 edge 代理与审计，与已交付的探针上报通道（#60，docs/07 §7.3，edge 自行终结的单向浏览器→edge 通道）是两件事；此前 edge 对声明了 Upgrade 的业务路由没有任何处理：Pingora 原生的 HTTP/1 非缓冲代理路径虽然已经支持双向 Upgrade 透传，但 (a) 这类路由在准入侧没有被当作一等操作声明和校验，(b) 既有的累计请求体大小限制会在长连接 WS 会话上误触发断连，(c) docs/11 要求的逐请求审计在已升级连接上完全缺失。

调研结论：读取 vendor 的 pingora-proxy/pingora-core 源码确认 `HttpTask::UpgradedBody` 已经双向透传、`session.as_downstream().was_upgraded()` 是检测升级完成的公开 API；由于网关只是在真实浏览器与真实源站之间做哑字节转发，端到端帧完全由两端自己维护，被动审计扫描器不需要重建掩码或帧，只需要在不管是否被掩码的情况下正确跟踪帧/消息边界，对无法完全处理的内容（超过观测上限的超大帧、未知/保留位、孤立续传帧）优雅降级为"降级标记"而不是阻断连接。

决定：

1. 复用现有 `OperationDto`/`CompiledOperation`/准入体系，新增 `business_websocket` 声明块（`compile_business_websocket`），让业务 WS 路由像其它操作一样走 PUBLIC/AUTHENTICATED_ROOT 等既有准入策略，只在握手请求（裸 GET，不带响应转换、请求加密、资源视图、分页、source_action）时鉴权一次；不做逐帧重新鉴权，不新增并行的路由表抽象。
2. 升级完成后（`was_upgraded()` 为真）绕开原有累计请求体/响应体大小限制逻辑，交给 Pingora 原生双向 Upgrade 透传；新增 `FrameScanner`（RFC 6455 帧头解析，掩码无关、容忍 RSV 位）在 `request_body_filter`/`response_body_filter` 中以只读旁路方式对两个方向分别跟踪消息边界，只产出 `MessageAudit`（kind/byte_len/frame_count/degraded），不修改、不重建、不阻断已转发的字节。
3. 单连接审计明细上限 256 条消息（`BUSINESS_WS_MAX_AUDITED_MESSAGES`），超过后降级为仅保留汇总，不无限增长内存；观测帧长度上限可按路由配置（`max_observed_frame_bytes`，默认 256 KiB），超限帧标记 `degraded: true` 但继续转发，不断开连接。
4. 连接关闭时把本次连接的消息审计明细/汇总写入既有的哈希链审计 journal（新增 `Payload::BusinessWs{Closed,Message}` 两个事件类型），并同步在 `xshield-worker` 侧新增对应的解析器（`family()`/`parse()` 分支）与测试覆盖，避免未注册事件类型导致整段 journal 发布中止。
5. 不支持扩展协商（如 permessage-deflate）、不支持内容级加解密接管、不提供控制台编排——业务 WS 路由目前只能通过 `gateway-config.json` 声明；以上均为后续如需可另立 ADR 的范围，不在本次交付。

后果：

- docs/22 M2 完成度从约 45% 上调至约 48%，"主要缺口"改为精确描述仍缺的逐帧重新鉴权、任意流式响应、WASM 加密接管、HTTP/3；docs/00 §0.3、docs/11 §11.1/§11.15 同步更新为"OBSERVE 已交付，逐帧鉴权未交付"的准确表述。
- 运维侵入性极小：对没有声明 `business_websocket` 的路由，行为与之前完全一致（走 Pingora 原生非缓冲路径），不影响既有缓冲响应/请求加密的操作。
- 若未来需要逐帧重新鉴权或内容级加密接管，需要新的、与本 ADR 不同的设计（例如维护每帧的授权状态机、或引入内容转换层），到时应另立 ADR，不能假设本次交付的 OBSERVE 能力可以无缝升级。

