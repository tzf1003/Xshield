# Xshield Helm chart

`xshield/` 把一个租户、一个站点部署到 Kubernetes。设计取舍见 [docs/19 19.9](../../docs/19-deployment-operations.md)。这里只写操作步骤。

## 前提

- Kubernetes 1.27 或更新版本，Helm 3。
- 三个镜像：发布标签由 `release-images.yml` 推到 GHCR 并签名，使用前按 docs/19 19.7 用 `cosign verify` 验证，values 里按 digest 引用。
- 运维自备以下几项：
  - **PostgreSQL**：首次安装前按序执行 `migrations/`，以后每次升级前执行新增的迁移。
  - **ClickHouse**：执行 `sql/clickhouse.sql`，并建一个对 `xshield.*` 有权限的账号（参考 `deploy/compose/clickhouse-user.sh`）。
  - **企业 OIDC IdP**：必须是 HTTPS。
  - **管理面 HTTPS 同源代理与控制台静态文件**：见下文“管理入口”。
- Pod 地址必须在 10/8、172.16/12 或 192.168/16 内，因为 edge 的数据面监听器只绑定私网地址。使用 100.64/10 等其他 Pod 网段的集群不适用。

## 安装

```sh
# 1. 生成密钥。数据库 URL、ClickHouse 密码和 IdP 客户端密钥由你提供
read -rs XSHIELD_DATABASE_URL; read -rs XSHIELD_CLICKHOUSE_PASSWORD; read -rs XSHIELD_OIDC_CLIENT_SECRET
export XSHIELD_DATABASE_URL XSHIELD_CLICKHOUSE_PASSWORD XSHIELD_OIDC_CLIENT_SECRET
deploy/helm/xshield-secrets.sh ./xshield-secrets
kubectl create namespace xshield
kubectl -n xshield create secret generic xshield --from-file=./xshield-secrets

# 2. 写 values（必填项见 values.yaml 中标注 required 的字段），然后安装
helm install xshield deploy/helm/xshield -n xshield -f my-values.yaml
```

`./xshield-secrets` 里的文件和 PostgreSQL 数据同等重要，要离线备份，不要提交。丢失封存密钥或 journal 密钥后，已有审计将无法验证（docs/19 19.6）。

Secret 需要的键：

- 由你提供：`database_url`、`clickhouse_password`、`oidc_client_secret`。
- 由脚本生成：
  - `control_cursor_key`、`control_idempotency_key`、`control_api_key_hash_key`
  - `control_journal_key`、`edge_journal_key`、`edge_apply_key`
  - `fingerprint_key`、`share_token_key`、`evidence_key`
  - `edge_seal_key`、`edge_seal_public_key`、`control_seal_key`、`control_seal_public_key`
  - `control_token`、`control_token_issued_at`、`control_token_expires_at`

## 部署了什么

| 对象 | 内容 |
| --- | --- |
| StatefulSet `<release>`（`replicaCount` 个副本，默认 2） | 每个副本各自一个 Pod：运行 edge、control、两组封存与发布任务，挂载各自独立的持久卷 `state` |
| Deployment `<release>-outbox`（`outbox.replicaCount` 个副本，默认 2） | 十个 outbox 家族的常驻发布任务，每个副本运行全部十个 |
| Service `<release>-edge` | 数据面站点端口，默认 6400–6409，按 Pod 就绪状态在全部副本间负载均衡 |
| Service `<release>-ops` | edge 9554、control 9555 的 `/livez`、`/readyz`、`/metrics`，均不认证 |
| ConfigMap `<release>-edge` | edge 引导配置模板，Pod 启动时填入 Pod IP |
| PodDisruptionBudget `<release>-core`/`<release>-outbox` | 仅在对应副本数 > 1 时渲染，`maxUnavailable: 1` |
| 可选资源 | ServiceMonitor（`metrics.serviceMonitor.enabled`）、NetworkPolicy（`networkPolicy.enabled`） |

edge 与 control 必须在同一个 Pod 里，因为管理 API（`127.0.0.1:9443`）和 apply 通道（`127.0.0.1:9553`）只监听 loopback；这个耦合本身不变（docs/19 19.9.1，ADR-014）。这样放有一个代价：Pod 的就绪状态同时决定数据面是否接流量。因此 control 不设 readiness 探针，它的 `/readyz` 只供监控抓取。但 control 进程如果反复崩溃，例如启动时 IdP 不可达，该副本的 Pod 仍会变为未就绪——其余副本不受影响，Service 只把流量转给仍就绪的副本。

常驻任务每轮成功后写心跳。超过三个间隔加一分钟没有更新时，liveness 探针重启该容器。启动后的前 `jobs.firstSuccessGraceSeconds` 秒不检查，留给依赖启动。这些任务不设 readiness 探针，所以 ClickHouse 不可用时不会把数据面撤出流量。

持久卷 `state` 在 `helm uninstall` 后保留（`persistentVolumeClaimRetentionPolicy: Retain`），因为其中有尚未发布的审计和证据；每个副本有自己的一份，互不共享。

## 高可用（`replicaCount`/`outbox.replicaCount` > 1，ADR-014）

每个副本是一套完全独立的 edge+control+journal 任务+PVC，副本之间不直接通信：

- **配置收敛**：一次管理写请求只会同步 apply 给处理它的那个 control 副本自己的本地 edge。control 另有一个常驻的收敛任务（`jobs.reconcileIntervalSeconds`，默认 30 秒），按相同间隔重新读取当前已批准的完整站点配置并重放给本地 edge；重放用的是既有幂等 apply 协议，配置没变时是一次快速空操作。因此写请求落在哪个副本上都无所谓，所有副本最终（至多一个收敛间隔）收敛到同一配置。
- **journal 封存/发布**：按清单/checkpoint 幂等重放，每个副本处理自己卷上的 journal，互不冲突，不需要 leader election。
- **outbox**：基于 PostgreSQL 行级租约认领任务，天然支持任意副本数并发，不需要 leader election。
- **已知限制**：现有的 apply 状态位（desired/active）按"至少一个 edge 已收敛"记录，不是"全部副本已收敛"；要确认某个具体副本是否已经跟上，读它自己 Pod IP 上的签名健康接口或 `<release>-ops` 的 `/metrics`（snapshot revision）。跨 Region/跨故障域不在范围内（docs/19 19.6）。
- 默认的 Pod 反亲和是软约束（`preferredDuringSchedulingIgnoredDuringExecution`），单节点集群（例如 kind）仍能把全部副本调度上去；设置 `.Values.affinity` 可完全替换它。

## 管理入口

管理 API 只能从 Pod 内访问。用 `extraContainers` 加入你的 HTTPS 同源代理，上游写 `http://127.0.0.1:9443`，要求见 [web/console/README.md](../../web/console/README.md)：

- 只转发 Xshield 的会话与 state Cookie；
- 不缓存，也不记录正文；
- 透传 reauth 的 `Set-Cookie`。

代理容器也受 Pod 的 `runAsNonRoot` 约束。

引导 Bearer（Secret 的 `control_token`）最长 24 小时有效，角色取 `control.bootstrapRoles`，默认只有 `observer`。轮换步骤：

```sh
deploy/helm/xshield-secrets.sh ./xshield-secrets
kubectl -n xshield create secret generic xshield --from-file=./xshield-secrets --dry-run=client -o yaml | kubectl apply -f -
kubectl -n xshield rollout restart statefulset/xshield
```

这会重启整个 Pod，包括 edge。

## 升级

1. 先在 PostgreSQL 执行 CHANGELOG 列出的新迁移。
2. 修改 values 中的镜像 digest。
3. 执行 `helm upgrade`。

StatefulSet 按序逐个删掉旧 Pod 再建新 Pod；`replicaCount` ≥ 2 时其余副本仍在服务，数据面不中断。`replicaCount` 为 1 时和此前一样，期间数据面中断。edge 从持久卷上的签名快照恢复已发布的站点。

## 限制

- 按副本粒度的收敛状态没有单独的可观测表，只能逐个 Pod 读健康接口（见上文"高可用"）。
- 封存任务和 edge、control 共享 Pod 网络，不像 Compose 那样完全断网。
- 控制面默认拒绝私网上游。源站在内网时，在 `control.allowedUpstreamCidrs` 列出它所在的网段（docs/19 19.2）。
- 跨 Region/跨故障域不在范围内，备份按 docs/19 19.6 自行安排。
- `smoke/` 只用于 CI 冒烟（`scripts/test_helm_deployment.sh`）。其中的开发 Keycloak、测试数据库和示例源站不得用于任何共享环境。
