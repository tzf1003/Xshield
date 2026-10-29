# Xshield 单机参考部署（Docker Compose）

一台主机运行一个租户、一个站点的全部组件。设计取舍与约束见 [docs/19 19.8](../../docs/19-deployment-operations.md)，这里只写操作步骤。

## 前提

- Docker Engine 与 Compose v2.24 或更新版本。
- 三个镜像：在仓库根目录执行 `docker build --target edge -t xshield-edge:<tag> .`，`control`、`worker` 同理。也可以推到自己的镜像仓库，再在 `.env` 设置 `XSHIELD_IMAGE_PREFIX` 与 `XSHIELD_IMAGE_TAG`。
- 企业 OIDC IdP（必须是 HTTPS）里已注册控制台客户端，回调地址为 `<控制台 origin>/control/v1/auth/oidc/callback`，要求的 `acr` 代表 MFA。
- `openssl`（`init.sh` 用它生成密钥）。

## 首次启动

```sh
cd deploy/compose
cp env.example .env              # 填写租户/站点、OIDC、控制台 origin、端口
mkdir -m 700 -p secrets
read -rs secret && printf '%s' "$secret" > secrets/oidc_client_secret && unset secret  # 粘贴 IdP 客户端密钥
./init.sh                        # 生成 secrets/、edge-config.json、引导 Bearer
docker compose up -d
curl -s http://127.0.0.1:9554/readyz   # edge
curl -s http://127.0.0.1:9555/readyz   # control
```

`secrets/`、`.env`、`edge-config.json` 与 `control-token.env` 是生成物，已被 `.gitignore` 排除，不要提交，也不要放进镜像。备份时它们与 PostgreSQL 数据同等重要，丢失封存或 journal 密钥会让已有审计无法验证（docs/19 19.6）。

## 组件

| 服务 | 作用 | 持久卷 |
| --- | --- | --- |
| `net` | 持有 edge 与 control 共享的网络命名空间，发布端口，永不重启 | 无 |
| `edge` | 数据面；apply 通道只在命名空间内 `127.0.0.1:9553` | `edge-audit`、`edge-snapshot` |
| `control` | 管理 API 只在命名空间内 `127.0.0.1:9443` | `control-audit`、`evidence` |
| `edge-seal` / `control-seal` | 封存 journal 关闭段（无网络） | 各自 manifest 卷 |
| `edge-publish` / `control-publish` | 把封存段发布到 ClickHouse | 各自 checkpoint 卷 |
| `outbox-*` | 十个事务 outbox 家族的发布任务 | 无 |
| `postgres` / `clickhouse` | 真相库与索引 | `postgres`、`clickhouse` |
| `volumes-init` | 一次性把数据卷设为 uid 10001、0700 | 无 |

后台任务都以常驻模式运行，每轮成功后把时间戳写入 `heartbeat` 卷，如 `/var/lib/xshield/heartbeat/edge-publish`。监控应对超过三个间隔未更新的心跳告警，因为一直失败的常驻进程不会自行退出。查看方式：`docker compose exec edge-seal cat /var/lib/xshield/heartbeat/edge-publish`。

## 管理入口

管理 API 与控制台需要你自己提供一个 HTTPS 同源代理，满足 [web/console/README.md](../../web/console/README.md) 的要求：

- 只转发 Xshield 的会话与 state Cookie；
- 不缓存，也不记录正文；
- 透传 reauth 的 `Set-Cookie`。

把代理容器以 `network_mode: service:net` 加入同一命名空间，上游写 `http://127.0.0.1:9443`。控制台静态文件来自 `web/console` 的 `npm run build`。

`init.sh` 签发的引导 Bearer 在 `secrets/control_token`，24 小时内有效，角色取 `.env` 的 `XSHIELD_CONTROL_ROLES`（默认只有 `observer`）。它只用于首次排障，日常操作走 OIDC 登录。重新运行 `init.sh` 会签发新的引导 Bearer，旧的随之失效，已有密钥保持不变；签发后须执行 `docker compose up -d control` 让它生效。

## 升级

1. 构建或拉取新镜像，更新 `XSHIELD_IMAGE_TAG`。
2. 按 CHANGELOG 先手工应用新迁移，例如 `docker compose exec -T postgres psql -U xshield -d xshield -v ON_ERROR_STOP=1 < ../../migrations/00NN_xxx.sql`。PostgreSQL 只在首次初始化时自动执行迁移。
3. 执行 `docker compose up -d`。edge 从签名快照恢复，control 重启后重新发布。

## 限制

- 单机部署，没有高可用。PostgreSQL 与 ClickHouse 的备份按 docs/19 19.6 自行安排。
- 控制面默认拒绝私网和回环上游地址。源站在内网时，在 `.env` 的 `XSHIELD_ALLOWED_UPSTREAM_CIDRS` 列出它所在的网段（docs/19 19.2），并改动后重启 control。
- 站点端口必须落在 `XSHIELD_EDGE_SITE_PORTS` 发布的范围内（默认 6400–6409）。bootstrap 占用 6400，站点从 6401 起选。
- `compose.smoke.yaml` 只用于 CI 冒烟，里面的开发 Keycloak 与示例源站不得用于任何共享环境。
