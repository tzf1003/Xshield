# Xshield 的 systemd 单元（参考部署）

把 edge、control 与各项日志/outbox 维护任务跑成 systemd 服务，供不用容器编排的单机或虚拟机部署使用。设计取舍与环境变量见 [docs/19](../../docs/19-deployment-operations.md)；本目录只给出可直接安装的单元文件与示例环境文件，语义与 [deploy/compose](../compose/) 的参考部署一致，只是把容器编排换成了 systemd 自己的调度、重启与 journal。

## 和 Compose 参考部署的差异

- Compose 用一个永不重启的 `net` 服务持有共享网络命名空间,好让 edge 的签名 apply 通道(`127.0.0.1:9553`)与 control 的管理 API(`127.0.0.1:9443`)互通。裸机或虚拟机上两者本就共享同一个 loopback,不需要这个技巧。
- 常驻维护进程(`xshield-audit-seal`、审计发布、outbox 发布)在这里不是常驻循环(`XSHIELD_RUN_INTERVAL_SECONDS`),而是 systemd 的 oneshot + timer 模板单元,对应 docs/19 自己给出的另一种选择("一次性模式...适合 cron 或 Kubernetes CronJob")。因此这里**不设置** `XSHIELD_RUN_HEARTBEAT_FILE`(docs/19:只能与常驻间隔一起设置);是否按时成功运行改用 systemd 自身的记录:`systemctl list-timers`、`systemctl status xshield-seal@edge.service`、`journalctl -u xshield-seal@edge`,或给模板单元加 `OnFailure=` 去触发告警(配合 20 `deploy/prometheus/` 的告警规则按 node_exporter 的 systemd collector 接入)。
- 证据保留清理(`xshield-evidence-retain`)不随任何 target 自动启用,也没有配套 `.timer`:这是一条删除路径,先按 [docs/26](../../docs/26-runbooks.md) 的运行手册手工跑熟悉节奏,再自行决定是否加定时器。

## 安装

```sh
# 1) 解压 release tarball(docs/19 19.7 的 scripts/package_release.sh 产物),建立 current 软链接方便升级
tar xzf xshield-<版本>-<系统>-<架构>.tar.gz -C /opt/xshield
ln -s /opt/xshield/xshield-<版本>-<系统>-<架构> /opt/xshield/current

# 2) 建立服务账号与数据目录(uid/gid 10001,与容器镜像一致)
install -m 0644 deploy/systemd/xshield.sysusers.conf /etc/sysusers.d/xshield.conf
systemd-sysusers
install -m 0644 deploy/systemd/xshield.tmpfiles.conf /etc/tmpfiles.d/xshield.conf
systemd-tmpfiles --create

# 3) 环境文件:每个 *.env.example 复制到 /etc/xshield/ 下去掉 .example 后缀,0640 root:xshield,按文件头注释填写
install -d -m 0750 -o root -g xshield /etc/xshield /etc/xshield/secrets
for f in deploy/systemd/*.env.example; do
    dest="/etc/xshield/$(basename "$f" .example)"
    install -m 0640 -o root -g xshield "$f" "$dest"
done
$EDITOR /etc/xshield/edge.env /etc/xshield/control.env …
# 秘密一律用 _FILE 形式,文件放进 /etc/xshield/secrets/,0400 root:xshield 或 xshield:xshield(docs/19)
# XSHIELD_CONFIG 指向的站点配置(/etc/xshield/edge.json)不在本目录内,按 docs/19 自行编写或由控制面签名 apply 下发

# 4) 安装单元
install -m 0644 deploy/systemd/xshield-edge.service deploy/systemd/xshield-control.service \
    deploy/systemd/xshield-seal@.service deploy/systemd/xshield-seal@.timer \
    deploy/systemd/xshield-publish@.service deploy/systemd/xshield-publish@.timer \
    deploy/systemd/xshield-outbox@.service deploy/systemd/xshield-outbox@.timer \
    deploy/systemd/xshield-evidence-retain.service \
    /etc/systemd/system/
systemctl daemon-reload

# 5) 启动
systemctl enable --now xshield-edge.service xshield-control.service
systemctl enable --now xshield-seal@edge.timer xshield-seal@control.timer
systemctl enable --now xshield-publish@edge.timer xshield-publish@control.timer
for family in case evidence_catalog evidence_access evidence_retention calibration \
              identity grant response_grant share_grant ui_action; do
    systemctl enable --now "xshield-outbox@$family.timer"
done

curl -s http://127.0.0.1:9554/readyz   # edge
curl -s http://127.0.0.1:9555/readyz   # control
```

## 单元一览

| 单元 | 对应 Compose 服务 | 调度 |
| --- | --- | --- |
| `xshield-edge.service` | `edge` | 常驻 |
| `xshield-control.service` | `control` | 常驻,`Requires=`/`After=` edge |
| `xshield-seal@edge`、`@control` | `edge-seal`、`control-seal` | timer,默认 30s |
| `xshield-publish@edge`、`@control` | `edge-publish`、`control-publish` | timer,默认 15s |
| `xshield-outbox@<family>`(10 个家族) | `outbox-*`(10 个服务) | timer,默认 5s |
| `xshield-evidence-retain` | 无(手工步骤) | 手动 `systemctl start` |

## 加固

每个单元都是 `User=xshield`、`NoNewPrivileges=yes`、`ProtectSystem=strict` 外加按角色收紧到最小的 `ReadWritePaths=`/`ReadOnlyPaths=`,以及一组去特权的 `Protect*`/`Restrict*` 开关(禁止新命名空间、改内核参数、内存里又写又执行等)。edge 与 control 需要网络;维护型 oneshot 单元里只有 `xshield-publish@`、`xshield-outbox@` 需要(它们要连 ClickHouse/PostgreSQL),`xshield-seal@` 额外加了 `PrivateNetwork=yes`,因为封存纯是本地文件操作(对应 Compose 里 `edge-seal`/`control-seal` 的 `network_mode: none`)。

## 升级

1. 解压新版本 tarball 到 `/opt/xshield/xshield-<新版本>-...`。
2. 按 CHANGELOG 手工应用新的数据库迁移。
3. 把 `/opt/xshield/current` 软链接指向新版本目录。
4. `systemctl restart xshield-edge.service xshield-control.service`(edge 从签名快照恢复;control 重启后重新发布);oneshot 单元下次由 timer 触发时自动使用新二进制,无需单独重启。

## 限制

- 单机部署,没有高可用;PostgreSQL 与 ClickHouse 的备份按 [docs/19 19.6](../../docs/19-deployment-operations.md) 自行安排,和 Compose 参考部署相同。
- 本目录不提供反向代理/TLS 终止单元:管理 API 与控制台仍需要你自己的同源代理,要求见 [web/console/README.md](../../web/console/README.md)。
- `*.env.example` 只是起点,不是完整契约;字段语义与取值范围以 docs/19、docs/13、docs/26 为准,这里的注释只是导航。
