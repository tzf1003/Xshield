# Xshield 的 Prometheus 告警规则

`alerts.yml` 是针对 edge 与 control 的 `/metrics`（[docs/19 19.5](../../docs/19-deployment-operations.md)）写的告警规则，字段名直接取自导出代码（`crates/xshield-gateway/src/ops_api.rs`、`crates/xshield-control/src/ops.rs`），不依赖任何固定的 `job`/`instance` 标注约定——Helm 的 ServiceMonitor 与手写 `scrape_configs` 打的标签不同，规则只按指标名本身区分 edge/control（已经是 `xshield_edge_*`/`xshield_control_*` 前缀,互不冲突）。

## 接入

把文件路径加入 Prometheus 的 `rule_files`：

```yaml
rule_files:
  - /etc/prometheus/rules/alerts.yml
```

Kubernetes（kube-prometheus-stack 等 Operator）下通常包成 `PrometheusRule` CR；本仓库暂不提供该 CR 模板（Helm chart 的 `deploy/helm/xshield` 范围是部署一个租户/站点，不含监控栈本身），按你所在集群已有的 Operator 约定转换即可，规则内容不变。

## 校验

```sh
scripts/test_prometheus_alerts.sh
```

用官方 `prom/prometheus` 镜像跑 `promtool check rules`，CI 的 `prometheus-alerts` 作业同样调用它。

## 阈值与覆盖范围

- 带比例/延迟阈值的规则（如 `XshieldEdgeHighRefusalRatio`、`XshieldControlHighErrorRatio`、两条延迟规则）注释里标注“按你的流量调整”，不是经过验证的 SLO；docs/21 的延迟预算本身仍是待测目标（§21.7 只有单机基线）。
- 证据相关规则（容量、清理失败、清理停滞）只在启用 `response.evidence_capture` / 网关内置清理时才有数据，未启用时规则天然不产生样本、不会误报。
- TLS 相关规则（握手失败、重载失败）在未启用原生 TLS 时计数器恒为 0，不会触发；因此没有单独按“是否启用 TLS”去条件化。
- 本文件不覆盖 systemd 维护单元（`deploy/systemd` 的 seal/publish/outbox oneshot+timer）本身的运行状态——它们不暴露 `/metrics`，运行健康按 systemd 自身状态查看（`systemctl list-timers`、单元的 `OnFailure=`），`deploy/systemd/README.md` 已有说明；若要把这部分也接入 Prometheus，常见做法是 node_exporter 的 textfile/systemd collector，不在本次范围内。
- 没有 Alertmanager 路由/分组/静默配置：告警去向因组织而异，这里只给规则本身。
