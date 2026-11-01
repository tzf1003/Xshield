# Xshield

**基于会话上下文的越权拦截 WAF · Jev 模型判定 · Rust**

Xshield 部署在源站前面，记住每个登录会话正常走过的路（从哪个入口进来、源站给它看过哪些数据）。请求里出现这条路上没出现过的东西时，网关把会话上下文和请求一起交给 Jev 模型判断是否越权或攻击，判为不正常就在到达源站之前拦截。后端没有做对象级鉴权时，它仍然能挡住改 ID 访问别人数据的请求；注入类攻击也交给模型判断，不维护规则库。

## 当前状态

2026-11-01 设计重置为 v4：只保留"会话上下文 + Jev 判定"这一条主线，单管理员、配置最少，大量删减 v3 的审批、资格账本、探针、证据链和校准体系。

**目前只有文档是 v4。** `crates/`、`web/console/`、`migrations/` 等代码仍是 v3 实现，改造清单见 [05 删减清单](docs/05-v3-removal.md)。v3 的文档、测试结果和 CI 状态记录在提交 `ad524d4` 及 [CHANGELOG](CHANGELOG.md) 中。

## 文档

| 编号 | 文档 |
|---|---|
| 00 | [产品定位与核心规则](docs/00-overview.md) |
| 01 | [请求判定流程](docs/01-request-flow.md) |
| 02 | [Jev 判定](docs/02-jev.md) |
| 03 | [管理员、配置与判定日志](docs/03-admin-config-audit.md) |
| 04 | [部署与验收](docs/04-deployment-testing.md) |
| 05 | [从 v3 到 v4 的删减清单](docs/05-v3-removal.md) |

## 仓库地图

`crates/`（Rust：`xshield-gateway` 网关、`xshield-control` 控制面、`xshield-core` 领域逻辑，其余 crate 按 05 删除）、`web/console`（控制台）、`migrations/`（PostgreSQL 迁移）、`scripts/`（验证与回归脚本）、`tests/`（靶场与集成回归）、`deploy/`（参考部署）、`docs/`（v4 设计文档）。

## 运行与验证（当前 v3 代码）

```bash
python3 -m pip install -r scripts/requirements.txt
python3 scripts/validate_library.py     # Schema、样例与文档链接
scripts/verify_all.sh                    # fmt、clippy、测试、PostgreSQL、真实二进制与控制台
./dev.sh                                 # 本地开发栈
```

构建输出很大，请把 `CARGO_TARGET_DIR` 指向大容量卷。
