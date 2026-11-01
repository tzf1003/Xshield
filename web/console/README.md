# Xshield 管理控制台

v4 单管理员控制台，按 [docs/03 3.5](../../docs/03-admin-config-audit.md#35-控制台范围) 只保留四块功能：

- **站点列表与配置表单**（`/sites`、`/sites/new`、`/sites/{name}`）：新建、编辑站点的 `hosts`/`origin`/`session`/`entries`/`bypass` 等字段（见 [docs/03 3.2](../../docs/03-admin-config-audit.md#32-站点配置)），以及删除站点。
- **模式切换**：站点详情表单里的观察（observe）/拦截（enforce）开关，随表单一起保存，没有单独的接口。
- **配置历史与回滚**：站点详情页下方列出每次修改的时间与字段级前后对比，可一键回滚到任意历史版本。
- **判定日志**（`/decisions`）：按站点、会话前缀、路径前缀、结论和时间范围筛选，游标分页“加载更多”；点击一行在抽屉里查看完整记录，包括调用 Jev 时的脱敏 `state`、`access`/`attack` 概率表和耗时。
- 顶部栏常驻一个 Jev 连通状态徽标（`GET /api/jev/status`，目前恒为 `unknown`）和退出登录按钮。

v3 的 OIDC 登录、多角色、step-up 认证、案件管理、证据访问、导出与保全、投资调查检索等全部删除；管理员只用一个口令登录（`POST /api/login`，`XSHIELD_ADMIN_PASSWORD_HASH` 配置哈希），会话靠 Cookie 维持。

## 开发

```bash
npm install
npm run dev        # 需要 XSHIELD_CONTROL_PROXY 指向本地后端（默认 http://127.0.0.1:9443）
npm run build       # tsc --noEmit && vite build
npm run lint         # biome check
npm test             # node --test tests/*.test.ts（API 客户端与历史 diff 的单元测试）
npm run test:e2e     # playwright test（登录与站点列表的 mocked-fetch 冒烟测试）
```

## 代码结构

```
src/
  main.tsx          应用入口：QueryClient、ConfigProvider、Router
  router.tsx        路由定义（@tanstack/react-router，code-based）
  Shell.tsx          站点/判定日志页面共用的顶部栏布局
  api.ts             fetch 封装、ApiError、401 监听、错误码到中文提示的映射
  types.ts           与后端契约一致的 wire 类型（SiteSpecJson/SiteRecord/HistoryEntry/DecisionLogRow…）
  diff.ts             站点配置历史的字段级 diff 辅助函数
  pages/              LoginPage / SitesListPage / SiteNewPage / SiteDetailPage / DecisionsPage
  components/         SiteForm（新建/详情共用表单）、HistoryPanel、DecisionDrawer
tests/
  api.test.ts, diff.test.ts   单元测试
  login.spec.ts, sites.spec.ts   Playwright 冒烟测试（mock `/api/*`，不依赖真实后端）
```

本仓库的后端（`crates/`）与本目录是独立并行开发的；本地没有可用的真实后端时，`npm run dev` 的 `/api` 代理会连接失败，请改用单元测试和 mocked Playwright 测试验证改动。
