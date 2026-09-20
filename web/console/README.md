# Xshield 只读调查控制台

React + TypeScript 界面，按请求 ID 读取摘要、事件分页和证据元数据。UI 只调用现有的四个 GET 端点；权限、访问审计和 tenant/site 范围由 `xshield-control` 决定。需要显式 `Observer` 角色，其他管理角色不隐含此权限。

## 本地运行

使用 Node.js 22.12+（22 系列）或 24+，在此目录执行：

```sh
npm ci
npm run dev
```

页面为 `http://127.0.0.1:5173`。开发代理默认连接 `http://127.0.0.1:9443`；该端口需运行已按 [管理 API](../../docs/29-api-endpoint-catalog.md) 配置的控制服务。可由操作者设置 `XSHIELD_CONTROL_PROXY=https://control.internal.example` 后启动 Vite；只接受 HTTPS origin 或 loopback HTTP origin，拒绝 URL 用户信息、路径、查询和片段。该变量是开发服务器配置，不进入浏览器 bundle。

代理只转发四类只读 GET 路径，剥离 Cookie/Set-Cookie，不注入管理身份、不跟随重定向。连接表单只在页面内存中保存 Bearer；首次查询返回后显示经服务端确认的范围。应用中没有演示数据入口；合成响应仅在 `tests/` 用于回归。

## 查询与安全语义

- 摘要后再读事件；证据目录和单项元数据按点击惰性读取。分页显式触发，每页替换前页，换请求重置游标。
- `complete` 表示观察到保留的请求终态，不表示索引无缺口。页面分别显示摘要/事件水位和观察时间；水位只覆盖配置 journal，不覆盖所有 Outbox。
- 转发意图不是源站已执行证明，确认源站响应不等于业务成功。缺失判定与 `UNKNOWN`、等待终态分开显示；确定性证明保持空置信度。
- 证据 `found=false` 显示“当前不可用”，不推断对象存在性；manifest 不证明内容读取权或对象侧完整性。locator、密钥引用和密文摘要在客户端投影时丢弃。
- Bearer 不写 URL、日志或浏览器持久存储；所有请求 `credentials: omit`、`cache: no-store`、禁止重定向，读取上限 16 MiB、全程期限 15 秒。凭证须可被浏览器原样编码为 Authorization 头。
- 401、断连、页面离开、刷新或闲置 15 分钟清空会话。更换请求与详情选择会使旧响应失效；跨响应 tenant/site 偏差断连。客户端清态不等于服务端凭证撤销，JavaScript 也不提供秘密内存可靠清零保证。
- 403、429 和依赖失败显示固定安全文案、稳定代码及管理 request_id；用户显式重试，不自动重试或释放原文。

## 构建与部署边界

```sh
npm run build
```

`dist/` 是静态产物。部署到专用管理 origin，由同源受控反向代理将 `/control/v1` 指向控制服务；生产环境必须使用 TLS、网络隔离和企业身份入口，配置 MFA、凭证发放/撤销及会话策略。当前版本的浏览器连接使用机器 Bearer，尚未实现 OIDC/MFA 登录或服务端浏览器会话，因此不能宣称达到 15.3 的完整生产身份要求。Vite dev/preview 只供本地开发，不是生产管理边界。

静态服务器应返回 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`，并以响应头设置：

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

API 同样保持 `private, no-store`。生产代理仅向指定控制服务传递 Authorization，剥离业务 Cookie，禁止缓存、重定向和请求/响应正文日志；日志须脱敏认证头。不要把秘密放进 `VITE_*` 或静态配置。证据内容审批、搜索、模型详情、案件与导出界面属于后续独立闭环。

## 验证

```sh
npm test
npm run build
npx playwright install chromium --only-shell
npm run test:e2e
# 从仓库根目录执行，Node.js 22 必须在 PATH：
cargo test -p xshield-control --lib console_client_reads_real_http_wire_contract -- --ignored
```

Node 单测覆盖请求/响应边界、精度、空值、取消、超时和流式上限。Playwright 使用真实客户端加显式合成 HTTP 响应，覆盖分页、403/429、401/闲置/刷新清态、异步响应隔离、跨范围拒绝、文本注入及 1536/390 像素布局；默认不记录截图或 trace。需要本地截图时显式将 `XSHIELD_CONSOLE_SCREENSHOT_DIR` 设为仓库外临时目录，验收后清理。

Rust 跨语言测试启动真实 Axum 路由、复用合成 ClickHouse 行和管理 journal，验证摘要、事件分页与微秒时间、目录依赖故障和 401。浏览器回归的 manifest 成功数据是合成契约，不代表已在生产数据源或企业 SSO 上验收。

## 依赖与维护

运行依赖仅 `react` / `react-dom`（MIT），负责界面与 DOM 更新。构建依赖 `vite`（MIT）和 `typescript`（Apache-2.0），类型依赖 `@types/react`、`@types/react-dom`、`@types/node`（MIT）；`@playwright/test`（Apache-2.0）仅用于真实浏览器回归。全部直接依赖固定版本并提交 npm lockfile；依赖升级通过审查，重新执行类型、构建、API、浏览器及 Rust wire 测试。安全修复优先处理，主版本升级需核对 Node 兼容性。复用全局 npm 和 Playwright 浏览器缓存，不为临时分支重复安装。

工具依据：[Vite 指南](https://vite.dev/guide/)、[React 构建指南](https://react.dev/learn/build-a-react-app-from-scratch)、[Playwright 测试服务器](https://playwright.dev/docs/test-webserver)。
