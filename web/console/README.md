# 控制台（web/console）

v4 控制台的前端：React 19、TypeScript、Vite 和 antd。构建产物 `dist/` 由控制面二进制嵌入，并与 API 同源提供（docs/07 7.2）。

设计依据：

- [docs/06-console-ui.md](../../docs/06-console-ui.md)：页面、交互、视觉与无障碍要求
- [docs/07-console-architecture.md](../../docs/07-console-architecture.md)：架构、接口与测试要求

## 常用命令

```sh
npm ci            # 按锁文件安装依赖
npm run dev       # 开发服务器
npm run lint      # Biome 检查
npm test          # 单元测试（node --test）
npm run build     # 类型检查，然后构建到 dist/
npm run test:e2e  # Playwright 浏览器测试，需要 Chromium
```

## 目录

- `src/app`：外壳、路由、搜索参数、命令面板与快捷键
- `src/features`：请求追溯、请求详情、Jev、会话、站点与系统页面
- `src/lib`：不依赖界面的纯函数（对齐、校验、文案），由单元测试覆盖
- `src/api`：与控制面接口对应的类型与请求
- `tests`：单元测试（`*.test.ts`）与浏览器测试（`*.spec.ts`）
