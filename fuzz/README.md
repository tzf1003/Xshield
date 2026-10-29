# 模糊测试

这里对读取外部字节的解析器做覆盖引导的模糊测试，对应可行性建议 P1 的“外部解析器模糊测试”和 docs/20 的 Fuzz 一行。本 crate 是独立的 Cargo 工作区，产品构建与 `cargo deny` 都不包含它：libFuzzer 只在这里编译，不会进入任何镜像。

## 目标

每个目标定义在 `src/lib.rs`。对任意输入都不能 panic；对解析器接受的输入，还要满足注释里写明的不变量。

| 目标 | 解析器 | 额外检查 |
| --- | --- | --- |
| `proxy_header` | PROXY v1/v2 头 | 完整头不超过给定字节与版本上限；单独解析头得到相同结果；头的每个严格前缀都是“未完成” |
| `path_shape` | 未匹配路径的审计形状 | 结果总是合法形状且有上界 |
| `route_admission` | 方法与路径的路由匹配 | 准入与准入类别对“是否匹配”一致；未匹配总是 `OPERATION_NOT_MATCHED` |
| `query_pagination` | 分页查询串 | 转发的查询只含声明参数，再次准入得到同一文本 |
| `routing_authority` | `Host` 与请求目标 authority | 路由名是客户端发来的名字之一；源站目标不带 scheme 和 authority |
| `request_crypto` | 浏览器加密请求封包 | 没有客户端密钥时不可能通过认证 |
| `auth_binding` | 源站登录响应 | 不 panic |
| `strict_json` | 缓冲响应的严格 JSON | 接受的输入都是普通 JSON |
| `sensor_batch` | 传感器观测批次 | 1 到 16 个事件，序号连续 |
| `site_config` | 控制面收到的站点配置 | 解析、校验与拒绝分类都不 panic |
| `page_fingerprint` | 前端构建页面指纹 | 注入偏移指向第一个小写 `</head>` |
| `upstream_address` | 上游地址与私网放行列表 | 不 panic |
| `seal_manifest` | 对象存储里的段封存清单 | 任意字节都不能通过签名校验 |

## 运行

每个 PR 只要改了相关 crate，CI 的 `fuzz-replay` 作业就会运行。它用稳定版工具链跑 `cargo test`，覆盖每个已提交的种子，再对种子做固定数量的确定性变异。本地运行：

```sh
cd fuzz && cargo test
```

覆盖引导的长跑由 `.github/workflows/fuzz.yml` 负责：每天定时运行，也可以手动触发并指定每个目标的秒数。语料在两次运行之间缓存，发现崩溃时作业失败，并上传 `artifacts/`。本地运行需要 `cargo install cargo-fuzz --locked --version 0.13.2`：

```sh
cd fuzz
cargo fuzz build -s none -O
cargo fuzz run -s none -O route_admission -- -max_total_time=300
```

这里用 `-s none` 在固定的稳定版工具链上构建，不加 sanitizer。代码都是安全 Rust，要找的是 panic 和不变量被破坏。

## 发现崩溃之后

1. 用 `cargo fuzz tmin -s none <target> <artifact>` 最小化输入。
2. 把最小化后的输入放进 `seeds/<target>/`，文件名写明问题。
3. 修复解析器。

此后每次 CI 都会回放这个输入。

## 依赖

本 crate 新增了两个依赖，只在这里使用：

- `libfuzzer-sys` 0.4，许可证为 (MIT OR Apache-2.0) AND NCSA。它是 LLVM libFuzzer 的 Rust 绑定。
- 它依赖 `arbitrary` 1.x，许可证为 MIT OR Apache-2.0。

`cargo-fuzz` 在 CI 里按固定版本从 crates.io 构建。

`fuzz/Cargo.lock` 通过路径依赖跟随产品 crate。产品依赖变化后，在这里运行一次 `cargo test` 会更新它，把更新一起提交。
