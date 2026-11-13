# 模糊测试

这里对读取外部字节的解析器做覆盖引导的模糊测试。本 crate 是独立的 Cargo 工作区，产品构建与 `cargo deny` 都不包含它：libFuzzer 只在这里编译，不会进入任何镜像。

## 目标

每个目标定义在 `src/lib.rs`。对任意输入都不能 panic；对解析器接受的输入，还要满足注释里写明的不变量。

| 目标 | 解析器 | 额外检查 |
| --- | --- | --- |
| `request_path` | 请求路径的规范写法与展示模板（`path_template`） | 规范写法是绝对路径，没有空段和点段，再规范一次不变；模板不改变段数 |
| `site_config` | 控制面收到、网关加载的站点配置（`SiteSpec`） | 拒绝时只返回错误；接受后入口与旁路匹配都不 panic，且两种问法答案一致 |

## 运行

每个 PR 只要改了相关 crate，CI 的 `fuzz-replay` 作业就会运行。它用稳定版工具链跑 `cargo test`，覆盖每个已提交的种子，再对种子做固定数量的确定性变异。本地运行：

```sh
cd fuzz && cargo test
```

覆盖引导的长跑由 `.github/workflows/fuzz.yml` 负责：每天定时运行，也可以手动触发并指定每个目标的秒数。语料在两次运行之间缓存，发现崩溃时作业失败，并上传 `artifacts/`。本地运行需要 `cargo install cargo-fuzz --locked --version 0.13.2`：

```sh
cd fuzz
cargo fuzz build -s none -O
cargo fuzz run -s none -O site_config -- -max_total_time=300
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
