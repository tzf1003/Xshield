# #262 本地发布打包验证

| 项目 | 记录 |
| --- | --- |
| 日期 | 2026-11-26 |
| 源码基线 | `4752ed9f2484c8b583ddabe5f198eacac2d92412`（`origin/main`，干净副本） |
| 版本和平台 | `v0.1.1-243-g4752ed9f`，Linux x86_64 |
| 归档 | `xshield-v0.1.1-243-g4752ed9f-linux-x86_64.tar.gz`（18,060,220 字节） |
| SHA-256 | `505bc11619c320c3849574c4413a17db7333299950b341dd176b023fbc53f8d5` |
| 构建环境 | Debian Bookworm 容器，Rust / Cargo 1.99.0，Node 22.23.4，npm 10.9.9，CMake 3.25.1，OpenSSL 3.0.22 |

构建使用 [仓库 Dockerfile](../Dockerfile) 固定摘要的 Rust 和 Node 基础镜像，在同一个本地容器里从干净的源码副本运行 `bash -n scripts/package_release.sh` 和 `scripts/package_release.sh`。脚本先运行 `npm ci` 和控制台构建，再运行 `cargo build --release --locked -p xshield-edge -p xshield-control`，最后组装归档并写出校验和。`XSHIELD_DIST_DIR`、`CARGO_TARGET_DIR`、`CARGO_HOME`、npm 缓存、`TMPDIR` 和日志位于工作树之外的 ext4 卷，Cargo 并行度设为 2。

第一次准备构建镜像时，主机的 Docker legacy builder 拒绝了 `--progress=plain`，退出码为 125。移除该选项后，镜像构建成功。Vite 报告 Ant Design 的 `use client` 模块指令可能无法保留，控制台构建成功生成 47 个文件。

## 结果

**通过。** 原打包脚本退出码为 0，`cargo build --release --locked` 用时 21 分 55 秒。产物于北京时间 15:01 生成并校验。

- `shasum -a 256 -c` 校验归档成功，`sha256sum` 独立计算出的散列值一致。`gzip -t` 和 `tar -xzf` 均通过。
- 解包后校验 `MANIFEST.sha256` 的全部 76 个条目，清单覆盖除自身之外的所有文件。`VERSION`、文档、示例和迁移文件与构建输入一致。
- 两个二进制均为权限 `0755` 的 Linux x86-64 ELF，与 Cargo 发布产物逐字节一致。归档中的 47 个控制台文件与 Vite 输出一致，并逐个确认位于 `xshield-control` 二进制中。
- `validate_library.py` 499/499 项通过，`check_env_docs.py`、`check_secrets.py` 和 `git diff --cached --check` 均通过。

本地日志位于 `$HOME/.local/state/xshield/release-smoke/issue-262/4752ed9f.TPHiDORV/logs/`，其中 `build.log` 记录完整构建，`verify.log` 记录逐文件校验。归档和脚本生成的 `.sha256` 在同一运行目录的 `dist/` 下。

`.sha256` 中的文件名是构建机绝对路径。归档移动后，可重新用 `sha256sum` 计算并与上表的散列值核对。

本次验证范围为本地打包和产物检查。未执行服务运行测试、部署、发版、上传或实时 Jev 请求。
