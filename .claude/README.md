# Claude Code 项目配置

给人看的说明。Agent 的规则在仓库根目录的 `AGENTS.md`（`CLAUDE.md` 导入它）。

| 文件 | 作用 |
|---|---|
| `settings.json` | 团队共用：免确认的检查命令、禁止读取的文件、hook |
| `hooks/guard-bash.sh` | 执行 Bash 前检查 git 命令，见下 |
| `settings.local.json` | 个人覆盖，不入库（`.gitignore`） |
| `worktrees/` | Claude Code 的工作树，不入库 |

## 权限
- `allow` 只列 `AGENTS.md`「质量」一节里的检查命令（cargo、npm、`scripts/` 下的验证脚本），省掉重复确认。它们会执行仓库里的构建脚本和测试，所以只在信任本仓库的检出里生效。推送、发布、`./dev.sh --reset`、Docker 等不在其中，仍按各人的权限模式处理。
- `deny` 挡住 `.env`、`.env.*` 和开发 TLS 私钥，避免把密钥读进对话。

## Hook：`guard-bash.sh`
把三条能机械判断的规则交给 hook，不依赖 agent 记住：

1. 不强推（`--force`、`-f`、`+refspec`；`--force-with-lease` 放行）。
2. 不直接推送 `main`/`master`。
3. Rust 源码没通过 `cargo fmt --check` 时不让 `git commit`。

被拦下时 agent 会收到原因和改法。需要 `jq`；没有 `jq` 时 hook 放行。它防的是 agent 的失误，不是访问控制，真正的门槛是 GitHub 的分支保护和 CI。

手工测试：

```sh
echo '{"tool_input":{"command":"git push -f origin x"}}' | .claude/hooks/guard-bash.sh
```

## 有意没有加的
- **MCP 服务（`.mcp.json`）**：开发本仓库不需要外部服务。以后要加，逐个在 `enabledMcpjsonServers` 里列出，不要用 `enableAllProjectMcpServers`。
- **skills、commands、子代理**：目前的流程一张检查表就能说清，放在 `AGENTS.md`。等同一段多步操作确实反复出现再抽成 skill。
- **固定模型或思考强度**：留给各人和各会话自己选。
