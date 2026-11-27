# 设计记录

这里是设计稿、实现规划、评审和分析的快照，2026-11-27 从项目共享文件夹导入，写于 2026 年 11 月。它们不是产品规格：产品行为以 [docs/](../) 下的现行文档（00–08）和 [CHANGELOG](../../CHANGELOG.md) 为准。每份文件的状态写在文件里，已经落地的内容以对应 PR 为准。

| 目录 | 内容 |
|---|---|
| `designs/` | 设计稿、实现规划和验收结论，如功能级越权防护、凭证换发、学习质量、self 档位 |
| `notes/` | 界面与结构草稿，如控制台对象表、学习界面、字段类别、路由 |
| `plans/` | 实施规划与验收方案，如防护有效性、WAF P0 修复、批次 9 设计 |
| `answers/` | 评审意见与分析，如 WAF 策略评审、先查后改的 IDOR、v4 Agent 与部署配置 |

这里的 `plans/` 和仓库根目录的 `plans/`（带执行状态表的实施计划）是两类文件，不要混用。

## 路径

文中 `docs/design-records/` 下的路径就是本目录里的文件。指向没有入库的文件的路径（如 `/mnt/project-files/acceptance/` 下的验收产物、`search-provenance-draft.patch`）保留原样，见下面的列表。

## 没有入库的内容

- 验收产物、测试输出和报告：项目共享文件夹里的 `acceptance/`、`batch-10/`、`pr211-self-tier/`、`waf-audit/`、`t5b-functions-console/`。
- 用户上传的截图、数据和压缩包：项目共享文件夹里的 `uploads/`，不是设计文档。
- 代码补丁草稿：`designs/waf-batch6-field-name-readings.patch` 和 `answers/search-provenance-draft.patch`，不是设计文档；`patches/` 下的补丁同样不入库。
- 真实 Jev 调用的输出：`designs/function-level-authz-probe/` 里的 `out_*.json` 和 `held_draft*.json`。探针源码保留，运行时需要环境变量 `XSHIELD_JEV_API_KEY`，它们不参与构建和 CI。探针的基线指令取自 2026-11-13 的 `main`；当前源码已经改过，用它重跑的结果不能和文中的历史结果对照。
