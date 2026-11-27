# 接口档位学习：并行工作交接说明

- 日期：2026-11-03
- 定稿讨论稿（含背景、误判分析）：https://claude.ai/artifact/Dvi6J8AUPvdPtDAUDFg3eV （“对象归属与会话身份：判定设计讨论稿”）
- 早先分析：`docs/design-records/answers/search-then-modify-idor.md`
- 已暂停的旧草稿补丁（搜索来源标记，可复用其中的“来源标记”“写目标识别”）：`/mnt/project-files/answers/search-provenance-draft.patch`

## 已确认的决定（用户 2026-11-03）

1. **收紧条件**：写操作（或私密读）的目标值只来自“公共档”的响应位置，并且这个请求位置在正常流量里几乎不接受公共来源，两边可靠性都高时，才收紧。“无证据”本身不拦。
2. **档位来自学习**：控制面从流量里学出每个响应位置的档位（自身、机构、管理、公共）和可靠性，以及每个请求位置是否接受公共来源；判定时把档位和可靠性带进 Jev 的 state。
3. **管理员**：身份响应里的 role 只作辅助。管理档接口展示的对象，对管理员会话算正证，按正常逻辑判；管理员没见过就直接改，照常拦。角色不是放行理由。

暂按以下默认推进（用户未否决，可在 PR 里说明）：

- 身份只认对象表声明的身份位置，不从请求里取；JWT 声明以后再加。
- “尝试越权”交 Jev，指令要求 DENY；网关不做确定性拒绝。
- 属性级越权只告警，不遮字段。
- 先在观察模式统计“本应拦截”，开启拦截的门槛看数据再定。
- 站点没有档位、没有声明身份时，判定和日志必须与现在一致。

## 工作项

| 编号 | 目标 | 涉及模块 | 依赖 | 完成标准 |
| --- | --- | --- | --- | --- |
| W1 身份与角色 | 对象表可把响应位置标为“本会话的用户 / 机构 / 角色”；网关在会话上下文记住身份（键控哈希）和角色；判定记录带会话身份标签，供学习按用户统计 | xshield-core `context/objects.rs`；xshield-judge `context.rs`、`engine.rs`（observe）；xshield-core `context/trace.rs`；xshield-control `object_map.rs`（API）；docs/01 §1.2、docs/07 | 无 | 靶场声明 `GET /api/home` 的 `doctor.id` 后，判定记录带会话身份；换账号身份不同；未声明时判定与日志不变；单测与靶场用例通过 |
| W2 响应值指纹 | `trace.response` 按响应位置（`METHOD route field`，与 `slots::response_slot` 同格式）记少量值指纹：按站点派生的键控哈希，每个位置取最小的至多 8 个；不存原文；供控制面算跨用户重叠 | xshield-judge `engine.rs`（observe）；xshield-core `context/trace.rs`（`ObservationSummary`）；docs/07 §7.4 | 无 | 同站点不同会话里同一值指纹相同、跨站点不同；单条记录增量有上限（位置数和指纹数都封顶）；单测通过 |
| W3 档位学习 | 学习流程新增两类结果：(a) 响应位置档位 + 可靠性：跨用户重叠高为公共，各用户互不相交为自身，只有管理角色会话拿到 2xx 为管理，规则定不了的问学习代理；(b) 请求位置是否接受公共来源：用现有流向投票（`learning.rs` 的 `Vote.from` / `FlowShare`）按来源档位汇总，按角色分开。结果走提议，管理员确认后写入站点配置 | xshield-core `context/learning.rs`（纯函数）；xshield-control `object_learning.rs`、`object_agent.rs`、`object_map.rs`、迁移；docs/07 | W2（重叠需要指纹）；W1（按用户、角色统计。没有身份时按会话统计，可靠性降一档） | 用靶场流量学出：“我的患者” `GET /api/patients` 为自身，`GET /api/search` 为公共，`DELETE /api/patients/{id}` 不接受公共来源；纯函数单测 + 控制面集成测试通过 |
| W4 判定使用档位 | 网关从站点配置读档位；state 的每个 `seen_as` 来源附档位和可靠性，请求位置附是否接受公共来源；满足收紧条件时：trace 值上记“尝试越权”，不快速放行，交 Jev，Jev 指令要求 DENY（提示词版本号随之更新）；管理员会话的管理档来源算正证 | xshield-judge `engine.rs`（`plan`）、`state.rs`（`StateValue`、`ACCESS_INSTRUCTIONS`、固定的提示词 id）；xshield-core trace；`tests/security-lab/fake_jev.py`、`scripts/test_idor_lab.py`；docs/01 §1.4–1.5、docs/02 §2.2 | 配置格式与 W3 约定（可先用手写配置开发）；管理员部分依赖 W1 | 靶场 A9（PR #159）改为拦截；新增：管理员搜到后删除放行、管理员没搜到直接删除拦截、给搜到的患者加备注（POST 子路径）放行、没有档位的站点行为不变；judge、edge 测试和全量靶场通过 |
| W5 控制台展示 | 请求详情显示来源档位和“尝试越权”；对象表页显示档位、可靠性和提议（确认、驳回）；切换拦截前的就绪检查列出尝试越权次数 | xshield-control `requests.rs`、`insights.rs`；控制台前端；docs/06、docs/07 | W3、W4 合入 | 控制台测试通过 |
| W6 属性级越权告警 | 读到不是自己的用户类对象，响应又含手机号、邮箱、身份证号类字段（字段名和格式两种识别）时记告警，不拦 | xshield-judge observe；trace；控制台 | W1 合入 | 单测通过；靶场新增“评论作者资料带手机号”用例，记一条告警 |

建议并行：W1、W2、W3、W4 同时开工；W3 与 W4 联调；W5 在 W3、W4 合入后开始；W6 在 W1 合入后开始。

## 并行开发的约定格式

字段名由 W3（配置、学习结果）和 W4（state、trace）在各自第一个 PR 里定稿，并写进 docs/07；另一方按定稿调整。

- **站点配置**：对象表位置增加可选字段。响应位置带档位（`self`、`org`、`admin`、`public`）和可靠性；请求位置带是否接受公共来源；身份位置带 `user`、`org` 或 `role`（W1）。不带这些字段时行为不变。注意现有 `ObjectSlot` 必须带 `class`，且 `deny_unknown_fields`，档位是否允许不带类别由 W3 决定。
- **判定记录**：响应指纹写在 `trace.response`（W2）；身份标签写在会话层的记录里（W1）；“尝试越权”写在 `trace.values` 的值上（W4）。
- **state**：`seen_as` 的每个来源附档位和可靠性；尝试越权的值带标记（W4）。

## 仓库约束（来自 AGENTS.md 和本项目约定）

- 会话凭证和口令类字段不得原样写日志或发给 Jev；身份值只存键控哈希。
- Jev 超时、出错或答不上来时按站点 `on_jev_unavailable` 处理，不得默认放行。判定日志不作为授权依据。
- 新增配置项、表、环境变量之前，先确认现有机制不够用，并在 PR 里写明理由（理由：现在没有任何地方记录会话是谁、接口展示的是谁的对象）。
- 提交前执行 `cargo fmt`、`cargo clippy`（`-D warnings`）和相关测试，涉及判定的还要跑 `python3 scripts/test_idor_lab.py` 全量。生产输入路径禁止 `unwrap`/`expect`/`panic`。
- 靶场源站只能在靶场里运行，不得部署。
- 推送、开 PR、合并 PR 已授权；等 CI 时用定时检查，不依赖自动通知。
