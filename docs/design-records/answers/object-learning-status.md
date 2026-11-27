# 对象学习：现在能跑什么，还缺什么，学到的对象怎么处理

依据：仓库 HEAD `82ef557` 的代码（2026-11-03 核对）。docs/06 和 docs/07 自己的状态也写着“设计稿，待实现”。

## 1. 结论

学习已经在跑，但还没有完整开发完。能学到对象，学到之后能确认、驳回、标为有歧义，判定器也会读取保存后的确认结果。下面这几块还是占位或没接通：冷启动候选、自动收紧、自动暂停、学习代理、路径里的 id 确认。

## 2. 现在能跑的部分

| 环节 | 行为 | 代码 |
|---|---|---|
| 学习任务 | 控制台启动时跑一次，之后每小时跑一次。每次读各站点判定日志里 10 分钟前的记录，按位置统计投票。 | `crates/xshield-control/src/maintenance.rs`（PASS_INTERVAL 1 小时）、`object_learning.rs` |
| 提议门槛 | 同一位置在 7 天窗口内至少 20 次使用、来自至少 5 个会话，且规则能给它命名类别（字段名或路由词）才会提议。 | `crates/xshield-core/src/context/learning.rs`（VOTES_MIN、SESSIONS_MIN、WINDOW_DAYS） |
| 自动学习开关 | 站点的 `objects.learning.auto_learn` 关闭后不再学习。 | `object_learning.rs:70` |
| 状态流转 | 新位置先是“学习中”或“待确认”（proposed）；已确认的位置证据转向别的类别时变为“暂停”（suspended）；30 天没有投票退役，退役满 90 天后删除。 | `object_learning.rs` 文件头和 `learn_site` 注释 |
| 对象表页面 | 计数、位置列表、位置抽屉（流向、Jev 判定次数、最近请求）。 | `web/console/src/features/sites/objects/`、`object_map.rs` 的 list 和 slot |
| 驳回 | 记住驳回时的类别和票数，证据有实质变化才会再次提议。 | `object_map.rs` 的 dismiss |
| 标为有歧义 | 永久交给 Jev，学习不再提议。 | `object_map.rs` 的 ambiguous |
| 确认 | 抽屉里的确认按钮把字段名声明（`advanced.field_kinds` 的一项，`field`、`kind`、`in`）加进草稿，再通过保存对话框生成新版本。 | `SlotDrawer.tsx`、`objects-model.ts` 的 `declarationFor` 和 `withDeclarations` |
| 判定 | 判定器读取保存后的站点配置（`objects` 和 `advanced.field_kinds`），确认并保存后的字段类别会用于判定。 | `crates/xshield-judge/src/engine.rs:407`、`crates/xshield-core/src/kind.rs:124` |

## 3. 还没完成的部分

1. **冷启动候选一直为空。** `GET /objects/bootstrap` 固定返回空数组，注释写着“candidates are not read yet”（`object_map.rs:209`、`:373`）。新站点只能等学习攒够证据。
2. **位置抽屉的“结构、历史、影响”为空。** `object_map.rs:195` 写明这些部分为空，“同字段的兄弟字段”也没有计算（`:160`）。
3. **自动收紧、自动暂停没有生效。** 这两个开关只会被保存和解析，代码里没有任何地方执行它们。文档写的是 PR-3d 才生效。“自动变更”横幅没有记录（`:175`）。
4. **暂停不影响判定。** 判定器不读学习状态（学习状态只在数据库的 `object_positions` 等表里），已确认后又暂停的字段照常生效。
5. **学习代理没有实现。** `agent_configured` 写死为 false，网关也拒绝 `agent.enabled: true`，控制台的 agent 开关禁用（见上一条回复）。
6. **URL 路径里的 id 无法通过抽屉确认。** 确认只能写字段名声明，而 `fieldOfKey` 对 `path[...]` 位置返回 null，确认按钮因此禁用（`objects-model.ts:26`）。这类位置（例如 `GET /doctor/{id} path[1]`）只能看到提议，不能确认。
7. **命名规则之外的位置学不到。** 纯小写的裸路径段（例如 `/users/alice` 里的 `alice`）没有字段名，规则给不出类别，也就不会学习（`docs/01-request-flow.md` 已知缺口）。
8. **文档和代码不一致。** `docs/03` 3.2 写“确认后写入 `objects.slots`”，但控制台实际写入的是 `advanced.field_kinds`。以代码为准。

## 4. 学到的对象怎么处理（现在的实际流程）

1. 学习任务把位置写成“待确认”（proposed），在对象表里可以看到计数和抽屉。
2. 管理员在抽屉里做三选一：**确认**（加入草稿，保存后生效）、**驳回**（之后证据变化才会再提议）、**标为有歧义**（永久交给 Jev）。路径里的 id 目前只能驳回或标为有歧义。
3. 确认并保存后，判定器按字段名把对应的值当作该类别的对象，检查它是否在本会话里出现过。
4. 已确认的位置如果证据转向别的类别，会被标为“暂停”，但判定仍然照常使用原来的声明，需要人工处理。

## 5. 对你的部署的提示

学习数据来自判定日志，所以低流量时要很久才有提议。你可以在对象表看各状态的计数，或在数据库里查 `object_evidence`、`object_positions` 两张表（表名见 `docs/07` 第 39 到 41 行）。我没有你库里的数据，无法判断你现在学到了多少。
