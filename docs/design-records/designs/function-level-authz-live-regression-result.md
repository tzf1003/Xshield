# T6 真实模型回归的结果（2026-11-13）

验收人在 PR 219 的头 `38ee887` 合入 main `fd51252` 之后的树上跑的。密钥只经环境变量传入。三遍共 222 次模型调用。

下面第 1 节是要加进 docs/04 的文字，第 2 节是测试文件里要跟着改的地方，第 3 节是三遍的原始数字。

## 1. 加进 docs/04 的文字

放在 4.5.4 之后，作为新的一小节，逐字使用：

```markdown
### 4.5.5 功能表回归（2026-11-13，三遍共 222 次调用）

用 TypeSafe `jev-1.13.0` 的直连端点、提示词 `jq_77be488d34440d84`，把 4.4 的 `live_function_table` 连跑三遍。每遍 77 条请求，74 条调用模型，3 条快速放行。调用耗时 170 到 520 毫秒，中位数 210 毫秒，没有超时，也没有限流。

69 条必须符合预期的请求，三遍全部符合：

- 管理档功能上的尝试越权 4 条（`POST /api/admin/export`、`GET /api/audit-logs`、`PUT /api/staff/{id}/role`、`GET /api/settings/clinic`）全部被拦，DENY 概率不低于 0.98。最后一条的路径名看不出是管理功能，靠的是功能表里的管理档。
- 功能表里没有、名字显示管理或运维功能的 29 条（`/metrics`、`/actuator/env`、`/.env`、`/backup.sql`、`/ftp/` 等）全部被拦。其中 `DELETE /api/patients`（DENY 0.64 到 0.73）和 `POST /api/permissions/grant`（0.63 到 0.77）离平局较近。
- 功能表里没有的普通接口 30 条全部放行，DENY 概率最高的是 `GET /api/wards/occupancy`（0.21 到 0.37）。
- 不带 `function` 的对照 6 条不受新指令影响：没展示过的病人编号仍被拦（DENY 1.00），其余 5 条放行。

6 条已知做不到的（`KnownGap`，只记录，不算失败）：

| 请求 | 想要的结论 | 三遍的结果 | 原因 |
|---|---|---|---|
| `GET /api/patients/export-all` | 拦 | 三遍都放行，没有问模型 | 功能表里 `GET /api/patients/{id}` 的 `{id}` 盖住了 `export-all` 这个路由词，请求被当成已知功能快速放行 |
| `GET /trace` | 拦 | 拦了一遍（DENY 0.44 到 0.50） | 接近平局 |
| `GET /api/accounts/all` | 拦 | 拦了两遍（DENY 0.47 到 0.53） | 接近平局 |
| 商店 `GET /api/Users` | 拦 | 三遍都放行（DENY 0.05 到 0.07） | 路径名看不出是全部用户的列表 |
| 商店 `GET /redirect?to=https://example.org/x` | 拦 | 三遍都放行（`access` 答 ALLOW 约 0.90，`attack` 的 ATTACK 概率 0.41 到 0.45） | 功能表管不到开放重定向，要靠 `attack` 问题，而它在这条上接近平局 |
| `GET /api/config/ui` | 放行 | 三遍都被拦（DENY 0.92 到 0.95） | 普通接口，路径里的 `config` 被当成配置功能。这是误拦 |

另外两条只记录的请求：被认作管理员的会话请求功能表里没有的 `GET /api/admin/reports` 和 `GET /api/admin/users/export`，三遍都被拦（DENY 0.99 和 1.00）。这说明打开“未知功能交 Jev”之后，管理员用到没有进功能表的管理接口也会被拦，打开之前要先把这些接口加进功能表。

样本很小，只说明这组请求上的表现，不构成准确率。
```

## 2. 测试文件和 4.4 要跟着改的地方

1. `GET /api/accounts/all` 由 `Must` 改为 `KnownGap`（加 `.known_gap()`），注释写明：DENY 概率 0.47 到 0.53，三遍里拦了两遍。
2. 商店 `GET /redirect?to=` 由 `Must` 改为 `KnownGap`，注释写明：`access` 答 ALLOW，`attack` 答 BENIGN（ATTACK 的概率 0.41 到 0.45），三遍都放行；这条靠的是 `attack` 问题，不是功能表。
3. `function_cases_reach_jev_as_intended` 里 `KnownGap` 的个数由 4 改为 6，注释同步。
4. docs/04 4.4 那句里的“其中 4 例是已知做不到的”改为“其中 6 例”。

改完后 `Must` 是 69 条，`KnownGap` 6 条，`Observe` 2 条。不要改 `expect_block`，也不要动别的用例。

## 3. 三遍的数字

`access` 的 DENY 概率，按遍次列出。没有列出的 `Must` 用例三遍结论一致，DENY 概率在应拦的用例上不低于 0.76，在应放的用例上不高于 0.15。

| 请求 | 状态 | 想要 | 第 1 遍 | 第 2 遍 | 第 3 遍 |
|---|---|---|---|---|---|
| `GET /api/accounts/all` | 原为 Must | 拦 | 0.50 拦 | 0.47 放 | 0.53 拦 |
| 商店 `GET /redirect?to=` | 原为 Must | 拦 | 0.08 放（ATTACK 0.41） | 0.08 放（ATTACK 0.42） | 0.08 放（ATTACK 0.45） |
| `DELETE /api/patients` | Must | 拦 | 0.66 拦 | 0.73 拦 | 0.64 拦 |
| `POST /api/permissions/grant` | Must | 拦 | 0.77 拦 | 0.63 拦 | 0.69 拦 |
| `GET /api/wards/occupancy` | Must | 放 | 0.27 放 | 0.37 放 | 0.21 放 |
| `GET /trace` | KnownGap | 拦 | 0.47 放 | 0.44 放 | 0.50 拦 |
| `GET /api/config/ui` | KnownGap | 放 | 0.92 拦 | 0.94 拦 | 0.95 拦 |
| 商店 `GET /api/Users` | KnownGap | 拦 | 0.07 放 | 0.06 放 | 0.05 放 |
| `GET /api/patients/export-all` | KnownGap | 拦 | 未问模型，放 | 未问模型，放 | 未问模型，放 |
| `adminA GET /api/admin/reports` | Observe | | 0.99 拦 | 0.99 拦 | 0.99 拦 |
| `adminA GET /api/admin/users/export` | Observe | | 1.00 拦 | 1.00 拦 | 1.00 拦 |

与设计阶段的预检相比：`GET /api/accounts/all` 当时是 DENY 0.58，`POST /api/permissions/grant` 0.61，`POST /api/users/{id}/impersonate` 0.76（这次 0.86 到 0.91），`GET /api/wards/occupancy` 的 DENY 0.28。商店的重定向在预检里 `attack` 答的是 ATTACK，这次三遍都是 BENIGN 0.53 到 0.56。

WAF 批次 7 的置信度门槛（0.60）合入后，`GET /api/accounts/all`、`GET /trace` 和商店的重定向这三条接近平局的答案会按“答不上来”处理，届时这三条的状态要重新定。

## 合入 main 之后的复跑（PR 219 头 `0096335`，2026-11-13 16:55Z）

原因：PR 209 改了指令，提示词版本从 `jq_77be488d34440d84` 变成 `jq_d5df87392a92b44d`，前面三遍是在旧版本上跑的。在合并了 main `d9cf90a` 的头上把 `live_function_table` 再跑一遍：77 条请求，74 次调用，全部 200，耗时 179 到 370 毫秒，测试通过。

- 69 条必须符合预期的请求全部符合。管理档功能上的 4 条尝试越权 DENY 0.97 到 0.99；`DELETE /api/patients` DENY 0.64，`POST /api/permissions/grant` DENY 0.62（比前三遍的下限 0.63 低 0.01，仍被拦），`POST /api/users/{id}/impersonate` 0.78，`GET /api/tenants/list-all` 0.75。
- 普通接口全部放行，DENY 最高的仍是 `GET /api/wards/occupancy`（0.29）；登录表单 ALLOW 0.75。
- 6 条已知做不到的与前三遍在同一范围：`export-all` 快速放行；`GET /trace` 这一遍被拦（DENY 0.53）；`GET /api/accounts/all` 放行（DENY 0.44）；商店 `GET /api/Users` 放行（DENY 0.06）；商店 `/redirect?to=` 放行（ATTACK 0.37）；`GET /api/config/ui` 被拦（DENY 0.92，误拦）。

结论：新提示词下功能表的判定没有退化。日志和转发记录里没有密钥。

## T4b 之后的复跑（PR 231 头 `af1f356`，2026-11-13 18:05Z）

T4b 让功能表的 `{id}` 不再覆盖路由词，并让管理员会话不判未知功能。在合并了 main `510badd` 的头上把 `live_function_table` 跑一遍：77 条请求，73 次调用（`export-all` 多一次，两条管理员请求各少一次），全部 200，耗时 183 到 385 毫秒，测试通过。

- 72 条必须符合预期的请求全部符合。`GET /api/patients/export-all` 作为未知功能交给模型并被拦（DENY 1.00），从已知做不到改回必须符合；带已核验编号的 `GET /api/patients/{id}/export-pdf` 放行（DENY 0.10）。
- 管理员会话的 `GET /api/admin/reports` 和 `GET /api/admin/users/export` 快速放行，不调用模型。
- `DELETE /api/patients` DENY 0.58（此前 0.64 到 0.73，离平局更近，仍被拦），`POST /api/permissions/grant` 0.66；普通接口里 `GET /api/wards/occupancy` DENY 0.36。
- 5 条已知做不到的与此前在同一范围：`GET /trace`（DENY 0.49）、`GET /api/accounts/all`（0.47）放行；商店 `GET /api/Users`（0.06）、`/redirect?to=`（ATTACK 0.40）放行；`GET /api/config/ui` 被拦（0.91，误拦）。

日志和转发记录里没有密钥。
