# 本地安全靶场

本目录用于验证真实 edge 对已知缺陷源站的增量保护。Compose 只将靶场映射到 127.0.0.1:53000–53002，不使用生产身份、数据或密钥。

## 来源与运行

- [OWASP Juice Shop 官方仓库](https://github.com/juice-shop/juice-shop) 的 [v20.2.0 版本](https://github.com/juice-shop/juice-shop/releases/tag/v20.2.0)，镜像按已核对的 sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b 固定；官方 [Docker 运行说明](https://github.com/juice-shop/juice-shop/blob/v20.2.0/README.md#docker-container)，MIT 许可见该版本 LICENSE。
- idor_origin.py 是仓库自有的双用户测试源站。患者实验账号为 `user_a / user-a-password`（患者 C、D）和 `user_b / user-b-password`（患者 E、F）。直连源站故意不核对患者详情和修改的所有者；用户 A 访问患者 E/F 会返回 200。经 `site_idor` 的 HTTPS edge 会生成受信的对象访问标记，源站随后执行归属校验并返回 403。
- invoice_origin.py 是独立进程中的账单源站，使用另一组路由、资源字段和站点作用域；它同样故意在账单详情遗漏所有者校验。
- independent_labels.json 在模型调用前固定两个站点各一条正常和一条越权请求的资源归属真值。标签按源站代码中的所有者关系定义，评估脚本只读取它；模型输入不包含期望标签。它是合成 fixture 真值，尚未经外部人工复核。

    docker compose -f docker-compose.security-lab.yml up -d
    cargo build -p xshield-gateway --bin xshield-gateway
    python3 scripts/test_security_lab.py
    python3 scripts/test_idor_lab.py
    python3 scripts/test_idor_lab.py --scenario all
    docker compose -f docker-compose.security-lab.yml down

## 不依赖 Docker 的越权回归

`scripts/test_idor_lab_local.sh` 把两个靶场源站作为本机 Python 进程（仅监听 127.0.0.1:53001/53002，由 `LAB_ORIGIN_HOST`/`LAB_ORIGIN_PORT` 控制，容器默认值不变）启动，再运行 `scripts/test_idor_lab.py --scenario all`：脚本创建一次性 PostgreSQL 库并应用全部迁移，启动真实 edge 二进制，分别用本人和他人对象请求。PostgreSQL 连接默认指向开发 Compose（127.0.0.1:55432），可用 `XSHIELD_LAB_PGHOST/PGPORT/PGUSER/PGPASSWORD` 改写（密码留空表示 trust 认证）；edge 二进制取自 `${CARGO_TARGET_DIR:-<仓库>/target}/debug`。该脚本已进入 CI，不调用模型，也不覆盖 Juice Shop（仍需 Docker）。

2026-10-05 本机一次运行结果：源站对两个站点的越权请求都返回 200（故意缺陷），经 edge 后越权请求为 403 `CAPABILITY_MISSING`，本人对象请求仍为 200。这只证明这两个合成站点、这一类对象级越权在该账本流程下被拒绝，不代表其他攻击家族的检出率。

## 患者 IDOR 手工验证

完整开发栈由 `./dev.sh --all` 启动后，使用下面两个入口对照测试：

- 未套 WAF：`http://127.0.0.1:53001`（源站）
- 套 WAF：`https://idor.local:5444`（edge；本机 `/etc/hosts` 需有 `127.0.0.1 idor.local`，自签证书可用 `scripts/generate_dev_tls_cert.sh target/xshield-dev/tls --install` 安装）

登录接口是 `POST /login`，JSON 为 `{"username":"user_a","password":"user-a-password"}`。拿到 `access_token` 后：

```bash
curl -sS http://127.0.0.1:53001/patients -H 'Authorization: Bearer lab-token-user_a'
curl -sS http://127.0.0.1:53001/patients/patient-e -H 'Authorization: Bearer lab-token-user_a'  # 故意 200
curl -k --resolve idor.local:5444:127.0.0.1 -sS https://idor.local:5444/patients/patient-e -H 'Authorization: Bearer lab-token-user_a'  # 403
curl -k --resolve idor.local:5444:127.0.0.1 -sS -X POST https://idor.local:5444/patients/patient-e \
  -H 'Authorization: Bearer lab-token-user_a' -H 'Content-Type: application/json' \
  -d '{"diagnosis":"越权修改尝试"}'  # 403
```

浏览器页面是 `http://127.0.0.1:53001/` 与 `https://idor.local:5444/`。页面中的“加载我的患者”只列出当前主体的 C/D 或 E/F；将详情 ID 改成另一主体的患者即可观察直连与 edge 的差异。每个 edge 响应都带 `X-Xshield-Request-Id`，可在控制台“请求调查”中检索。

需要准备 Jev 离线评估样本时，指定一个尚不存在的私有目录：

    python3 scripts/test_idor_lab.py --jev-fixtures-dir /tmp/xshield-jev-idor-inputs
    cargo build -p xshield-worker --bin xshield-model-eval
    target/debug/xshield-model-eval --validate-input /tmp/xshield-jev-idor-inputs/own_order_review_required.json
    target/debug/xshield-model-eval --validate-input /tmp/xshield-jev-idor-inputs/cross_order_review_required.json

受控测试环境可通过 Vercel AI Gateway 执行真实 Jev 评估，进程环境需提供 `AI_GATEWAY_API_KEY` 并设置 `XSHIELD_JEV_ROUTE=gateway`：

    cargo build -p xshield-worker --bin xshield-model-eval
    python3 scripts/test_idor_lab.py --scenario orders --evaluate-jev
    python3 scripts/test_idor_lab.py --scenario all --evaluate-jev


每个站点两个输入分别对应预期 `ALLOW` 与 `DENY`。脚本从本次真实 edge 请求对应的 PostgreSQL `response_evidence`、`ui_actions`、`auth_bindings` 和 `resource_grants` 读取来源链，并从实际列表响应取得动作资源；它按网关资源 HMAC 格式逐项核对当前主体、来源动作与目标资源的活动资格数量（本人恰好一条，跨对象零条），再创建权限为 0600 的样本文件。`attempt_request_id` 把影子输入与已完成的 edge 请求关联；它仍是操作者提供的离线引用，不是授权事实。模型输入文件不含 Cookie、Bearer、动作引用或期望标签。`--validate-input` 只执行严格 DTO 和供应商载荷预算校验，不发出模型请求。目录必须由操作者检查、批准外发内容并单独配置模型容量、证据库及供应商密钥后，才可使用 `--approved-input` 执行真实 Jev 评估。

test_idor_lab.py 使用本地开发 PostgreSQL（127.0.0.1:55432，默认 xshield_dev 账号），新建随机名称的专用数据库，按顺序应用迁移并在结束时删除该专用数据库；已有 xshield 数据库和 Docker 卷不受影响。若开发数据库密码不同，可设置 XSHIELD_LAB_PGPASSWORD。测试脚本的网关监听端口由操作系统临时分配，审计目录与进程随脚本结束清理。

## 2026-09-27 观测矩阵

| 输入 | 源站直连 | 经真实 edge | 判定 |
|---|---:|---:|---|
| Juice Shop 正常商品查询 | 200 | 200 | 允许 |
| 未列入站点操作的产品 API | 200 | 403 | OPERATION_NOT_MATCHED |
| 带策略阻断的请求头 | 未作为源站基线 | 403 | WAF_HEADER_BLOCKED |
| 超出策略 Cookie 字节上限 | 未作为源站基线 | 413 | WAF_COOKIE_TOO_LARGE |
| 含配置的 SQLi 查询片段 | 500 | 403 | WAF_QUERY_BLOCKED |
| 同片段的加号空格编码 | 未作为源站基线 | 403 | WAF_QUERY_BLOCKED |
| 含配置的 XSS 查询片段 | 未作为源站基线 | 403 | WAF_QUERY_BLOCKED |
| 畸形百分号编码 | 未作为源站基线 | 400 | WAF_QUERY_INVALID |
| Alice 读取 Bob 的订单详情 | 200 | 403 | CAPABILITY_MISSING，源站未收到请求 |
| Alice 缺少 UI 来源读取自己的订单 | 未作为源站基线 | 403 | UI_ACTION_NOT_AVAILABLE |
| Bob 复用 Alice 的 UI 动作 | 未作为源站基线 | 403 | UI_ACTION_NOT_AVAILABLE |
| 已撤销资源资格后重放 | 未作为源站基线 | 403 | CAPABILITY_MISSING，源站未收到请求 |
| Alice 读取 Bob 的账单详情（第二站点） | 200 | 403 | CAPABILITY_MISSING，源站未收到请求 |

这些是固定策略和真实 PostgreSQL 历史资格账本的结果。blocked_query_fragments 是站点显式配置的、单次严格百分号解码后的 ASCII 子串规则，最多 32 项，每项 3–128 字节；畸形查询在启用规则时返回 WAF_QUERY_INVALID/400。它只承诺命中所配置的片段，不能代表所有 SQL 注入、XSS 变体或其他漏洞族的检出率。响应保持 request_id，拒绝继续走耐久审计。

当前网关的在线授权决策依靠确定性身份、UI 来源和资源资格；`--evaluate-jev` 会对同一批真实 edge 请求调用 Vercel AI Gateway Jev，并将模型结论与实际 edge 结果做一致性验收。Jev 不能覆盖硬性拒绝，也不直接写入资格账本。`--validate-input` 校验格式但不独立认证文件内容；评估会读回受限证据、审计终态和租约。聚合报告以 0600 权限保存到 `target/xshield-security-lab/live-jev-*.json`，包含冻结标签文件的 SHA-256、匿名靶场请求引用和各层观察，不含供应商密钥。此集合只有两个缺陷源站和一种对象级越权家族，尚不能估计跨构建、跨攻击家族检出率或发布阈值；外部标签复核、更多独立样本和线上接入仍需另行验收。
