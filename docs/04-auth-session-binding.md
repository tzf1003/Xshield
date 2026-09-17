# 04 身份与会话绑定

## 4.1 标识及生命周期

WAF 签发随机不透明 Cookie，建议 256 位随机材料：

```http
Set-Cookie: __Host-xshield_sid=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400
```

一天是建议初始最长会话期限，不是无限滑动续期。服务端记录 absolute_expires_at；Cookie 本身的浏览器期限不是安全验证。按站测试 SSO、跨域、子域及 SameSite；不以 Cookie 属性取代 CSRF 控制。SSO 跨域必须通过受控一次性引导完成，不放宽 Cookie Domain 为所有子域共享凭证。[S10]

身份上下文：site_id、waf_session_id、auth_binding_id、principal_ref、tenant_ref、auth_epoch、credential_generation。秘密凭证只在必要执行内存/秘密存储中使用，账本索引用租户隔离的 HMAC 指纹。

## 4.2 状态机

```text
ANONYMOUS
  --verified_login--> AUTHENTICATED(epoch=n)
  --verified_share--> LIMITED_SHARE(scope)
AUTHENTICATED
  --verified_refresh_same_context--> AUTHENTICATED(epoch=n, generation+1)
  --account_or_tenant_change--> AUTHENTICATED(epoch=n+1, new_ledger)
  --logout/revoke/expire--> INVALID
ordinary_credential_substitution --> DENY（不自动换绑）
```

授权作用域变化即使 sub 相同，也要重新评估或新 epoch。源站沿用同一个 Session 字符串而身份已改变时，也必须轮换 epoch。refresh token 参与刷新链的绑定，不能以 B 的 refresh token 为 A 的账本续期。

## 4.3 实际认证方式

认证 profile 按站点和端点定义 Cookie、Authorization、body token 的优先级和共同条件。Cookie=Session_A 与 Bearer=JWT_B 冲突时拒绝；只有经证实源站的接受规则与 WAF 一致才允许多凭证。

JWT 可作为不透明字符串精确匹配；使用 claims 建立身份时验证签名、算法白名单、issuer、audience、用途和期限，不接受仅解码。多个合法 JWT 签发方/受众用互斥配置，避免令牌跨用途替换。[S11]

## 4.4 合法更新

验证旧 WAF 会话与旧认证链 → 请求认可的认证端点 → 识别真实业务成功 → 提取新凭证 → 验证继承关系和权限范围 → 原子更新 generation/epoch → 轮换必要 Cookie → 向客户端释放响应。

并发刷新采用 compare-and-swap 或行锁与版本字段。新旧兼容窗口只存明确合法的凭证组合，不能把同用户历史上的所有 WAF Cookie 与所有 Token 做笛卡尔组合。未知替换记录 AUTH_BINDING_MISMATCH，不改变原账本。

## 4.5 异步响应与 WSS

每条请求保存 AuthSnapshot。A 的列表晚于切换 B 的响应返回时，只能针对 A 的旧快照尝试发行，epoch 不再有效就丢弃发行动作并审计。不同 tab 使用不同 Bearer token 时按 profile 隔离绑定；不能只靠同域 Cookie 合并身份。

WSS 握手及消息处理检查绑定、Origin、票据和消息 Schema。登录/登出时重认证或断开，不让旧连接把页面证据关联给新用户。[S12]

## 4.6 边界与日志

绑定阻止 A/B 凭证拼接，不识别完整有效 A 凭证被复制后的设备冒用。每日过期缩短暴露时间但不等于防盗用。

必须记录 binding.created、refresh.verified、binding.mismatch、epoch.changed、binding.revoked，以及新旧非秘密指纹、来源认证请求 ID、轮换原因。禁止在普通日志中写原始 Cookie/JWT 或将其传给 Jev。
