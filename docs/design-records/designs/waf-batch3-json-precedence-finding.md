# PR 227 头 `a05cc85`：JSON 读法优先于表单读法带来的回归

2026-11-13，验收 PR 230（T4c，叠在 PR 227 上）时发现。结论先说：`a05cc85` 里“任何类型的请求体，以 `{` 或 `[` 开头且能解析成 JSON 的都按 JSON 读，并且优先于按表单读”这一条，让类型是 `application/x-www-form-urlencoded` 的请求体可以绕过表单读法。上一版 `bfaef70` 没有这个问题。

## 现象

请求体是合法 JSON，同时按 `&` 和 `=` 切开又是一个表单。源站按 `Content-Type` 读表单（PHP、Rails、Django、Express 的 urlencoded、Laravel 都是），网关只按 JSON 读，两边看到的字段不同。

| 编号 | 请求 | 源站读到的 | 网关读到的 | `bfaef70` | `a05cc85` |
|---|---|---|---|---|---|
| Z4 | `POST /api/notes`，表单类型，体 `{"a":"&note=x&patient_id=PT-7004&b="}`，医生 A 的会话 | `patient_id=PT-7004`（别人的患者） | `body.a` 一个文本值 | 拦截（`jev_deny`） | 放行，201，源站已处理 |
| Z3（对照） | 同一请求，体 `note=x&patient_id=PT-7004` | 同上 | `body.patient_id` 是引用 | 拦截 | 拦截 |
| Z1 | `POST /api/patients/{id}`，表单类型，体 `{"a":"&_method=DELETE&b="}`，非管理员 | `_method=DELETE` | `body.a` 一个文本值 | 记为尝试越权，拦截 | 放行，不记功能尝试 |
| Z2 | 同上，没有 `Content-Type`，体 `{"a=":"&_method=DELETE&b="}`（形状是表单，也是 JSON） | Rack 在没有类型时按表单读，得到 `_method=DELETE` | `body.a=` 一个文本值 | 放行 | 放行 |

Z2 在 `bfaef70` 上就存在（没有类型的 JSON 从 `48a209e` 起就只按 JSON 读），Z1 和 Z4 是 `a05cc85` 新引入的。

## 复现

在 `a05cc85`（或它与 PR 230 的合并结果）上，把下面的场景加进 `scripts/test_idor_lab.py` 后跑 `--only Z3,Z4`。靶场用的是假 Jev；真实模型看到 `body.a` 里的一段文本会怎么答没有测，也不该依赖它。

```python
@scenario("Z4", "表单类型的请求体包成能解析的 JSON，里面是别人的患者编号")
def z4(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("Z4 wrapped form names patient D", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie, body=b'{"a":"&note=x&patient_id=PT-7004&b="}',
        headers={"Content-Type": "application/x-www-form-urlencoded"}),
        Expect(403, "jev_deny", "blocked", False))
```

Z3 把 `body=` 换成 `form={"note": "x", "patient_id": "PT-7004"}`，去掉 `headers`。

注意：靶场和工作树共用一个 `CARGO_TARGET_DIR` 时，换工作树后 cargo 可能认为网关二进制是新的而不重编，先 `touch` 一下 `crates/` 下的源文件再跑。

## 建议

JSON 读法是加一种读法，不是替换原来的读法：请求体能解析成 JSON 而类型不是 JSON 类型时，JSON 的值照读，类型本来的读法也照做。

- `application/x-www-form-urlencoded`：照常按字段读，再加 JSON 的值。
- 没有类型：形状是表单的照常按字段读，否则整段作为一个文本值，再加 JSON 的值。
- `text/plain` 等其他类型：是否再加整段文本由 WAF 规划决定（加了会置 `truncated`，这类请求不再快速放行）。

这样 Z1、Z2、Z4 里的字段都会被读到。测试建议：Z4 和 Z1 各加一条靶场场景，`values.rs` 加一条“表单类型的 JSON 形状请求体两种读法都读”。

## 对 PR 230（T4c）的影响

PR 230 的 `method_field_unread` 在 JSON 提前返回之后才计算，合并 `a05cc85` 后 Z1、Z2 不走兜底。PR 227 按上面的建议改了以后，Z1、Z2 由表单读法读到 `body._method`，PR 230 只需要补测试；PR 227 不改的话，PR 230 要把“按 JSON 读而类型不是 JSON 类型”也算作没读成字段。细节在 `designs/function-level-authz-plan-method-field.md` 第 2.5 节。
