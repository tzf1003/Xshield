# 攻击与良性语料

`attacks.jsonl`（攻击）和 `benign.jsonl`（良性）供理想模型 Jev（`tests/security-lab/fake_jev.py`）和防护有效性度量共用。每行一条 JSON：

```json
{"id": "atk-sqli-01", "class": "sqli", "text": "' OR 1=1--", "quick": true, "note": "基础形式：永真条件"}
```

- `id`：稳定标识，报告和基线按它引用。已发布的 id 不改、不重新编号，新增的行接在同类末尾。
- `class`：攻击为 `sqli`、`cmd`、`traversal`、`xss`、`nosql`、`ssti`、`ssrf`，每类 22 条。良性为 `name`、`clinic`、`keyword`、`path_url`、`math`、`code_markup`、`json`、`contact`、`long`，每类 17 条。
- `text`：原文。驱动把它放进注入点（搜索查询、JSON 字段、表单字段、路径段）时按注入点编码，语料本身不编码。大小写、注释、URL 编码、双重编码、全角变形都以原文保存，一条一个变形。
- `quick`：快速模式用的子集。攻击和良性各约 30 条，攻击的每一类至少 2 条。
- `note`：这一条测什么。

攻击语料是自写的，不复制外部载荷库，只含检测用的字符串，不含可直接利用的完整攻击链。良性语料专挑容易被误判的正常文本：带撇号的姓名、中文病历用语、含 select、drop、union 等词的普通句子、文件路径和网址、数学式和化验说明里的等式、Markdown 与代码片段、JSON 文本、邮箱电话、长文本。

## 约束

`test_fake_jev.py` 逐条核对：

- 每个攻击类至少 15 条；id 唯一；同一文件里原文不重复。
- 攻击与良性的原文，以及规范化后的形式，都没有交集。
- 任何良性文本规范化后都不包含任何攻击文本的规范化形式。否则理想模型会把这条良性文本判成 ATTACK。

规范化见 `fake_jev.normalize`：反复做百分号解码（`+` 当空格）直到不变，再做 NFKC（全角转为 ASCII），最后做大小写折叠。理想模型用它比较，所以同一攻击的各种变形规范化后相同，它们的区别只在真实 Jev 看到原文的时候。

## 运行

```sh
python3 -m unittest discover -s tests/security-lab -p "test_*.py"
```
