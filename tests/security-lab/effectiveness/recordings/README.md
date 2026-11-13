# 真实 Jev 的录制

`quick.jsonl` 是快速模式的真实 Jev 录制。`lab --jev record` 把每次应答按请求摘要写进去，`lab --jev replay` 只从它答复。录制入库后，没有密钥的人也能重放同一批判定并核对报告。

**这个文件目前不存在。** 它要用真实 Jev 和用户提供的密钥生成，由验收线程执行（步骤见下）。在它存在之前，`--jev replay` 以退出码 2 退出并说明没有录制文件；`test_jev_relay.py` 里依赖它的用例跳过。

## 每行的格式

```json
{"digest": "<64 位小写十六进制>", "status": 200, "body": "<真实 Jev 的应答原文>"}
```

同一摘要出现多行时按录制的先后顺序返回，所以同一批请求在回放中得到同样的应答。文件里没有请求头、没有密钥，也没有请求体，只有摘要、状态码和应答。

## 摘要

摘要是请求体（规范化 JSON，键排序，无空白）的 SHA-256，去掉 `state.session.age_seconds`。那是挂钟时间，任何两次运行都不同，指令也不读它。请求体里有问题文本，所以判定指令一改，摘要就变；模型名也在摘要里。两者任何一个变了，旧录制就对不上，要重新录制，不要放宽未命中。

回放时摘要不在文件里的调用收到 UNKNOWN（两问都答不上来），计入“回放未命中率”。同一批请求的回放未命中率应为 0。不为 0 说明请求体里还有随时间变化的字段，要先找出来，再录制。

## 录制步骤（验收线程，用用户提供的密钥）

密钥只从环境变量读取，不写进命令行参数、文件、提交或聊天。

```sh
export XSHIELD_JEV_ENDPOINT=<真实 Jev 的地址>
export XSHIELD_JEV_API_KEY=<密钥>
python3 scripts/measure_effectiveness.py lab --jev record --out <输出目录>
cp <输出目录>/jev-recording.jsonl tests/security-lab/effectiveness/recordings/quick.jsonl
python3 scripts/measure_effectiveness.py lab --jev replay --out <另一个输出目录>
```

回放的报告应与录制时的报告逐项一致（指标、门槛、调用数），回放未命中率为 0。两者一致后再提交 `quick.jsonl`。`record` 的三次重复都写进同一个文件，回放按摘要的先后顺序取用。

## 为什么入库

录制是对真实模型的一次性记录，之后每次度量都不再需要密钥或流量，结果可以复现。文件里只有应答，不含密钥。摘要字段名不含 key、secret、token 或 password，`scripts/check_secrets.py` 不会把它当成密钥；提交前仍要跑一遍这个检查。
