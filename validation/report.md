# 文档和合成样例验证

结果：通过；318/318 项检查通过。

覆盖：JSON、JSONL 和 YAML 语法；JSON Schema 本身；站点配置样例、模板和负例；判定日志样例的字段、路径与结论的对应关系、Jev 状态结构和概率；文档围栏与本地链接。

不覆盖：Rust 行为（`cargo test` 中的 `crates/xshield-core/tests/v4_samples.rs` 用同一批样例运行站点配置和判定记录的解析）、真实判定效果、模型准确率和性能。
