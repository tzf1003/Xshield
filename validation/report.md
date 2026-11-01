# 文档和合成样例验证

结果：存在失败；3836/3844 项检查通过。

覆盖：JSON/YAML、JSON Schema、合成事件/证据/模型契约、摘要及引用闭合、负向约束、文档来源和本地链接。

不覆盖：Rust 编译、PostgreSQL/ClickHouse 实际执行、代理部署、站点安全测试、模型准确率和性能。78 项安全验收用例：automated 2、partial 18、planned 58；覆盖声明只校验所引用的测试文本仍然存在，不表示该测试已执行或通过。

失败：
- {'name': 'acceptance:AGENT-03:coverage_claim', 'passed': False, 'detail': 'test text not found in crates/xshield-control/src/lib.rs: search_rejects_unauthorized_or_invalid_plans_before_index_access'}
- {'name': 'acceptance:AGENT-04:coverage_claim', 'passed': False, 'detail': 'covered_by file does not exist: crates/xshield-control/src/tests/site_approval.rs'}
- {'name': 'acceptance:AUDIT-02:coverage_claim', 'passed': False, 'detail': 'covered_by file does not exist: web/console/tests/request-detail.spec.ts'}
- {'name': 'acceptance:AUDIT-04:coverage_claim', 'passed': False, 'detail': 'test text not found in crates/xshield-control/src/lib.rs: request_events_are_scoped_bounded_and_audited; covered_by file does not exist: web/console/tests/request-detail.spec.ts'}
- {'name': 'acceptance:AUDIT-09:coverage_claim', 'passed': False, 'detail': 'test text not found in crates/xshield-control/src/lib.rs: evidence_access_request_is_idempotent_bounded_and_audited'}
- {'name': 'acceptance:AUDIT-10:coverage_claim', 'passed': False, 'detail': 'covered_by file does not exist: crates/xshield-control/src/tests/hold_console_wire.rs; covered_by file does not exist: crates/xshield-control/src/tests/case_close.rs; covered_by file does not exist: crates/xshield-control/src/tests/ledger_inspection.rs'}
- {'name': 'acceptance:AUDIT-11:coverage_claim', 'passed': False, 'detail': 'test text not found in crates/xshield-control/src/lib.rs: evidence_access_request_is_idempotent_bounded_and_audited; test text not found in crates/xshield-control/src/lib.rs: evidence_access_decision_is_independent_short_lived_and_audited'}
- {'name': 'acceptance:AUDIT-14:coverage_claim', 'passed': False, 'detail': 'covered_by file does not exist: web/console/tests/request-detail.spec.ts; covered_by file does not exist: web/console/tests/search.spec.ts; covered_by file does not exist: web/console/tests/downloads.spec.ts'}
