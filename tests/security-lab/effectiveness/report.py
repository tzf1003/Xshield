"""Rendering of the effectiveness report: report.md, the terminal summary and report.json.

The report never quotes a request value. It names cases, categories, configurations, decision
paths, request IDs and Jev answers with their probabilities, which is what section 7 asks for.
"""

from __future__ import annotations

from typing import Any

from .score import CONFIG_ORDER

FAILURES_IN_TERMINAL = 10
SECTION_TITLES = (
    "结论",
    "记分表",
    "防护明细",
    "学习明细",
    "回归用例",
    "失败清单",
    "成本",
    "未执行的部分",
)
CONFIG_LABELS = {"none": "无对象表", "learned": "学到的", "truth": "真值"}
SIDE_LABELS = {"request": "请求", "response": "响应", "non_object": "非对象", "unknown": "未知"}


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _count(value: int | None) -> str:
    return "—" if value is None else str(value)


def _ratio(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def _cell(metric: dict[str, Any] | None) -> str:
    """A rate with its counts, for the defence table: 100.0%（3/3）."""
    if not metric or metric["value"] is None:
        return "—"
    return f"{_pct(metric['value'])}（{metric['num']}/{metric['den']}）"


def _configs(*tables: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    for table in tables:
        seen.update(table)
    order = [config for config in CONFIG_ORDER if config in seen]
    return order + sorted(seen - set(CONFIG_ORDER))


def _verdict(gates: dict[str, dict[str, Any]], name: str) -> str:
    gate = gates.get(name)
    if gate is None or gate["ok"] is None:
        return "未执行"
    return "是" if gate["ok"] else "否"


def conclusion(result: dict[str, Any], meta: dict[str, Any]) -> str:
    failed = [gate["name"] for gate in result["gates"] if gate["ok"] is False]
    verdict = "结论：通过" if not failed else f"结论：失败（未通过的门槛：{'、'.join(failed)}）"
    parts = [verdict]
    if result["failures"]:
        parts.append(f"失败项 {len(result['failures'])} 条")
    if not result["baseline"]["compared"]:
        parts.append("未与基线比较")
    for item in result["skipped"]:
        if item["section"] == "学习段":
            parts.append(f"学习段 SKIP（{item['why']}）")
    seed = "—" if meta.get("seed") is None else str(meta["seed"])
    parts += [
        f"Jev 模式：{meta['jev']}",
        f"提交：{meta['commit']}",
        f"种子：{seed}",
        f"用时：{meta['seconds']:.2f} 秒",
    ]
    return "；".join(parts)


def score_rows(result: dict[str, Any]) -> list[tuple[str, str, str, str, str, str]]:
    """The scoring table of section 2: metric, this run, baseline, change, gate, passed."""
    metrics = result["metrics"]
    gates = {gate["name"]: gate for gate in result["gates"]}
    baseline = result["baseline"]
    reference = baseline["reference"]
    regressed = {item["name"] for item in baseline["regressions"]}

    def base_text(name: str, fmt: Any) -> str:
        return fmt(reference[name]) if name in reference else "—"

    def change_text(name: str, value: float | None, pct: bool) -> str:
        if name not in reference or value is None:
            return "—"
        delta = value - reference[name]
        return f"{delta * 100:+.1f} 个百分点" if pct else f"{delta:+g}"

    def base_verdict(name: str) -> str:
        # The overall row covers its categories too (P1/category/config), so one regressed cell fails it.
        covered = [key for key in reference if key == name or key.startswith(name + "/")]
        if not baseline["compared"] or not covered:
            return "—"
        failed = any(item == name or item.startswith(name + "/") for item in regressed)
        return "否" if failed else "是"

    rows: list[tuple[str, str, str, str, str, str]] = []

    def rate(label: str, name: str, value: float | None, limit: str, verdict: str) -> None:
        rows.append((label, _pct(value), base_text(name, _pct),
                     change_text(name, value, True), limit, verdict))

    def count(label: str, value: int | None, limit: str, verdict: str) -> None:
        rows.append((label, _count(value), "—", "—", limit, verdict))

    s1, s2, s3, s4 = metrics["S1"], metrics["S2"], metrics["S3"], metrics["S4"]
    rate("S1 正常引用核验率", "S1", s1["value"], "不低于基线", base_verdict("S1"))
    for config, cell in s1["by_config"].items():  # one row per configuration, beside the total (plan 12a)
        rate(f"S1 正常引用核验率 · {CONFIG_LABELS.get(config, config)}", f"S1/{config}", cell["value"],
             "不低于基线", base_verdict(f"S1/{config}"))
    count("S2 误核验数", s2["value"], "必须为 0", _verdict(gates, "S2 误核验数"))
    rate("S3 快速放行占比", "S3", s3["value"], "不低于基线", base_verdict("S3"))
    for config, cell in s3["by_config"].items():
        rate(f"S3 快速放行占比 · {CONFIG_LABELS.get(config, config)}", f"S3/{config}", cell["value"],
             "不低于基线", base_verdict(f"S3/{config}"))
    rows.append(("S4 每请求 Jev 调用数", _ratio(s4["value"]), "—", "—", "只报告", "—"))
    for config, cell in s4["by_config"].items():
        rows.append((f"S4 每请求 Jev 调用数 · {CONFIG_LABELS.get(config, config)}", _ratio(cell["value"]),
                     "—", "—", "只报告", "—"))

    for layer, label in (("L0", "冷启动候选"), ("L1", "请求位置类别"),
                         ("L2", "响应位置档位"), ("L3", "请求位置接受公共来源")):
        learning = metrics.get(layer)
        accuracy = learning["accuracy"]["value"] if learning else None
        coverage = learning["coverage"]["value"] if learning else None
        wrong = learning["wrong"] if learning else None
        rate(f"{layer} {label}准确率", f"{layer}.accuracy", accuracy, "不低于基线",
             base_verdict(f"{layer}.accuracy"))
        rate(f"{layer} {label}覆盖率", f"{layer}.coverage", coverage, "不低于基线",
             base_verdict(f"{layer}.coverage"))
        count(f"{layer} 误学数", wrong, "必须为 0", _verdict(gates, f"{layer} 误学数"))
    stability = metrics.get("stability")
    stable = stability["value"] if stability else None
    rows.append(("学习稳定性", "—" if stable is None else ("不变" if stable else "变化"),
                 "—", "—", "必须不变", _verdict(gates, "学习稳定性（不加数据再跑一轮，提议集合不变）")))

    p1, p2, p3 = metrics["P1"], metrics["P2"], metrics["P3"]
    rate("P1 拦截率（总体）", "P1", p1["value"], "各类别不低于基线", base_verdict("P1"))
    rate("P2 误拦率（总体）", "P2", p2["value"], "各类别不高于基线", base_verdict("P2"))
    rate("P3 拦截原因正确率", "P3", p3["value"], "不低于基线", base_verdict("P3"))
    p4, p5, p7 = metrics["P4"], metrics["P5"], metrics["P7"]
    rate("P4 未判定率", "P4", p4["value"], "必须为 0", _verdict(gates, "P4 未判定请求数（理想模型下必须为 0）"))
    count("P5 被拦请求到达源站数", p5["value"], "必须为 0", _verdict(gates, "P5 被拦请求到达源站数"))
    rate("P7 must 用例通过率", "P7", p7["value"], "必须 100%", _verdict(gates, "P7 must 用例通过率"))
    count("P7 意外通过数", p7["unexpected_pass"], "必须为 0", _verdict(gates, "P7 意外通过数"))
    return rows


def _md_table(header: list[str], rows: list[list[str]]) -> list[str]:
    def escape(text: str) -> str:
        return str(text).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(escape(cell) for cell in row) + " |" for row in rows]
    return lines


NEEDS_LABELS = {"tiers": "需要档位", "functions": "需要功能表", "classes": "需要对象表"}


def _gap_verdict(item: dict[str, Any]) -> str:
    """Whether a known gap passed by mistake, or is left out of the scoring for a missing capability."""
    if item["lacks"]:
        return "不计分：" + "、".join(NEEDS_LABELS.get(name, name) for name in item["lacks"])
    return "是，请把状态改为 must" if item["unexpected_pass"] else "否"


def _needs_lines(needs: dict[str, Any]) -> list[str]:
    """One line per capability that some rows lack (plan 9.3): the counts by configuration, then the regression
    cases among them, so a gap that is not scored still shows its name."""
    lines = []
    for name, label in NEEDS_LABELS.items():
        entry = needs.get(name)
        if not entry:
            continue
        counts = "；".join(f"{CONFIG_LABELS.get(c, c)} {n} 条" for c, n in entry["counts"].items())
        text = f"{label}（不计分）：{counts}"
        if entry["cases"]:
            text += f"；回归用例：{'、'.join(entry['cases'])}"
        lines += ["", text]
    return lines


def _defence_lines(result: dict[str, Any], meta: dict[str, Any]) -> list[str]:
    metrics = result["metrics"]
    p1 = metrics["P1"]["by_category"]
    p2 = metrics["P2"]["by_category"]
    configs = _configs(*(metrics["P1"]["by_config"], metrics["P2"]["by_config"]))
    header = ["类别"] + [f"拦截率 · {CONFIG_LABELS.get(c, c)}" for c in configs] \
        + [f"误拦率 · {CONFIG_LABELS.get(c, c)}" for c in configs]
    categories = sorted(set(p1) | set(p2))
    rows = []
    for category in categories:
        rows.append([category]
                    + [_cell(p1.get(category, {}).get(c)) for c in configs]
                    + [_cell(p2.get(category, {}).get(c)) for c in configs])
    lines = ["### 拦截率（P1）与误拦率（P2）", ""]
    lines += _md_table(header, rows) if rows else ["没有可计分的类别。"]
    lines += _needs_lines(result["needs"])
    unsent = meta.get("unsent") or {}
    lines += ["", "路径段未送出（载荷含路径分隔符，放不进一个路径段，按 4.3 不计入）："
              f"攻击 {unsent.get('attack', 0)} 条，良性 {unsent.get('benign', 0)} 条。"]
    return lines


def _baseline_lines(baseline: dict[str, Any]) -> list[str]:
    if not baseline["compared"]:
        return ["未提供基线：只做门槛判定，不做只进不退的比较。"]
    lines = [f"基线比较：退步 {len(baseline['regressions'])} 项，进步 {len(baseline['improvements'])} 项。"]
    lines += [f"- 退步：{item['name']}，基线 {_pct(item['baseline'])}，本次 {_pct(item['value'])}"
              for item in baseline["regressions"]]
    if baseline["absent"]:
        lines.append(f"基线里有、本次没有的指标（未比较）：{'、'.join(baseline['absent'])}")
    return lines


def _label_lines(checks: dict[str, Any]) -> list[str]:
    """The three label checks of section 4.6, with the case names of each flagged probe."""
    status = ("已应用：可疑和旁路的探针从拦截率分母里单列。" if checks["applied"]
              else "未应用：探针全部留在分母里（靶场模式）。")

    def names(cases: list[str]) -> str:
        return "、".join(cases) if cases else "无"

    return [
        "### 标签自检（4.6）", "", status, "",
        f"- 标签可疑（目标对象在本会话里展示过）：{len(checks['suspicious'])} 条，{names(checks['suspicious'])}",
        f"- 不经判定（探针走了旁路）：{len(checks['bypass'])} 条，{names(checks['bypass'])}",
        f"- 因标签自检从分母拿出的探针：{checks['excluded']} 条",
    ]


def _learning_lines(result: dict[str, Any]) -> list[str]:
    learning = [item for item in result["skipped"] if item["section"] == "学习段"]
    if learning:
        return [f"学习段：SKIP（{learning[0]['why']}）。"]
    rows = []
    for item in result["learning"]:
        truth = item["truth"]
        learned = item["learned"]
        rows.append([
            item["key"],
            SIDE_LABELS.get(item["side"], item["side"]),
            _describe(truth),
            _describe(learned),
            "✓" if item["ok"] else "✗",
            item["why"] or "—",
        ])
    if not rows:
        return ["没有真值位置，也没有学到的提议。"]
    return _md_table(["位置", "侧", "真值", "学到", "结果", "原因"], rows)


def _describe(fields: dict[str, Any]) -> str:
    labels = {"class": "类别", "tier": "档位", "reliability": "可靠性",
              "accepts_public": "接受公共来源", "object": "对象", "learnable": "可学"}
    parts = []
    for name, value in fields.items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "是" if value else "否"
        parts.append(f"{labels.get(name, name)} {value}")
    return "，".join(parts) or "—"


def _failure_rows(failures: list[dict[str, Any]]) -> list[list[str]]:
    return [[
        item["case"],
        item["category"],
        CONFIG_LABELS.get(item["config"], item["config"]),
        item["expect"],
        item["got"],
        item["outcome"] or "—",
        item["request_id"],
        item["jev"] or "—",
        item["detail"],
    ] for item in failures]


def render_markdown(result: dict[str, Any], meta: dict[str, Any]) -> str:
    gates = result["gates"]
    passed = sum(gate["ok"] is True for gate in gates)
    failed = sum(gate["ok"] is False for gate in gates)
    unexecuted = sum(gate["ok"] is None for gate in gates)
    lines = ["# 防护有效性报告", "", f"## 1 {SECTION_TITLES[0]}", "", conclusion(result, meta), "",
             f"门槛共 {len(gates)} 项：通过 {passed}，失败 {failed}，未执行 {unexecuted}。",
             "", f"## 2 {SECTION_TITLES[1]}", ""]
    lines += _md_table(["指标", "本次", "基线", "变化", "门槛", "是否通过"],
                       [list(row) for row in score_rows(result)])
    lines += ["", *_baseline_lines(result["baseline"])]
    lines += ["", f"## 3 {SECTION_TITLES[2]}", ""] + _defence_lines(result, meta) + ["", *_label_lines(result["label_checks"])]
    lines += ["", f"## 4 {SECTION_TITLES[3]}", ""] + _learning_lines(result)

    must_failures = [item for item in result["failures"]
                     if item["group"] == "regression" and item["status"] == "must"]
    lines += ["", f"## 5 {SECTION_TITLES[4]}", "", "### 必须通过的用例（失败项）", ""]
    lines += _md_table(["用例", "类别", "配置", "预期", "判定路径", "结论", "请求 ID", "Jev 答案与概率", "说明"],
                       _failure_rows(must_failures)) if must_failures else ["没有失败项。"]
    lines += ["", "### 已知缺口（known_gap）", ""]
    if result["known_gaps"]:
        lines += _md_table(["用例", "评审编号", "现象", "类别", "配置", "意外通过或不计分"], [
            [item["case"], item["ref"] or "—", item["note"] or "—", item["category"],
             CONFIG_LABELS.get(item["config"], item["config"]), _gap_verdict(item)]
            for item in result["known_gaps"]
        ])
    else:
        lines.append("没有已知缺口的用例。")

    lines += ["", f"## 6 {SECTION_TITLES[5]}", ""]
    if result["failures"]:
        lines += _md_table(["用例", "类别", "配置", "预期", "判定路径", "结论", "请求 ID", "Jev 答案与概率", "说明"],
                           _failure_rows(result["failures"]))
    else:
        lines.append("没有失败项。")

    costs = result["costs"]
    failures = "、".join(f"{code} {count} 次" for code, count in costs["jev_failures"].items()) or "无"
    lines += ["", f"## 7 {SECTION_TITLES[6]}", "",
              f"- Jev 调用次数：{costs['jev_calls']}（判定记录 {costs['requests']} 条，"
              f"每请求 {_ratio(costs['calls_per_request'])} 次）",
              f"- 判定耗时：中位数 {_count(costs['judge_ms_median'])} ms，p95 {_count(costs['judge_ms_p95'])} ms",
              f"- Jev 失败码：{failures}",
              "", f"## 8 {SECTION_TITLES[7]}", ""]
    lines += [f"- {item['section']}：{item['why']}" for item in result["skipped"]] or ["没有。"]
    return "\n".join(lines) + "\n"


def render_terminal(result: dict[str, Any], meta: dict[str, Any]) -> str:
    lines = [conclusion(result, meta), ""]
    lines += _md_table(["指标", "本次", "基线", "变化", "门槛", "是否通过"],
                       [list(row) for row in score_rows(result)])
    failures = result["failures"]
    if failures:
        lines += ["", f"失败（前 {min(FAILURES_IN_TERMINAL, len(failures))} 条，共 {len(failures)} 条）："]
        for item in failures[:FAILURES_IN_TERMINAL]:
            lines.append(f"  - {item['case']}（{item['category']}，{CONFIG_LABELS.get(item['config'], item['config'])}）"
                         f" 预期 {item['expect']}，判定 {item['got']}：{item['detail']}（请求 {item['request_id']}）")
    return "\n".join(lines)


def report_document(result: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """The machine-readable report (section 9.5), with the extra keys the report also prints."""
    return {
        "meta": {**meta, "skipped": result["skipped"]},
        "metrics": result["metrics"],
        "gates": result["gates"],
        "baseline": {key: result["baseline"][key]
                     for key in ("compared", "regressions", "improvements", "absent")},
        "failures": result["failures"],
        "known_gaps": result["known_gaps"],
        "learning": result["learning"],
        "label_checks": result["label_checks"],
        "costs": result["costs"],
        "counts": result["counts"],
        "needs": result["needs"],
        "passed": result["passed"],
    }
