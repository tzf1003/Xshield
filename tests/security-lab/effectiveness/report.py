"""Rendering of the effectiveness report: report.md, the terminal summary and report.json.

The report never quotes a request value. It names cases, categories, configurations, decision
paths, request IDs and Jev answers with their probabilities, which is what section 7 asks for.
"""

from __future__ import annotations

from typing import Any

from .full import CONSISTENCY_GATE, LAYER_TITLES
from .score import CONFIG_ORDER, LEARNING_GATE_NAMES, POLLUTED_SET_SITE, POLLUTED_SITE

FAILURES_IN_TERMINAL = 10
KIND_LABELS = {"wrong": "误学", "unmodeled": "未模板化", "miss": "没学到", "failure": "学到的配置上失败"}
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
    if failed:
        verdict = f"结论：失败（未通过的门槛：{'、'.join(failed)}）"
    elif meta.get("mode") == "site":
        verdict = "结论：门槛通过（真实站点只设记录缺失与学习误学的门槛，拦截与误拦只报告）"
    else:
        verdict = "结论：通过"
    parts = [verdict]
    if result["failures"]:
        parts.append(f"失败项 {len(result['failures'])} 条")
    if not result["baseline"]["compared"]:
        parts.append("未与基线比较")
    for item in result["skipped"]:
        if item["section"] == "学习段":
            parts.append(f"学习段 SKIP（{item['why']}）")
    seed = "—" if meta.get("seed") is None else str(meta["seed"])
    parts.append(f"Jev 模式：{meta['jev']}")
    if meta.get("note"):
        parts.append(meta["note"])
    parts += [
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
        count(f"{layer} 误学数（未登记）", wrong, "必须为 0", _verdict(gates, f"{layer} 误学数"))
        if learning is not None:
            count(f"{layer} 误学数（已登记为已知缺口）", learning["listed"], "不计门槛", "—")
        if layer in ("L2", "L3") and learning is not None:
            count(f"{layer} 其中类别不符（类别错、档位或接受公共来源对，计入准确率）",
                  learning["class_wrong"], "不计门槛", "—")
    stability = metrics.get("stability")
    stable = stability["value"] if stability else None
    rows.append(("学习稳定性", "—" if stable is None else ("不变" if stable else "变化"),
                 "—", "—", "必须不变", _verdict(gates, "学习稳定性（不加数据再跑一轮，提议集合不变）")))
    unmodeled = metrics.get("unmodeled")
    count("未模板化的位置（未登记）", None if unmodeled is None else unmodeled["unlisted"],
          "必须为 0", _verdict(gates, LEARNING_GATE_NAMES[5]))
    known = result.get("learning_known")
    stale = None if known is None or known["stale"] is None else len(known["stale"])
    count("学习的已知缺口清单：已不再出现的条目", stale, "必须为 0", _verdict(gates, LEARNING_GATE_NAMES[6]))

    p1, p2, p3 = metrics["P1"], metrics["P2"], metrics["P3"]
    rate("P1 拦截率（总体）", "P1", p1["value"], "各类别不低于基线", base_verdict("P1"))
    rate("P2 误拦率（总体）", "P2", p2["value"], "各类别不高于基线", base_verdict("P2"))
    rate("P3 拦截原因正确率", "P3", p3["value"], "不低于基线", base_verdict("P3"))
    p4, p5, p7 = metrics["P4"], metrics["P5"], metrics["P7"]
    rate("P4 未判定率", "P4", p4["value"], "必须为 0", _verdict(gates, "P4 未判定请求数（理想模型下必须为 0）"))
    count("P5 被拦请求到达源站数", p5["value"], "必须为 0", _verdict(gates, "P5 被拦请求到达源站数"))
    rate("P7 must 用例通过率", "P7", p7["value"], "必须 100%", _verdict(gates, "P7 must 用例通过率"))
    count("P7 意外通过数", p7["unexpected_pass"], "必须为 0", _verdict(gates, "P7 意外通过数"))
    p6 = metrics.get("P6")
    if p6 is not None and p6["den"]:  # the full mode only: a gate, which must be 0 (plan 3.3)
        count("P6 观察与拦截不一致的请求数", p6["num"], "必须为 0", _verdict(gates, CONSISTENCY_GATE))
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
        # A real site lists a probe once per run it was sent in; each case is named once.
        unique = list(dict.fromkeys(cases))
        return "、".join(unique) if unique else "无"

    lines = [
        "### 标签自检（4.6）", "", status, "",
        f"- 标签可疑（目标对象在本会话里展示过）：{len(checks['suspicious'])} 条，{names(checks['suspicious'])}",
        f"- 不经判定（探针走了旁路）：{len(checks['bypass'])} 条，{names(checks['bypass'])}",
        f"- 因标签自检从分母拿出的探针：{checks['excluded']} 条",
    ]
    if "business_error" in checks:
        cases = checks["business_error"]
        lines.append("- 源站业务错误（套件标 business_error）：" + f"{len(cases)} 条，{names(cases)}"
                     + "；已按判定记录计分，源站状态码不参与计分")
    if "conflict" in checks:
        conflicts = checks["conflict"]
        lines.append(f"- 标签冲突（同一请求 ID 的标签不一致，全部不计分）：{len(conflicts)} 个请求")
        lines += [f"  - 请求 {item['request_id']}：{'、'.join(item['cases'])}" for item in conflicts]
    return lines


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
            item.get("gap") or "—",
        ])
    lines = _md_table(["位置", "侧", "真值", "学到", "结果", "原因", "已知缺口"], rows) if rows \
        else ["没有真值位置，也没有学到的提议。"]
    return lines + _known_lines(result.get("learning_known"))


def _entry_target(entry: dict[str, Any]) -> str:
    kind = entry["kind"]
    if kind == "wrong":
        return f"{entry['metric']} {entry['key']}"
    if kind == "unmodeled":
        return entry["pattern"]
    if kind == "miss":
        return entry["key"]
    return f"{entry['case']}（{CONFIG_LABELS.get(entry['config'], entry['config'])}）"


def _known_lines(known: dict[str, Any] | None) -> list[str]:
    """The learning known-gap list (plan 8, 12b): each entry, the probes it still matches, and the batch that fixes it.
    A stale entry says what to do: delete it in the change that fixed the problem."""
    if known is None:
        return ["", "学习的已知缺口清单：学习段未执行，没有核对。"]
    rows = [[
        entry["id"],
        KIND_LABELS.get(entry["kind"], entry["kind"]),
        _entry_target(entry),
        entry.get("learned") or "—",
        entry["ref"],
        "长期" if entry["lq"] is None else entry["lq"],
        f"仍出现 {entry['matched']} 处" if entry["matched"] else "已不再出现：删除这一条",
    ] for entry in known["entries"]]
    lines = ["", "### 学习的已知缺口清单", ""]
    lines += _md_table(["编号", "类别", "位置、模式或用例", "学到的值", "评审编号", "修法批次", "本次"], rows) if rows \
        else ["清单是空的。"]
    if not known["checked"]:
        lines += ["", "本次只跑了一部分探针（--only），清单没有核对是否已不再出现。"]
    return lines


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


def _share(num: int, den: int) -> str:
    return "—" if not den else _pct(num / den)


def _scan_block(scan: dict[str, Any] | None) -> list[str]:
    """The confidence threshold scan of plan 3.4, printed only for a run with a real model (score.confidence_scan)."""
    if scan is None:
        return []
    rows = [[
        f"{item['threshold']:.2f}",
        f"{item['benign_blocks']}（{_share(item['benign_blocks'], scan['benign_total'])}）",
        f"{item['leaks_closed']} / {scan['probe_allows']}",
        f"{item['unanswered']}（{_share(item['unanswered'], scan['judgements'])}）",
    ] for item in scan["thresholds"]]
    lines = ["", "### 置信度门槛扫描（3.4）", "",
             "同一批判定记录按门槛重算，不重新发流量。放行的置信度与决策日志的 jev_confidence 同一算法"
             "（两问各自最高概率中较小的一个）；恰好等于门槛的放行保留，低于门槛的放行按“答不上来”处理，"
             "站点按 on_jev_unavailable: deny 计。", ""]
    lines += _md_table(["门槛", "新增误拦（良性请求）", "减少的漏拦（探针：条 / 原被放行的）", "答不上来的 Jev 判定"], rows)
    lines += ["", f"分母：良性请求 {scan['benign_total']} 条，有置信度的放行 {scan['allows']} 条，"
              f"Jev 判定 {scan['judgements']} 次（分批的判定计一次）。只改判 jev_allow 的记录，以及复用了这类放行的 cached_allow；"
              "fast_allow 和拦截不受影响；已知缺口的回归用例不计入（按记分表规则只在 P7 里计）。",
              "这是一阶估计：一个请求改判后，后面的请求会少见到一些值，这部分连带影响没有算。"]
    if scan["cache_unresolved"]:
        lines.append(f"有 {scan['cache_unresolved']} 条缓存放行找不到它复用的放行记录，没有改判。")
    return lines


def _relay_line(relay: dict[str, Any]) -> str:
    """The record or replay line of the cost section (plan 6 and batch 9)."""
    if relay["mode"] == "replay":
        return (f"- 回放未命中率：{relay['misses']} / {relay['calls']} 次调用（{_share(relay['misses'], relay['calls'])}），"
                "未命中的调用收到 UNKNOWN，计为无法判定")
    return (f"- 录制：{relay['recorded']} 条应答写入录制文件（转发 {relay['calls']} 次，"
            f"没有得到可用应答 {relay['failures']} 次）")


def _convergence_lines(convergence: dict[str, Any] | None) -> list[str]:
    """L4 (plan 3.2, full mode): per layer and number of users, the wrong proposals, the learnable positions learned
    right (and the high ones, for the layers whose proposals carry a reliability), and the first number of users at which
    the layer is at its top (plan 3.2: no wrong proposal, and the right positions with the reliabilities the largest
    user count learned)."""
    if convergence is None:
        return []
    points = convergence["points"]
    rows = []
    for layer in ("L0", "L1", "L2", "L3"):
        cells = [_convergence_cell(point["layers"][layer]) for point in points]
        first = convergence["first_top"][layer]
        rows.append([f"{layer} {LAYER_TITLES[layer]}", *cells, "未达到" if first is None else f"{first} 用户"])
    header = ["层", *[f"{point['users']} 用户" for point in points], "首次到顶"]
    return ["", "### 收敛成本（L4）", "",
            "每格是这个用户数下的误学数，以及可学的真值位置里学对的个数；有可靠性的层（L2、L3）另写学对的里面 high 的个数。"
            "“首次到顶”是没有误学、学对的位置和各自的可靠性都与最大用户数那一次相同的最少用户数。"
            "这里不拿真值作标准，已知缺口清单里的条目也不排除；最大用户数那一次与真值还差什么，由学习明细给出。",
            "", *_md_table(header, rows)]


def _convergence_cell(summary: dict[str, Any]) -> str:
    text = f"误学 {summary['wrong']}，学对 {summary['right']}/{summary['learnable']}"
    if "high" in summary:
        text += f"（high {summary['high']}）"
    return text


def _pollution_lines(pollution: dict[str, Any] | None) -> list[str]:
    """L5 (plan 3.2, full mode). The wrong proposals are findings, not a gate; the lost positions are reported, and the
    attack requests are counted by what the observation run did with them."""
    if pollution is None:
        return []
    rows = [[f"{layer} {LAYER_TITLES[layer]}", str(item["wrong_clean"]), str(item["wrong_polluted"]),
             str(len(item["lost"])), str(len(item["weaker"]))] for layer, item in pollution["layers"].items()]
    lines = ["", "### 抗污染（L5）", "",
             f"训练流量混入攻击会话 {pollution['attackers']} 个，占全部会话 {_pct(pollution['share'])}"
             f"（良性会话 {pollution['benign_sessions']} 个）。误学数是发现，不计门槛；“学不到”只报告。"
             "“学不到”包括两种：干净训练学对了、混入后没有学对，或学对了但可靠性比干净训练低（表中“其中可靠性下降”）。",
             "", *_md_table(["层", "干净训练的误学数", "混入攻击后的误学数", "本来能学到却学不到", "其中可靠性下降"], rows)]
    if pollution["false_learns"]:
        lines.append(f"- 发现：混入攻击后误学 {pollution['false_learns']} 个位置。")
    return [*lines, *_attack_request_lines(pollution.get("attack_requests") or {}), *_consequence_lines(pollution)]


CONSEQUENCE_TITLES = {POLLUTED_SITE: "原样使用（clinic-polluted）", POLLUTED_SET_SITE: "照一栏设定之后（clinic-polluted-set）"}


def _case_lines(cases: list[dict[str, Any]]) -> list[str]:
    return [f"- `{item['case']}`（{item['category']}，第 {item['run']} 遍）" for item in cases]


def _consequence_lines(pollution: dict[str, Any]) -> list[str]:
    """The protection consequence of the anti-pollution (plan 10, batch 10): the polluted mapping against the clean run,
    probe by probe, and the positions the lab set by hand for the administrator. The set site's misses are a gate; the
    polluted site's misses are in the baseline, where they may only go down. Both sites' over-blocked benign requests are
    a gate."""
    consequence = pollution.get("consequence")
    if not consequence:
        return []
    rows = [[CONSEQUENCE_TITLES[site], str(item["compared"]), str(item["missed"]), str(item["over"])]
            for site, item in consequence.items() if site in CONSEQUENCE_TITLES]
    lines = ["", "### 防护后果", "",
             "两个站点各自先跑的良性旅程，以及同一批攻击和良性探针，逐条与干净训练学出的映射（`clinic-learned`）比较。"
             "“少拦的攻击”指干净映射拦了、这里放行的；“多拦的良性”指干净映射放行、这里拦了的。两边都比较了的探针数如下（旅程的步骤也按探针计）：", "",
             *_md_table(["配置", "比较的探针数", "少拦的攻击", "多拦的良性"], rows)]
    for site, item in consequence.items():
        if site not in CONSEQUENCE_TITLES:
            continue
        lines.append(f"- {CONSEQUENCE_TITLES[site]}：两边对不上的探针 {item['incomparable']} 个（门槛 0）。")
        if item["missed_cases"]:
            lines += ["", f"{CONSEQUENCE_TITLES[site]} 少拦的用例：", "", *_case_lines(item["missed_cases"])]
    shares = pollution.get("set_shares") or []
    if shares:
        share_rows = [[f"`{item['key']}`", f"{item['public_per_mille']}‰", f"{item['pending_per_mille']}‰",
                       str(item["votes"]), str(item["sessions"])] for item in shares]
        lines += ["", "靶场替管理员设定的位置（规则不下结论的请求位置，设成不接受公共来源、可靠性高）：", "",
                  *_md_table(["位置", "公共份额", "待定份额", "票数", "会话数"], share_rows)]
    else:
        lines += ["", "没有规则不下结论的请求位置，两个站点的配置相同。"]
    return lines


ATTACK_CATEGORY_TITLES = {
    "pollution_walk": "遍历 id",
    "pollution_read": "搜索后打开",
    "pollution_delete": "搜索后删除",
}


def _attack_request_lines(table: dict[str, dict[str, int]]) -> list[str]:
    """The attack sessions' requests by category (plan 3.2, L5). Each one should be blocked; the columns say how many the
    observation run would have blocked, and how many it let through, so that their responses were learned."""
    if not table:
        return []
    rows = [[ATTACK_CATEGORY_TITLES.get(category, category), str(item["requests"]), str(item["would_block"]),
             str(item["allowed"]), str(item["other"])] for category, item in sorted(table.items())]
    return ["", "攻击会话的请求：每个都本应拦截。观察模式下会被拦的、被放行的（响应进入学习）各有多少：", "",
            *_md_table(["类别", "请求数", "会被拦", "放行", "其他"], rows)]


def _natural_order_lines(natural: dict[str, Any] | None) -> list[str]:
    """The deletions in the order of the day (plan 10, batch 7): the search result under the two orders, beside each other,
    with the tier and reliability each one learned. The natural order is a gate (natural_order_gate)."""
    if natural is None:
        return []

    def learned(side: dict[str, Any]) -> str:
        if side.get("tier") is None:
            return "没有学到"
        return f"{side['tier']}，可靠性 {side.get('reliability') or '—'}"

    def agreement(side: dict[str, Any]) -> str:
        return "没有学到" if side.get("agreement") is None else f"{side['agreement']}‰"

    ordered, in_order = natural["ordered"], natural["natural"]
    rows = [["删除排在最后（快速顺序）", learned(ordered), agreement(ordered)],
            ["删除穿插在别人的搜索之间（自然顺序）", learned(in_order), agreement(in_order)]]
    lines = ["", "### 删除穿插在搜索之间（自然顺序，门槛）", "",
             f"公共搜索结果 `{natural['key']}` 在两种顺序下学到的档位和可靠性，以及它的一致程度"
             f"（自然顺序一侧必须学到 public、high）：", "",
             *_md_table(["顺序", "学到的档位与可靠性", "一致程度"], rows)]
    if in_order.get("tier") == "public" and in_order.get("reliability") == "high":
        lines.append("- 门槛通过：自然顺序下公共搜索结果学到 public、high。")
    else:
        found = "没有学到档位" if in_order.get("tier") is None else f"学到 {learned(in_order)}"
        lines.append(f"- 门槛未通过：自然顺序下公共搜索结果{found}，不是 public、high。")
    return lines


def _consistency_line(p6: dict[str, Any] | None) -> list[str]:
    """P6 (plan 3.3, full mode): the number of requests on which the two modes disagree. A gate of the full mode: 0."""
    if p6 is None or not p6["den"]:
        return []
    return [f"- P6 观察与拦截一致性：两个站点各自从全新的源站开始、跑同一批请求，比较的请求有 {p6['den']} 个；"
            f"观察模式的“本应拦截”与拦截模式的“已拦截”不一致的有 {p6['num']} 个（完整模式门槛，必须为 0）"]


def _two_pass_line(two_pass: dict[str, Any] | None) -> str | None:
    if two_pass is None:
        return None
    first, second = two_pass["seconds"]
    if two_pass["differing"]:
        return f"两遍核对：不同，不同的部分是 {'、'.join(two_pass['differing'])}（用时 {first:.0f} 秒和 {second:.0f} 秒）"
    return f"两遍核对：两遍的记分、门槛、失败项和学习明细逐位相同（用时 {first:.0f} 秒和 {second:.0f} 秒）"


def _eviction_line(timings: dict[str, Any] | None) -> list[str]:
    """The time the session-table case took (plan 10, batch 7): above 90 seconds it is raised with the coordinator."""
    eviction = (timings or {}).get("b11-session-eviction")
    if not eviction:
        return []
    return [f"- 会话表填满的用例（b11-session-eviction）：{eviction['logins']} 次登录，用时 "
            f"{eviction['seconds']:.1f} 秒（超过 90 秒需要另行提出）"]


def render_markdown(result: dict[str, Any], meta: dict[str, Any]) -> str:
    gates = result["gates"]
    passed = sum(gate["ok"] is True for gate in gates)
    failed = sum(gate["ok"] is False for gate in gates)
    unexecuted = sum(gate["ok"] is None for gate in gates)
    two_pass = _two_pass_line(meta.get("two_pass"))
    lines = ["# 防护有效性报告", "", f"## 1 {SECTION_TITLES[0]}", "", conclusion(result, meta), "",
             f"门槛共 {len(gates)} 项：通过 {passed}，失败 {failed}，未执行 {unexecuted}。",
             *([two_pass, ""] if two_pass else []),
             "", f"## 2 {SECTION_TITLES[1]}", ""]
    lines += _md_table(["指标", "本次", "基线", "变化", "门槛", "是否通过"],
                       [list(row) for row in score_rows(result)])
    lines += ["", *_baseline_lines(result["baseline"])]
    lines += ["", f"## 3 {SECTION_TITLES[2]}", ""] + _defence_lines(result, meta) + ["", *_label_lines(result["label_checks"])]
    lines += _consistency_line(result["metrics"].get("P6"))
    lines += _scan_block(result.get("confidence_scan"))
    lines += ["", f"## 4 {SECTION_TITLES[3]}", ""] + _learning_lines(result)
    lines += _convergence_lines(result.get("convergence")) + _pollution_lines(result.get("pollution"))
    lines += _natural_order_lines(result.get("natural_order"))

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
              f"已判定 {costs['judged_requests']} 条，每已判定请求 {_ratio(costs['calls_per_request'])} 次）",
              f"- 窗口内全部已判定记录 {costs['judged_requests']} 条（含探针，不含 bypass）："
              f"快速放行占比 {_pct(costs['fast_share'])}，每个已判定请求的 Jev 调用数 "
              f"{_ratio(costs['calls_per_judged_request'])}",
              f"- 判定耗时：中位数 {_count(costs['judge_ms_median'])} ms，p95 {_count(costs['judge_ms_p95'])} ms",
              f"- Jev 失败码：{failures}",
              *([_relay_line(meta["jev_relay"])] if meta.get("jev_relay") else []),
              *_eviction_line(meta.get("timings")),
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
        "learning_known": result.get("learning_known"),
        "label_checks": result["label_checks"],
        "costs": result["costs"],
        "counts": result["counts"],
        "needs": result["needs"],
        "confidence_scan": result.get("confidence_scan"),
        "convergence": result.get("convergence"),
        "pollution": result.get("pollution"),
        "natural_order": result.get("natural_order"),
        "passed": result["passed"],
    }
