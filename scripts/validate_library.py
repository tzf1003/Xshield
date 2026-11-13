#!/usr/bin/env python3
"""Validate v4 documentation, JSON Schemas and synthetic samples, not a running WAF."""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
# Repository-owned contracts only. Generated output and local tooling are not discovered.
DISCOVERY_EXCLUDED_PARTS = frozenset({'validation', 'target', '.codex', '.claude', 'node_modules', 'test-results'})
REPORT = ROOT / 'validation' / 'report.md'
SITE_SCHEMA = 'site-config'
DECISION_SCHEMA = 'decision-record'
EMR_SITE = 'examples/site-emr.yaml'
TEMPLATE_SITE = 'templates/site.yaml'
DEV_SITES = 'examples/sites-dev.json'
DECISION_LOG = 'examples/decision-log.jsonl'
# The outcomes each decision path can end in (docs/03 section 3.4 and
# crates/xshield-core/src/context/log.rs).
OUTCOMES_BY_PATH = {
    'bypass': {'allowed'},
    'fast_allow': {'allowed'},
    'cached_allow': {'allowed'},
    'jev_allow': {'allowed'},
    'body_not_inspectable': {'blocked'},
    'unknown_site': {'blocked'},
    'jev_deny': {'blocked', 'would_block'},
    'jev_unavailable': {'blocked', 'would_block', 'unjudged'},
    'no_session': {'blocked', 'would_block'},
}
def slot_site(**fields: object):
    """A mutation that gives the emr sample one object position carrying the given fields."""
    def mutate(site: dict) -> None:
        slot = {'key': 'GET /api/patients/{id} path[2]', 'class': 'patient', 'source': 'admin', **fields}
        site.update(objects={'classes': [{'id': 'patient', 'name': '患者'}], 'slots': [slot]})
    return mutate


def functions_site(**fields: object):
    """A mutation that gives the emr sample one function entry carrying the given fields."""
    def mutate(site: dict) -> None:
        entry = {'key': 'GET /api/patients/{id}', 'source': 'admin', **fields}
        site.update(objects={'functions': [entry]})
    return mutate


# Each mutation of the emr sample must be refused by the site configuration schema.
SITE_NEGATIVES = [
    ('unknown_key', lambda site: site.update(owner='admin')),
    ('two_credentials', lambda site: site.update(session={'cookie': 'SESSIONID', 'header': 'Authorization'})),
    ('no_credential', lambda site: site.update(session={})),
    ('unknown_mode', lambda site: site.update(mode='block')),
    ('unknown_on_jev_unavailable', lambda site: site.update(on_jev_unavailable='skip')),
    ('no_entries', lambda site: site.update(entries=[])),
    ('query_in_entry', lambda site: site.update(entries=['/login?next=/'])),
    ('relative_bypass', lambda site: site.update(bypass=['static/*'])),
    ('interior_wildcard', lambda site: site.update(entries=['/api/*/x'])),
    ('dot_segment', lambda site: site.update(entries=['/share/../api'])),
    ('uppercase_name', lambda site: site.update(name='EMR')),
    ('ftp_origin', lambda site: site.update(origin='ftp://10.0.0.5')),
    ('origin_with_path', lambda site: site.update(origin='http://10.0.0.5:8080/app')),
    ('jev_timeout_out_of_range', lambda site: site.update(advanced={'jev_timeout_ms': 50})),
    ('unknown_advanced_key', lambda site: site.update(advanced={'retry': 3})),
    ('too_many_hosts', lambda site: site.update(hosts=[f'h{i}.example.com' for i in range(17)])),
    ('tier_with_accepts_public', slot_site(tier='admin', accepts_public=False, reliability='high')),
    ('reliability_without_judgement', slot_site(reliability='high')),
    ('unknown_tier', slot_site(tier='everyone', reliability='high')),
    ('unknown_reliability', slot_site(tier='public', reliability='certain')),
    ('undeclared_identity', slot_site(identity='tenant')),
    ('paused_not_boolean', slot_site(tier='public', reliability='high', paused='yes')),
    ('accepts_public_not_boolean', slot_site(accepts_public='no', reliability='high')),
    ('function_tier_not_admin', functions_site(tier='self')),
    ('function_reliability_without_tier', functions_site(reliability='high')),
    ('function_unknown_reliability', functions_site(tier='admin', reliability='certain')),
    ('function_key_method_not_upper', functions_site(key='get /api/patients/{id}')),
    ('function_key_without_slash', functions_site(key='GET api/patients')),
    ('function_carries_paused', functions_site(paused=True)),
]

checks: list[dict[str, object]] = []


def check(name: str, ok: bool, detail: str = '') -> None:
    checks.append({'name': name, 'passed': bool(ok), 'detail': detail})


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def errors(schema: dict, instance: object) -> str:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return '; '.join(error.message for error in validator.iter_errors(instance))


def valid(schema: dict, instance: object) -> bool:
    return not errors(schema, instance)


def discovered(pattern: str):
    for path in sorted(ROOT.rglob(pattern)):
        if not DISCOVERY_EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts):
            yield path


def check_syntax() -> None:
    for path in discovered('*.json'):
        try:
            json.loads(path.read_text(encoding='utf-8'))
            check(f'json:{path.relative_to(ROOT)}', True)
        except (ValueError, OSError) as exc:
            check(f'json:{path.relative_to(ROOT)}', False, str(exc))
    for path in discovered('*.jsonl'):
        try:
            for line in path.read_text(encoding='utf-8').splitlines():
                if line.strip():
                    json.loads(line)
            check(f'jsonl:{path.relative_to(ROOT)}', True)
        except (ValueError, OSError) as exc:
            check(f'jsonl:{path.relative_to(ROOT)}', False, str(exc))
    for path in discovered('*.yaml'):
        # Helm templates are Go templates, not YAML; CI's helm job lints and renders them.
        if path.parent.name == 'templates' and (path.parent.parent / 'Chart.yaml').is_file():
            continue
        try:
            list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
            check(f'yaml:{path.relative_to(ROOT)}', True)
        except (yaml.YAMLError, OSError) as exc:
            check(f'yaml:{path.relative_to(ROOT)}', False, str(exc))


def check_schemas() -> dict[str, dict]:
    schemas: dict[str, dict] = {}
    for path in sorted((ROOT / 'schemas').glob('*.json')):
        name = path.name.removesuffix('.schema.json')
        schemas[name] = json.loads(path.read_text(encoding='utf-8'))
        try:
            Draft202012Validator.check_schema(schemas[name])
            check(f'schema:{name}', True)
        except Exception as exc:  # report every broken schema, not only the first
            check(f'schema:{name}', False, str(exc))
    return schemas


def check_sites(schema: dict) -> list[str]:
    emr = yaml.safe_load(read(EMR_SITE))
    check('site:example_emr', valid(schema, emr), errors(schema, emr))
    template = yaml.safe_load(read(TEMPLATE_SITE))
    check('site:template', valid(schema, template), errors(schema, template))
    minimal = {'name': 'emr', 'hosts': ['emr.example.com'], 'origin': 'http://10.0.0.5:8080',
               'session': {'cookie': 'SESSIONID'}, 'entries': ['/login']}
    check('site:minimal_accepted', valid(schema, minimal), errors(schema, minimal))
    judged = copy.deepcopy(emr)
    judged['objects'] = {
        'classes': [{'id': 'doctor', 'name': '医生'}, {'id': 'patient', 'name': '患者'}],
        'slots': [
            {'key': 'GET /doctor/{id} path[1]', 'class': 'doctor', 'source': 'admin', 'identity': 'user'},
            {'key': 'GET /api/patients/{id} path[2]', 'class': 'patient', 'source': 'rule',
             'tier': 'admin', 'reliability': 'high'},
            {'key': 'GET /api/search q', 'class': 'patient', 'source': 'agent',
             'tier': 'public', 'reliability': 'medium'},
            {'key': 'DELETE /api/patients/{id} path[2]', 'class': 'patient', 'source': 'admin',
             'accepts_public': False, 'reliability': 'high', 'paused': True},
        ],
    }
    check('site:judgements_accepted', valid(schema, judged), errors(schema, judged))
    functions = copy.deepcopy(emr)
    functions['objects'] = {'functions': [
        {'key': 'POST /api/admin/export', 'source': 'rule', 'tier': 'admin', 'reliability': 'high'},
        {'key': 'GET /api/search', 'source': 'agent'},
    ]}
    check('site:functions_accepted', valid(schema, functions), errors(schema, functions))
    for label, mutate in SITE_NEGATIVES:
        site = copy.deepcopy(emr)
        mutate(site)
        check(f'negative:site_{label}', not valid(schema, site))
    sites = json.loads(read(DEV_SITES))
    check('sites_dev:nonempty_array', isinstance(sites, list) and bool(sites))
    names = [site.get('name') for site in sites]
    for site in sites:
        check(f'sites_dev:{site.get("name")}', valid(schema, site), errors(schema, site))
    check('sites_dev:unique_names', len(set(names)) == len(names))
    return names


def path_outcome_ok(row: dict) -> bool:
    return row['outcome'] in OUTCOMES_BY_PATH.get(row['decision_path'], set())


def check_decision_log(schema: dict, site_names: list[str]) -> None:
    rows = [json.loads(line) for line in read(DECISION_LOG).splitlines() if line.strip()]
    check('decision_log:nonempty', bool(rows))
    ids = [row.get('request_id') for row in rows]
    check('decision_log:unique_request_ids', len(set(ids)) == len(ids))
    for number, row in enumerate(rows, 1):
        name = f'decision_log:row{number}'
        check(f'{name}:schema', valid(schema, row), errors(schema, row))
        check(f'{name}:outcome_for_path', path_outcome_ok(row))
        check(f'{name}:site_known', row['site'] is None or row['site'] in site_names)
        jev = row['jev']
        check(f'{name}:deny_iff_jev_deny',
              (row['decision_path'] == 'jev_deny') == bool(jev and jev['conclusion'] == 'deny'))
        if jev is None:
            continue
        if jev['state'] is not None:
            state = json.loads(jev['state'])
            check(f'{name}:jev_state_shape', set(state) == {'entry', 'session', 'recent', 'request'}
                  and isinstance(state['request']['values'], list))
        for question in ('access', 'attack'):
            if jev[question]:
                total = sum(jev[question].values())
                check(f'{name}:jev_{question}_sums_to_one', abs(total - 1) < 1e-6, str(total))
    # Negative samples: a row that contradicts its decision path, or lacks a required field.
    judged = next(row for row in rows if row['decision_path'] == 'jev_deny' and row['outcome'] == 'would_block')
    forged = copy.deepcopy(judged)
    forged['outcome'] = 'allowed'
    check('negative:jev_deny_allowed_rejected', not path_outcome_ok(forged))
    no_trace = copy.deepcopy(judged)
    del no_trace['trace']
    check('negative:row_without_trace_rejected', not valid(schema, no_trace))
    bad_id = copy.deepcopy(judged)
    bad_id['request_id'] = 'req_short'
    check('negative:bad_request_id_rejected', not valid(schema, bad_id))
    # A tiered record: its position's public access and attempt, and its source's tier.
    tiered = copy.deepcopy(judged)
    tiered_value = tiered['trace']['values'][0]
    tiered_value['public_access'] = {'accepts': False, 'reliability': 'high'}
    tiered_value['attempt'] = 'over_privilege'
    tiered_value['sources'] = [{'field': 'results[].id', 'request': 'GET /api/search', 'request_id': None,
                                'at_millis': 1, 'tier': 'public', 'reliability': 'high'}]
    check('tiered:record_schema', valid(schema, tiered), errors(schema, tiered))
    unknown_tier = copy.deepcopy(tiered)
    unknown_tier['trace']['values'][0]['sources'][0]['tier'] = 'owner'
    check('negative:unknown_tier_rejected', not valid(schema, unknown_tier))


def check_docs() -> None:
    for path in sorted(ROOT.glob('docs/*.md')):
        text = path.read_text(encoding='utf-8')
        check(f'fences:{path.name}', len(re.findall(r'^```', text, re.M)) % 2 == 0)
        check(f'no_tool_tokens:{path.name}', '' not in text)
    for path in sorted(ROOT.rglob('*.md')):
        if DISCOVERY_EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts):
            continue
        for target in re.findall(r'\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith(('#', 'mailto:')):
                continue
            target = target.split('#')[0]
            if target:
                resolved = (path.parent / target).resolve()
                generated_report = resolved == REPORT.resolve()
                check(f'link:{path.relative_to(ROOT)}:{target}', resolved.exists() or generated_report,
                      'generated by this validator' if generated_report else '')


def main() -> int:
    check_syntax()
    schemas = check_schemas()
    site_names = check_sites(schemas[SITE_SCHEMA])
    check_decision_log(schemas[DECISION_SCHEMA], site_names)
    check_docs()
    failed = [c for c in checks if not c['passed']]
    passed = not failed
    result = {
        'scope': 'Document syntax, JSON Schema and synthetic sample checks only. Not Rust behaviour '
                 '(cargo test runs crates/xshield-core/tests/v4_samples.rs over the same samples), '
                 'not WAF effectiveness and not model accuracy.',
        'passed': passed,
        'checks_total': len(checks),
        'passed_count': sum(1 for c in checks if c['passed']),
        'checks': checks,
    }
    out = ROOT / 'validation'
    out.mkdir(exist_ok=True)
    (out / 'report.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    report = (
        '# 文档和合成样例验证\n\n'
        f'结果：{"通过" if passed else "存在失败"}；{result["passed_count"]}/{len(checks)} 项检查通过。\n\n'
        '覆盖：JSON、JSONL 和 YAML 语法；JSON Schema 本身；站点配置样例、模板和负例；'
        '判定日志样例的字段、路径与结论的对应关系、Jev 状态结构和概率；文档围栏与本地链接。\n\n'
        '不覆盖：Rust 行为（`cargo test` 中的 `crates/xshield-core/tests/v4_samples.rs` 用同一批样例运行'
        '站点配置和判定记录的解析）、真实判定效果、模型准确率和性能。\n'
    )
    if failed:
        report += '\n失败：\n' + '\n'.join('- ' + str(c) for c in failed) + '\n'
    REPORT.write_text(report, encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'checks'}, ensure_ascii=False, indent=2))
    for c in failed:
        print('FAIL', c)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
