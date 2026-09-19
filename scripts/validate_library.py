#!/usr/bin/env python3
"""Validate documentation contracts and synthetic fixtures, not a running WAF."""
from __future__ import annotations
import copy, hashlib, json, re, sys
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker
ROOT = Path(__file__).resolve().parents[1]
checks: list[dict[str, object]] = []
def check(name: str, ok: bool, detail: str = '') -> None:
    checks.append({'name': name, 'passed': bool(ok), 'detail': detail})
def load(path: str):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))
def valid(schema: dict, instance: object) -> bool:
    return not list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(instance))

def check_model_evaluation_contracts(schemas: dict, model_stage: dict, choice: dict) -> None:
    """Exercise the implemented offline lifecycle and provider capture record."""
    model_event = copy.deepcopy(model_stage)
    model_event['event_type'] = 'model.responded'
    model_event['payload'] = {
        'model_call_id': choice['model_call_id'], 'model_revision': 'jev-1.13.0',
        'prompt_revision': 'evaluation-r1', 'question_type': 'choice', 'status': 'success',
        'reason_code': 'MODEL_EVALUATED', 'confidence': 0.6, 'confidence_status': 'provided',
        'duration_us': 1200,
        'input_artifact_id': choice['input_artifact_id'].replace('art_', 'artifact_'),
        'output_artifact_id': choice['output_artifact_id'].replace('art_', 'artifact_'),
        'call_artifact_id': 'artifact_01a0afa6-3320-7001-8000-000000000001',
    }
    for event_type, status in [
        ('model.started', 'started'), ('model.requested', 'requested'),
        ('model.responded', 'success'), ('model.failed', 'error'),
        ('model.timeout', 'timeout'), ('model.cancelled', 'cancelled'),
    ]:
        event = copy.deepcopy(model_event)
        event['event_type'] = event_type
        event['payload']['status'] = status
        if status != 'success':
            event['payload'].update(confidence=None, confidence_status='unavailable',
                                    output_artifact_id=None, call_artifact_id=None)
            if status != 'requested': event['payload']['input_artifact_id'] = None
        check('model_lifecycle:' + status, valid(schemas['audit-event'], event))
        event['payload']['status'] = 'requested' if status == 'started' else 'started'
        check('model_lifecycle:status_mismatch_' + status, not valid(schemas['audit-event'], event))
    for label, fields, expected in [
        ('confidence_absent', {'confidence': None, 'confidence_status': 'not_provided'}, True),
        ('noul', {'question_type': 'noul', 'confidence': None, 'confidence_status': 'not_applicable'}, True),
        ('wrong_call_prefix', {'model_call_id': choice['model_call_id'].replace('mdl_', 'model_')}, False),
        ('unsupported_primitive', {'question_type': 'score'}, False),
        ('empty_revision', {'model_revision': ''}, False),
        ('oversized_revision', {'model_revision': 'r' * 129}, False),
        ('newline_revision', {'model_revision': 'jev-1.13.0\n'}, False),
        ('invalid_prompt_revision', {'prompt_revision': 'prompt/revision'}, False),
        ('invalid_reason', {'reason_code': 'invalid reason'}, False),
        ('provided_null', {'confidence': None}, False),
        ('out_of_range_confidence', {'confidence': 1.1}, False),
        ('absent_confidence_with_value', {'confidence_status': 'not_provided'}, False),
        ('noul_confidence', {'question_type': 'noul'}, False),
        ('noul_status', {'question_type': 'noul', 'confidence': None, 'confidence_status': 'not_provided'}, False),
        ('null_input', {'input_artifact_id': None}, False),
        ('null_output', {'output_artifact_id': None}, False),
        ('null_call', {'call_artifact_id': None}, False),
        ('wrong_artifact_prefix', {'input_artifact_id': choice['input_artifact_id']}, False),
        ('unknown_field', {'provider_body': 'synthetic'}, False),
    ]:
        event = copy.deepcopy(model_event)
        event['payload'].update(fields)
        check('model_lifecycle:' + label, valid(schemas['audit-event'], event) == expected)
    for field in ['confidence', 'input_artifact_id', 'output_artifact_id', 'call_artifact_id']:
        event = copy.deepcopy(model_event)
        del event['payload'][field]
        check('model_lifecycle:missing_' + field, not valid(schemas['audit-event'], event))
    for field in ['tenant_id', 'site_id', 'policy_revision', 'producer_id']:
        event = copy.deepcopy(model_event)
        event[field] = 'invalid scope'
        check('model_lifecycle:invalid_' + field, not valid(schemas['audit-event'], event))
    event = copy.deepcopy(model_event)
    event['event_type'] = 'model.requested'
    event['payload'].update(status='requested', confidence=None, confidence_status='unavailable', input_artifact_id=None)
    check('model_lifecycle:requested_requires_input', not valid(schemas['audit-event'], event))
    event = copy.deepcopy(model_event)
    event['event_type'] = 'model.started'
    event['payload']['status'] = 'started'
    check('model_lifecycle:started_confidence_rejected', not valid(schemas['audit-event'], event))
    event = copy.deepcopy(model_event)
    event['request_id'] = None
    check('model_lifecycle:request_required', not valid(schemas['audit-event'], event))

    record = copy.deepcopy(choice)
    record.update(provider='typesafe', model_revision='jev-1.13.0', prompt_revision='evaluation-r1',
                  resolved_model_revision='jev-1.13.0', reason_code='MODEL_EVALUATED', http_status=200,
                  capture_status='complete', retry_after_seconds=None, provider_request_id=None,
                  schema_validation='valid', provider_internal='unavailable')
    check('model_capture:success', valid(schemas['model-call'], record))
    for status in ['error', 'timeout', 'cancelled']:
        failure = copy.deepcopy(record)
        failure.update(status=status, output_artifact_id=None, result=None, probabilities={},
                       provider_confidence=None, confidence_status='unavailable',
                       resolved_model_revision=None, reason_code='MODEL_TRANSPORT_ERROR',
                       http_status=None, capture_status='unavailable', schema_validation='unavailable')
        check('model_capture:unavailable_' + status, valid(schemas['model-call'], failure))
    for capture in ['complete', 'partial_limit', 'partial_timeout', 'partial_transport', 'excluded_policy']:
        failure = copy.deepcopy(record)
        failure.update(status='error', provider_confidence=None, confidence_status='unavailable',
                       capture_status=capture, reason_code='MODEL_RESPONSE_INVALID', schema_validation='invalid')
        check('model_capture:error_' + capture, valid(schemas['model-call'], failure))
    for label, fields in [
        ('success_requires_output', {'output_artifact_id': None}),
        ('success_requires_complete', {'capture_status': 'partial_timeout'}),
        ('success_capture_unavailable', {'capture_status': 'unavailable'}),
        ('invalid_resolved_revision', {'resolved_model_revision': 'model/version'}),
        ('newline_resolved_revision', {'resolved_model_revision': 'jev-1.13.0\n'}),
        ('invalid_reason', {'reason_code': 'invalid reason'}),
        ('invalid_http_status', {'http_status': 99}),
        ('oversized_http_status', {'http_status': 1000}),
        ('negative_retry', {'retry_after_seconds': -1}),
        ('oversized_retry', {'retry_after_seconds': 86401}),
        ('invalid_request_id', {'provider_request_id': 'https://example.invalid'}),
        ('invalid_capture_status', {'capture_status': 'unknown'}),
        ('invalid_validation_status', {'schema_validation': 'unknown'}),
        ('invalid_provider_internal', {'provider_internal': 'complete'}),
        ('unknown_usage_field', {'usage': dict(record['usage'], extra=1)}),
        ('unknown_field', {'provider_body': 'synthetic'}),
    ]:
        invalid = copy.deepcopy(record)
        invalid.update(fields)
        check('model_capture:' + label, not valid(schemas['model-call'], invalid))

def main() -> int:
    for p in sorted(ROOT.rglob('*.json')):
        if 'validation' in p.parts or 'target' in p.parts: continue
        try: json.loads(p.read_text(encoding='utf-8'));check(f'json:{p.relative_to(ROOT)}',True)
        except (ValueError,OSError) as exc: check(f'json:{p.name}',False,str(exc))
    for p in sorted(ROOT.rglob('*.yaml')):
        if 'validation' in p.parts or 'target' in p.parts: continue
        try: yaml.safe_load(p.read_text(encoding='utf-8'));check(f'yaml:{p.relative_to(ROOT)}',True)
        except yaml.YAMLError as exc: check(f'yaml:{p.name}',False,str(exc))
    schemas = {p.stem.replace('.schema',''):json.loads(p.read_text()) for p in (ROOT/'schemas').glob('*.json')}
    for name,s in schemas.items():
        try: Draft202012Validator.check_schema(s);check(f'schema:{name}',True)
        except Exception as exc:check(f'schema:{name}',False,str(exc))
    policy=yaml.safe_load((ROOT/'examples/site-policy.yaml').read_text())
    check('policy:positive',valid(schemas['site-policy'],policy))
    negative=copy.deepcopy(policy);negative['crypto']['client_can_select_fallback']=True
    check('negative:client_selected_fallback_rejected',not valid(schemas['site-policy'],negative))
    negative=copy.deepcopy(policy);negative['identity']['ordinary_replacement']='auto_rebind'
    check('negative:ordinary_replacement_rejected',not valid(schemas['site-policy'],negative))
    events=[json.loads(x) for x in (ROOT/'examples/request-timeline.jsonl').read_text().splitlines() if x]
    ev_ids={e['event_id'] for e in events}
    check('events:unique_ids',len(ev_ids)==len(events))
    check('events:producer_sequence', [e['producer_seq'] for e in events]==list(range(1,len(events)+1)))
    manifests={}
    for p in sorted((ROOT/'examples/manifests').glob('*.json')):
        m=json.loads(p.read_text());check(f'manifest_schema:{p.name}',valid(schemas['artifact-manifest'],m));manifests[m['artifact_id']]=m
        f=ROOT/m['storage']['locator'];check(f'artifact_exists:{p.name}',f.is_file())
        if f.is_file():
            body=f.read_bytes();check(f'artifact_digest:{p.name}',hashlib.sha256(body).hexdigest()==m['integrity']['digest'])
            check(f'artifact_length:{p.name}',len(body)==m['bytes_saved'])
    for mid,m in manifests.items():check('artifact_parent_refs:'+m['kind'],all(x in manifests for x in m['parent_refs']))
    for e in events:
        check('event_schema:'+e['event_id'],valid(schemas['audit-event'],e))
        check('event_references:'+e['event_id'],all(x in manifests for x in e['evidence_refs']) and all(x in ev_ids for x in e['cause_event_ids']))
    calls=[]
    for p in sorted((ROOT/'examples').glob('model-call-*.json')):
        c=json.loads(p.read_text());calls.append(c);check('model_schema:'+p.name,valid(schemas['model-call'],c))
        check('model_evidence:'+p.name,c['input_artifact_id'] in manifests and c['output_artifact_id'] in manifests)
        if c['probabilities']:check('model_probability_sum:'+p.name,abs(sum(c['probabilities'].values())-1)<1e-8)
    det=copy.deepcopy(next(e for e in events if e['event_type']=='stage.completed' and e['payload']['proof_kind']=='deterministic'))
    det['payload']['confidence']=1.0;check('negative:deterministic_fake_confidence_rejected',not valid(schemas['audit-event'],det))
    n=copy.deepcopy(next(c for c in calls if c['question_type']=='noul'));n['provider_confidence']=.99
    check('negative:noul_fake_confidence_rejected',not valid(schemas['model-call'],n))
    model_stage=next(e for e in events if e['event_type']=='stage.completed' and e['payload']['proof_kind']=='model')
    for label, fields, expected in [
        ('resolved_revision', {'model_revision':'jev-1.13.0'}, True),
        ('unavailable_revision', {'model_revision':None}, True),
        ('missing_confidence', {'confidence':None, 'confidence_status':'not_provided'}, True),
        ('noul_confidence', {'confidence':None, 'confidence_status':'not_applicable'}, True),
        ('timeout', {'outcome':'ERROR', 'confidence':None, 'confidence_status':'unavailable'}, True),
        ('wrong_call_prefix', {'model_call_id':model_stage['payload']['model_call_id'].replace('mdl_', 'model_')}, False),
        ('null_model_call', {'model_call_id':None}, False),
        ('non_model_call', {'proof_kind':'none'}, False),
        ('provided_null', {'confidence':None}, False),
        ('unavailable_value', {'confidence_status':'unavailable'}, False),
        ('not_provided_value', {'confidence_status':'not_provided'}, False),
        ('cancelled_value', {'outcome':'CANCELLED'}, False),
        ('skipped_value', {'outcome':'SKIPPED'}, False),
        ('empty_revision', {'model_revision':''}, False),
        ('oversized_revision', {'model_revision':'r'*129}, False),
        ('invalid_revision', {'model_revision':'invalid revision'}, False),
        ('non_model_revision', {'proof_kind':'none', 'model_call_id':None, 'model_revision':'model-r1'}, False),
    ]:
        event=copy.deepcopy(model_stage);event['payload'].update(fields)
        check('model_stage:'+label,valid(schemas['audit-event'],event)==expected)
    missing_call=copy.deepcopy(model_stage);del missing_call['payload']['model_call_id']
    check('model_stage:missing_model_call',not valid(schemas['audit-event'],missing_call))
    missing_confidence=copy.deepcopy(model_stage);del missing_confidence['payload']['confidence']
    missing_confidence['payload']['confidence_status']='not_provided'
    check('model_stage:missing_confidence',not valid(schemas['audit-event'],missing_confidence))
    choice=next(c for c in calls if c['question_type']=='choice')
    for label, fields in [
        ('wrong_call_prefix', {'model_call_id':choice['model_call_id'].replace('mdl_', 'model_')}),
        ('provided_null', {'provider_confidence':None}),
        ('not_provided_value', {'confidence_status':'not_provided'}),
    ]:
        call=copy.deepcopy(choice);call.update(fields)
        check('model_call:'+label,not valid(schemas['model-call'],call))
    check_model_evaluation_contracts(schemas, model_stage, choice)
    idx=load('examples/request-index.json');check('request_index:events',set(idx['event_ids'])==ev_ids)
    check('request_index:artifacts',set(idx['artifact_ids'])==set(manifests))
    check('fixture:all_synthetic',all(e['example_only'] for e in events) and all(c['example_only'] for c in calls))
    reqs=set(re.findall(r'RQ-\d{2}',(ROOT/'docs/00-product-requirements.md').read_text()))
    mapping=(ROOT/'docs/28-conversation-decisions-and-traceability.md').read_text()
    check('requirements:20_ids',len(reqs)==20)
    check('requirements:traceability',all(x in mapping for x in reqs))
    invs=set(re.findall(r'INV-\d{2}',(ROOT/'docs/01-threat-model-and-invariants.md').read_text()))
    check('invariants:20_ids',len(invs)==20)
    tests=load('examples/acceptance-cases.json');check('acceptance:count',tests['total']==len(tests['cases']))
    check('acceptance:not_falsely_executed',all(c['status']=='planned' for c in tests['cases']))
    check('acceptance:unique_ids',len({c['id'] for c in tests['cases']})==len(tests['cases']))
    clickhouse=(ROOT/'sql/clickhouse.sql').read_text()
    check('clickhouse:active_views_deduplicate',clickhouse.count('LIMIT 1 BY event_id')==2)
    check('clickhouse:active_views_filter_expiry',clickhouse.count('WHERE retention_expires_at > now64(6)')==2)
    reg=(ROOT/'docs/25-source-register.md').read_text();known=set(re.findall(r'S\d{2}',reg))
    for p in sorted(ROOT.glob('docs/*.md')):
        text=p.read_text();used=set(re.findall(r'\[(S\d{2})\]',text));check('sources:'+p.name,used<=known)
        check('fences:'+p.name,len(re.findall(r'^```',text,re.M))%2==0)
        check('no_tool_tokens:'+p.name,'' not in text)
    for p in sorted(ROOT.rglob('*.md')):
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text()):
            if '://' in target or target.startswith(('#','mailto:')):continue
            target=target.split('#')[0]
            if target:
                resolved=(p.parent/target).resolve()
                generated_report=resolved==(ROOT/'validation/report.md').resolve()
                check('link:'+str(p.relative_to(ROOT))+':'+target,resolved.exists() or generated_report,'generated by this validator' if generated_report else '')
    result={'scope':'Document syntax, schema and synthetic fixture checks only. Not Rust compilation, SQL integration, WAF security evaluation or model benchmark.', 'passed':all(c['passed'] for c in checks),'checks_total':len(checks),'passed_count':sum(c['passed'] for c in checks),'planned_security_test_cases':tests['total'],'checks':checks}
    out=ROOT/'validation';out.mkdir(exist_ok=True)
    (out/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    failed=[c for c in checks if not c['passed']]
    report=f'# 文档和合成样例验证\n\n结果：{"通过" if result["passed"] else "存在失败"}；{result["passed_count"]}/{len(checks)} 项检查通过。\n\n覆盖：JSON/YAML、JSON Schema、合成事件/证据/模型契约、摘要及引用闭合、负向约束、文档来源和本地链接。\n\n不覆盖：Rust 编译、PostgreSQL/ClickHouse 实际执行、代理部署、站点安全测试、模型准确率和性能。78 项安全验收用例仍为 planned。\n'
    if failed: report+='\n失败：\n'+ '\n'.join('- '+str(c) for c in failed)+'\n'
    (out/'report.md').write_text(report,encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='checks'},ensure_ascii=False,indent=2))
    for c in failed:print('FAIL',c)
    return 0 if result['passed'] else 1
if __name__=='__main__':sys.exit(main())
