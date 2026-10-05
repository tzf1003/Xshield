#!/usr/bin/env python3
"""Validate documentation contracts and synthetic fixtures, not a running WAF."""
from __future__ import annotations
import copy, hashlib, json, re, sys
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker
ROOT = Path(__file__).resolve().parents[1]
# Repository-owned contracts only. Local automation and package installations
# may carry valid JSON/YAML with unrelated external links and schemas.
DISCOVERY_EXCLUDED_PARTS = frozenset({'validation', 'target', '.codex', '.claude', 'node_modules', 'test-results'})
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
        for field in ['input_artifact_id', 'output_artifact_id', 'call_artifact_id']:
            missing = copy.deepcopy(event)
            del missing['payload'][field]
            check(f'model_lifecycle:{status}_missing_{field}', not valid(schemas['audit-event'], missing))
        event['payload']['status'] = 'requested' if status == 'started' else 'started'
        check('model_lifecycle:status_mismatch_' + status, not valid(schemas['audit-event'], event))
    for label, fields, expected in [
        ('confidence_absent', {'confidence': None, 'confidence_status': 'not_provided'}, True),
        ('noul', {'question_type': 'noul', 'confidence': None, 'confidence_status': 'not_applicable'}, True),
        ('wrong_call_prefix', {'model_call_id': choice['model_call_id'].replace('mdl_', 'model_')}, False),
        ('score', {'question_type': 'score'}, True),
        ('unsupported_primitive', {'question_type': 'unknown'}, False),
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
    score = copy.deepcopy(record)
    score.update(question_type='score', result=0.7,
                 legend={'0': 'Low', '1': 'Medium', '2': 'High'},
                 probabilities={'0': 0.6, '1': 0.1, '2': 0.3})
    check('model_capture:score', valid(schemas['model-call'], score))
    projected = copy.deepcopy(score)
    projected['risk_projection'] = {
        'mapping_revision': 'risk-map-r1', 'benign_probability': 0.6,
        'unknown_probability': 0.1, 'malicious_probability': 0.3,
        'abstained': True, 'reason_code': 'MODEL_RISK_ABSTAINED'}
    check('model_capture:risk_projection', valid(schemas['model-call'], projected))
    for field, value in [('abstained', False), ('unknown_probability', 0),
                         ('malicious_probability', 1.1), ('mapping_revision', 'bad/revision'),
                         ('reason_code', 'MODEL_RISK_PROJECTED')]:
        invalid = copy.deepcopy(projected)
        invalid['risk_projection'][field] = value
        check('model_capture:risk_projection_' + field, not valid(schemas['model-call'], invalid))
    for label, fields in [
        ('result_type', {'result': '0.7'}),
        ('result_range', {'result': 10}),
        ('result_null', {'result': None}),
        ('legend_null', {'legend': None}),
        ('legend_missing_level', {'legend': {'0': 'Low'}}),
        ('legend_noncanonical', {'legend': {'0': 'Low', '01': 'High'}}),
        ('distribution_empty', {'probabilities': {}}),
        ('distribution_key', {'probabilities': {'0': 0.6, '01': 0.4}}),
    ]:
        invalid = copy.deepcopy(score)
        invalid.update(fields)
        check('model_capture:score_' + label, not valid(schemas['model-call'], invalid))
    missing_legend = copy.deepcopy(score)
    del missing_legend['legend']
    check('model_capture:score_missing_legend', not valid(schemas['model-call'], missing_legend))
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

def check_outbox_contracts(schemas: dict) -> None:
    """Exercise the implemented catalog, retention, hold and identity outbox shapes."""
    artifact = 'artifact_018f2a3b-4c5d-7000-8000-000000000005'
    base = {
        'schema_version': 3, 'event_id': 'ev_018f2a3b-4c5d-7000-8000-000000000001',
        'event_type': 'evidence.cataloged', 'tenant_id': 'tenant_demo', 'site_id': 'site_demo',
        'request_id': 'req_018f2a3b-4c5d-7000-8000-000000000003',
        'trace_id': '018f2a3b4c5d70008000000000000003', 'span_id': '018f2a3b4c5d7000',
        'producer_id': 'gateway-evidence-catalog',
        'producer_boot_id': '018f2a3b-4c5d-7000-8000-000000000006',
        'producer_seq': 1, 'request_seq': 2,
        'occurred_at': '2026-09-19T00:00:00.123Z', 'observed_at': '2026-09-19T00:00:00.123Z',
        'policy_revision': 'policy-r1', 'example_only': False,
        'evidence_refs': [artifact],
        'cause_event_ids': ['ev_018f2a3b-4c5d-7000-8000-000000000007'],
        'payload': {'stage': 'evidence_catalog', 'outcome': 'PASS',
                    'reason_code': 'EVIDENCE_CATALOG_PUBLISHED', 'artifact_id': artifact},
        'sensitivity': 'RESTRICTED',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
    }
    for producer in ['gateway-evidence-catalog', 'model-eval']:
        event = copy.deepcopy(base)
        event['producer_id'] = producer
        check('outbox:evidence_catalog:' + producer, valid(schemas['audit-event'], event))
    for label, fields in [
        ('wrong_producer', {'producer_id': 'xshield-control'}),
        ('wrong_sensitivity', {'sensitivity': 'INTERNAL'}),
        ('wrong_boot', {'producer_boot_id': 'req_018f2a3b-4c5d-7000-8000-000000000002'}),
        ('wrong_producer_seq', {'producer_seq': 2}),
        ('missing_cause', {'cause_event_ids': []}),
        ('unknown_payload', {'payload': dict(base['payload'], extra=True)}),
    ]:
        event = copy.deepcopy(base)
        event.update(fields)
        check('outbox:evidence_catalog_reject_' + label,
              not valid(schemas['audit-event'], event))
    check_retention_outbox_contracts(schemas['audit-event'], base)
    check_hold_outbox_contracts(schemas['audit-event'], base)
    check_identity_outbox_contracts(schemas['audit-event'], base)
    check_control_hold_access_contracts(schemas['audit-event'], base)
    check_control_case_list_contracts(schemas['audit-event'], base)
    check_control_access_list_contracts(schemas['audit-event'], base)
    check_control_access_detail_contracts(schemas['audit-event'], base)

def check_control_access_list_contracts(schema: dict, base: dict) -> None:
    """Request discovery journals contain scoped access facts and exact failure reasons."""
    event = copy.deepcopy(base)
    event.update(event_type='console.evidence.access.list', producer_id='xshield-control',
                 request_seq=1, policy_revision='control-v1', sensitivity='INTERNAL',
                 cause_event_ids=[], evidence_refs=[])
    event['payload'] = {'method': 'GET', 'path': '/control/v1/evidence-access-requests',
                        'subject_ref': 'audit-operator', 'outcome': 'PASS',
                        'reason_code': 'CONTROL_EVIDENCE_ACCESS_LIST_READ'}
    prefix = 'control_access_list:'
    check(prefix + 'success', valid(schema, event))
    for field in event['payload']:
        missing = copy.deepcopy(event)
        del missing['payload'][field]
        check(prefix + 'missing_' + field, not valid(schema, missing))
        missing['payload'][field] = None
        check(prefix + 'null_' + field, not valid(schema, missing))
    for index, (field, value) in enumerate([
        ('method', 'POST'), ('path', '/control/v1/evidence-access-requests?view=mine'),
        ('path', '/control/v1/evidence-access-requests/{access_request_id}'),
        ('subject_ref', ''), ('subject_ref', 'actor\nname'), ('subject_ref', 'a' * 257),
        ('outcome', 'UNKNOWN'), ('reason_code', 'CONTROL_EVIDENCE_ACCESS_READ'),
        ('reason_code', 'CONTROL_EVIDENCE_ACCESS_LIST_READ\n'), ('reason_code', 'A' * 129),
        ('view', 'mine'), ('cursor', 'opaque'), ('rows', []), ('items', []),
        ('justification', 'synthetic'), ('decision_reason', 'synthetic'),
        ('requested_by', 'other-actor'), ('decided_by', 'other-actor'), ('confidence', None),
    ]):
        invalid = copy.deepcopy(event)
        invalid['payload'][field] = value
        check(f'{prefix}invalid_payload_{index}_{field}', not valid(schema, invalid))
    forbidden = ['target_request_id', 'target_artifact_id', 'target_case_id',
                 'target_access_request_id', 'target_model_call_id', 'target_grant_id',
                 'target_binding_id', 'target_hold_id', 'query_digest', 'bytes_read']
    for field in forbidden:
        optional = copy.deepcopy(event)
        optional['payload'][field] = None
        check(prefix + 'null_' + field, valid(schema, optional))
        optional['payload'][field] = 0 if field == 'bytes_read' else base['event_id']
        check(prefix + 'reject_' + field, not valid(schema, optional))
    for index, (field, value) in enumerate([
        ('producer_id', 'evidence-access'), ('producer_boot_id', base['event_id']),
        ('request_seq', 2), ('policy_revision', 'evidence-access-v1'),
        ('sensitivity', 'RESTRICTED'), ('request_id', None), ('request_id', base['event_id']),
        ('tenant_id', 'tenant\n'), ('site_id', 'site\n'),
        ('event_id', base['request_id']), ('example_only', True), ('schema_version', 2),
        ('evidence_refs', base['evidence_refs']), ('cause_event_ids', [base['event_id']]),
        ('connection_id', None), ('agent_run_id', None), ('unknown', None),
    ]):
        invalid = copy.deepcopy(event)
        invalid[field] = value
        check(f'{prefix}invalid_envelope_{index}_{field}', not valid(schema, invalid))
    for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
        invalid = copy.deepcopy(event)
        invalid['integrity'][field] = value
        check(prefix + 'integrity_' + field, not valid(schema, invalid))
    for outcome, reason in [
        ('DENY', 'CONTROL_AUTH_REQUIRED'), ('DENY', 'CONTROL_SCOPE_DENIED'),
        ('DENY', 'CONTROL_RATE_LIMITED'), ('DENY', 'CONTROL_CURSOR_INVALID'),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID'),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_BUSY'),
        ('ERROR', 'CONTROL_CURSOR_UNAVAILABLE'),
        ('ERROR', 'CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE'),
        ('ERROR', 'CONTROL_RATE_UNAVAILABLE'), ('ERROR', 'CONTROL_CLOCK_UNAVAILABLE'),
    ]:
        failure = copy.deepcopy(event)
        failure['payload'].update(outcome=outcome, reason_code=reason)
        for subject in ['audit-operator', None]:
            failure['payload']['subject_ref'] = subject
            check(prefix + reason + '_subject_' + str(subject), valid(schema, failure))
        del failure['payload']['subject_ref']
        check(prefix + reason + '_subject_absent', valid(schema, failure))
        for other in ['PASS', 'ERROR' if outcome == 'DENY' else 'DENY']:
            invalid = copy.deepcopy(failure)
            invalid['payload'].update(outcome=other, subject_ref='audit-operator')
            check(prefix + reason + '_outcome_' + other, not valid(schema, invalid))
        for invalid_reason in ['CONTROL_EVIDENCE_ACCESS_LIST_READ', 'CONTROL_UNKNOWN', 'CONTROL_AUDIT_UNAVAILABLE']:
            invalid = copy.deepcopy(failure)
            invalid['payload']['reason_code'] = invalid_reason
            check(prefix + reason + '_reason_' + invalid_reason, not valid(schema, invalid))
        for field in forbidden:
            invalid = copy.deepcopy(failure)
            invalid['payload'][field] = 0 if field == 'bytes_read' else base['event_id']
            check(prefix + reason + '_target_' + field, not valid(schema, invalid))
        failure['evidence_refs'] = base['evidence_refs']
        check(prefix + reason + '_evidence', not valid(schema, failure))
    crossed = copy.deepcopy(event)
    crossed['payload'] = {'stage': 'evidence_access', 'outcome': 'PASS',
                           'reason_code': 'EVIDENCE_ACCESS_APPROVED', 'access_request_id': 'synthetic'}
    check(prefix + 'transaction_payload', not valid(schema, crossed))
    # Duplicate JSON keys, journal sequence identity and UTF-8 byte caps are checked by Rust.
    unicode_subject = copy.deepcopy(event)
    unicode_subject['payload']['subject_ref'] = '\u754c' * 86
    check(prefix + 'rust_only_utf8', valid(schema, unicode_subject))

def check_control_access_detail_contracts(schema: dict, base: dict) -> None:
    """Validate scoped approval-detail observations and their failure shapes."""
    event = copy.deepcopy(base)
    event.update(event_type='console.evidence.access.read', producer_id='xshield-control',
                 request_seq=1, policy_revision='control-v1', sensitivity='INTERNAL', cause_event_ids=[])
    access = 'access_018f2a3b-4c5d-7000-8000-000000000007'
    event['payload'] = {
        'method': 'GET', 'path': '/control/v1/evidence-access-requests/{access_request_id}',
        'subject_ref': 'audit-operator', 'outcome': 'PASS', 'reason_code': 'CONTROL_EVIDENCE_ACCESS_READ',
        'target_access_request_id': access, 'target_case_id': 'case_018f2a3b-4c5d-7000-8000-000000000004',
        'target_artifact_id': base['evidence_refs'][0],
    }
    prefix = 'control_access_detail:'
    check(prefix + 'success', valid(schema, event))
    for field in event['payload']:
        missing = copy.deepcopy(event)
        del missing['payload'][field]
        check(prefix + 'missing_' + field, not valid(schema, missing))
        missing['payload'][field] = None
        check(prefix + 'null_' + field, not valid(schema, missing))
    for field in ['target_access_request_id', 'target_case_id', 'target_artifact_id']:
        target = event['payload'][field]
        for index, value in enumerate([base['event_id'], target.upper(),
                                       target.replace('-7000-', '-4000-'), target + '\n', 'invalid']):
            invalid = copy.deepcopy(event)
            invalid['payload'][field] = value
            check(f'{prefix}invalid_target_{field}_{index}', not valid(schema, invalid))
    for index, (field, value) in enumerate([
        ('method', 'POST'), ('path', '/control/v1/evidence-access-requests/' + access),
        ('path', '/control/v1/evidence-access-requests/{access_request_id}/approve'),
        ('path', '/control/v1/evidence-access-requests/{access_request_id}?extra=1'),
        ('subject_ref', ''), ('subject_ref', 'actor\nname'), ('subject_ref', 'a' * 257),
        ('outcome', 'UNKNOWN'), ('reason_code', 'CONTROL_EVIDENCE_ACCESS_APPROVED'),
        ('reason_code', 'CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE'),
        ('reason_code', 'CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE'),
        ('reason_code', 'CONTROL_EVIDENCE_ACCESS_READ\n'),
        ('justification', 'synthetic'), ('decision_reason', 'synthetic'),
        ('requester_subject', 'requester'), ('decided_by_subject', 'approver'),
        ('status', 'approved'), ('content', 'synthetic'), ('confidence', None), ('unknown', None),
    ]):
        invalid = copy.deepcopy(event)
        invalid['payload'][field] = value
        check(f'{prefix}invalid_payload_{index}_{field}', not valid(schema, invalid))
    for field in ['target_request_id', 'target_model_call_id', 'target_grant_id',
                  'target_binding_id', 'target_hold_id', 'query_digest', 'bytes_read']:
        optional = copy.deepcopy(event)
        optional['payload'][field] = None
        check(prefix + 'optional_null_' + field, valid(schema, optional))
        optional['payload'][field] = 0 if field == 'bytes_read' else base['event_id']
        check(prefix + 'forbidden_' + field, not valid(schema, optional))
    for index, (field, value) in enumerate([
        ('producer_id', 'evidence-access'), ('producer_boot_id', base['event_id']),
        ('producer_boot_id', base['producer_boot_id'] + '\n'), ('request_seq', 2),
        ('policy_revision', 'evidence-access-v1'), ('sensitivity', 'RESTRICTED'),
        ('request_id', None), ('request_id', base['event_id']),
        ('event_id', base['request_id']), ('example_only', True), ('schema_version', 2),
        ('tenant_id', 'tenant\n'), ('site_id', 'site\n'), ('cause_event_ids', [base['event_id']]),
        ('evidence_refs', []), ('evidence_refs', [access]), ('evidence_refs', base['evidence_refs'] * 2),
        ('connection_id', None), ('agent_run_id', None), ('unknown', None),
    ]):
        invalid = copy.deepcopy(event)
        invalid[field] = value
        check(f'{prefix}invalid_envelope_{index}_{field}', not valid(schema, invalid))
    for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
        invalid = copy.deepcopy(event)
        invalid['integrity'][field] = value
        check(prefix + 'integrity_' + field, not valid(schema, invalid))
    for outcome, reason, before_target in [
        ('DENY', 'CONTROL_AUTH_REQUIRED', True), ('DENY', 'CONTROL_SCOPE_DENIED', True),
        ('DENY', 'CONTROL_RATE_LIMITED', True), ('ERROR', 'CONTROL_RATE_UNAVAILABLE', True),
        ('ERROR', 'CONTROL_CLOCK_UNAVAILABLE', True),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_ID_INVALID', True),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID', False),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE', False),
        ('DENY', 'CONTROL_EVIDENCE_ACCESS_BUSY', False),
        ('ERROR', 'CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE', False),
    ]:
        failure = copy.deepcopy(event)
        failure['payload'].update(outcome=outcome, reason_code=reason)
        check(prefix + reason + '_reject_success_targets', not valid(schema, failure))
        failure['evidence_refs'] = []
        failure['payload'].update(target_case_id=None, target_artifact_id=None)
        check(prefix + reason + '_validated_target', valid(schema, failure) == (not before_target))
        failure['payload']['target_access_request_id'] = None
        check(prefix + reason + '_no_target', valid(schema, failure))
        for field in ['target_case_id', 'target_artifact_id']:
            invalid = copy.deepcopy(failure)
            invalid['payload'][field] = event['payload'][field]
            check(prefix + reason + '_reject_' + field, not valid(schema, invalid))
        invalid = copy.deepcopy(failure)
        invalid['evidence_refs'] = event['evidence_refs']
        check(prefix + reason + '_reject_evidence', not valid(schema, invalid))
        invalid = copy.deepcopy(failure)
        invalid['payload']['outcome'] = 'ERROR' if outcome == 'DENY' else 'DENY'
        check(prefix + reason + '_outcome_crossing', not valid(schema, invalid))
        for invalid_reason in ['CONTROL_EVIDENCE_ACCESS_READ', 'CONTROL_UNKNOWN', 'CONTROL_AUDIT_UNAVAILABLE']:
            invalid = copy.deepcopy(failure)
            invalid['payload']['reason_code'] = invalid_reason
            check(prefix + reason + '_reject_' + invalid_reason, not valid(schema, invalid))
        for subject in ['audit-operator', None]:
            failure['payload']['subject_ref'] = subject
            check(prefix + reason + '_subject_' + str(subject), valid(schema, failure))
        del failure['payload']['subject_ref']
        check(prefix + reason + '_subject_absent', valid(schema, failure))
        failure['payload']['target_access_request_id'] = access
        check(prefix + reason + '_target_before_auth', not valid(schema, failure))
    crossed = copy.deepcopy(event)
    crossed['payload'] = {'stage': 'evidence_access', 'outcome': 'PASS',
                           'reason_code': 'EVIDENCE_ACCESS_APPROVED', 'access_request_id': access,
                           'case_id': event['payload']['target_case_id'], 'artifact_id': base['evidence_refs'][0]}
    check(prefix + 'transaction_payload', not valid(schema, crossed))
    # Cross-field equality, duplicate JSON keys and UTF-8 byte lengths are enforced by Rust.
    mismatch = copy.deepcopy(event)
    mismatch['evidence_refs'] = ['artifact_018f2a3b-4c5d-7000-8000-000000000006']
    mismatch['payload']['subject_ref'] = '\u754c' * 86
    check(prefix + 'rust_only_equality_and_utf8', valid(schema, mismatch))

def check_control_case_list_contracts(schema: dict, base: dict) -> None:
    """Owner-scoped discovery records access facts, independently of page contents."""
    event = copy.deepcopy(base)
    event.update(event_type='console.case.list', producer_id='xshield-control',
                 request_seq=1, policy_revision='control-v1', sensitivity='INTERNAL',
                 cause_event_ids=[], evidence_refs=[])
    event['payload'] = {'method': 'GET', 'path': '/control/v1/cases',
                        'subject_ref': 'audit-operator', 'outcome': 'PASS',
                        'reason_code': 'CONTROL_CASES_READ'}
    prefix = 'control_case_list:'
    check(prefix + 'success', valid(schema, event))
    for field in ['method', 'path', 'subject_ref', 'outcome', 'reason_code']:
        missing = copy.deepcopy(event)
        del missing['payload'][field]
        check(prefix + 'missing_' + field, not valid(schema, missing))
        missing['payload'][field] = None
        check(prefix + 'null_' + field, not valid(schema, missing))
    for field, value in [
        ('method', 'POST'), ('path', '/control/v1/cases?cursor=opaque'),
        ('subject_ref', ''), ('subject_ref', 'actor\nname'), ('subject_ref', 'a' * 257),
        ('outcome', 'UNKNOWN'), ('reason_code', 'CONTROL_CASE_CREATED'),
        ('reason_code', 'invalid'), ('reason_code', 'CONTROL_CASES_READ\n'),
        ('reason_code', 'A' * 129), ('purpose', 'investigation'), ('cursor', 'opaque'),
        ('items', []), ('confidence', None),
    ]:
        invalid = copy.deepcopy(event)
        invalid['payload'][field] = value
        check(prefix + 'invalid_payload_' + field + '_' + str(value), not valid(schema, invalid))
    for field in ['target_request_id', 'target_artifact_id', 'target_case_id',
                  'target_access_request_id', 'target_model_call_id', 'target_grant_id',
                  'target_binding_id', 'target_hold_id', 'query_digest', 'bytes_read']:
        optional = copy.deepcopy(event)
        optional['payload'][field] = None
        check(prefix + 'null_' + field, valid(schema, optional))
        optional['payload'][field] = 0 if field == 'bytes_read' else base['event_id']
        check(prefix + 'reject_' + field, not valid(schema, optional))
    for field, value in [
        ('producer_id', 'investigation-case'), ('request_seq', 2),
        ('policy_revision', 'case-v1'), ('sensitivity', 'RESTRICTED'),
        ('request_id', None), ('request_id', base['event_id']),
        ('tenant_id', 'tenant\n'), ('site_id', 'site\n'),
        ('event_id', base['request_id']), ('example_only', True), ('schema_version', 2),
        ('evidence_refs', base['evidence_refs']), ('cause_event_ids', [base['event_id']]),
        ('connection_id', None), ('agent_run_id', None), ('unknown', None),
    ]:
        invalid = copy.deepcopy(event)
        invalid[field] = value
        check(prefix + 'invalid_envelope_' + field + '_' + str(value), not valid(schema, invalid))
    for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
        invalid = copy.deepcopy(event)
        invalid['integrity'][field] = value
        check(prefix + 'integrity_' + field, not valid(schema, invalid))
    for outcome in ['DENY', 'ERROR']:
        failure = copy.deepcopy(event)
        failure['payload'].update(outcome=outcome, reason_code='CONTROL_CASE_STORE_UNAVAILABLE')
        for subject in ['audit-operator', None]:
            failure['payload']['subject_ref'] = subject
            check(prefix + outcome + '_subject_' + str(subject), valid(schema, failure))
        del failure['payload']['subject_ref']
        check(prefix + outcome + '_subject_absent', valid(schema, failure))

def check_control_hold_access_contracts(schema: dict, base: dict) -> None:
    """Validate hold journal access attempts and their transaction boundary."""
    hold = 'ev_018f2a3b-4c5d-7000-8000-00000000000b'
    case = 'case_018f2a3b-4c5d-7000-8000-000000000004'
    routes = [
        ('console.evidence.hold.created', 'POST', '/control/v1/cases/{case_id}/holds',
         ['CONTROL_EVIDENCE_HOLD_CREATED', 'CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED']),
        ('console.evidence.hold.released', 'POST', '/control/v1/evidence-holds/{hold_id}/release',
         ['CONTROL_EVIDENCE_HOLD_RELEASED', 'CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED']),
        ('console.evidence.hold.read', 'GET', '/control/v1/cases/{case_id}/holds',
         ['CONTROL_EVIDENCE_HOLD_READ']),
    ]
    for kind, method, path, reasons in routes:
        listing = kind.endswith('.read')
        event = copy.deepcopy(base)
        event.update(event_type=kind, producer_id='xshield-control', request_seq=1,
                     policy_revision='control-v1', sensitivity='INTERNAL', cause_event_ids=[])
        event['payload'] = {
            'method': method, 'path': path, 'subject_ref': 'audit-operator',
            'target_request_id': None, 'target_artifact_id': None if listing else base['evidence_refs'][0],
            'target_case_id': case, 'target_access_request_id': None,
            'outcome': 'PASS', 'reason_code': reasons[0],
        }
        if not listing:
            event['payload']['target_hold_id'] = hold
        prefix = 'control_hold:' + kind + ':'
        for reason in reasons:
            accepted = copy.deepcopy(event)
            accepted['payload']['reason_code'] = reason
            check(prefix + reason, valid(schema, accepted))
        required = ['method', 'path', 'outcome', 'reason_code', 'subject_ref', 'target_case_id']
        if not listing:
            required += ['target_artifact_id', 'target_hold_id']
        for field in required:
            missing = copy.deepcopy(event)
            del missing['payload'][field]
            check(prefix + 'missing_' + field, not valid(schema, missing))
            missing['payload'][field] = None
            check(prefix + 'null_' + field, not valid(schema, missing))
        for field, value in [
            ('method', 'GET' if method == 'POST' else 'POST'), ('path', '/control/v1/cases'),
            ('reason_code', 'CONTROL_EVIDENCE_HOLD_UNKNOWN'), ('reason_code', 'invalid'),
            ('reason_code', 'CONTROL_READ\n'), ('reason_code', 'A' * 129),
            ('subject_ref', ''), ('subject_ref', 'actor\nname'), ('subject_ref', 'a' * 257),
            ('target_request_id', base['request_id']), ('target_case_id', hold),
            ('target_hold_id', case), ('target_hold_id', hold.upper()),
            ('target_hold_id', hold.replace('-7000-', '-4000-')),
            ('target_hold_id', hold + '\n'), ('target_access_request_id', hold),
            ('target_model_call_id', hold), ('target_grant_id', hold), ('target_binding_id', hold),
            ('query_digest', 'a' * 64), ('bytes_read', 0), ('confidence', None),
            ('stage', 'evidence_hold'), ('hold_until', '2026-09-20T00:00:00.123Z'),
            ('unknown', None),
        ]:
            invalid = copy.deepcopy(event)
            invalid['payload'][field] = value
            check(prefix + 'invalid_payload_' + field + '_' + str(value), not valid(schema, invalid))
        for field, value in [
            ('producer_id', 'evidence-hold'), ('policy_revision', 'evidence-hold-v1'),
            ('request_id', None), ('request_id', hold), ('request_seq', 2),
            ('sensitivity', 'RESTRICTED'), ('cause_event_ids', [hold]),
            ('example_only', True), ('schema_version', 2), ('event_id', case),
            ('evidence_refs', [hold]), ('evidence_refs', base['evidence_refs'] * 2),
            ('connection_id', None), ('agent_run_id', None), ('unknown', None),
        ]:
            invalid = copy.deepcopy(event)
            invalid[field] = value
            check(prefix + 'invalid_envelope_' + field + '_' + str(value), not valid(schema, invalid))
        for refs in [[], base['evidence_refs'] + ['artifact_018f2a3b-4c5d-7000-8000-000000000006']]:
            changed = copy.deepcopy(event)
            changed['evidence_refs'] = refs
            check(prefix + 'evidence_count_' + str(len(refs)), valid(schema, changed) == listing)
        for field in ['target_model_call_id', 'target_grant_id', 'target_binding_id', 'query_digest', 'bytes_read']:
            nullable = copy.deepcopy(event)
            nullable['payload'][field] = None
            check(prefix + 'optional_null_' + field, valid(schema, nullable))
        if listing:
            for field, value in [('target_hold_id', hold), ('target_artifact_id', base['evidence_refs'][0])]:
                invalid = copy.deepcopy(event)
                invalid['payload'][field] = value
                check(prefix + 'list_target_' + field, not valid(schema, invalid))
        for outcome in ['DENY', 'ERROR']:
            failure = copy.deepcopy(event)
            failure['payload'].update(outcome=outcome, reason_code='CONTROL_INVALID_INPUT')
            check(prefix + outcome + '_reject_refs', not valid(schema, failure))
            failure['evidence_refs'] = []
            check(prefix + outcome + '_validated_targets', valid(schema, failure))
            for field in ['subject_ref', 'target_case_id', 'target_artifact_id', 'target_hold_id']:
                failure['payload'][field] = None
                check(prefix + outcome + '_null_' + field, valid(schema, failure))
                del failure['payload'][field]
                check(prefix + outcome + '_absent_' + field, valid(schema, failure))
            failure['payload']['target_hold_id'] = case
            check(prefix + outcome + '_invalid_target', not valid(schema, failure))
        for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
            invalid = copy.deepcopy(event)
            invalid['integrity'][field] = value
            check(prefix + 'integrity_' + field, not valid(schema, invalid))
        crossed = copy.deepcopy(event)
        crossed['payload'] = {
            'stage': 'evidence_hold', 'outcome': 'PASS', 'reason_code': 'EVIDENCE_HOLD_CREATED',
            'hold_id': hold, 'case_id': case, 'artifact_id': base['evidence_refs'][0],
        }
        check(prefix + 'transaction_payload', not valid(schema, crossed))
        crossed = copy.deepcopy(event)
        crossed['event_type'] = 'evidence.hold.created'
        check(prefix + 'transaction_event_type', not valid(schema, crossed))
        # Field-shape schemas cannot compare two values or count UTF-8 bytes.
        mismatch = copy.deepcopy(event)
        mismatch['evidence_refs'] = ['artifact_018f2a3b-4c5d-7000-8000-000000000006']
        mismatch['payload']['subject_ref'] = '\u754c' * 86
        check(prefix + 'rust_only_equality_and_utf8', valid(schema, mismatch))

    for kind in ['console.health.read', 'console.request.read', 'console.events.read',
                 'console.manifest.read', 'console.model.read', 'console.grant.read',
                 'console.binding.read', 'console.query.executed', 'console.case.read',
                 'case.created', 'case.closed', 'case.evidence.added',
                 'evidence.access.requested', 'evidence.access.approved', 'evidence.access.denied',
                 'evidence.read']:
        legacy = copy.deepcopy(base)
        legacy['event_type'] = kind
        legacy['payload'] = {'outcome': 'DENY', 'reason_code': 'CONTROL_INVALID_INPUT'}
        check('control_hold:legacy_absent:' + kind, valid(schema, legacy))
        legacy['payload']['target_hold_id'] = None
        check('control_hold:legacy_null:' + kind, valid(schema, legacy))
        legacy['payload']['target_hold_id'] = hold
        check('control_hold:legacy_reject_target:' + kind, not valid(schema, legacy))

def check_hold_outbox_contracts(schema: dict, base: dict) -> None:
    """Check hold field shapes; Rust owns clock arithmetic and cross-field binding."""
    for kind, reason in [('evidence.hold.created', 'EVIDENCE_HOLD_CREATED'),
                         ('evidence.hold.released', 'EVIDENCE_HOLD_RELEASED')]:
        created = kind.endswith('created')
        hold_id = base['event_id'] if created else base['cause_event_ids'][0]
        event = copy.deepcopy(base)
        event.update(event_type=kind, producer_id='evidence-hold', request_id=None,
                     producer_boot_id=base['event_id'], request_seq=1,
                     trace_id=base['event_id'][3:].replace('-', ''),
                     policy_revision='evidence-hold-v1', cause_event_ids=[] if created else [hold_id])
        event['payload'] = {
            'stage': 'evidence_hold', 'outcome': 'PASS', 'reason_code': reason,
            'proof_kind': 'deterministic', 'confidence': None, 'confidence_status': 'not_applicable',
            'hold_id': hold_id, 'case_id': 'case_018f2a3b-4c5d-7000-8000-000000000004',
            'artifact_id': base['payload']['artifact_id'], 'subject_ref': 'investigator-1',
            'request_digest': 'a' * 64, 'hold_until': '2026-09-20T00:00:00.123Z',
        }
        prefix = 'outbox:hold:' + kind + ':'
        check(prefix + 'valid', valid(schema, event))
        for path in ['', 'payload', 'integrity']:
            target = event[path] if path else event
            for field in target:
                missing = copy.deepcopy(event)
                del (missing[path] if path else missing)[field]
                optional_hash = path == 'integrity' and field in ['previous_hash', 'event_hash']
                check(prefix + 'missing_' + path + '_' + field,
                      valid(schema, missing) == optional_hash)
                wrong_type = copy.deepcopy(event)
                (wrong_type[path] if path else wrong_type)[field] = (
                    'invalid' if isinstance(target[field], list) else [])
                check(prefix + 'wrong_type_' + path + '_' + field, not valid(schema, wrong_type))
            unknown = copy.deepcopy(event)
            (unknown[path] if path else unknown)['extra'] = None
            check(prefix + 'unknown_' + path, not valid(schema, unknown))
        for field, value in [
            ('producer_id', 'evidence-retention'), ('producer_boot_id', base['request_id']),
            ('producer_boot_id', base['producer_boot_id']), ('producer_boot_id', base['event_id'].upper()),
            ('request_id', base['request_id']), ('producer_seq', 0), ('producer_seq', 2),
            ('request_seq', 0), ('request_seq', 2), ('sensitivity', 'INTERNAL'),
            ('policy_revision', 'policy-r1'), ('example_only', True), ('schema_version', 2),
            ('event_id', base['request_id']), ('tenant_id', 'invalid scope'), ('site_id', 'invalid scope'),
            ('trace_id', event['trace_id'] + '\n'), ('span_id', event['span_id'] + '\n'),
            ('evidence_refs', []), ('evidence_refs', [base['request_id']]),
            ('evidence_refs', base['evidence_refs'] * 2),
            ('cause_event_ids', [hold_id] if created else []),
            ('cause_event_ids', [hold_id, hold_id]), ('cause_event_ids', base['evidence_refs']),
            ('connection_id', None), ('agent_run_id', None),
        ]:
            invalid = copy.deepcopy(event)
            invalid[field] = value
            check(prefix + 'reject_envelope_' + field + '_' + str(value), not valid(schema, invalid))
        for field, value in [
            ('stage', 'evidence_retention'), ('outcome', 'ERROR'),
            ('reason_code', 'EVIDENCE_HOLD_RELEASED' if created else 'EVIDENCE_HOLD_CREATED'),
            ('proof_kind', 'model'), ('confidence', 0.0), ('confidence_status', 'provided'),
            ('hold_id', base['request_id']), ('hold_id', hold_id.upper()),
            ('hold_id', hold_id.replace('-7000-', '-4000-')),
            ('case_id', base['event_id']), ('case_id', event['payload']['case_id'] + '\n'),
            ('artifact_id', None), ('artifact_id', base['request_id']),
            ('artifact_id', base['payload']['artifact_id'] + '\n'),
            ('subject_ref', ''), ('subject_ref', 'a' * 257), ('subject_ref', ' actor'),
            ('subject_ref', 'actor '), ('subject_ref', '\u2003actor'),
            ('subject_ref', 'actor\nname'), ('subject_ref', 'actor\u0085name'),
            ('request_digest', 'a' * 63), ('request_digest', 'a' * 65),
            ('request_digest', 'A' * 64), ('request_digest', 'g' * 64),
            ('body', 'synthetic'), ('storage_locator', '/private/synthetic.xev'),
        ]:
            invalid = copy.deepcopy(event)
            invalid['payload'][field] = value
            check(prefix + 'reject_payload_' + field + '_' + str(value), not valid(schema, invalid))
        for subject in ['a' * 256, '\u754c' * 85, 'actor name']:
            accepted = copy.deepcopy(event)
            accepted['payload']['subject_ref'] = subject
            check(prefix + 'subject_boundary_' + subject, valid(schema, accepted))
        for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
            invalid = copy.deepcopy(event)
            invalid['integrity'][field] = value
            check(prefix + 'reject_integrity_' + field, not valid(schema, invalid))
        for timestamp in ['invalid', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00.123456Z',
                          '2026-09-19T00:00:00.123+00:00', '2026-09-19T08:00:00.123+08:00',
                          '2026-09-19T00:00:60.000Z', '2026-09-19T00:00:60.999Z',
                          '2026-09-19T00:00:00.123Z\n']:
            for field in ['occurred_at', 'observed_at', 'hold_until']:
                invalid = copy.deepcopy(event)
                (invalid['payload'] if field == 'hold_until' else invalid)[field] = timestamp
                check(prefix + 'timestamp_' + field + '_' + timestamp, not valid(schema, invalid))
        for timestamp in ['2026-09-19T00:00:59.000Z', '2026-09-19T00:00:59.999Z',
                          '2026-09-19T00:01:00.000Z']:
            for field in ['occurred_at', 'observed_at', 'hold_until']:
                accepted = copy.deepcopy(event)
                (accepted['payload'] if field == 'hold_until' else accepted)[field] = timestamp
                check(prefix + 'ordinary_second_' + field + '_' + timestamp, valid(schema, accepted))

        # JSON Schema describes local shape. The Rust tests reject these bindings,
        # deadlines and UTF-8 byte bounds; no cross-event completeness is inferred.
        for field, value in [
            ('producer_boot_id', 'ev_018f2a3b-4c5d-7000-8000-000000000009'),
            ('trace_id', 'a' * 32), ('span_id', 'a' * 16),
            ('observed_at', '2026-09-19T00:00:00.124Z'),
            ('evidence_refs', ['artifact_018f2a3b-4c5d-7000-8000-000000000008']),
        ]:
            mismatch = copy.deepcopy(event)
            mismatch[field] = value
            check(prefix + 'rust_only_binding_' + field, valid(schema, mismatch))
        for field, value in [('hold_id', base['cause_event_ids'][0] if created else base['event_id']),
                             ('hold_until', '1969-12-31T23:59:59.999Z'), ('subject_ref', '\u754c' * 86)]:
            mismatch = copy.deepcopy(event)
            mismatch['payload'][field] = value
            check(prefix + 'rust_only_payload_' + field, valid(schema, mismatch))
        for timestamp in ['2026-09-19T00:00:00.123Z', '2026-09-19T00:00:00.124Z',
                          '2026-10-19T00:00:00.123Z', '2026-10-19T00:00:00.124Z',
                          '1970-01-01T00:00:00.000Z']:
            deadline = copy.deepcopy(event)
            deadline['payload']['hold_until'] = timestamp
            check(prefix + 'rust_only_deadline_' + timestamp, valid(schema, deadline))
        if not created:
            mismatch = copy.deepcopy(event)
            mismatch['cause_event_ids'] = [event['event_id']]
            check(prefix + 'rust_only_cause_binding', valid(schema, mismatch))

def check_retention_outbox_contracts(schema: dict, base: dict) -> None:
    """Check six maintenance events; Rust owns equality and source/row binding."""
    variants = {
        'evidence.purge_requested': ['EVIDENCE_PURGE_REQUESTED'],
        'evidence.deleted': ['EVIDENCE_DELETED', 'EVIDENCE_DELETE_ALREADY_ABSENT'],
        'evidence.purge_failed': ['EVIDENCE_PURGE_REJECTED', 'EVIDENCE_PURGE_UNAVAILABLE'],
        'evidence.orphan.purge_requested': ['EVIDENCE_ORPHAN_PURGE_REQUESTED'],
        'evidence.orphan.deleted': ['EVIDENCE_ORPHAN_DELETED', 'EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT'],
        'evidence.orphan.purge_failed': ['EVIDENCE_ORPHAN_PURGE_REJECTED', 'EVIDENCE_ORPHAN_PURGE_UNAVAILABLE'],
    }
    for kind, reasons in variants.items():
        orphan = kind.startswith('evidence.orphan.')
        intent = kind.endswith('purge_requested')
        event = copy.deepcopy(base)
        event.update(event_type=kind, producer_id='evidence-retention', request_id=None,
                     request_seq=1, policy_revision='evidence-retention-v1',
                     cause_event_ids=[] if intent else base['cause_event_ids'])
        event['payload'] = {
            'stage': 'evidence_orphan_retention' if orphan else 'evidence_retention',
            'outcome': 'ERROR' if kind.endswith('purge_failed') else 'PASS',
            'reason_code': reasons[0], 'artifact_id': base['payload']['artifact_id'],
            'proof_kind': 'deterministic', 'confidence': None,
            'confidence_status': 'not_applicable',
        }
        if orphan:
            event['payload']['authenticated_manifest'] = True
        else:
            event['payload'].update(source_request_id=base['request_id'],
                                    expires_at='2026-09-18T00:00:00.123Z', retained_metadata=True)
        prefix = 'outbox:retention:' + kind + ':'
        for reason in reasons:
            variant = copy.deepcopy(event)
            variant['payload']['reason_code'] = reason
            check(prefix + reason, valid(schema, variant))
            for other_kind in variants:
                if other_kind == kind:
                    continue
                mismatch = copy.deepcopy(variant)
                mismatch['event_type'] = other_kind
                check(prefix + reason + '_reject_' + other_kind, not valid(schema, mismatch))

        for path in ['', 'payload', 'integrity']:
            target = event[path] if path else event
            for field in target:
                missing = copy.deepcopy(event)
                del (missing[path] if path else missing)[field]
                optional_hash = path == 'integrity' and field in ['previous_hash', 'event_hash']
                check(prefix + 'missing_' + path + '_' + field,
                      valid(schema, missing) == optional_hash)
                wrong_type = copy.deepcopy(event)
                (wrong_type[path] if path else wrong_type)[field] = (
                    'invalid' if isinstance(target[field], list) else [])
                check(prefix + 'wrong_type_' + path + '_' + field, not valid(schema, wrong_type))
            unknown = copy.deepcopy(event)
            (unknown[path] if path else unknown)['extra'] = None
            check(prefix + 'unknown_' + path, not valid(schema, unknown))

        for field, value in [
            ('producer_id', 'gateway-evidence-catalog'), ('producer_boot_id', base['request_id']),
            ('producer_boot_id', '018f2a3b-4c5d-4000-8000-000000000006'),
            ('producer_boot_id', base['producer_boot_id'].upper()),
            ('request_id', base['request_id']), ('producer_seq', 2), ('request_seq', 2),
            ('sensitivity', 'SENSITIVE'), ('policy_revision', 'policy-r1'),
            ('example_only', True), ('event_id', base['request_id']),
            ('tenant_id', 'invalid scope'), ('site_id', 'invalid scope'),
            ('trace_id', base['trace_id'] + '\n'), ('span_id', base['span_id'] + '\n'),
            ('evidence_refs', []), ('evidence_refs', [base['request_id']]),
            ('evidence_refs', base['evidence_refs'] * 2),
            ('cause_event_ids', base['cause_event_ids'] if intent else []),
            ('cause_event_ids', base['cause_event_ids'] * 2),
            ('cause_event_ids', base['evidence_refs']), ('connection_id', None), ('agent_run_id', None),
        ]:
            invalid = copy.deepcopy(event)
            invalid[field] = value
            check(prefix + 'reject_envelope_' + field + '_' + str(value), not valid(schema, invalid))
        for field, value in [
            ('stage', 'request_completed'), ('outcome', 'DENY'), ('reason_code', 'EVIDENCE_UNKNOWN'),
            ('outcome', 'PASS' if kind.endswith('purge_failed') else 'ERROR'),
            ('proof_kind', 'model'), ('confidence', 0.0), ('confidence_status', 'provided'),
            ('artifact_id', None), ('artifact_id', base['request_id']),
            ('artifact_id', base['payload']['artifact_id'] + '\n'),
            ('body', 'synthetic'), ('storage_locator', '/private/synthetic.xev'),
            ('source_request_id', base['request_id'] if orphan else base['payload']['artifact_id']),
            ('retained_metadata', True if orphan else False),
        ]:
            invalid = copy.deepcopy(event)
            invalid['payload'][field] = value
            check(prefix + 'reject_payload_' + field + '_' + str(value), not valid(schema, invalid))
        if orphan:
            manifest_absent = copy.deepcopy(event)
            manifest_absent['payload']['authenticated_manifest'] = False
            check(prefix + 'unauthenticated_manifest', valid(schema, manifest_absent))
        else:
            crossed = copy.deepcopy(event)
            crossed['payload']['authenticated_manifest'] = True
            check(prefix + 'reject_orphan_field', not valid(schema, crossed))
        for field, value in [('state', 'sealed'), ('previous_hash', 'a' * 64), ('event_hash', 'b' * 64)]:
            invalid = copy.deepcopy(event)
            invalid['integrity'][field] = value
            check(prefix + 'reject_integrity_' + field, not valid(schema, invalid))
        for timestamp in ['invalid', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00.123456Z',
                          '2026-09-19T00:00:00.123+00:00', '2026-09-19T08:00:00.123+08:00',
                          '2026-09-19T00:00:00.123Z\n']:
            for field in ['occurred_at', 'observed_at'] + ([] if orphan else ['expires_at']):
                invalid = copy.deepcopy(event)
                (invalid['payload'] if field == 'expires_at' else invalid)[field] = timestamp
                check(prefix + 'timestamp_' + field + '_' + timestamp, not valid(schema, invalid))

        # Schema checks field shapes; the Rust publisher rejects these unequal
        # evidence, trace/span, clock and self-cause values before indexing.
        mismatch = copy.deepcopy(event)
        mismatch['evidence_refs'] = ['artifact_018f2a3b-4c5d-7000-8000-000000000008']
        mismatch['span_id'] = 'a' * 16
        mismatch['observed_at'] = '2026-09-19T00:00:00.124Z'
        if not intent:
            mismatch['cause_event_ids'] = [event['event_id']]
        check(prefix + 'rust_only_cross_field_checks', valid(schema, mismatch))

def check_identity_outbox_contracts(schema: dict, base: dict) -> None:
    """Check JSON Schema boundaries; cross-field state transitions stay in Rust."""
    events = {}
    reasons = {
        'session.created': 'SESSION_CREATED', 'binding.created': 'BINDING_CREATED',
        'identity.refreshed': 'IDENTITY_REFRESHED', 'epoch.changed': 'IDENTITY_CONTEXT_CHANGED',
    }
    for event_type, reason in reasons.items():
        event = copy.deepcopy(base)
        event.update(event_type=event_type, producer_id='gateway-identity',
                     producer_boot_id=event['request_id'], request_seq=1,
                     evidence_refs=[], cause_event_ids=[], sensitivity='SENSITIVE')
        event['payload'] = {
            'stage': 'identity_lifecycle', 'outcome': 'PASS', 'reason_code': reason,
            'binding_id': 'auth_018f2a3b-4c5d-7000-8000-000000000011',
            'auth_epoch': 1, 'credential_generation': 1,
        }
        payload = event['payload']
        if event_type == 'session.created':
            payload.update(status='anonymous', auth_epoch=0, credential_generation=0)
        else:
            payload.update(principal_ref='principal-new', authorization_context_ref='context-new')
        if event_type in ['identity.refreshed', 'epoch.changed']:
            payload.update(previous_credential_generation=1, credential_generation=2,
                           previous_credentials=[{'kind': 'bearer', 'fingerprint': 'a' * 64}],
                           credentials=[{'kind': 'bearer', 'fingerprint': 'b' * 64}],
                           rotation_reason='same_context_refresh' if event_type == 'identity.refreshed'
                           else 'account_context_changed')
        if event_type == 'epoch.changed':
            payload.update(previous_principal_ref='principal-old',
                           previous_authorization_context_ref='context-old',
                           previous_auth_epoch=1, auth_epoch=2)
        events[event_type] = event
        prefix = 'outbox:identity:' + event_type + ':'
        check(prefix + 'valid', valid(schema, event))
        for field in event:
            missing = copy.deepcopy(event)
            del missing[field]
            check(prefix + 'missing_envelope_' + field, not valid(schema, missing))
        for field in payload:
            missing = copy.deepcopy(event)
            del missing['payload'][field]
            check(prefix + 'missing_payload_' + field, not valid(schema, missing))
        for field, value in [
            ('stage', 'identity'), ('outcome', 'DENY'), ('reason_code', 'AUTH_REQUIRED'),
            ('binding_id', event['request_id']), ('binding_id', payload['binding_id'] + '\n'),
            ('extra', None), ('cookie', 'synthetic'), ('bearer', 'synthetic'), ('confidence', None),
        ]:
            invalid = copy.deepcopy(event)
            invalid['payload'][field] = value
            label = 'binding_newline' if isinstance(value, str) and value.endswith('\n') else field
            check(prefix + 'reject_payload_' + label, not valid(schema, invalid))
        for field, value in [
            ('producer_id', 'xshield-control'), ('producer_boot_id', event['event_id']),
            ('request_id', None), ('producer_seq', 2), ('request_seq', 2),
            ('sensitivity', 'INTERNAL'), ('example_only', True),
            ('evidence_refs', [base['payload']['artifact_id']]),
            ('cause_event_ids', [event['event_id']]),
            ('event_id', event['request_id']), ('trace_id', event['trace_id'] + '\n'),
            ('span_id', event['span_id'] + '\n'), ('connection_id', None), ('agent_run_id', None),
            ('extra', None), ('tenant_id', 'invalid scope'), ('site_id', 'invalid scope'),
            ('policy_revision', ''),
        ]:
            invalid = copy.deepcopy(event)
            invalid[field] = value
            check(prefix + 'reject_envelope_' + field, not valid(schema, invalid))
        for field in ['previous_hash', 'event_hash']:
            invalid = copy.deepcopy(event)
            del invalid['integrity'][field]
            check(prefix + 'optional_integrity_' + field, valid(schema, invalid))
            invalid['integrity'][field] = 'a' * 64
            check(prefix + 'reject_integrity_' + field, not valid(schema, invalid))
        invalid = copy.deepcopy(event)
        invalid['integrity']['state'] = 'sealed'
        check(prefix + 'reject_sealed_integrity', not valid(schema, invalid))
        sparse = dict(payload, **{key: event[key] for key in [
            'schema_version', 'event_type', 'event_id', 'request_id',
        ]})
        check(prefix + 'reject_legacy_sparse', not valid(schema, sparse))
        for field in ['auth_epoch', 'credential_generation']:
            for label, value in [('negative', -1), ('fractional', 1.5), ('bigint_overflow', 2**63)]:
                invalid = copy.deepcopy(event)
                invalid['payload'][field] = value
                check(prefix + field + '_' + label, not valid(schema, invalid))
        for field in ['principal_ref', 'authorization_context_ref',
                      'previous_principal_ref', 'previous_authorization_context_ref']:
            if field not in payload:
                continue
            for label, value, expected in [
                ('empty', '', False), ('too_long', 'a' * 257, False),
                ('c0_control', 'bad\x00ref', False), ('c1_control', 'bad\u0085ref', False),
                ('ascii_boundary', 'a' * 256, True), ('unicode_boundary', 'é' * 128, True),
            ]:
                changed = copy.deepcopy(event)
                changed['payload'][field] = value
                check(prefix + field + '_' + label, valid(schema, changed) == expected)

    for event_type in ['session.created', 'binding.created']:
        for field in ['auth_epoch', 'credential_generation']:
            invalid = copy.deepcopy(events[event_type])
            invalid['payload'][field] += 1
            check(f'outbox:identity:{event_type}:reject_initial_{field}', not valid(schema, invalid))
    invalid = copy.deepcopy(events['session.created'])
    invalid['payload']['status'] = 'active'
    check('outbox:identity:session.created:reject_active_status', not valid(schema, invalid))

    for event_type in ['identity.refreshed', 'epoch.changed']:
        prefix = 'outbox:identity:' + event_type + ':'
        event = events[event_type]
        for field in ['previous_credentials', 'credentials']:
            for label, values in [
                ('empty', []), ('too_many', [{'kind': 'bearer', 'fingerprint': 'a' * 64}] * 4),
                ('unknown_kind', [{'kind': 'unknown', 'fingerprint': 'a' * 64}]),
                ('uppercase', [{'kind': 'bearer', 'fingerprint': 'A' * 64}]),
                ('short', [{'kind': 'bearer', 'fingerprint': 'a' * 63}]),
                ('newline', [{'kind': 'bearer', 'fingerprint': 'a' * 64 + '\n'}]),
                ('unknown_field', [{'kind': 'bearer', 'fingerprint': 'a' * 64, 'token': 'synthetic'}]),
                ('missing_kind', [{'fingerprint': 'a' * 64}]),
                ('missing_fingerprint', [{'kind': 'bearer'}]),
                ('duplicate_kind', [{'kind': 'bearer', 'fingerprint': 'a' * 64},
                                    {'kind': 'bearer', 'fingerprint': 'b' * 64}]),
            ]:
                invalid = copy.deepcopy(event)
                invalid['payload'][field] = values
                check(prefix + field + '_' + label, not valid(schema, invalid))
        complete = copy.deepcopy(event)
        complete['payload']['previous_credentials'] = [
            {'kind': kind, 'fingerprint': 'a' * 64} for kind in ['cookie', 'bearer', 'body_token']
        ]
        complete['payload']['credentials'] = [
            {'kind': kind, 'fingerprint': 'b' * 64} for kind in ['body_token', 'bearer', 'cookie']
        ]
        check(prefix + 'all_credential_kinds', valid(schema, complete))
        maximum = copy.deepcopy(event)
        maximum['payload'].update(previous_credential_generation=2**63 - 2,
                                  credential_generation=2**63 - 1)
        if event_type == 'epoch.changed':
            maximum['payload'].update(previous_auth_epoch=2**63 - 2, auth_epoch=2**63 - 1)
        check(prefix + 'bigint_boundary', valid(schema, maximum))
        for field in ['previous_credential_generation', 'previous_auth_epoch']:
            if field not in event['payload']:
                continue
            for label, value in [('zero', 0), ('fractional', 1.5), ('no_successor', 2**63 - 1)]:
                invalid = copy.deepcopy(event)
                invalid['payload'][field] = value
                check(prefix + field + '_' + label, not valid(schema, invalid))
        invalid = copy.deepcopy(event)
        invalid['payload']['rotation_reason'] = 'ordinary_replacement'
        check(prefix + 'reject_rotation_reason', not valid(schema, invalid))

def check_response_grant_contracts(schema: dict) -> None:
    """Exercise the complete response-grant envelope and payload boundary."""
    issued = 1_789_776_000
    base = {
        'schema_version': 3,
        'event_type': 'response_grant.issued',
        'event_id': 'ev_018f2a3b-4c5d-7000-8000-000000000021',
        'tenant_id': 'tenant_demo',
        'site_id': 'site_demo',
        'request_id': 'req_018f2a3b-4c5d-7000-8000-000000000023',
        'trace_id': '018f2a3b4c5d70008000000000000023',
        'span_id': '018f2a3b4c5d7023',
        'producer_id': 'gateway-response-grant',
        'producer_boot_id': 'req_018f2a3b-4c5d-7000-8000-000000000023',
        'producer_seq': 1,
        'request_seq': 1,
        'occurred_at': '2026-09-19T00:00:00Z',
        'observed_at': '2026-09-19T00:00:00Z',
        'policy_revision': 'policy-r1',
        'example_only': False,
        'evidence_refs': [],
        'cause_event_ids': [],
        'payload': {
            'stage': 'response_grant',
            'outcome': 'PASS',
            'reason_code': 'GRANT_ISSUED',
            'grant_id': 'grant_018f2a3b-4c5d-7000-8000-000000000031',
            'binding_id': 'auth_018f2a3b-4c5d-7000-8000-000000000032',
            'auth_epoch': 1,
            'response_evidence_id': 'response_018f2a3b-4c5d-7000-8000-000000000033',
            'action_ref': 'action.' + 'a' * 64,
            'action_id': 'profile.read',
            'source_operation_id': 'profile.list',
            'operation_id': 'profile.read',
            'resource_type': 'profile',
            'view_profile': 'public',
            'mapping_revision': 'mapping-r1',
            'method': 'GET',
            'route_template': '/api/v1/profiles',
            'resource_key_hmac': 'b' * 64,
            'response_body_sha256': 'c' * 64,
            'fields': ['display_name'],
            'response_status': 200,
            'candidate_count': 2,
            'issued_at_unix': issued,
            'expires_at_unix': issued + 60,
        },
        'sensitivity': 'SENSITIVE',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
    }
    first = copy.deepcopy(base)
    second = copy.deepcopy(base)
    second['event_id'] = 'ev_018f2a3b-4c5d-7000-8000-000000000022'
    second['producer_seq'] = second['request_seq'] = 2
    second['payload']['grant_id'] = 'grant_018f2a3b-4c5d-7000-8000-000000000034'
    second['payload']['resource_key_hmac'] = 'e' * 64
    second['payload']['action_ref'] = 'action.' + 'd' * 64
    check('outbox:response_grant:valid_first_candidate', valid(schema, first))
    check('outbox:response_grant:valid_second_candidate', valid(schema, second))

    for field in first:
        missing = copy.deepcopy(first)
        del missing[field]
        check('outbox:response_grant:missing_envelope_' + field, not valid(schema, missing))
    for field in first['payload']:
        missing = copy.deepcopy(first)
        del missing['payload'][field]
        check('outbox:response_grant:missing_payload_' + field, not valid(schema, missing))
    for field in ['previous_hash', 'event_hash']:
        missing = copy.deepcopy(first)
        del missing['integrity'][field]
        check('outbox:response_grant:optional_integrity_' + field, valid(schema, missing))

    for label, field, value in [
        ('event_id_prefix', 'event_id', 'grant_018f2a3b-4c5d-7000-8000-000000000021'),
        ('request_id_prefix', 'request_id', 'auth_018f2a3b-4c5d-7000-8000-000000000023'),
        ('producer_boot_prefix', 'producer_boot_id', 'auth_018f2a3b-4c5d-7000-8000-000000000023'),
        ('grant_id_prefix', 'grant_id', 'auth_018f2a3b-4c5d-7000-8000-000000000031'),
        ('binding_id_prefix', 'binding_id', 'grant_018f2a3b-4c5d-7000-8000-000000000032'),
        ('response_evidence_prefix', 'response_evidence_id', 'artifact_018f2a3b-4c5d-7000-8000-000000000033'),
        ('action_ref_uppercase', 'action_ref', 'action.' + 'A' * 64),
        ('action_ref_short', 'action_ref', 'action.' + 'a' * 63),
        ('resource_hmac_uppercase', 'resource_key_hmac', 'A' * 64),
        ('resource_hmac_short', 'resource_key_hmac', 'a' * 63),
        ('body_hash_uppercase', 'response_body_sha256', 'C' * 64),
        ('body_hash_short', 'response_body_sha256', 'c' * 63),
    ]:
        invalid = copy.deepcopy(first)
        target = invalid['payload'] if field in invalid['payload'] else invalid
        target[field] = value
        check('outbox:response_grant:reject_' + label, not valid(schema, invalid))

    domain_fields = [
        'action_id', 'source_operation_id', 'operation_id', 'resource_type',
        'view_profile', 'mapping_revision',
    ]
    for field in domain_fields:
        for label, value in [('empty', ''), ('too_long', 'a' * 129),
                             ('unicode', 'é'), ('control', 'bad\x00name')]:
            invalid = copy.deepcopy(first)
            invalid['payload'][field] = value
            check(f'outbox:response_grant:{field}_{label}', not valid(schema, invalid))
        boundary = copy.deepcopy(first)
        boundary['payload'][field] = 'a' * 128
        check(f'outbox:response_grant:{field}_ascii_boundary', valid(schema, boundary))

    for label, value in [
        ('missing_slash', 'api/v1/profiles'), ('query', '/api/v1/profiles?x=1'),
        ('fragment', '/api/v1/profiles#x'), ('unicode', '/api/v1/profiles/é'),
        ('control', '/api/v1/profiles\x00'), ('too_long', '/' + 'a' * 512),
        ('trailing_newline', '/api/v1/profiles\n'),
    ]:
        invalid = copy.deepcopy(first)
        invalid['payload']['route_template'] = value
        check('outbox:response_grant:route_' + label, not valid(schema, invalid))
    route_boundary = copy.deepcopy(first)
    route_boundary['payload']['route_template'] = '/' + 'a' * 511
    check('outbox:response_grant:route_ascii_512_bytes', valid(schema, route_boundary))
    for label, value in [('lower_status', 199), ('upper_status', 300),
                         ('empty_status', 204),
                         ('fractional_status', 200.5)]:
        invalid = copy.deepcopy(first)
        invalid['payload']['response_status'] = value
        check('outbox:response_grant:status_' + label, not valid(schema, invalid))
    for label, value in [('zero', 0), ('too_many', 1001), ('fractional', 1.5)]:
        invalid = copy.deepcopy(first)
        invalid['payload']['candidate_count'] = value
        check('outbox:response_grant:candidate_count_' + label, not valid(schema, invalid))
    max_sequence = copy.deepcopy(first)
    max_sequence['producer_seq'] = max_sequence['request_seq'] = 1000
    max_sequence['payload']['candidate_count'] = 1000
    check('outbox:response_grant:sequence_upper_boundary', valid(schema, max_sequence))
    for label, value in [('zero', 0), ('too_large', 1001), ('fractional', 1.5)]:
        invalid = copy.deepcopy(first)
        invalid['producer_seq'] = invalid['request_seq'] = value
        check('outbox:response_grant:sequence_' + label, not valid(schema, invalid))
    for field in ['auth_epoch', 'issued_at_unix', 'expires_at_unix']:
        for label, value in [('negative', -1), ('fractional', 1.5),
                             ('bigint_overflow', 2 ** 63)]:
            invalid = copy.deepcopy(first)
            invalid['payload'][field] = value
            check(f'outbox:response_grant:{field}_{label}', not valid(schema, invalid))

    fields_empty = copy.deepcopy(first)
    fields_empty['payload']['fields'] = []
    check('outbox:response_grant:fields_empty', not valid(schema, fields_empty))
    fields_many = copy.deepcopy(first)
    fields_many['payload']['fields'] = ['display_name', 'email']
    check('outbox:response_grant:fields_many', not valid(schema, fields_many))
    fields_unknown = copy.deepcopy(first)
    fields_unknown['payload']['fields'] = ['display/name']
    check('outbox:response_grant:fields_unknown', not valid(schema, fields_unknown))
    for label, fields in [
        ('unknown_payload', {'extra': True}), ('unknown_envelope', {'extra': True}),
    ]:
        invalid = copy.deepcopy(first)
        (invalid['payload'] if label.endswith('payload') else invalid).update(fields)
        check('outbox:response_grant:' + label, not valid(schema, invalid))
    for label, field, value in [
        ('wrong_producer', 'producer_id', 'gateway-identity'),
        ('wrong_sensitivity', 'sensitivity', 'INTERNAL'),
        ('example_fixture', 'example_only', True),
        ('nonempty_evidence_refs', 'evidence_refs', ['artifact_018f2a3b-4c5d-7000-8000-000000000001']),
        ('nonempty_causes', 'cause_event_ids', ['ev_018f2a3b-4c5d-7000-8000-000000000002']),
    ]:
        invalid = copy.deepcopy(first)
        invalid[field] = value
        check('outbox:response_grant:' + label, not valid(schema, invalid))
    for label, value in [('sealed', 'sealed'), ('fixture_unsealed', 'fixture_unsealed')]:
        invalid = copy.deepcopy(first)
        invalid['integrity']['state'] = value
        check('outbox:response_grant:integrity_' + label, not valid(schema, invalid))

    # These are intentionally accepted by the shape schema; Rust compares the
    # values and rejects the mismatch or non-positive lease during publication.
    mismatch = copy.deepcopy(first)
    mismatch['producer_boot_id'] = 'req_018f2a3b-4c5d-7000-8000-000000000024'
    mismatch['payload']['expires_at_unix'] = mismatch['payload']['issued_at_unix']
    check('outbox:response_grant:rust_only_cross_field_checks', valid(schema, mismatch))
    for label, value in [('fractional', '2026-09-19T00:00:00.1Z'),
                         ('offset', '2026-09-19T08:00:00+08:00')]:
        invalid = copy.deepcopy(first)
        invalid['occurred_at'] = invalid['observed_at'] = value
        check('outbox:response_grant:timestamp_' + label, not valid(schema, invalid))
    sparse = dict(first['payload'], schema_version=3, event_type='response_grant.issued',
                  event_id=first['event_id'], request_id=first['request_id'])
    check('outbox:response_grant:reject_legacy_sparse', not valid(schema, sparse))

def check_grant_contracts(schema: dict) -> None:
    """Validate generic resource-grant issuance shape; Rust owns row binding."""
    issued = 1_789_776_000
    event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000041'
    base = {
        'schema_version': 3, 'event_type': 'grant.issued', 'event_id': event_id,
        'tenant_id': 'tenant_demo', 'site_id': 'site_demo',
        'request_id': 'req_018f2a3b-4c5d-7000-8000-000000000043',
        'trace_id': '018f2a3b4c5d70008000000000000043', 'span_id': '018f2a3b4c5d7043',
        'producer_id': 'gateway-grant', 'producer_boot_id': event_id,
        'producer_seq': 1, 'request_seq': 1,
        'occurred_at': '2026-09-19T00:00:00Z', 'observed_at': '2026-09-19T00:00:00Z',
        'policy_revision': 'policy-r1', 'example_only': False,
        'evidence_refs': [], 'cause_event_ids': [], 'sensitivity': 'SENSITIVE',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
        'payload': {
            'stage': 'grant', 'outcome': 'PASS', 'reason_code': 'GRANT_ISSUED',
            'grant_id': 'grant_018f2a3b-4c5d-7000-8000-000000000041',
            'binding_id': 'auth_018f2a3b-4c5d-7000-8000-000000000042',
            'auth_epoch': 4, 'action_ref': 'action_order_read',
            'source_request_id': 'req_018f2a3b-4c5d-7000-8000-000000000043',
            'resource_type': 'order', 'resource_key_hmac': 'b' * 64,
            'operation_id': 'orders.read', 'view_profile': 'customer_detail',
            'policy_revision': 'policy-r1', 'constraints_digest': 'c' * 64,
            'issued_at_unix': issued, 'expires_at_unix': issued + 60,
        },
    }
    check('outbox:grant:valid', valid(schema, base))
    for payload in [False, True]:
        for field in base['payload'] if payload else base:
            missing = copy.deepcopy(base)
            del (missing['payload'] if payload else missing)[field]
            check(f'outbox:grant:missing_{"payload" if payload else "envelope"}_{field}',
                  not valid(schema, missing))
    for label, field, value in [
        ('producer', 'producer_id', 'gateway-response-grant'),
        ('boot', 'producer_boot_id', base['request_id']),
        ('request', 'request_id', event_id),
        ('request_null', 'request_id', None),
        ('source_request', 'source_request_id', event_id),
        ('stage', 'stage', 'response_grant'), ('outcome', 'outcome', 'DENY'),
        ('reason', 'reason_code', 'GRANT_DENIED'),
        ('sensitivity', 'sensitivity', 'INTERNAL'),
        ('example', 'example_only', True),
        ('hmac', 'resource_key_hmac', 'B' * 64),
        ('hmac_newline', 'resource_key_hmac', 'b' * 64 + '\n'),
        ('digest', 'constraints_digest', 'c' * 63),
        ('digest_uppercase', 'constraints_digest', 'C' * 64),
        ('digest_newline', 'constraints_digest', 'c' * 64 + '\n'),
        ('evidence_refs', 'evidence_refs', ['artifact_018f2a3b-4c5d-7000-8000-000000000001']),
        ('causes', 'cause_event_ids', [event_id]),
    ]:
        invalid = copy.deepcopy(base)
        (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
        check('outbox:grant:reject_' + label, not valid(schema, invalid))
    for field in ['grant_id', 'binding_id', 'action_ref', 'source_request_id', 'resource_type',
                  'resource_key_hmac', 'operation_id', 'view_profile', 'policy_revision',
                  'constraints_digest']:
        invalid = copy.deepcopy(base)
        invalid['payload'][field] = ''
        check('outbox:grant:empty_' + field, not valid(schema, invalid))
    for payload, field, values in [
        (False, 'producer_seq', [0, 2, 1.5, 2 ** 64]),
        (False, 'request_seq', [0, 2, 1.5, 2 ** 32]),
        (True, 'auth_epoch', [0, -1, 1.5, 2 ** 63]),
        (True, 'issued_at_unix', [-1, 1.5, 2 ** 63]),
        (True, 'expires_at_unix', [0, -1, 1.5, 2 ** 63]),
    ]:
        for value in values:
            invalid = copy.deepcopy(base)
            (invalid['payload'] if payload else invalid)[field] = value
            check('outbox:grant:range_' + field + '_' + str(value), not valid(schema, invalid))
    for payload, field in [(False, 'event_id'), (False, 'producer_boot_id'),
                           (False, 'request_id'), (True, 'grant_id'),
                           (True, 'binding_id'), (True, 'source_request_id')]:
        original = (base['payload'] if payload else base)[field]
        for label, value in [
            ('prefix', 'other_' + original.split('_', 1)[1]),
            ('v4', original.replace('-7000-', '-4000-')),
            ('variant', original.replace('-8000-', '-0000-')),
            ('uppercase', original.upper()), ('newline', original + '\n'),
        ]:
            invalid = copy.deepcopy(base)
            (invalid['payload'] if payload else invalid)[field] = value
            check('outbox:grant:id_' + field + '_' + label, not valid(schema, invalid))
    for payload, field in [(False, 'tenant_id'), (False, 'site_id'), (False, 'policy_revision'),
                           (True, 'action_ref'), (True, 'resource_type'), (True, 'operation_id'),
                           (True, 'view_profile'), (True, 'policy_revision')]:
        for label, value in [('empty', ''), ('oversized', 'a' * 129), ('unicode', 'é'),
                             ('newline', 'bad\n')]:
            invalid = copy.deepcopy(base)
            (invalid['payload'] if payload else invalid)[field] = value
            check(f'outbox:grant:scoped_{payload}_{field}_{label}', not valid(schema, invalid))
        boundary = copy.deepcopy(base)
        (boundary['payload'] if payload else boundary)[field] = 'a' * 128
        if field == 'policy_revision':
            boundary['policy_revision'] = boundary['payload']['policy_revision'] = 'a' * 128
        check(f'outbox:grant:scoped_{payload}_{field}_boundary', valid(schema, boundary))
    for field, value in [('state', 'sealed'), ('event_hash', 'a' * 64),
                         ('previous_hash', 'a' * 64)]:
        invalid = copy.deepcopy(base)
        invalid['integrity'][field] = value
        check('outbox:grant:integrity_' + field, not valid(schema, invalid))
    for field in ['previous_hash', 'event_hash']:
        missing = copy.deepcopy(base)
        del missing['integrity'][field]
        check('outbox:grant:optional_integrity_' + field, valid(schema, missing))
    for field in ['unknown', 'constraints', 'issuance_key', 'credential', 'token', 'confidence']:
        invalid = copy.deepcopy(base)
        invalid['payload'][field] = None
        check('outbox:grant:unknown_payload_' + field, not valid(schema, invalid))
    for field in ['connection_id', 'agent_run_id', 'extra']:
        invalid = copy.deepcopy(base)
        invalid[field] = None
        check('outbox:grant:unknown_envelope_' + field, not valid(schema, invalid))
    for field in ['occurred_at', 'observed_at']:
        for label, value in [('fractional', '2026-09-19T00:00:00.1Z'),
                             ('offset', '2026-09-19T08:00:00+08:00'), ('invalid', 'invalid')]:
            invalid = copy.deepcopy(base)
            invalid[field] = value
            check('outbox:grant:timestamp_' + field + '_' + label, not valid(schema, invalid))
    for ttl in [1, 86_400]:
        boundary = copy.deepcopy(base)
        boundary['payload']['expires_at_unix'] = issued + ttl
        boundary['payload']['auth_epoch'] = 2 ** 63 - 1
        check('outbox:grant:ttl_boundary_' + str(ttl), valid(schema, boundary))
    # JSON Schema validates field shape; the Rust parser binds these values to
    # each other and to the scoped outbox row before any ClickHouse insertion.
    for label, payload, field, value in [
        ('boot', False, 'producer_boot_id', event_id[:-2] + '99'),
        ('source_request', True, 'source_request_id', base['request_id'][:-2] + '99'),
        ('policy', True, 'policy_revision', 'policy-r2'),
        ('zero_ttl', True, 'expires_at_unix', issued),
        ('oversized_ttl', True, 'expires_at_unix', issued + 86_401),
        ('frozen_time', False, 'observed_at', '2026-09-19T01:00:00Z'),
    ]:
        shaped = copy.deepcopy(base)
        (shaped['payload'] if payload else shaped)[field] = value
        check('outbox:grant:rust_cross_field_' + label, valid(schema, shaped))
    sparse = dict(base['payload'], schema_version=3, event_type='grant.issued', event_id=event_id)
    check('outbox:grant:reject_legacy_sparse', not valid(schema, sparse))

def check_share_grant_contracts(schema: dict) -> None:
    """Validate share issuance shape; Rust owns row and cross-field checks."""
    issued = 1_789_776_000
    event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000021'
    base = {
        'schema_version': 3, 'event_type': 'share.issued', 'event_id': event_id,
        'tenant_id': 'tenant_demo', 'site_id': 'site_demo',
        'request_id': 'req_018f2a3b-4c5d-7000-8000-000000000023',
        'trace_id': '018f2a3b4c5d70008000000000000023', 'span_id': '018f2a3b4c5d7023',
        'producer_id': 'gateway-share-grant', 'producer_boot_id': event_id,
        'producer_seq': 1, 'request_seq': 1,
        'occurred_at': '2026-09-19T00:00:00Z', 'observed_at': '2026-09-19T00:00:00Z',
        'policy_revision': 'policy-r1', 'example_only': False,
        'evidence_refs': [], 'cause_event_ids': [], 'sensitivity': 'SENSITIVE',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
        'payload': {
            'stage': 'share_grant', 'outcome': 'PASS', 'reason_code': 'SHARE_ISSUED',
            'share_id': event_id.replace('ev_', 'share_'),
            'issuer_binding_id': 'auth_018f2a3b-4c5d-7000-8000-000000000032',
            'issuer_auth_epoch': 1,
            'issuer_grant_id': 'grant_018f2a3b-4c5d-7000-8000-000000000033',
            'issuance_rule_id': 'profile-share-r1',
            'issuer_operation_id': 'profile.read', 'issuer_view_profile': 'private',
            'resource_type': 'profile', 'resource_key_hmac': 'b' * 64,
            'operation_id': 'profile.share.read', 'view_profile': 'public',
            'method': 'GET', 'use_policy': 'reusable_read',
            'issued_at_unix': issued, 'expires_at_unix': issued + 60,
        },
    }
    check('outbox:share_grant:valid', valid(schema, base))
    for payload in [False, True]:
        for field in base['payload'] if payload else base:
            missing = copy.deepcopy(base)
            del (missing['payload'] if payload else missing)[field]
            check(f'outbox:share_grant:missing_{"payload" if payload else "envelope"}_{field}',
                  not valid(schema, missing))
    for field in ['previous_hash', 'event_hash']:
        missing = copy.deepcopy(base)
        del missing['integrity'][field]
        check('outbox:share_grant:optional_integrity_' + field, valid(schema, missing))
    for label, field, value in [
        ('event_prefix', 'event_id', base['payload']['share_id']),
        ('boot_prefix', 'producer_boot_id', base['request_id']),
        ('request_prefix', 'request_id', event_id),
        ('request_null', 'request_id', None),
        ('share_prefix', 'share_id', event_id),
        ('share_v4', 'share_id', base['payload']['share_id'].replace('-7000-', '-4000-')),
        ('binding_prefix', 'issuer_binding_id', base['payload']['issuer_grant_id']),
        ('grant_prefix', 'issuer_grant_id', base['payload']['issuer_binding_id']),
        ('hmac_uppercase', 'resource_key_hmac', 'B' * 64),
        ('hmac_short', 'resource_key_hmac', 'b' * 63),
        ('hmac_newline', 'resource_key_hmac', 'b' * 64 + '\n'),
        ('producer', 'producer_id', 'gateway-response-grant'),
        ('sensitivity', 'sensitivity', 'INTERNAL'),
        ('example', 'example_only', True),
        ('stage', 'stage', 'response_grant'), ('outcome', 'outcome', 'DENY'),
        ('reason', 'reason_code', 'GRANT_ISSUED'), ('method', 'method', 'POST'),
        ('use_policy', 'use_policy', 'single_use'),
        ('evidence_refs', 'evidence_refs', ['artifact_018f2a3b-4c5d-7000-8000-000000000001']),
        ('causes', 'cause_event_ids', [event_id]),
    ]:
        invalid = copy.deepcopy(base)
        (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
        check('outbox:share_grant:reject_' + label, not valid(schema, invalid))
    for field in ['tenant_id', 'site_id', 'policy_revision', 'issuance_rule_id',
                  'issuer_operation_id', 'issuer_view_profile', 'resource_type',
                  'operation_id', 'view_profile']:
        for label, value in [('empty', ''), ('oversized', 'a' * 129), ('unicode', 'é'),
                             ('control', 'bad\x00'), ('newline', 'bad\n')]:
            invalid = copy.deepcopy(base)
            (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
            check(f'outbox:share_grant:{field}_{label}', not valid(schema, invalid))
        boundary = copy.deepcopy(base)
        (boundary['payload'] if field in boundary['payload'] else boundary)[field] = 'a' * 128
        check(f'outbox:share_grant:{field}_ascii_boundary', valid(schema, boundary))
    for field in ['producer_seq', 'request_seq']:
        for value in [0, 2, 1.5]:
            invalid = copy.deepcopy(base)
            invalid[field] = value
            check(f'outbox:share_grant:{field}_{value}', not valid(schema, invalid))
    for field in ['issuer_auth_epoch', 'issued_at_unix', 'expires_at_unix']:
        for label, value in [('negative', -1), ('fractional', 1.5), ('overflow', 2 ** 63)]:
            invalid = copy.deepcopy(base)
            invalid['payload'][field] = value
            check(f'outbox:share_grant:{field}_{label}', not valid(schema, invalid))
        for value in [0, 2 ** 63 - 1]:
            boundary = copy.deepcopy(base)
            boundary['payload'][field] = value
            expected = value != 0 or field == 'issued_at_unix'
            check(f'outbox:share_grant:{field}_boundary_{value}', valid(schema, boundary) == expected)
    for field in ['unknown', 'credential', 'token', 'fingerprint', 'issuance_key',
                  'proof_kind', 'confidence', 'confidence_status']:
        invalid = copy.deepcopy(base)
        invalid['payload'][field] = None
        check('outbox:share_grant:unknown_payload_' + field, not valid(schema, invalid))
    for field in ['extra', 'connection_id', 'agent_run_id']:
        invalid = copy.deepcopy(base)
        invalid[field] = None
        check('outbox:share_grant:unknown_envelope_' + field, not valid(schema, invalid))
    for field, value in [('state', 'sealed'), ('state', 'fixture_unsealed'),
                         ('event_hash', 'a' * 64), ('previous_hash', 'a' * 64)]:
        invalid = copy.deepcopy(base)
        invalid['integrity'][field] = value
        check(f'outbox:share_grant:integrity_{field}_{value}', not valid(schema, invalid))
    for field in ['occurred_at', 'observed_at']:
        for label, value in [('fractional', '2026-09-19T00:00:00.0Z'),
                             ('offset', '2026-09-19T00:00:00+00:00'), ('invalid', 'invalid')]:
            invalid = copy.deepcopy(base)
            invalid[field] = value
            check(f'outbox:share_grant:{field}_{label}', not valid(schema, invalid))

    # Each field is valid alone. Rust, not JSON Schema, compares these values
    # with the event identity and original issue time during publication.
    for label, field, value in [
        ('boot_mismatch', 'producer_boot_id', event_id[:-1] + '9'),
        ('share_mismatch', 'share_id', base['payload']['share_id'][:-1] + '9'),
        ('occurred_mismatch', 'occurred_at', '2026-09-19T01:00:00Z'),
        ('observed_mismatch', 'observed_at', '2026-09-19T01:00:00Z'),
        ('zero_ttl', 'expires_at_unix', issued),
        ('negative_ttl', 'expires_at_unix', issued - 1),
        ('overlong_ttl', 'expires_at_unix', issued + 86_401),
    ]:
        mismatch = copy.deepcopy(base)
        (mismatch['payload'] if field in mismatch['payload'] else mismatch)[field] = value
        check('outbox:share_grant:rust_only_' + label, valid(schema, mismatch))
    sparse = dict(base['payload'], schema_version=3, event_type='share.issued', event_id=event_id)
    check('outbox:share_grant:reject_legacy_sparse', not valid(schema, sparse))

def check_calibration_report_contract(schema: dict) -> None:
    """Validate offline report metadata; Rust owns provenance equality checks."""
    event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000061'
    report_id = 'calr_018f2a3b-4c5d-7000-8000-000000000062'
    artifact = 'artifact_018f2a3b-4c5d-7000-8000-000000000063'
    evaluation = 'artifact_018f2a3b-4c5d-7000-8000-000000000064'
    training = 'artifact_018f2a3b-4c5d-7000-8000-000000000065'
    calibration = 'artifact_018f2a3b-4c5d-7000-8000-000000000066'
    labels = 'artifact_018f2a3b-4c5d-7000-8000-000000000067'
    base = {
        'schema_version': 3, 'event_type': 'calibration.reported', 'event_id': event_id,
        'tenant_id': 'tenant_demo', 'site_id': 'site_demo', 'request_id': None,
        'trace_id': report_id[5:].replace('-', ''),
        'span_id': report_id[5:].replace('-', '')[:16],
        'producer_id': 'calibration-evaluator', 'producer_boot_id': event_id,
        'producer_seq': 1, 'request_seq': 1,
        'occurred_at': '2026-09-20T00:00:00.123Z',
        'observed_at': '2026-09-20T00:00:00.123Z',
        'policy_revision': 'calibration-v1', 'example_only': False,
        'evidence_refs': [artifact], 'cause_event_ids': [], 'sensitivity': 'RESTRICTED',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
        'payload': {
            'stage': 'calibration_report', 'outcome': 'PASS',
            'reason_code': 'CALIBRATION_REPORTED', 'report_id': report_id,
            'report_artifact_id': artifact, 'approval_ref': 'approval-r1',
            'dataset_revision': 'dataset-r1', 'label_revision': 'labels-r1',
            'task_revision': 'task-r1', 'threshold_policy_revision': 'threshold-r1',
            'mapping_revision': 'mapping-r1',
            'evaluation_manifest_artifact_id': evaluation,
            'training_manifest_artifact_id': training,
            'calibration_manifest_artifact_id': calibration,
            'label_manifest_artifact_id': labels,
            'provider': 'vercel_ai_gateway', 'provider_model_id': 'typesafe-ai/jev',
            'model_revision': 'jev-1.13.0', 'prompt_revision': 'prompt-r1',
            'resolved_model_revision': None,
        },
    }
    check('outbox:calibration:valid_unknown_resolved_revision', valid(schema, base))
    known = copy.deepcopy(base)
    known['payload']['resolved_model_revision'] = 'jev-1.13.0'
    check('outbox:calibration:valid_known_resolved_revision', valid(schema, known))
    for payload in [False, True]:
        for field in base['payload'] if payload else base:
            missing = copy.deepcopy(base)
            del (missing['payload'] if payload else missing)[field]
            check(f'outbox:calibration:missing_{"payload" if payload else "envelope"}_{field}',
                  not valid(schema, missing))
    for field in ['previous_hash', 'event_hash']:
        missing = copy.deepcopy(base)
        del missing['integrity'][field]
        check('outbox:calibration:optional_integrity_' + field, valid(schema, missing))
    for label, field, value in [
        ('event_prefix', 'event_id', report_id), ('boot_prefix', 'producer_boot_id', report_id),
        ('request', 'request_id', event_id), ('producer', 'producer_id', 'model-eval'),
        ('sequence', 'producer_seq', 2), ('request_sequence', 'request_seq', 2),
        ('policy', 'policy_revision', 'policy-r1'), ('example', 'example_only', True),
        ('sensitivity', 'sensitivity', 'INTERNAL'), ('causes', 'cause_event_ids', [event_id]),
        ('evidence_empty', 'evidence_refs', []),
        ('evidence_many', 'evidence_refs', [artifact, evaluation]),
        ('integrity', 'integrity', {'state': 'sealed', 'previous_hash': None, 'event_hash': None}),
        ('stage', 'stage', 'calibration'), ('outcome', 'outcome', 'UNKNOWN'),
        ('reason', 'reason_code', 'CALIBRATION_DATASET_EVALUATED'),
        ('report_prefix', 'report_id', event_id),
        ('report_artifact_prefix', 'report_artifact_id', report_id),
        ('resolved_empty', 'resolved_model_revision', ''),
        ('resolved_invalid', 'resolved_model_revision', 'bad revision'),
        ('resolved_type', 'resolved_model_revision', True),
    ]:
        invalid = copy.deepcopy(base)
        (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
        check('outbox:calibration:reject_' + label, not valid(schema, invalid))
    for field in ['approval_ref', 'dataset_revision', 'label_revision', 'task_revision',
                  'threshold_policy_revision', 'mapping_revision', 'provider',
                  'model_revision', 'prompt_revision']:
        for label, value in [('empty', ''), ('oversized', 'a' * 129), ('unicode', 'é'),
                             ('space', 'bad value')]:
            invalid = copy.deepcopy(base)
            invalid['payload'][field] = value
            check(f'outbox:calibration:{field}_{label}', not valid(schema, invalid))
    for label, value in [('extra_segment', 'typesafe-ai/jev/extra'),
                         ('space', 'typesafe ai/jev'), ('oversized', 'a' * 129)]:
        invalid = copy.deepcopy(base)
        invalid['payload']['provider_model_id'] = value
        check('outbox:calibration:provider_model_' + label, not valid(schema, invalid))
    for field in ['occurred_at', 'observed_at']:
        for label, value in [('fractional', '2026-09-20T00:00:00.1Z'),
                             ('offset', '2026-09-20T08:00:00.123+08:00'),
                             ('seconds', '2026-09-20T00:00:00Z')]:
            invalid = copy.deepcopy(base)
            invalid[field] = value
            check(f'outbox:calibration:{field}_{label}', not valid(schema, invalid))
    for label, field, value in [
        ('trace', 'trace_id', '0' * 32), ('span', 'span_id', '0' * 16),
        ('frozen_observation', 'observed_at', '2026-09-20T01:00:00.123Z'),
        ('report_artifact_binding', 'report_artifact_id', evaluation),
        ('report_manifest_alias', 'evaluation_manifest_artifact_id', artifact),
        ('manifest_overlap', 'training_manifest_artifact_id', evaluation),
    ]:
        shaped = copy.deepcopy(base)
        (shaped['payload'] if field in shaped['payload'] else shaped)[field] = value
        check('outbox:calibration:rust_cross_field_' + label, valid(schema, shaped))
    sparse = dict(base['payload'], schema_version=3, event_type='calibration.reported',
                  event_id=event_id)
    check('outbox:calibration:reject_legacy_sparse', not valid(schema, sparse))

def check_calibration_lineage_review_retention_contract(schema: dict) -> None:
    """Validate six restricted lineage-review retention event shapes."""
    event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000081'
    review_id = 'calrev_018f2a3b-4c5d-7000-8000-000000000082'
    artifact = 'artifact_018f2a3b-4c5d-7000-8000-000000000083'
    trace_id = review_id[7:].replace('-', '')
    cases = [
        ('purge_requested', 'PASS', 'CALIBRATION_LINEAGE_REVIEW_PURGE_REQUESTED', []),
        ('deleted', 'PASS', 'CALIBRATION_LINEAGE_REVIEW_DELETE_ALREADY_ABSENT', [event_id]),
        ('purge_failed', 'ERROR', 'CALIBRATION_LINEAGE_REVIEW_PURGE_REJECTED', [event_id]),
        ('orphan_purge_requested', 'PASS', 'CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_REQUESTED', []),
        ('orphan_deleted', 'PASS', 'CALIBRATION_LINEAGE_REVIEW_ORPHAN_DELETED', [event_id]),
        ('orphan_purge_failed', 'ERROR', 'CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_UNAVAILABLE', [event_id]),
    ]
    for suffix, outcome, reason_code, causes in cases:
        base = {
            'schema_version': 3,
            'event_type': 'calibration.lineage_review_retention.' + suffix,
            'event_id': event_id, 'tenant_id': 'tenant_demo', 'site_id': 'site_demo',
            'request_id': None, 'trace_id': trace_id, 'span_id': trace_id[:16],
            'producer_id': 'calibration-lineage-review-retention',
            'producer_boot_id': '018f2a3b-4c5d-7000-8000-000000000084',
            'producer_seq': 1, 'request_seq': 1,
            'occurred_at': '2026-09-20T00:00:00.123Z',
            'observed_at': '2026-09-20T00:00:00.123Z',
            'policy_revision': 'calibration-retention-v1', 'example_only': False,
            'evidence_refs': [artifact], 'cause_event_ids': causes,
            'sensitivity': 'RESTRICTED',
            'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
            'payload': {
                'stage': 'calibration_lineage_review_retention', 'outcome': outcome,
                'reason_code': reason_code, 'proof_kind': 'deterministic',
                'confidence': None, 'confidence_status': 'not_applicable',
                'review_id': review_id, 'review_artifact_id': artifact,
                'expires_at': '2026-09-20T00:00:00.122Z', 'retained_metadata': True,
            },
        }
        check('outbox:lineage_review_retention:valid_' + suffix, valid(schema, base))
        for payload in [False, True]:
            for field in base['payload'] if payload else base:
                missing = copy.deepcopy(base)
                del (missing['payload'] if payload else missing)[field]
                check(f'outbox:lineage_review_retention:missing_{suffix}_{field}',
                      not valid(schema, missing))
        for label, field, value in [
            ('producer', 'producer_id', 'calibration-report-retention'),
            ('request', 'request_id', event_id),
            ('sensitivity', 'sensitivity', 'INTERNAL'),
            ('evidence_many', 'evidence_refs', [artifact, artifact]),
            ('confidence', 'confidence', 0.1),
            ('review_prefix', 'review_id', event_id),
            ('review_artifact_prefix', 'review_artifact_id', review_id),
            ('expiry_seconds', 'expires_at', '2026-09-20T00:00:00Z'),
        ]:
            invalid = copy.deepcopy(base)
            (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
            check(f'outbox:lineage_review_retention:reject_{suffix}_{label}',
                  not valid(schema, invalid))
        if causes:
            invalid = copy.deepcopy(base)
            invalid['cause_event_ids'] = []
            check('outbox:lineage_review_retention:terminal_requires_cause_' + suffix,
                  not valid(schema, invalid))
        else:
            invalid = copy.deepcopy(base)
            invalid['cause_event_ids'] = [event_id]
            check('outbox:lineage_review_retention:intent_has_no_cause_' + suffix,
                  not valid(schema, invalid))

def check_calibration_read_capability_issued_contract(schema: dict) -> None:
    """Validate restricted capability issuance fields; Rust owns cross-field binding."""
    event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000071'
    capability_id = 'calcap_018f2a3b-4c5d-7000-8000-000000000072'
    trace_id = capability_id[7:].replace('-', '')
    base = {
        'schema_version': 3, 'event_type': 'calibration.read_capability.issued',
        'event_id': event_id, 'tenant_id': 'tenant_demo', 'site_id': 'site_demo',
        'request_id': None, 'trace_id': trace_id, 'span_id': trace_id[:16],
        'producer_id': 'calibration-capability-issuer', 'producer_boot_id': event_id,
        'producer_seq': 1, 'request_seq': 1,
        'occurred_at': '2026-09-20T00:00:00.123Z',
        'observed_at': '2026-09-20T00:00:00.123Z',
        'policy_revision': 'calibration-v1', 'example_only': False,
        'evidence_refs': [], 'cause_event_ids': [], 'sensitivity': 'RESTRICTED',
        'integrity': {'state': 'pending', 'previous_hash': None, 'event_hash': None},
        'payload': {
            'stage': 'calibration_read_capability', 'outcome': 'PASS',
            'reason_code': 'CALIBRATION_READ_CAPABILITY_ISSUED',
            'capability_id': capability_id, 'scope_digest': 'a' * 64,
            'member_count': 6, 'frozen_total_bytes': 1,
            'not_before_unix': 1_789_689_600, 'expires_at_unix': 1_789_693_200,
        },
    }
    check('outbox:calibration_read_capability:valid', valid(schema, base))
    for payload in [False, True]:
        for field in base['payload'] if payload else base:
            missing = copy.deepcopy(base)
            del (missing['payload'] if payload else missing)[field]
            check(f'outbox:calibration_read_capability:missing_{"payload" if payload else "envelope"}_{field}',
                  not valid(schema, missing))
    for field in ['previous_hash', 'event_hash']:
        missing = copy.deepcopy(base)
        del missing['integrity'][field]
        check('outbox:calibration_read_capability:optional_integrity_' + field,
              valid(schema, missing))
    for field in ['unknown', 'connection_id', 'agent_run_id']:
        invalid = copy.deepcopy(base)
        invalid[field] = None
        check('outbox:calibration_read_capability:unknown_envelope_' + field,
              not valid(schema, invalid))
    invalid = copy.deepcopy(base)
    invalid['payload']['unknown'] = None
    check('outbox:calibration_read_capability:unknown_payload', not valid(schema, invalid))
    for label, field, value in [
        ('event_prefix', 'event_id', capability_id),
        ('boot_prefix', 'producer_boot_id', capability_id),
        ('request', 'request_id', event_id),
        ('producer', 'producer_id', 'calibration-evaluator'),
        ('producer_sequence', 'producer_seq', 2),
        ('request_sequence', 'request_seq', 2),
        ('policy', 'policy_revision', 'policy-r1'),
        ('example', 'example_only', True),
        ('evidence', 'evidence_refs', ['artifact_018f2a3b-4c5d-7000-8000-000000000073']),
        ('causes', 'cause_event_ids', [event_id]),
        ('sensitivity', 'sensitivity', 'INTERNAL'),
        ('integrity', 'integrity', {'state': 'sealed', 'previous_hash': None, 'event_hash': None}),
        ('trace', 'trace_id', 'A' * 32),
        ('span', 'span_id', 'a' * 15),
        ('stage', 'stage', 'calibration'),
        ('outcome', 'outcome', 'UNKNOWN'),
        ('reason', 'reason_code', 'CALIBRATION_REPORTED'),
        ('capability_prefix', 'capability_id', event_id),
        ('scope_digest', 'scope_digest', 'A' * 64),
        ('member_below_minimum', 'member_count', 5),
        ('member_above_maximum', 'member_count', 20_005),
        ('bytes_zero', 'frozen_total_bytes', 0),
        ('bytes_above_maximum', 'frozen_total_bytes', 536_870_913),
    ]:
        invalid = copy.deepcopy(base)
        (invalid['payload'] if field in invalid['payload'] else invalid)[field] = value
        check('outbox:calibration_read_capability:reject_' + label, not valid(schema, invalid))
    for field in ['not_before_unix', 'expires_at_unix']:
        for label, value in [('negative', -1), ('fractional', 1.5), ('above_i64', 2 ** 63)]:
            invalid = copy.deepcopy(base)
            invalid['payload'][field] = value
            check(f'outbox:calibration_read_capability:{field}_{label}',
                  not valid(schema, invalid))
    for field in ['occurred_at', 'observed_at']:
        for label, value in [('fractional', '2026-09-20T00:00:00.1Z'),
                             ('offset', '2026-09-20T08:00:00.123+08:00'),
                             ('seconds', '2026-09-20T00:00:00Z')]:
            invalid = copy.deepcopy(base)
            invalid[field] = value
            check(f'outbox:calibration_read_capability:{field}_{label}',
                  not valid(schema, invalid))
    # These comparisons require the parsed, leased producer contract. JSON
    # Schema intentionally validates only each field's standalone shape.
    for label, field, value in [
        ('boot_mismatch', 'producer_boot_id', event_id[:-1] + '9'),
        ('trace_derivation', 'trace_id', '0' * 32),
        ('span_derivation', 'span_id', '0' * 16),
        ('observed_mismatch', 'observed_at', '2026-09-20T01:00:00.123Z'),
        ('odd_member_count', 'member_count', 7),
        ('equal_lease_times', 'expires_at_unix', base['payload']['not_before_unix']),
        ('reversed_lease_times', 'expires_at_unix', base['payload']['not_before_unix'] - 1),
    ]:
        shaped = copy.deepcopy(base)
        (shaped['payload'] if field in shaped['payload'] else shaped)[field] = value
        check('outbox:calibration_read_capability:rust_only_' + label,
              valid(schema, shaped))
    sparse = dict(base['payload'], schema_version=3,
                  event_type='calibration.read_capability.issued', event_id=event_id)
    check('outbox:calibration_read_capability:reject_legacy_sparse', not valid(schema, sparse))

def main() -> int:
    for p in sorted(ROOT.rglob('*.json')):
        if DISCOVERY_EXCLUDED_PARTS.intersection(p.relative_to(ROOT).parts): continue
        try: json.loads(p.read_text(encoding='utf-8'));check(f'json:{p.relative_to(ROOT)}',True)
        except (ValueError,OSError) as exc: check(f'json:{p.name}',False,str(exc))
    for p in sorted(ROOT.rglob('*.yaml')):
        if DISCOVERY_EXCLUDED_PARTS.intersection(p.relative_to(ROOT).parts): continue
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
    check_outbox_contracts(schemas)
    check_response_grant_contracts(schemas['audit-event'])
    check_grant_contracts(schemas['audit-event'])
    check_share_grant_contracts(schemas['audit-event'])
    check_calibration_report_contract(schemas['audit-event'])
    check_calibration_lineage_review_retention_contract(schemas['audit-event'])
    check_calibration_read_capability_issued_contract(schemas['audit-event'])
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
        if DISCOVERY_EXCLUDED_PARTS.intersection(p.relative_to(ROOT).parts): continue
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
