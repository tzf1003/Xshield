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

def check_outbox_contracts(schemas: dict) -> None:
    """Exercise the implemented catalog and identity outbox wire shapes."""
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
    check_identity_outbox_contracts(schemas['audit-event'], base)

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
    check_outbox_contracts(schemas)
    check_response_grant_contracts(schemas['audit-event'])
    check_grant_contracts(schemas['audit-event'])
    check_share_grant_contracts(schemas['audit-event'])
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
