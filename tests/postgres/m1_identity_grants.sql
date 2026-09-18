BEGIN;

INSERT INTO xshield.policy_revisions (
    tenant_id, site_id, revision, status, content_digest, artifact_ref
) VALUES (
    'tenant_a', 'site_a', 'policy-r1', 'active', repeat('a', 64), 'art_policy_1'
);

INSERT INTO xshield.auth_bindings (
    tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
    authorization_context_ref, auth_epoch, credential_generation, status,
    absolute_expires_at
) VALUES (
    'tenant_a', 'site_a', 'auth_018f2a3b-4c5d-7000-8000-000000000001',
    decode(repeat('11', 32), 'hex'), 'principal_a', 'tenant_a:user',
    4, 2, 'active', now() + interval '1 day'
);

INSERT INTO xshield.credential_bindings (
    tenant_id, site_id, binding_id, generation, credential_kind,
    fingerprint, expires_at, status
) VALUES (
    'tenant_a', 'site_a', 'auth_018f2a3b-4c5d-7000-8000-000000000001',
    2, 'cookie', decode(repeat('22', 32), 'hex'), now() + interval '1 hour', 'active'
);

DO $$
DECLARE
    rejected boolean := false;
BEGIN
    BEGIN
        INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            auth_epoch, credential_generation, status, absolute_expires_at
        ) VALUES (
            'tenant_a', 'site_a', 'auth_018f2a3b-4c5d-7000-8000-000000000099',
            decode(repeat('99', 32), 'hex'), 'unexpected_principal',
            0, 0, 'anonymous', now() + interval '1 day'
        );
    EXCEPTION WHEN check_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'anonymous binding accepted a principal';
    END IF;
END
$$;

INSERT INTO xshield.auth_bindings (
    tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
    auth_epoch, credential_generation, status, absolute_expires_at
) VALUES (
    'tenant_a', 'site_a', 'auth_018f2a3b-4c5d-7000-8000-000000000098',
    decode(repeat('98', 32), 'hex'), NULL, 0, 0, 'anonymous', now() + interval '1 day'
);
UPDATE xshield.auth_bindings
SET status = 'revoked'
WHERE binding_id = 'auth_018f2a3b-4c5d-7000-8000-000000000098';

INSERT INTO xshield.page_evidence (
    tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
    source_request_id, response_artifact_ref, page_template, build_fingerprint,
    policy_revision, mapping_revision, status, verified_at, expires_at
) VALUES (
    'tenant_a', 'site_a', 'page_018f2a3b-4c5d-7000-8000-000000000011',
    'auth_018f2a3b-4c5d-7000-8000-000000000001', 4,
    'req_018f2a3b-4c5d-7000-8000-000000000010', 'artifact_page_1',
    'orders_page', decode(repeat('55', 32), 'hex'), 'policy-r1', 'mapping-r1',
    'verified', now(), now() + interval '45 minutes'
);

INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_a', 'site_a', 'orders.open', 'orders_page', 'orders.read', 'GET',
    '/api/orders/{id}', '{"kind":"resource","resource_type":"order"}', '[]',
    'customer_detail', 'policy-r1', 'mapping-r1', 'approved'
);

INSERT INTO xshield.ui_actions (
    tenant_id, site_id, action_ref, binding_id, auth_epoch,
    source_request_id, page_evidence_id, source_action_ref, operation_id,
    target_constraints, field_profile, source_rule, policy_revision,
    status, issued_at, expires_at, mapping_revision, method, route_template,
    allowed_fields
) VALUES (
    'tenant_a', 'site_a', 'action_order_1',
    'auth_018f2a3b-4c5d-7000-8000-000000000001', 4,
    'req_018f2a3b-4c5d-7000-8000-000000000010',
    'page_018f2a3b-4c5d-7000-8000-000000000011',
    'orders.open', 'orders.read', '{"resource":"order-1"}', 'customer_detail',
    'orders-list-r1', 'policy-r1', 'active', now(), now() + interval '30 minutes',
    'mapping-r1', 'GET', '/api/orders/{id}', '[]'
);

DO $$
DECLARE
    rejected boolean := false;
BEGIN
    BEGIN
        INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, source_action_ref, operation_id,
            target_constraints, field_profile, source_rule, policy_revision,
            status, issued_at, expires_at, mapping_revision, method, route_template,
            allowed_fields
        ) VALUES (
            'tenant_a', 'site_a', 'action_unapproved',
            'auth_018f2a3b-4c5d-7000-8000-000000000001', 4,
            'req_018f2a3b-4c5d-7000-8000-000000000010',
            'page_018f2a3b-4c5d-7000-8000-000000000011',
            'orders.unknown', 'orders.read', '{}', 'customer_detail',
            'orders-list-r1', 'policy-r1', 'active', now(), now() + interval '5 minutes',
            'mapping-r1', 'GET', '/api/orders/{id}', '[]'
        );
    EXCEPTION WHEN foreign_key_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'action grant accepted an unapproved descriptor';
    END IF;
END
$$;

INSERT INTO xshield.resource_grants (
    tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
    resource_type, resource_key_hmac, operation_id, view_id, constraints,
    source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_a', 'site_a', 'grant_018f2a3b-4c5d-7000-8000-000000000020',
    'auth_018f2a3b-4c5d-7000-8000-000000000001', 4, 'action_order_1',
    'order', decode(repeat('33', 32), 'hex'), 'orders.read', 'customer_detail', '{}',
    'ev_018f2a3b-4c5d-7000-8000-000000000021', 'issue-order-1',
    'policy-r1', 'active', now(), now() + interval '20 minutes'
);

INSERT INTO xshield.audit_outbox (
    event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
) VALUES (
    'ev_018f2a3b-4c5d-7000-8000-000000000021', 'tenant_a', 'site_a',
    'grant_018f2a3b-4c5d-7000-8000-000000000020', 'grant.issued',
    '{"schema_version":3,"reason_code":"AUTH_BINDING_VALID"}'
);

DO $$
BEGIN
    IF (SELECT count(*) FROM xshield.resource_grants) <> 1
        OR (SELECT count(*) FROM xshield.audit_outbox
            WHERE event_type = 'grant.issued') <> 1 THEN
        RAISE EXCEPTION 'grant and outbox were not committed together';
    END IF;
END
$$;

INSERT INTO xshield.resource_grants (
    tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
    resource_type, resource_key_hmac, operation_id, view_id, constraints,
    source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_a', 'site_a', 'grant_018f2a3b-4c5d-7000-8000-000000000022',
    'auth_018f2a3b-4c5d-7000-8000-000000000001', 4, 'action_order_1',
    'order', decode(repeat('44', 32), 'hex'), 'orders.update', 'admin_full', '{}',
    'ev_018f2a3b-4c5d-7000-8000-000000000023', 'issue-order-1',
    'policy-r1', 'active', now(), now() + interval '10 minutes'
) ON CONFLICT (tenant_id, site_id, issuance_key) DO NOTHING;

DO $$
DECLARE
    changed integer;
BEGIN
    IF (SELECT count(*) FROM xshield.resource_grants WHERE issuance_key = 'issue-order-1') <> 1 THEN
        RAISE EXCEPTION 'issuance key was not idempotent';
    END IF;

    UPDATE xshield.auth_bindings
    SET credential_generation = 3, updated_at = now()
    WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
      AND binding_id = 'auth_018f2a3b-4c5d-7000-8000-000000000001'
      AND auth_epoch = 4 AND credential_generation = 2 AND status = 'active';
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'first credential compare-and-swap failed';
    END IF;

    UPDATE xshield.auth_bindings
    SET credential_generation = 3, updated_at = now()
    WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
      AND binding_id = 'auth_018f2a3b-4c5d-7000-8000-000000000001'
      AND auth_epoch = 4 AND credential_generation = 2 AND status = 'active';
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 0 THEN
        RAISE EXCEPTION 'stale credential compare-and-swap succeeded';
    END IF;

    UPDATE xshield.auth_bindings
    SET principal_ref = 'principal_b', auth_epoch = 5,
        credential_generation = 4, updated_at = now()
    WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
      AND binding_id = 'auth_018f2a3b-4c5d-7000-8000-000000000001'
      AND auth_epoch = 4 AND credential_generation = 3 AND status = 'active';
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'identity epoch transition failed';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM xshield.resource_grants grant_row
        JOIN xshield.auth_bindings binding
          ON binding.tenant_id = grant_row.tenant_id
         AND binding.site_id = grant_row.site_id
         AND binding.binding_id = grant_row.binding_id
         AND binding.auth_epoch = grant_row.auth_epoch
        WHERE grant_row.status = 'active'
          AND grant_row.tenant_id = 'tenant_a'
          AND grant_row.site_id = 'site_a'
          AND grant_row.issuance_key = 'issue-order-1'
    ) THEN
        RAISE EXCEPTION 'old epoch grant remained eligible';
    END IF;
END
$$;

ROLLBACK;
