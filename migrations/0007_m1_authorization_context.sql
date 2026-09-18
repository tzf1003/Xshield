BEGIN;

ALTER TABLE xshield.auth_bindings
    ADD COLUMN authorization_context_ref text;

-- Existing active bindings did not prove a permission/tenant context. Revoking
-- them prevents a deployment upgrade from silently preserving unknown grants.
WITH legacy AS (
    SELECT tenant_id, site_id, binding_id,
           md5('authorization-context-migration:' || tenant_id || ':' || site_id || ':' || binding_id) AS digest
    FROM xshield.auth_bindings
    WHERE status = 'active'
)
INSERT INTO xshield.audit_outbox (
    event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
)
SELECT event_id, tenant_id, site_id, binding_id, 'binding.revoked',
       jsonb_build_object(
           'schema_version', 3,
           'event_type', 'binding.revoked',
           'event_id', event_id,
           'binding_id', binding_id,
           'reason_code', 'AUTH_BINDING_REVOKED',
           'rotation_reason', 'authorization_context_unverified_migration'
       )
FROM (
    SELECT tenant_id, site_id, binding_id,
           'ev_' || substr(digest, 1, 8) || '-' || substr(digest, 9, 4)
               || '-7' || substr(digest, 14, 3) || '-8' || substr(digest, 18, 3)
               || '-' || substr(digest, 21, 12) AS event_id
    FROM legacy
) events;

UPDATE xshield.credential_bindings credential
SET status = 'revoked'
FROM xshield.auth_bindings binding
WHERE binding.status = 'active'
  AND credential.tenant_id = binding.tenant_id
  AND credential.site_id = binding.site_id
  AND credential.binding_id = binding.binding_id
  AND credential.status IN ('active', 'transition');

UPDATE xshield.auth_bindings
SET status = 'revoked', updated_at = now()
WHERE status = 'active';

ALTER TABLE xshield.auth_bindings
    ADD CHECK (
        status <> 'active'
        OR (
            authorization_context_ref IS NOT NULL
            AND authorization_context_ref <> ''
            AND octet_length(authorization_context_ref) <= 256
            AND authorization_context_ref !~ '[[:cntrl:]]'
        )
    );

COMMIT;
