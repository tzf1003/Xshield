-- Upgrade before enabling more than one model-evaluation worker for a scope.
--
-- This schema is the authoritative tenant/site provider-call capacity fence.
-- It does not create a business grant, evidence-read capability, approval, or
-- policy publication. Deployment management pre-provisions each scope; the
-- model worker can only acquire, confirm, release, or expire an existing
-- private-token-bound lease.
--
-- Rollback: stop all model-evaluation workers and wait for active leases to
-- expire before disabling this feature. Do not drop the retained lease history
-- while model-call journal or incident evidence may still need it.
BEGIN;

CREATE TABLE xshield.model_evaluation_admission_scopes (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    policy_revision text NOT NULL CHECK (
        policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    max_active_calls integer NOT NULL CHECK (
        max_active_calls BETWEEN 1 AND 32
    ),
    lease_seconds integer NOT NULL CHECK (
        lease_seconds BETWEEN 30 AND 60
    ),
    configured_at timestamptz NOT NULL CHECK (
        isfinite(configured_at)
        AND configured_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', configured_at) = configured_at
    ),

    PRIMARY KEY (tenant_id, site_id)
);

CREATE TABLE xshield.model_evaluation_admission_leases (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    lease_id text NOT NULL CHECK (
        lease_id ~ '^mle_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    request_id text NOT NULL CHECK (
        request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    model_call_id text NOT NULL CHECK (
        model_call_id ~ '^mdl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    runner_id text NOT NULL CHECK (
        octet_length(runner_id) BETWEEN 1 AND 128
        AND runner_id !~ '[[:cntrl:]]'
        AND runner_id = btrim(runner_id)
    ),
    policy_revision text NOT NULL CHECK (
        policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    lease_token_digest bytea NOT NULL CHECK (
        octet_length(lease_token_digest) = 32
    ),
    status text NOT NULL CHECK (
        status IN ('active', 'released', 'expired')
    ),
    acquired_at timestamptz NOT NULL CHECK (
        isfinite(acquired_at)
        AND acquired_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', acquired_at) = acquired_at
    ),
    lease_until timestamptz NOT NULL CHECK (
        isfinite(lease_until)
        AND lease_until > acquired_at
        AND date_trunc('milliseconds', lease_until) = lease_until
    ),
    released_at timestamptz,
    expired_at timestamptz,

    PRIMARY KEY (tenant_id, site_id, lease_id),
    UNIQUE (lease_id),
    UNIQUE (tenant_id, site_id, model_call_id),
    FOREIGN KEY (tenant_id, site_id)
        REFERENCES xshield.model_evaluation_admission_scopes (tenant_id, site_id)
        ON DELETE RESTRICT,
    CONSTRAINT model_evaluation_admission_lease_state_shape CHECK (
        (status = 'active' AND released_at IS NULL AND expired_at IS NULL)
        OR (status = 'released' AND released_at IS NOT NULL AND expired_at IS NULL)
        OR (status = 'expired' AND released_at IS NULL AND expired_at IS NOT NULL)
    ),
    CHECK (
        (released_at IS NULL OR (
            isfinite(released_at)
            AND released_at >= acquired_at
            AND date_trunc('milliseconds', released_at) = released_at
        ))
        AND (expired_at IS NULL OR (
            isfinite(expired_at)
            AND expired_at >= lease_until
            AND date_trunc('milliseconds', expired_at) = expired_at
        ))
    )
);

CREATE INDEX model_evaluation_admission_active_scope
    ON xshield.model_evaluation_admission_leases (tenant_id, site_id, lease_until)
    WHERE status = 'active';

COMMIT;
