-- Durable, purpose-limited model-evaluation result cache.
--
-- The cache is an optimization, never an authorization or evidence-read
-- source. Every lookup is followed by a fresh catalog/vault revalidation in
-- the worker before a result can be reused. Rows expire no later than the
-- source evidence and retain only opaque key material plus typed references.
--
-- Rollback: stop model-evaluation workers with cache enabled, wait for any
-- in-flight calls to finish, then retain this table until the referenced
-- model-call evidence has reached its normal retention boundary.
BEGIN;

CREATE TABLE xshield.model_evaluation_cache (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    cache_key bytea NOT NULL CHECK (
        octet_length(cache_key) = 32
    ),
    source_request_id text NOT NULL CHECK (
        source_request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    source_model_call_id text NOT NULL CHECK (
        source_model_call_id ~ '^mdl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    internal_artifact_id text NOT NULL CHECK (
        internal_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    input_artifact_id text NOT NULL CHECK (
        input_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    output_artifact_id text NOT NULL CHECK (
        output_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    call_artifact_id text NOT NULL CHECK (
        call_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    provider text NOT NULL CHECK (
        provider IN ('typesafe', 'vercel_ai_gateway')
    ),
    provider_model_id text NOT NULL CHECK (
        provider_model_id IN ('jev-1.13.0', 'typesafe-ai/jev')
    ),
    model_revision text NOT NULL CHECK (
        model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    prompt_revision text NOT NULL CHECK (
        prompt_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    resolved_model_revision text CHECK (
        resolved_model_revision IS NULL
        OR resolved_model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    created_at timestamptz NOT NULL CHECK (
        isfinite(created_at)
        AND created_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', created_at) = created_at
    ),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at)
        AND expires_at > created_at
        AND date_trunc('milliseconds', expires_at) = expires_at
    ),
    PRIMARY KEY (tenant_id, site_id, cache_key),
    UNIQUE (tenant_id, site_id, source_model_call_id)
);

CREATE INDEX model_evaluation_cache_expiry
    ON xshield.model_evaluation_cache (tenant_id, site_id, expires_at);

COMMIT;
