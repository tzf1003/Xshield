-- Durable control-plane jobs. The first producer is the bounded case-inventory
-- analysis; the table keeps the state machine explicit so later long-running
-- producers cannot replace an accepted job with an in-memory promise.
--
-- No request body, evidence content, credential, or model output is retained.
BEGIN;

CREATE TABLE xshield.control_jobs (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    job_id text NOT NULL CHECK (
        job_id ~ '^job_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    kind text NOT NULL CHECK (kind IN ('case_analysis')),
    owner_ref text NOT NULL CHECK (
        octet_length(owner_ref) BETWEEN 1 AND 256
        AND owner_ref !~ '[[:cntrl:]]'
    ),
    case_id text NOT NULL CHECK (
        case_id ~ '^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    status text NOT NULL CHECK (
        status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    checkpoint text NOT NULL CHECK (
        checkpoint ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    reason_code text NOT NULL CHECK (
        reason_code ~ '^[A-Z0-9_]{1,128}$'
    ),
    retryable boolean NOT NULL,
    artifact_count bigint NOT NULL CHECK (artifact_count BETWEEN 0 AND 1000000),
    active_artifact_count bigint NOT NULL CHECK (
        active_artifact_count BETWEEN 0 AND artifact_count
    ),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, site_id, job_id),
    UNIQUE (tenant_id, site_id, owner_ref, idempotency_digest),
    FOREIGN KEY (tenant_id, site_id, case_id)
        REFERENCES xshield.investigation_cases (tenant_id, site_id, case_id),
    CHECK (
        isfinite(created_at)
        AND isfinite(updated_at)
        AND updated_at >= created_at
        AND (completed_at IS NULL OR (isfinite(completed_at) AND completed_at >= created_at))
    ),
    CHECK (
        (status IN ('queued', 'running') AND completed_at IS NULL)
        OR (status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)
    )
);

CREATE INDEX control_jobs_owner_lookup
    ON xshield.control_jobs (tenant_id, site_id, owner_ref, created_at DESC, job_id DESC);

COMMIT;
