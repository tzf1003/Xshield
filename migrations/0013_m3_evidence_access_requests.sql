BEGIN;

CREATE TABLE xshield.evidence_access_requests (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    access_request_id text NOT NULL CHECK (
        access_request_id ~ '^access_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    case_id text NOT NULL,
    artifact_id text NOT NULL,
    requested_by text NOT NULL CHECK (
        octet_length(requested_by) BETWEEN 1 AND 256
        AND requested_by !~ '[[:cntrl:]]'
    ),
    access_kind text NOT NULL CHECK (access_kind = 'sensitive_raw'),
    justification text NOT NULL CHECK (
        octet_length(justification) BETWEEN 1 AND 512
        AND justification !~ '[[:cntrl:]]'
        AND justification = btrim(justification)
    ),
    status text NOT NULL CHECK (
        status IN ('pending', 'approved', 'denied', 'expired', 'revoked')
    ),
    idempotency_digest bytea NOT NULL CHECK (
        octet_length(idempotency_digest) = 32
    ),
    request_digest bytea NOT NULL CHECK (
        octet_length(request_digest) = 32
    ),
    requested_event_id text NOT NULL UNIQUE CHECK (
        requested_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, access_request_id),
    UNIQUE (tenant_id, site_id, requested_by, idempotency_digest),
    FOREIGN KEY (tenant_id, site_id, case_id)
        REFERENCES xshield.investigation_cases (tenant_id, site_id, case_id),
    FOREIGN KEY (tenant_id, site_id, artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
);

CREATE INDEX evidence_access_pending_lookup
    ON xshield.evidence_access_requests (
        tenant_id, site_id, requested_by, requested_at, access_request_id
    )
    WHERE status = 'pending';

COMMIT;
