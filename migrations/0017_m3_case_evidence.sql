BEGIN;

CREATE TABLE xshield.case_items (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    case_id text NOT NULL,
    artifact_id text NOT NULL,
    added_by text NOT NULL CHECK (
        octet_length(added_by) BETWEEN 1 AND 256
        AND added_by !~ '[[:cntrl:]]'
    ),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    added_event_id text NOT NULL UNIQUE CHECK (
        added_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, case_id, artifact_id),
    UNIQUE (tenant_id, site_id, added_by, idempotency_digest),
    FOREIGN KEY (tenant_id, site_id, case_id)
        REFERENCES xshield.investigation_cases (tenant_id, site_id, case_id),
    FOREIGN KEY (tenant_id, site_id, artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
);

COMMIT;
