BEGIN;

CREATE TABLE xshield.case_closures (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    case_id text NOT NULL,
    closed_by text NOT NULL CHECK (
        octet_length(closed_by) BETWEEN 1 AND 256
        AND closed_by !~ '[[:cntrl:]]'
    ),
    reason text NOT NULL CHECK (
        octet_length(reason) BETWEEN 1 AND 512
        AND reason !~ '[[:cntrl:]]'
        AND reason = btrim(reason)
    ),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    closed_event_id text NOT NULL UNIQUE CHECK (
        closed_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    closed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, case_id),
    UNIQUE (tenant_id, site_id, closed_by, idempotency_digest),
    FOREIGN KEY (tenant_id, site_id, case_id)
        REFERENCES xshield.investigation_cases (tenant_id, site_id, case_id)
);

COMMIT;
