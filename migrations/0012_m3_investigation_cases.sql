BEGIN;

CREATE TABLE xshield.investigation_cases (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    case_id text NOT NULL CHECK (
        case_id ~ '^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    owner_ref text NOT NULL CHECK (
        octet_length(owner_ref) BETWEEN 1 AND 256
        AND owner_ref !~ '[[:cntrl:]]'
    ),
    purpose text NOT NULL CHECK (
        octet_length(purpose) BETWEEN 1 AND 512
        AND purpose !~ '[[:cntrl:]]'
        AND purpose = btrim(purpose)
    ),
    status text NOT NULL CHECK (status IN ('open', 'closed')),
    idempotency_digest bytea NOT NULL CHECK (
        octet_length(idempotency_digest) = 32
    ),
    request_digest bytea NOT NULL CHECK (
        octet_length(request_digest) = 32
    ),
    created_event_id text NOT NULL UNIQUE CHECK (
        created_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, case_id),
    UNIQUE (tenant_id, site_id, owner_ref, idempotency_digest)
);

CREATE INDEX investigation_case_open_lookup
    ON xshield.investigation_cases (
        tenant_id, site_id, owner_ref, created_at, case_id
    )
    WHERE status = 'open';

COMMIT;
