-- Metadata-only investigation exports. Package bytes remain in the encrypted
-- evidence vault; this table stores only authorization and package pointers.
BEGIN;

CREATE TABLE xshield.investigation_exports (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    export_id text NOT NULL CHECK (
        export_id ~ '^export_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    case_id text NOT NULL CHECK (
        case_id ~ '^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    requested_by text NOT NULL CHECK (
        octet_length(requested_by) BETWEEN 1 AND 256
        AND requested_by !~ '[[:cntrl:]]'
    ),
    purpose text NOT NULL CHECK (
        octet_length(purpose) BETWEEN 1 AND 512
        AND purpose !~ '[[:cntrl:]]'
        AND purpose = btrim(purpose)
    ),
    kind text NOT NULL CHECK (kind = 'metadata_only'),
    status text NOT NULL CHECK (
        status IN ('pending_approval', 'approved', 'ready', 'rejected', 'expired', 'failed')
    ),
    decided_by text CHECK (
        decided_by IS NULL OR (
            octet_length(decided_by) BETWEEN 1 AND 256
            AND decided_by !~ '[[:cntrl:]]'
        )
    ),
    decided_at timestamptz,
    decision_reason text CHECK (
        decision_reason IS NULL OR (
            octet_length(decision_reason) BETWEEN 1 AND 512
            AND decision_reason !~ '[[:cntrl:]]'
            AND decision_reason = btrim(decision_reason)
        )
    ),
    expires_at timestamptz,
    package_artifact_id text CHECK (
        package_artifact_id IS NULL OR package_artifact_id ~
        '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    package_request_id text CHECK (
        package_request_id IS NULL OR package_request_id ~
        '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    package_digest text CHECK (
        package_digest IS NULL OR package_digest ~ '^[0-9a-f]{64}$'
    ),
    package_bytes bigint CHECK (package_bytes IS NULL OR package_bytes BETWEEN 0 AND 67108864),
    download_count bigint NOT NULL DEFAULT 0 CHECK (download_count BETWEEN 0 AND 2),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    approval_digest bytea CHECK (approval_digest IS NULL OR octet_length(approval_digest) = 32),
    decision_request_digest bytea CHECK (
        decision_request_digest IS NULL OR octet_length(decision_request_digest) = 32
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, site_id, export_id),
    UNIQUE (tenant_id, site_id, requested_by, idempotency_digest),
    FOREIGN KEY (tenant_id, site_id, case_id)
        REFERENCES xshield.investigation_cases (tenant_id, site_id, case_id),
    CHECK (
        isfinite(created_at)
        AND isfinite(updated_at)
        AND updated_at >= created_at
        AND (decided_at IS NULL OR (isfinite(decided_at) AND decided_at >= created_at))
        AND (expires_at IS NULL OR isfinite(expires_at))
    ),
    CHECK (
        (status = 'pending_approval' AND decided_at IS NULL AND decided_by IS NULL
            AND approval_digest IS NULL AND decision_request_digest IS NULL)
        OR (status IN ('approved', 'ready', 'rejected', 'expired', 'failed')
            AND decided_at IS NOT NULL AND decided_by IS NOT NULL
            AND approval_digest IS NOT NULL AND decision_request_digest IS NOT NULL)
    ),
    CHECK (
        (status IN ('approved', 'ready') AND expires_at IS NOT NULL)
        OR (status IN ('pending_approval', 'rejected', 'expired', 'failed'))
    ),
    CHECK (
        (status = 'ready'
            AND package_artifact_id IS NOT NULL
            AND package_request_id IS NOT NULL
            AND package_digest IS NOT NULL
            AND package_bytes IS NOT NULL)
        OR (status <> 'ready'
            AND package_artifact_id IS NULL
            AND package_request_id IS NULL
            AND package_digest IS NULL
            AND package_bytes IS NULL)
    )
);

CREATE INDEX investigation_exports_requester_lookup
    ON xshield.investigation_exports (tenant_id, site_id, requested_by, created_at DESC, export_id DESC);

COMMIT;
