-- Serialize the external vault write for one metadata-only export.
-- The claim is scheduling state only; the export row and catalog remain the
-- authorization and evidence truths. A short lease lets a crashed writer be
-- retried while the ready transition still requires the current lease.
BEGIN;

CREATE TABLE xshield.investigation_export_package_claims (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    export_id text NOT NULL CHECK (
        export_id ~ '^export_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    package_request_id text NOT NULL CHECK (
        package_request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    parent_refs_digest bytea NOT NULL CHECK (octet_length(parent_refs_digest) = 32),
    package_expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('writing', 'published')),
    lease_until timestamptz NOT NULL,
    package_artifact_id text CHECK (
        package_artifact_id IS NULL OR package_artifact_id ~
        '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    package_digest text CHECK (
        package_digest IS NULL OR package_digest ~ '^[0-9a-f]{64}$'
    ),
    package_bytes bigint CHECK (package_bytes IS NULL OR package_bytes BETWEEN 0 AND 67108864),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, site_id, export_id),
    FOREIGN KEY (tenant_id, site_id, export_id)
        REFERENCES xshield.investigation_exports (tenant_id, site_id, export_id)
        ON DELETE CASCADE,
    CHECK (
        isfinite(package_expires_at)
        AND isfinite(lease_until)
        AND isfinite(created_at)
        AND isfinite(updated_at)
        AND lease_until >= created_at
        AND updated_at >= created_at
    ),
    CHECK (
        (state = 'writing'
            AND package_artifact_id IS NULL
            AND package_digest IS NULL
            AND package_bytes IS NULL)
        OR (state = 'published'
            AND package_artifact_id IS NOT NULL
            AND package_digest IS NOT NULL
            AND package_bytes IS NOT NULL)
    )
);

CREATE INDEX investigation_export_package_claims_lease
    ON xshield.investigation_export_package_claims (tenant_id, site_id, state, lease_until);

COMMIT;
