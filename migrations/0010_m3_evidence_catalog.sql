BEGIN;

CREATE TABLE xshield.artifact_catalog (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    artifact_id text NOT NULL CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    request_id text NOT NULL CHECK (
        request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    schema_version smallint NOT NULL CHECK (schema_version = 3),
    kind text NOT NULL CHECK (kind ~ '^[A-Za-z0-9_.-]{1,128}$'),
    content_type text NOT NULL CHECK (
        octet_length(content_type) BETWEEN 1 AND 256
        AND content_type !~ '[[:cntrl:]]'
    ),
    capture_status text NOT NULL CHECK (capture_status = 'complete'),
    fidelity text NOT NULL CHECK (
        fidelity IN ('entity_exact', 'semantic', 'redacted')
    ),
    bytes_observed bigint NOT NULL CHECK (
        bytes_observed BETWEEN 0 AND 67108864
    ),
    bytes_saved bigint NOT NULL CHECK (
        bytes_saved = bytes_observed
    ),
    classification text NOT NULL CHECK (
        classification IN ('INTERNAL', 'SENSITIVE', 'RESTRICTED')
    ),
    example_only boolean NOT NULL CHECK (NOT example_only),
    storage_profile text NOT NULL CHECK (storage_profile = 'aead_envelope_v1'),
    storage_locator text NOT NULL,
    key_ref text NOT NULL CHECK (key_ref ~ '^[A-Za-z0-9_.-]{1,128}$'),
    integrity_algorithm text NOT NULL CHECK (
        integrity_algorithm = 'sha256_ciphertext'
    ),
    integrity_digest text NOT NULL CHECK (
        integrity_digest ~ '^[0-9a-f]{64}$'
    ),
    parent_refs text[] NOT NULL CHECK (cardinality(parent_refs) <= 64),
    recorded_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > recorded_at),
    catalog_event_id text NOT NULL UNIQUE CHECK (
        catalog_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    status text NOT NULL CHECK (status IN ('active', 'deleted')),
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, site_id, artifact_id),
    CHECK (storage_locator = artifact_id || '.xev'),
    CHECK (
        (status = 'active' AND deleted_at IS NULL)
        OR (status = 'deleted' AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX artifact_request_lookup
    ON xshield.artifact_catalog (
        tenant_id, site_id, request_id, recorded_at, artifact_id
    )
    WHERE status = 'active' AND deleted_at IS NULL;

CREATE INDEX artifact_expiry_cleanup
    ON xshield.artifact_catalog (tenant_id, site_id, expires_at)
    WHERE status = 'active' AND deleted_at IS NULL;

COMMIT;
