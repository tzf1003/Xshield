BEGIN;

CREATE TABLE xshield.evidence_orphan_purges (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    artifact_id text NOT NULL CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    storage_locator text NOT NULL CHECK (storage_locator = artifact_id || '.xev'),
    observed_bytes bigint NOT NULL CHECK (observed_bytes >= 0 AND observed_bytes <= 67108893),
    observed_modified_seconds bigint NOT NULL CHECK (observed_modified_seconds >= 0),
    observed_modified_nanos integer NOT NULL CHECK (observed_modified_nanos BETWEEN 0 AND 999999999),
    authenticated_manifest boolean NOT NULL,
    requested_event_id text NOT NULL UNIQUE CHECK (
        requested_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    completed_event_id text UNIQUE CHECK (
        completed_event_id IS NULL OR completed_event_id ~
        '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    status text NOT NULL CHECK (status IN ('pending', 'deleted')),
    requested_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, site_id, artifact_id),
    CHECK (
        (status = 'pending' AND completed_event_id IS NULL AND completed_at IS NULL)
        OR (status = 'deleted' AND completed_event_id IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX evidence_orphan_purge_pending
    ON xshield.evidence_orphan_purges (tenant_id, site_id, requested_at, artifact_id)
    WHERE status = 'pending';

COMMIT;
