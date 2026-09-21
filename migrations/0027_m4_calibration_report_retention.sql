-- M4 calibration report retention. Calibration report evidence has its own
-- authenticated sidecar and must not enter the request artifact catalog.
--
-- The report projection and frozen provenance remain available after expiry;
-- only the encrypted body becomes physically unavailable. Retention records a
-- durable intent before removal and a tombstone only after the owner reports a
-- directory-synced result. This supports recovery when removal succeeds but a
-- later database completion does not. The local vault and PostgreSQL commit
-- independently; an intent records a recoverable boundary, not cross-storage
-- atomicity.
BEGIN;

ALTER TABLE xshield.calibration_report_artifacts
    ADD COLUMN retention_status text NOT NULL DEFAULT 'active' CHECK (
        retention_status IN ('active', 'deleted')
    ),
    ADD COLUMN purge_requested_event_id text UNIQUE,
    ADD COLUMN purge_completed_event_id text UNIQUE,
    ADD COLUMN deleted_at timestamptz,
    ADD CONSTRAINT calibration_report_artifact_purge_intent_valid CHECK (
        purge_requested_event_id IS NULL OR purge_requested_event_id ~
        '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    ADD CONSTRAINT calibration_report_artifact_purge_completion_valid CHECK (
        purge_completed_event_id IS NULL OR (
            purge_completed_event_id ~
            '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            AND purge_requested_event_id IS NOT NULL
            AND retention_status = 'deleted'
            AND deleted_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT calibration_report_artifact_retention_terminal_valid CHECK (
        (retention_status = 'active' AND purge_completed_event_id IS NULL AND deleted_at IS NULL)
        OR (retention_status = 'deleted' AND purge_completed_event_id IS NOT NULL AND deleted_at IS NOT NULL)
    );

CREATE INDEX calibration_report_artifact_retention_candidates
    ON xshield.calibration_report_artifacts (tenant_id, site_id, key_ref, expires_at, artifact_id)
    WHERE retention_status = 'active';

COMMENT ON COLUMN xshield.calibration_report_artifacts.retention_status IS
    'Physical report-body availability. Deleted is a tombstone; report provenance remains retained.';

CREATE TABLE xshield.calibration_report_orphan_purges (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    report_id text NOT NULL UNIQUE CHECK (
        report_id ~ '^calr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    artifact_id text NOT NULL UNIQUE CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    storage_locator text NOT NULL CHECK (storage_locator = artifact_id || '.xev'),
    sidecar_digest text NOT NULL CHECK (sidecar_digest ~ '^[0-9a-f]{64}$'),
    observed_bytes bigint NOT NULL CHECK (observed_bytes >= 0 AND observed_bytes <= 67108893),
    observed_modified_seconds bigint NOT NULL CHECK (observed_modified_seconds >= 0),
    observed_modified_nanos integer NOT NULL CHECK (observed_modified_nanos BETWEEN 0 AND 999999999),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at)
        AND expires_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', expires_at) = expires_at
    ),
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

CREATE INDEX calibration_report_orphan_purge_pending
    ON xshield.calibration_report_orphan_purges (tenant_id, site_id, requested_at, artifact_id)
    WHERE status = 'pending';

COMMENT ON TABLE xshield.calibration_report_orphan_purges IS
    'Intent and tombstone for authenticated request-free report sidecars lacking committed report metadata; not artifact_catalog and not a cross-storage transaction.';

COMMIT;
