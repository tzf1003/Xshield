BEGIN;

ALTER TABLE xshield.artifact_catalog
    ADD COLUMN purge_requested_event_id text UNIQUE,
    ADD COLUMN purge_completed_event_id text UNIQUE,
    ADD CONSTRAINT artifact_purge_intent_valid CHECK (
        purge_requested_event_id IS NULL OR purge_requested_event_id ~
        '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    ADD CONSTRAINT artifact_purge_completion_valid CHECK (
        purge_completed_event_id IS NULL OR (
            purge_completed_event_id ~
            '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            AND purge_requested_event_id IS NOT NULL AND status = 'deleted'
        )
    );

CREATE INDEX artifact_retention_candidates
    ON xshield.artifact_catalog (tenant_id, site_id, key_ref, expires_at, artifact_id)
    WHERE status = 'active';

COMMIT;
